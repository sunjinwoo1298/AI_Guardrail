"""Standalone guardrail API: ``POST /v1/guard/scan``.

For customers who keep calling their model provider directly (or use a framework with its
own gateway): send the text, get the decision and a sanitized copy back. It applies the
same detectors, policy and audit trail as the proxy path; nothing is forwarded to a model.

Input scan (``direction: "input"``): prompt injection (tripwires, classifier, verifier),
PII, deny rules, session escalation. Output scan (``direction: "output"``): PII and
secrets, system-prompt canary leaks, exfiltration channels (images / links that would leak
data when rendered), deny rules. Either direction can include ``tool_calls`` (the calls an
agent's model wants to make), which are checked against the project's tool policy.
"""
from __future__ import annotations

import asyncio
import contextvars
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.control.policy import policy_for
from app.core.config import ENABLE_PII_MASKING, MAX_CHAT_INPUT_CHARS, get_app_policy, get_canaries
from app.core.context import app_context
from app.core.redis_client import get_redis
from app.middleware import security_middleware as sm
from app.observability.metrics import record_guardrail_decision
from app.security import session_risk
from app.security.agent_guard import check_tool_call, scrub_exfiltration
from app.security.decision import Decision, decide, deny_hits, masks_pii, relevant_pii
from app.security.pii_detector import detect_pii
from app.security.prompt_guard import tripwire_matches
from app.security.sanitizer import canonical_type, mask_pii
from app.security.session_risk import session_id_from

router = APIRouter(tags=["guard"])


class GuardScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    direction: Literal["input", "output"] = "input"
    # Either a single text or OpenAI-style messages (input direction: user / tool
    # messages are scanned, system and assistant messages are trusted).
    input: Optional[str] = None
    messages: Optional[List[Dict[str, Any]]] = None
    # Tool calls proposed by the model, OpenAI style ({"function": {"name", "arguments"}})
    # or flat ({"name", "arguments"}). Checked against policy.tools.
    tool_calls: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=50)

    @model_validator(mode="after")
    def _one_of(self):
        if self.input is not None and self.messages is not None:
            raise ValueError("send only one of 'input' or 'messages'")
        if self.input is None and self.messages is None and not self.tool_calls:
            raise ValueError("send 'input', 'messages' or 'tool_calls'")
        if self.direction == "output" and self.messages is not None:
            raise ValueError("output scans take 'input' (the model's text)")
        if self.input is not None and not self.input.strip():
            raise ValueError("input must not be empty")
        return self


def _too_long(total: int, limit: int) -> JSONResponse:
    return JSONResponse(status_code=413, content={"error": {
        "message": f"Input too long: {total} characters (limit {limit})",
        "type": "invalid_request_error", "code": "input_too_long"}})


async def _in_scan_pool(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(sm._SCAN_EXECUTOR, contextvars.copy_context().run, func, *args)


def _tool_results(policy, tool_calls) -> List[dict]:
    results = []
    for call in tool_calls or []:
        function = call.get("function") if isinstance(call.get("function"), dict) else call
        name = str(function.get("name", ""))
        reasons = check_tool_call(policy, name, function.get("arguments"))
        results.append({"name": name, "allowed": not reasons, "reasons": reasons})
    return results


@router.post("/v1/guard/scan")
async def guard_scan(request: Request, body: GuardScanRequest):
    policy = policy_for(app_context.get())
    limit = policy.max_input_chars or MAX_CHAT_INPUT_CHARS
    skip = frozenset(policy.pii.allow_entities)
    request_id = getattr(request.state, "request_id", None)
    tools = _tool_results(policy, body.tool_calls)
    tool_reasons = [r for t in tools for r in t["reasons"]]
    session_id = session_id_from(request.headers, None)
    session = {"id": session_id, "tracked": False, "locked": False}
    exfiltration: List[str] = []
    risk, pii, matches = 0.0, [], []
    sanitized: Dict[str, Any] = {}

    extra_blocks = []
    if session_id and policy.session.enabled:
        session["tracked"] = get_redis() is not None
        if not session["tracked"]:
            session["note"] = "Session tracking needs Redis, which the proxy cannot reach"
        elif session_risk.is_locked(policy, session_id):
            session["locked"] = True
            extra_blocks.append("session_locked")

    if body.direction == "input" and (body.input is not None or body.messages is not None):
        if body.messages is not None:
            segments = sm._untrusted_segments(body.messages)
        else:
            segments = [(0, None, body.input)]
        texts = [t for _, _, t in segments]
        if sum(len(t) for t in texts) > limit:
            return _too_long(sum(len(t) for t in texts), limit)
        risk, pii, signals, by_segment = await _in_scan_pool(sm._score_segments, segments)
        threshold = get_app_policy(app_context.get()).get("max_risk_score")
        injection_blocked = (sm.should_block_prompt(risk, signals) if threshold is None
                             else sm.should_block_prompt(risk, signals, max_risk_score=float(threshold)))
        decision = decide(policy, injection_blocked=injection_blocked, injection_signals=signals,
                          pii_detections=pii, deny=deny_hits(policy, texts), tool_reasons=tool_reasons,
                          media_types=sm.media_types(body.messages), extra_blocks=extra_blocks)
        mask = ENABLE_PII_MASKING and masks_pii(policy)
        if body.messages is not None:
            sanitized = {"messages": sm.sanitize_messages(body.messages, by_segment, skip_types=skip or None, mask=mask)}
        else:
            sanitized = {"input": mask_pii(body.input, by_segment.get((0, None)), skip) if mask else body.input}
        # The phrases that tripped the injection tripwires, so a reviewer can see what was
        # caught (it is the caller's own text).
        matches = [m for text in texts for m in tripwire_matches(text)][:20]
        injection = {"detected": bool(signals) or injection_blocked, "signals": len(signals), "matches": matches}
    elif body.input is not None:
        text = body.input
        if len(text) > limit:
            return _too_long(len(text), limit)
        pii = await _in_scan_pool(detect_pii, text)
        decision = decide(policy, injection_blocked=False, injection_signals=[], pii_detections=pii,
                          deny=deny_hits(policy, [text]), tool_reasons=tool_reasons, extra_blocks=extra_blocks)
        leaked = [c for c in get_canaries(app_context.get()) if c and c in text]
        if leaked:
            # The model repeated the system-prompt canary: its instructions are leaking.
            decision = _with_block(decision, "canary_leak", policy.mode)
        redacted = mask_pii(text, pii, skip) if policy.pii.action != "off" else text
        for canary in leaked:
            redacted = redacted.replace(canary, "[REDACTED_SYSTEM_PROMPT]")
        redacted, exfiltration = scrub_exfiltration(redacted, policy)
        if exfiltration:
            decision.flags.extend(r for r in exfiltration if r not in decision.flags)
            if decision.action == "allow":
                decision.action = "flag"
        sanitized = {"input": redacted}
        injection = {"detected": False, "signals": 0, "matches": []}
    else:  # tool calls only
        decision = decide(policy, injection_blocked=False, injection_signals=[], pii_detections=[],
                          tool_reasons=tool_reasons, extra_blocks=extra_blocks)
        injection = {"detected": False, "signals": 0, "matches": []}

    if session["tracked"] and decision.action != "allow" and decision.reasons != ["session_locked"]:
        if session_risk.record_event(policy, session_id):
            session["locked"] = True

    record_guardrail_decision(decision.action, surface="guard")
    if decision.blocked:
        # Count guard-scan blocks too; the "Blocked Prompts" dashboard panels read this.
        sm.record_security_block(sm._block_metric_reason(decision, injection.get("matches") or []))
    from app.control import metering

    metering.record(guard_scans=1)
    sm._audit_decision(request, decision, risk, pii, policy)
    return JSONResponse(
        headers={"x-guardrail-action": decision.action},
        content={
            "action": decision.action,
            "blocked": decision.blocked,
            "reasons": decision.all_reasons(),
            "risk_score": round(risk, 4),
            "direction": body.direction,
            "policy_mode": policy.mode,
            "detections": {
                "pii": relevant_pii(policy, pii),
                "pii_all": sorted({canonical_type(d.get("type", "")) for d in pii if isinstance(d, dict)}),
                "prompt_injection": injection,
                "deny": [r.split(":", 1)[1] for r in decision.all_reasons() if r.startswith("deny:")],
                "exfiltration": exfiltration,
                "tool_calls": tools,
            },
            "session": session,
            "sanitized": sanitized,
            "request_id": request_id,
        },
    )


def _with_block(decision: Decision, reason: str, mode: str) -> Decision:
    reasons = decision.reasons + [reason]
    return Decision("would_block" if mode == "monitor" else "block", reasons, decision.flags)
