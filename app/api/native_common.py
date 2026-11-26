"""Shared machinery for the provider-native endpoints (/v1/messages, /v1/responses).

These endpoints forward the provider's own request format instead of translating it, so
SDKs and agents built on those APIs (Anthropic SDK, Claude-based agents, OpenAI
Responses / Agents SDK) can point their base URL at the proxy and keep every feature.
The guardrails are the same as on /v1/chat/completions: untrusted text is scanned and
masked in place, output is redacted, and tool calls are checked against the policy.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import time
from typing import Any, AsyncIterator, Callable, List, Optional, Tuple

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse

from app.control.policy import Policy, policy_for
from app.core.config import (
    ENABLE_PII_MASKING,
    GROQ_RETRY_ATTEMPTS,
    GROQ_RETRY_BASE_DELAY_SECONDS,
    MAX_CHAT_INPUT_CHARS,
    RETRY_MAX_DELAY_SECONDS,
    get_app_policy,
)
from app.core.context import app_context, request_id_context
from app.core.logger import logger
from app.core.resilience import is_transient_error, retry_async
from app.middleware import security_middleware as sm
from app.observability.metrics import record_guardrail_decision, record_model_observation, record_security_block
from app.providers.http import get_http_client
from app.security import moderation, session_risk
from app.security.agent_guard import check_declared_tools
from app.security.decision import Decision, decide, deny_hits, masks_pii
from app.security.rate_limiter import refund_tokens, settle_tokens
from app.security.sanitizer import _redact_plain, sanitize_text
from app.security.session_risk import session_id_from


class TextSlots:
    """Locations of untrusted text inside a provider-native request body: each slot is a
    (container, key) pair whose value is a string, so masked text can be written back."""

    def __init__(self):
        self.slots: List[Tuple[Any, Any]] = []
        self.media: List[str] = []

    def add(self, container, key) -> None:
        value = container.get(key) if isinstance(container, dict) else None
        if isinstance(value, str) and value.strip():
            self.slots.append((container, key))

    def texts(self) -> List[str]:
        return [container[key] for container, key in self.slots]

    def note_media(self, kind: str) -> None:
        if kind not in self.media:
            self.media.append(kind)


def error_response(status: int, code: str, message: str, kind: str = "invalid_request_error", **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"message": message, "type": kind, "code": code, **extra}})


async def guard_input(request: Request, payload: dict, slots: TextSlots, *, tools_param: Any,
                      surface: str) -> Tuple[Optional[JSONResponse], Decision, Policy]:
    """Scan, decide and mask in place. Returns (blocking response or None, decision, policy)."""
    policy = policy_for(app_context.get())
    texts = slots.texts()
    limit = policy.max_input_chars or MAX_CHAT_INPUT_CHARS
    total = sum(len(t) for t in texts)
    if total > limit:
        return error_response(413, "input_too_long", f"Untrusted input too long: {total} characters (limit {limit})"), \
            Decision(), policy

    segments = [(k, None, text) for k, text in enumerate(texts)]
    loop = asyncio.get_running_loop()
    risk, pii, signals, by_segment = await loop.run_in_executor(
        sm._SCAN_EXECUTOR, contextvars.copy_context().run, sm._score_segments, segments)
    threshold = get_app_policy(app_context.get()).get("max_risk_score")
    injection_blocked = (sm.should_block_prompt(risk, signals) if threshold is None
                         else sm.should_block_prompt(risk, signals, max_risk_score=float(threshold)))

    session_id = session_id_from(request.headers, payload)
    extra_blocks, extra_flags = [], []
    if session_risk.is_locked(policy, session_id):
        extra_blocks.append("session_locked")
    if moderation.wants(policy, "input") and texts:
        verdict = await moderation.moderate([{"role": "user", "content": texts[-1]}])
        mod_blocks, mod_flags = moderation.verdict_reasons(policy, verdict)
        extra_blocks += mod_blocks
        extra_flags += mod_flags
    decision = decide(policy, injection_blocked=injection_blocked, injection_signals=signals, pii_detections=pii,
                      deny=deny_hits(policy, texts), tool_reasons=check_declared_tools(policy, tools_param),
                      media_types=slots.media, extra_blocks=extra_blocks, extra_flags=extra_flags)
    if decision.action != "allow" and decision.reasons != ["session_locked"]:
        session_risk.record_event(policy, session_id)
    record_guardrail_decision(decision.action, surface=surface)
    sm._audit_decision(request, decision, risk, pii, policy)

    if decision.blocked:
        record_security_block(sm._block_metric_reason(decision, signals))
        return JSONResponse(status_code=403, headers={"x-guardrail-action": "block"}, content={"error": {
            "message": "Request blocked by the guardrail policy", "type": "permission_error",
            "code": "blocked_by_policy", "reasons": decision.reasons,
            "request_id": getattr(request.state, "request_id", None)}}), decision, policy

    if ENABLE_PII_MASKING and masks_pii(policy):
        skip = frozenset(policy.pii.allow_entities)
        for k, (container, key) in enumerate(slots.slots):
            detections = by_segment.get((k, None))
            container[key] = (sanitize_text(container[key], detections, skip) if skip
                              else sanitize_text(container[key], detections))
    return None, decision, policy


def redact_value(value: Any) -> Any:
    """Redact every string inside a JSON value (tool arguments, structured output),
    keeping the structure, so the result is always valid JSON."""
    if isinstance(value, str):
        return _redact_plain(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value


def guardrail_headers(decision: Decision) -> dict:
    headers = {"x-guardrail-action": decision.action}
    if decision.action != "allow":
        headers["x-guardrail-reasons"] = ",".join(decision.all_reasons())[:500]
    return headers


# --- upstream calls ---------------------------------------------------------------------------

async def post_json(url: str, headers: dict, body: dict) -> httpx.Response:
    """POST with retries on transient failures. Returns the final response; non-2xx
    responses are returned, not raised, so the caller can pass the provider's error on."""
    async def attempt():
        response = await get_http_client().post(url, headers=headers, json=body)
        if response.status_code >= 400 and is_transient_error(_status_error(response)):
            raise _status_error(response)
        return response

    try:
        return await retry_async(attempt, attempts=GROQ_RETRY_ATTEMPTS, base_delay_seconds=GROQ_RETRY_BASE_DELAY_SECONDS,
                                 should_retry=is_transient_error, max_delay_seconds=RETRY_MAX_DELAY_SECONDS)
    except httpx.HTTPStatusError as exc:
        return exc.response


async def open_stream(url: str, headers: dict, body: dict) -> httpx.Response:
    """Open a streaming POST (retrying transient failures before any byte is relayed).
    The caller must ``aclose()`` the response."""
    async def attempt():
        client = get_http_client()
        response = await client.send(client.build_request("POST", url, headers=headers, json=body), stream=True)
        if response.status_code >= 400:
            await response.aread()
            await response.aclose()
            if is_transient_error(_status_error(response)):
                raise _status_error(response)
        return response

    try:
        return await retry_async(attempt, attempts=GROQ_RETRY_ATTEMPTS, base_delay_seconds=GROQ_RETRY_BASE_DELAY_SECONDS,
                                 should_retry=is_transient_error, max_delay_seconds=RETRY_MAX_DELAY_SECONDS)
    except httpx.HTTPStatusError as exc:
        return exc.response


def _status_error(response: httpx.Response) -> httpx.HTTPStatusError:
    return httpx.HTTPStatusError(f"upstream {response.status_code}", request=response.request, response=response)


def upstream_error(response: httpx.Response) -> JSONResponse:
    """Pass the provider's own error through (status and body), as its SDK expects."""
    try:
        body = response.json()
    except ValueError:
        body = {"error": {"message": f"Upstream provider returned {response.status_code}", "type": "upstream_error"}}
    headers = {}
    if response.headers.get("retry-after"):
        headers["Retry-After"] = response.headers["retry-after"]
    return JSONResponse(status_code=response.status_code, content=body, headers=headers)


async def sse_events(response: httpx.Response) -> AsyncIterator[Tuple[Optional[str], str]]:
    """(event name, data) pairs from a server-sent-events body."""
    event, data = None, []
    async for line in response.aiter_lines():
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = None, []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        yield event, "\n".join(data)


def sse(event: Optional[str], data: Any) -> str:
    payload = data if isinstance(data, str) else json.dumps(data, separators=(",", ":"))
    return (f"event: {event}\n" if event else "") + f"data: {payload}\n\n"


# --- accounting -------------------------------------------------------------------------------

def settle(request: Request, *, model_label: str, endpoint: str, started: float,
           input_tokens: int, output_tokens: int, ok: bool = True) -> None:
    """Rate-limit settlement, cost and model metrics for one native call."""
    from app.services.llm_orchestrator import _priced_cost

    api_key = getattr(request.state, "api_key", None)
    reserved = getattr(request.state, "reserved_tokens", 0) or 0
    try:
        if api_key:
            if ok:
                settle_tokens(api_key, reserved, input_tokens + output_tokens)
            else:
                refund_tokens(api_key, reserved)
        cost = _priced_cost(model_label, input_tokens, output_tokens) if ok else 0.0
        record_model_observation(endpoint=endpoint, cache_hit=False, cache_type="generated" if ok else "error",
                                 latency_seconds=time.time() - started, prompt_tokens=input_tokens,
                                 completion_tokens=output_tokens, total_tokens=input_tokens + output_tokens,
                                 estimated_cost=cost)
    except Exception as exc:  # accounting must never fail a response
        logger.warning(f"Usage accounting failed for {endpoint}: {exc}")


async def moderate_output(policy: Policy, question: str, answer: str):
    """Output moderation verdict (Decision) or None when off."""
    if not moderation.wants(policy, "output") or not answer:
        return None
    from app.security.agent_guard import audit_output
    from app.security.decision import output_decision

    verdict = await moderation.moderate([{"role": "user", "content": question}, {"role": "assistant", "content": answer}])
    blocks, flags = moderation.verdict_reasons(policy, verdict)
    decision = output_decision(policy, blocks, "block") if blocks else output_decision(policy, flags, "flag")
    audit_output(policy, surface="moderation", decision=decision)
    return decision


def current_request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None) or request_id_context.get()
