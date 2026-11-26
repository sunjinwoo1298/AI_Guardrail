import asyncio
import contextvars
import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.control import audit
from app.control.policy import Policy, policy_for
from app.core.config import (
    AUDIT_LOG_ALLOWED_REQUESTS,
    ENABLE_PII_MASKING,
    MAX_CHAT_INPUT_CHARS,
    MAX_PROMPT_CHARS,
    get_app_policy,
)
from app.core.context import app_context, tenant_context
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.observability.tracing import trace
from app.observability.metrics import (
    record_guardrail_decision,
    record_security_block,
    record_security_event,
    record_security_risk,
)
from app.security.prompt_guard import detect_prompt_injection
from app.security.risk_engine import calculate_risk_score, should_block_prompt
from app.security import moderation, session_risk
from app.security.agent_guard import check_declared_tools
from app.security.decision import Decision, decide, deny_hits, masks_pii
from app.security.session_risk import session_id_from

# Content-part types that carry media the scanners cannot read (no OCR / ASR).
_MEDIA_PART_TYPES = {"image_url": "image", "image": "image", "input_image": "image", "input_audio": "audio",
                     "audio": "audio", "file": "file", "input_file": "file", "document": "file"}


def media_types(messages) -> list:
    """Media kinds in untrusted messages (policy.multimodal decides what happens to them)."""
    found = []
    for msg in messages if isinstance(messages, list) else []:
        if not isinstance(msg, dict) or msg.get("role") not in _UNTRUSTED_ROLES:
            continue
        content = msg.get("content")
        for part in content if isinstance(content, list) else []:
            if isinstance(part, dict) and part.get("type") in _MEDIA_PART_TYPES:
                kind = _MEDIA_PART_TYPES[part["type"]]
                if part.get("type") == "document" and (part.get("source") or {}).get("type") == "text":
                    continue  # plain-text documents are scanned as text
                if kind not in found:
                    found.append(kind)
    return found
from app.security.sanitizer import canonical_type, sanitize_text


def _block_metric_reason(decision: Decision, injection_detections: list) -> str:
    first = decision.reasons[0] if decision.reasons else "risk_score"
    if first.startswith("pii:"):
        return "pii"
    if first.startswith("deny:"):
        return "deny_rule"
    return "prompt_injection" if injection_detections else first


def _audit_decision(request, decision: Decision, risk_score: float, pii_detections: list, policy: Policy) -> None:
    """Blocks, flags and monitor-mode would-blocks are always audited; allowed requests
    only with AUDIT_LOG_ALLOWED_REQUESTS. Entity types and detector names only, no text."""
    if decision.action == "allow" and not AUDIT_LOG_ALLOWED_REQUESTS:
        return
    audit.record(
        f"request.{decision.action}",
        action=decision.action,
        reasons=decision.all_reasons(),
        risk_score=risk_score,
        details={
            "path": request.url.path,
            "policy_mode": policy.mode,
            "pii_types": sorted({canonical_type(d.get("type", "")) for d in pii_detections if isinstance(d, dict)}),
        },
        tenant=tenant_context.get(),
        app=app_context.get(),
        request_id=getattr(request.state, "request_id", None),
        monitor=decision.action == "would_block",
    )


def sanitize_messages(messages: list, detections_by_segment: Optional[dict] = None,
                      skip_types: Optional[frozenset] = None, mask: bool = True) -> list:
    """Mask PII in every message.

    Untrusted segments (user / tool text) are masked with the detections the scan
    already produced for them (Presidio + regex), keyed by (message index, part index or
    None). The chat path used to call sanitize_text() without detections, so only the
    regex patterns were masked and Presidio-only entities (IBAN, passport, driver's
    licence, ...) were scored but sent to the provider unmasked. Other roles get the
    regex pass, as before.
    """
    if not ENABLE_PII_MASKING or not mask:
        return messages
    detections_by_segment = detections_by_segment or {}

    def _mask(text, detections):
        # Only pass skip_types when set, so simple sanitize_text replacements still work.
        return sanitize_text(text, detections, skip_types) if skip_types else sanitize_text(text, detections)

    sanitized = []
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            sanitized.append(msg)
            continue
        new_msg = dict(msg)
        content = msg.get("content")
        if isinstance(content, str):
            new_msg["content"] = _mask(content, detections_by_segment.get((i, None)))
        elif isinstance(content, list):
            new_content = []
            for j, part in enumerate(content):
                if isinstance(part, dict) and part.get("type") == "text":
                    new_part = dict(part)
                    new_part["text"] = _mask(part.get("text", ""), detections_by_segment.get((i, j)))
                    new_content.append(new_part)
                else:
                    new_content.append(part)
            new_msg["content"] = new_content
        sanitized.append(new_msg)
    return sanitized


# Security scans (ONNX + Presidio, CPU-bound) run here, separate from the default pool that
# serves cache I/O. Scale beyond one core with more processes (WEB_CONCURRENCY).
_SCAN_EXECUTOR = ThreadPoolExecutor(
    max_workers=int(os.getenv("SECURITY_SCAN_THREADS", "4")), thread_name_prefix="security-scan"
)

# Roles whose content comes from outside the application: end users, and tool / function
# results (retrieved documents, web pages, API responses), where indirect prompt
# injection arrives. System prompts are the app's own instructions and stay trusted.
_UNTRUSTED_ROLES = {"user", "tool", "function"}


def _message_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def _untrusted_message_texts(messages) -> list:
    return [
        text
        for msg in messages if isinstance(msg, dict) and msg.get("role") in _UNTRUSTED_ROLES
        for text in [_message_text(msg.get("content"))] if text.strip()
    ]


def _untrusted_segments(messages) -> list:
    """(message index, part index or None, text) for every non-empty untrusted text."""
    segments = []
    if not isinstance(messages, list):
        return segments
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict) or msg.get("role") not in _UNTRUSTED_ROLES:
            continue
        content = msg.get("content")
        if isinstance(content, str):
            if content.strip():
                segments.append((i, None, content))
        elif isinstance(content, list):
            for j, part in enumerate(content):
                if isinstance(part, dict) and part.get("type") == "text":
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        segments.append((i, j, text))
    return segments


def _score_each(texts: list):
    """Score each untrusted message on its own and keep the riskiest. The injection
    classifier reads only the first ~512 tokens of its input, so one joined string
    would let an injection near the end of a long tool result slip past."""
    risk_score, pii_detections, injection_detections, _ = _score_segments(
        [(n, None, t) for n, t in enumerate(texts)])
    return risk_score, pii_detections, injection_detections


def _score_segments(segments: list):
    """Like _score_each, but also returns each segment's own PII detections (their
    offsets are relative to that segment), so the segment can be masked with them."""
    risk_score, pii_detections, injection_detections, by_segment = 0.0, [], [], {}
    for i, j, text in segments:
        score, pii, injections = calculate_risk_score(text)
        risk_score = max(risk_score, score)
        pii_detections.extend(pii)
        by_segment[(i, j)] = pii
        injection_detections.extend(x for x in injections if x not in injection_detections)
    return risk_score, pii_detections, injection_detections, by_segment


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", None) or request.headers.get("x-request-id") or generate_request_id()
        if request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        if not request.url.path.startswith(("/generate", "/stream", "/v1/chat/completions")):
            return await call_next(request)

        final_decision: Optional[Decision] = None
        try:
            payload = getattr(request.state, "raw_payload", None)
            if payload is None:
                body = await request.body()
                if not body:
                    return await call_next(request)
                payload = json.loads(body.decode("utf-8"))
            else:
                # Read the body so Starlette caches it and replays it downstream.
                # Do not override request._receive: that breaks streaming responses.
                await request.body()
            
            if not isinstance(payload, dict):
                return await call_next(request)  # the route's schema validation rejects it (422)

            policy = policy_for(app_context.get())
            mask_prompt = ENABLE_PII_MASKING and masks_pii(policy)
            skip_types = frozenset(policy.pii.allow_entities)

            # Extract prompt from messages array or prompt field
            if "messages" in payload:
                segments = _untrusted_segments(payload.get("messages"))
                untrusted_texts = [text for _, _, text in segments]
                prompt = "\n".join(untrusted_texts)
                # MAX_PROMPT_CHARS only covered /generate; chat payloads (long tool
                # results) were unbounded and every character goes through Presidio and
                # the classifier.
                total_chars = sum(len(t) for t in untrusted_texts)
                input_limit = policy.max_input_chars or MAX_CHAT_INPUT_CHARS
                if total_chars > input_limit:
                    return JSONResponse(
                        status_code=413,
                        content={"error": {
                            "message": f"Untrusted input too long: {total_chars} characters "
                                       f"(limit {input_limit})",
                            "type": "invalid_request_error",
                            "code": "input_too_long",
                        }},
                    )
            else:
                prompt = payload.get("prompt", "")
                untrusted_texts = [prompt] if isinstance(prompt, str) else []

            # Reject oversize prompts up front with a clear error. Previously they were
            # scanned (slow on long text) and reported as "blocked by security policy".
            if "messages" not in payload and isinstance(prompt, str) and len(prompt.strip()) > MAX_PROMPT_CHARS:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": f"Prompt too long: {len(prompt.strip())} characters (limit {MAX_PROMPT_CHARS})",
                        "max_prompt_chars": MAX_PROMPT_CHARS,
                    },
                )

            # The scan is CPU work (ONNX, Presidio) plus a possible verifier HTTP call. Run it
            # in a worker thread: done inline it blocked the event loop, so one slow scan
            # stalled every other request (p50 rose from ~45 ms idle to ~370 ms under load).
            # ONNX Runtime releases the GIL, so scans also run in parallel across cores.
            # A dedicated pool: when scans shared the default pool, overload queued the quick
            # Redis/Chroma lookups behind them until they timed out, and every timed-out
            # cache lookup became an extra (paid) model call.
            loop = asyncio.get_running_loop()
            ctx = contextvars.copy_context()  # keep app/request IDs for logs and metrics
            detections_by_segment = {}
            if "messages" in payload:
                risk_score, pii_detections, injection_detections, detections_by_segment = await loop.run_in_executor(
                    _SCAN_EXECUTOR, ctx.run, _score_segments, segments)
            else:
                risk_score, pii_detections, injection_detections = await loop.run_in_executor(
                    _SCAN_EXECUTOR, ctx.run, calculate_risk_score, prompt)
            def _mask(text, detections):
                return sanitize_text(text, detections, skip_types) if skip_types else sanitize_text(text, detections=detections)

            if not mask_prompt:
                sanitized_prompt = prompt
            elif "messages" in payload:
                # Detection offsets are per segment, so mask each segment with its own.
                sanitized_prompt = "\n".join(
                    _mask(text, detections_by_segment.get((i, j))) for i, j, text in segments
                )
            else:
                sanitized_prompt = _mask(prompt, pii_detections)
            app_threshold = get_app_policy(app_context.get()).get("max_risk_score")
            if app_threshold is None:
                injection_blocked = should_block_prompt(risk_score, injection_detections)
            else:
                injection_blocked = should_block_prompt(risk_score, injection_detections, max_risk_score=float(app_threshold))
            session_id = session_id_from(request.headers, payload)
            extra_blocks, extra_flags = [], []
            if session_risk.is_locked(policy, session_id):
                extra_blocks.append("session_locked")
            if moderation.wants(policy, "input") and untrusted_texts:
                verdict = await moderation.moderate([{"role": "user", "content": untrusted_texts[-1]}])
                mod_blocks, mod_flags = moderation.verdict_reasons(policy, verdict)
                extra_blocks += mod_blocks
                extra_flags += mod_flags
            decision = decide(policy, injection_blocked=injection_blocked, injection_signals=injection_detections,
                              pii_detections=pii_detections, deny=deny_hits(policy, untrusted_texts),
                              tool_reasons=check_declared_tools(policy, payload.get("tools") or payload.get("functions")),
                              media_types=media_types(payload.get("messages")),
                              extra_blocks=extra_blocks, extra_flags=extra_flags)
            if decision.action != "allow" and decision.reasons != ["session_locked"]:
                if session_risk.record_event(policy, session_id):
                    logger.warning("Session locked after repeated guardrail events")
            blocked = decision.blocked

            tracer = trace.get_tracer("ai_guardrail_proxy") if trace else None
            if tracer:
                try:
                    with tracer.start_as_current_span("middleware.security") as span:
                        if span and hasattr(span, "set_attribute"):
                            span.set_attribute("risk_score", risk_score)
                            span.set_attribute("pii_detected", bool(pii_detections))
                            span.set_attribute("prompt_injection_detected", bool(injection_detections))
                except Exception:
                    pass
            record_security_risk(risk_score)

            security_context = {
                "original_prompt": prompt,
                "sanitized_prompt": sanitized_prompt,
                "risk_score": round(risk_score, 2),
                "pii_detected": bool(pii_detections),
                "pii_detections": pii_detections,
                "prompt_injection_detected": bool(injection_detections),
                "prompt_injection_matches": injection_detections,
                "sanitized": sanitized_prompt != prompt,
                "blocked": blocked,
                "guardrail_action": decision.action,
                "guardrail_reasons": decision.all_reasons(),
                "policy_mode": policy.mode,
            }
            request.state.security_context = security_context
            
            # Save sanitized messages if messages exists
            if "messages" in payload:
                request.state.sanitized_messages = sanitize_messages(
                    payload.get("messages", []), detections_by_segment, skip_types=skip_types or None, mask=mask_prompt)
            else:
                request.state.sanitized_messages = None

            # Security events are counted once, in calculate_risk_score(); recording them
            # here as well double-counted every detection in Prometheus.
            if pii_detections:
                logger.warning(
                    "PII detected in prompt: %s",
                    ", ".join(sorted({item['type'] for item in pii_detections}))
                )

            if injection_detections:
                logger.warning(
                    "Prompt injection attempt detected: %s",
                    ", ".join(injection_detections)
                )

            logger.info(
                "Security score computed: risk_score=%s pii_detected=%s injection_detected=%s",
                security_context["risk_score"],
                security_context["pii_detected"],
                security_context["prompt_injection_detected"],
            )

            record_guardrail_decision(decision.action)
            _audit_decision(request, decision, risk_score, pii_detections, policy)

            if blocked:
                record_security_block(_block_metric_reason(decision, injection_detections))
                logger.warning(
                    "Prompt blocked by security policy: risk_score=%s path=%s",
                    security_context["risk_score"],
                    request.url.path,
                )
                return JSONResponse(
                    status_code=403,
                    headers={"x-guardrail-action": "block"},
                    content={
                        "error": "Prompt blocked due to security policy",
                        "code": "blocked_by_policy",
                        "reasons": decision.reasons,
                        "request_id": getattr(request.state, "request_id", None),
                        "risk_score": security_context["risk_score"],
                        "pii_detected": security_context["pii_detected"],
                        "prompt_injection_detected": security_context["prompt_injection_detected"],
                        "sanitized": security_context["sanitized"],
                    },
                )
            final_decision = decision

        except json.JSONDecodeError:
            logger.warning("Invalid JSON payload received by security middleware")
        except Exception as exc:
            # Fail closed: an unscreened prompt must never reach the model.
            logger.exception(f"Security middleware error, rejecting request: {exc}")
            return JSONResponse(
                status_code=503,
                content={"error": "Security screening unavailable, request rejected"},
            )

        response = await call_next(request)
        if final_decision is not None:
            response.headers["x-guardrail-action"] = final_decision.action
            if final_decision.action != "allow":
                response.headers["x-guardrail-reasons"] = ",".join(final_decision.all_reasons())[:500]
        return response
