import json

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import ENABLE_PII_MASKING
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.observability.tracing import trace
from app.observability.metrics import (
    record_security_block,
    record_security_event,
    record_security_risk,
)
from app.security.prompt_guard import detect_prompt_injection
from app.security.risk_engine import calculate_risk_score, should_block_prompt
from app.security.sanitizer import sanitize_text


def sanitize_messages(messages: list[dict]) -> list[dict]:
    if not ENABLE_PII_MASKING:
        return messages
    sanitized = []
    for msg in messages:
        if not isinstance(msg, dict):
            sanitized.append(msg)
            continue
        new_msg = dict(msg)
        content = msg.get("content")
        if isinstance(content, str):
            new_msg["content"] = sanitize_text(content)
        elif isinstance(content, list):
            new_content = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    new_part = dict(part)
                    new_part["text"] = sanitize_text(part.get("text", ""))
                    new_content.append(new_part)
                else:
                    new_content.append(part)
            new_msg["content"] = new_content
        sanitized.append(new_msg)
    return sanitized


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", None) or request.headers.get("x-request-id") or generate_request_id()
        if request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        if not request.url.path.startswith(("/generate", "/stream", "/v1/chat/completions")):
            return await call_next(request)

        try:
            payload = getattr(request.state, "raw_payload", None)
            if payload is None:
                body = await request.body()
                if not body:
                    return await call_next(request)
                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}
                request._receive = receive
                payload = json.loads(body.decode("utf-8"))
            else:
                body = await request.body()
                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}
                request._receive = receive
            
            # Extract prompt from messages array or prompt field
            if "messages" in payload:
                messages = payload.get("messages", [])
                user_contents = []
                for msg in messages:
                    if isinstance(msg, dict) and msg.get("role") == "user":
                        content = msg.get("content")
                        if isinstance(content, str):
                            user_contents.append(content)
                        elif isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "text":
                                    user_contents.append(part.get("text", ""))
                prompt = "\n".join(user_contents)
            else:
                prompt = payload.get("prompt", "")

            risk_score, pii_detections, injection_detections = calculate_risk_score(prompt)
            if ENABLE_PII_MASKING:
                try:
                    sanitized_prompt = sanitize_text(prompt, detections=pii_detections)
                except TypeError:
                    sanitized_prompt = sanitize_text(prompt)
            else:
                sanitized_prompt = prompt
            blocked = should_block_prompt(risk_score, injection_detections)

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
            }
            request.state.security_context = security_context
            
            # Save sanitized messages if messages exists
            if "messages" in payload:
                request.state.sanitized_messages = sanitize_messages(payload.get("messages", []))
            else:
                request.state.sanitized_messages = None

            if pii_detections:
                record_security_event("pii", "detected")
                logger.warning(
                    "PII detected in prompt: %s",
                    ", ".join(sorted({item['type'] for item in pii_detections}))
                )

            if injection_detections:
                record_security_event("prompt_injection", "detected")
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

            if blocked:
                record_security_block("prompt_injection" if injection_detections else "risk_score")
                logger.warning(
                    "Prompt blocked by security policy: risk_score=%s path=%s",
                    security_context["risk_score"],
                    request.url.path,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Prompt blocked due to security policy",
                        "risk_score": security_context["risk_score"],
                        "pii_detected": security_context["pii_detected"],
                        "prompt_injection_detected": security_context["prompt_injection_detected"],
                        "sanitized": security_context["sanitized"],
                    },
                )

        except json.JSONDecodeError:
            logger.warning("Invalid JSON payload received by security middleware")
        except Exception as exc:
            logger.error(f"Security middleware failed open due to error: {exc}")

        return await call_next(request)
