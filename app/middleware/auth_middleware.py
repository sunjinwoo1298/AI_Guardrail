import asyncio
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import (
    API_KEY_APPS,
    MAX_REQUEST_BODY_BYTES,
    REQUIRE_API_KEY,
    RPM_LIMIT_PER_MINUTE,
    TPM_LIMIT_PER_MINUTE,
    get_app_policy,
)
from app.control import db as control_db
from app.control.crypto import looks_like_issued_key
from app.control.tenancy import KeyRejected, required_scope, resolve_key
from app.core.context import app_context, tenant_context
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.core.tokens import estimate_messages_tokens, estimate_text_tokens
from app.security.rate_limiter import UNAVAILABLE_REASON, check_and_consume


def _error(status: int, code: str, message: str, kind: str, headers=None) -> JSONResponse:
    return JSONResponse(status_code=status, headers=headers,
                        content={"error": {"message": message, "type": kind, "code": code}})


def _too_large(size: int) -> JSONResponse:
    return JSONResponse(status_code=413, content={"error": {
        "message": f"Request body too large: {size} bytes (limit {MAX_REQUEST_BODY_BYTES})",
        "type": "invalid_request_error",
        "code": "request_too_large",
    }})


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", None) or request.headers.get("x-request-id") or generate_request_id()
        if request.url.path in {"/health", "/ready", "/metrics", "/"}:
            return await call_next(request)

        # Reject oversized bodies before reading, parsing or scanning them.
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return _too_large(int(content_length))

        if request.url.path.startswith(("/generate", "/stream", "/v1/")) and REQUIRE_API_KEY:
            # Accept the proxy key as x-api-key or as "Authorization: Bearer <key>", which
            # is what the OpenAI SDKs send, so apps only change base_url and api_key.
            provided_key = request.headers.get("x-api-key", "").strip()
            auth_header = request.headers.get("authorization", "")
            if not provided_key and auth_header.lower().startswith("bearer "):
                provided_key = auth_header[7:].strip()
            tenant = None
            if provided_key and provided_key in API_KEY_APPS:
                # Env-configured key (API_KEYS): the single-team / self-hosted mode.
                request.state.api_key = provided_key
                request.state.app_name = API_KEY_APPS[provided_key]
            elif provided_key and control_db.enabled() and looks_like_issued_key(provided_key):
                # Control-plane key: resolved from the in-memory cache, or the database
                # in a worker thread on a miss.
                try:
                    tenant = await asyncio.to_thread(resolve_key, provided_key)
                except KeyRejected as rejected:
                    logger.warning("API key rejected (%s) for path=%s", rejected.code, request.url.path)
                    return _error(rejected.status, rejected.code, rejected.message,
                                  "authentication_error" if rejected.status == 401 else "permission_error")
                except Exception as exc:
                    logger.exception(f"Control plane unavailable while resolving a key: {exc}")
                    return _error(503, "control_plane_unavailable", "Authentication is temporarily unavailable",
                                  "service_unavailable", headers={"Retry-After": "5"})
                scope = required_scope(request.url.path)
                if scope and scope not in tenant.scopes:
                    return _error(403, "insufficient_scope", f"This API key does not have the '{scope}' scope",
                                  "permission_error")
                # Limits, settlement and cache scope follow the project, not the key.
                request.state.api_key = tenant.limit_key
                request.state.app_name = tenant.app_name
                request.state.tenant = tenant
                tenant_context.set(tenant)
            else:
                logger.warning("Unauthorized request rejected for path=%s", request.url.path)
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized"},
                )

            app_context.set(request.state.app_name)
            estimated_tokens = 0
            if request.url.path.startswith(("/generate", "/stream", "/v1/chat/completions", "/v1/guard")):
                try:
                    # Starlette caches the body read here and replays it to
                    # downstream handlers; overriding request._receive breaks
                    # disconnect detection and crashes streaming responses.
                    body = await request.body()
                    if len(body) > MAX_REQUEST_BODY_BYTES:  # chunked uploads carry no Content-Length
                        return _too_large(len(body))
                    if body:
                        import json
                        payload = json.loads(body.decode("utf-8"))
                        request.state.raw_payload = payload
                        if "messages" in payload:
                            estimated_tokens = estimate_messages_tokens(payload.get("messages", []))
                        else:
                            text = payload.get("prompt", payload.get("input", ""))
                            estimated_tokens = max(1, estimate_text_tokens(text if isinstance(text, str) else json.dumps(text)))
                except Exception:
                    estimated_tokens = 1

            rate_limit = check_and_consume(
                request.state.api_key,
                estimated_tokens,
                # Per-app limits from APP_POLICIES, else the global defaults.
                rpm_limit=int(get_app_policy(request.state.app_name).get("rpm", RPM_LIMIT_PER_MINUTE)),
                tpm_limit=int(get_app_policy(request.state.app_name).get("tpm", TPM_LIMIT_PER_MINUTE)),
            )
            request.state.rate_limit = rate_limit
            request.state.reserved_tokens = estimated_tokens
            if not rate_limit.allowed and rate_limit.reason == UNAVAILABLE_REASON:
                logger.error("Rate limiter unavailable and RATE_LIMIT_FAIL_MODE=closed; rejecting request")
                return JSONResponse(
                    status_code=503,
                    headers={"Retry-After": "5"},
                    content={"error": {
                        "message": "Rate limiting is temporarily unavailable; request rejected",
                        "type": "service_unavailable",
                        "code": "rate_limiter_unavailable",
                    }},
                )
            if not rate_limit.allowed:
                logger.warning("Rate limit exceeded for path=%s reason=%s", request.url.path, rate_limit.reason)
                # Limits use fixed 60s buckets, so the budget resets at the next minute boundary.
                retry_after = max(1, int(60 - (time.time() % 60)) + 1)
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                    content={
                        "retry_after_seconds": retry_after,
                        "error": "Rate limit exceeded",
                        "reason": rate_limit.reason,
                        "rpm_used": rate_limit.rpm_used,
                        "rpm_limit": rate_limit.rpm_limit,
                        "tpm_used": rate_limit.tpm_used,
                        "tpm_limit": rate_limit.tpm_limit,
                    },
                )

        return await call_next(request)
