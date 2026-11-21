import time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import API_KEY_APPS, API_KEYS, REQUIRE_API_KEY, get_app_policy, RPM_LIMIT_PER_MINUTE, TPM_LIMIT_PER_MINUTE
from app.core.context import app_context
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.core.tokens import estimate_messages_tokens, estimate_text_tokens
from app.security.rate_limiter import check_and_consume


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", None) or request.headers.get("x-request-id") or generate_request_id()
        if request.url.path in {"/health", "/ready", "/metrics", "/"}:
            return await call_next(request)

        if request.url.path.startswith(("/generate", "/stream", "/v1/")) and REQUIRE_API_KEY:
            # Accept the proxy key as x-api-key or as "Authorization: Bearer <key>", which
            # is what the OpenAI SDKs send, so apps only change base_url and api_key.
            provided_key = request.headers.get("x-api-key", "").strip()
            auth_header = request.headers.get("authorization", "")
            if not provided_key and auth_header.lower().startswith("bearer "):
                provided_key = auth_header[7:].strip()
            if not provided_key or provided_key not in API_KEYS:
                logger.warning("Unauthorized request rejected for path=%s", request.url.path)
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized"},
                )

            request.state.api_key = provided_key
            request.state.app_name = API_KEY_APPS.get(provided_key, "anonymous")
            app_context.set(request.state.app_name)
            estimated_tokens = 0
            if request.url.path.startswith(("/generate", "/stream", "/v1/chat/completions")):
                try:
                    # Starlette caches the body read here and replays it to
                    # downstream handlers; overriding request._receive breaks
                    # disconnect detection and crashes streaming responses.
                    body = await request.body()
                    if body:
                        import json
                        payload = json.loads(body.decode("utf-8"))
                        request.state.raw_payload = payload
                        if "messages" in payload:
                            estimated_tokens = estimate_messages_tokens(payload.get("messages", []))
                        else:
                            estimated_tokens = max(1, estimate_text_tokens(str(payload.get("prompt", ""))))
                except Exception:
                    estimated_tokens = 1

            rate_limit = check_and_consume(
                provided_key,
                estimated_tokens,
                # Per-app limits from APP_POLICIES, else the global defaults.
                rpm_limit=int(get_app_policy(request.state.app_name).get("rpm", RPM_LIMIT_PER_MINUTE)),
                tpm_limit=int(get_app_policy(request.state.app_name).get("tpm", TPM_LIMIT_PER_MINUTE)),
            )
            request.state.rate_limit = rate_limit
            request.state.reserved_tokens = estimated_tokens
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
