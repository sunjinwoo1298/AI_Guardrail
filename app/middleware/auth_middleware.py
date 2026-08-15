from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import API_KEYS, REQUIRE_API_KEY, RPM_LIMIT_PER_MINUTE, TPM_LIMIT_PER_MINUTE
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.security.rate_limiter import check_and_consume


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", None) or request.headers.get("x-request-id") or generate_request_id()
        if request.url.path in {"/health", "/ready", "/metrics", "/"}:
            return await call_next(request)

        if request.url.path.startswith(("/generate", "/stream")) and REQUIRE_API_KEY:
            provided_key = request.headers.get("x-api-key", "").strip()
            if not provided_key or provided_key not in API_KEYS:
                logger.warning("Unauthorized request rejected for path=%s", request.url.path)
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized"},
                )

            request.state.api_key = provided_key
            estimated_tokens = 0
            if request.url.path.startswith(("/generate", "/stream")):
                try:
                    body = await request.body()
                    if body:
                        import json
                        payload = json.loads(body.decode("utf-8"))
                        prompt = str(payload.get("prompt", ""))
                        estimated_tokens = max(1, len(prompt) // 4)
                except Exception:
                    estimated_tokens = 1

            rate_limit = check_and_consume(
                provided_key,
                estimated_tokens,
                rpm_limit=RPM_LIMIT_PER_MINUTE,
                tpm_limit=TPM_LIMIT_PER_MINUTE,
            )
            request.state.rate_limit = rate_limit
            request.state.reserved_tokens = estimated_tokens
            if not rate_limit.allowed:
                logger.warning("Rate limit exceeded for path=%s reason=%s", request.url.path, rate_limit.reason)
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "reason": rate_limit.reason,
                        "rpm_used": rate_limit.rpm_used,
                        "rpm_limit": rate_limit.rpm_limit,
                        "tpm_used": rate_limit.tpm_used,
                        "tpm_limit": rate_limit.tpm_limit,
                    },
                )

        return await call_next(request)
