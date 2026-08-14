from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import API_KEYS, REQUIRE_API_KEY
from app.core.logger import logger
from app.core.request_id import generate_request_id


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

        return await call_next(request)
