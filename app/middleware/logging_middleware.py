from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.observability.metrics import record_http_request, set_active_request_count
import time


_KNOWN_ENDPOINTS = ("/generate", "/stream", "/v1/chat/completions", "/v1/messages", "/v1/responses",
                    "/v1/guard/scan", "/v1/models", "/metrics", "/health", "/ready")


def normalize_endpoint(path: str) -> str:
    """A bounded label value. Raw paths (admin URLs with ids, MCP server names, random
    404 probes) used to become label values, so any caller could create unlimited
    Prometheus series."""
    for known in _KNOWN_ENDPOINTS:
        if path.startswith(known):
            return known
    if path.startswith("/admin/"):
        return "/admin"
    if path.startswith("/mcp/"):
        return "/mcp"
    if path in ("/", "/docs", "/redoc", "/openapi.json"):
        return path
    return "other"

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start_time = time.perf_counter()
        request_id = request.headers.get("x-request-id") or generate_request_id()
        request.state.request_id = request_id
        endpoint = normalize_endpoint(request.url.path)
        set_active_request_count(1)
        response = None
        status_code = 500
        try:
            response = await call_next(request)
            status_code = getattr(response, "status_code", 200)
            response.headers["x-request-id"] = request_id
            return response
        except Exception as e:
            logger.error(f"Error occurred while processing request: {str(e)}")
            status_code = 500
            raise 
        finally:
            process_time = time.perf_counter() - start_time
            set_active_request_count(-1)
            record_http_request(request.method, endpoint, status_code, process_time,
                                app=getattr(request.state, "app_name", None) or "anonymous")
            logger.info(
                f"Request: {request.method} {request.url} - Process Time: {process_time:.2f} seconds"
            )
