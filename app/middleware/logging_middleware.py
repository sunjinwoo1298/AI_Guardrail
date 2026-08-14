from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.observability.metrics import record_http_request, set_active_request_count
import time


def normalize_endpoint(path: str) -> str:
    if path.startswith("/generate"):
        return "/generate"
    if path.startswith("/stream"):
        return "/stream"
    if path.startswith("/metrics"):
        return "/metrics"
    return path or "unknown"

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
            record_http_request(request.method, endpoint, status_code, process_time)
            logger.info(
                f"Request: {request.method} {request.url} - Process Time: {process_time:.2f} seconds"
            )
