from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import logger
import time

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start_time = time.time()
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Error occurred while processing request: {str(e)}")
            raise 
        finally:
            process_time = time.time() - start_time
            logger.info(f"Request: {request.method} {request.url} - Process Time: {process_time:.2f} seconds")
            return response