import json
import logging
from app.core.context import app_context, request_id_context


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or request_id_context.get() or "-",
            "app": app_context.get(),
        }
        for key in ("endpoint", "method", "status", "risk_score", "cache_hit", "cache_type", "reason"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        # Keep tracebacks: logger.exception() output was silently dropped before.
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class RequestContextFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_context.get() or "-"
        return True


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers = [handler]
root_logger.addFilter(RequestContextFilter())

# httpx/httpcore log every request URL at INFO. Keep them at WARNING so a provider
# that puts credentials in a URL can never write them to the logs.
for _noisy in ("httpx", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("ai_guardrail_proxy")
