import json
import logging
from app.core.context import request_id_context


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or request_id_context.get() or "-",
        }
        for key in ("endpoint", "method", "status", "risk_score", "cache_hit", "cache_type", "reason"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
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

logger = logging.getLogger("ai_guardrail_proxy")
