import logging
from app.core.context import request_id_context


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_context.get() or "-"
        return True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [request_id=%(request_id)s] %(message)s"
)

logger = logging.getLogger(__name__)
logger.addFilter(RequestIdFilter())
