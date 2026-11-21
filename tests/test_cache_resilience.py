import asyncio
import json
import logging
import time

from app.core.logger import JsonFormatter
from app.services import cache_service


def test_slow_redis_lookup_is_a_cache_miss_not_an_error(monkeypatch):
    class SlowRedis:
        def get(self, key):
            time.sleep(cache_service.REDIS_TIMEOUT_SECONDS + 0.3)
            return None

    monkeypatch.setattr(cache_service, "get_redis_client", lambda: SlowRedis())
    assert asyncio.run(cache_service.get_exact_cache("hello", "groq/openai/gpt-oss-20b")) is None


def test_json_logs_keep_tracebacks():
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.getLogger("t").makeRecord("t", logging.ERROR, __file__, 1, "failed", None, __import__("sys").exc_info())
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]
