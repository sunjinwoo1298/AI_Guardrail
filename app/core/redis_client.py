"""One shared, time-bounded Redis connection for the rate limiter, behaviour scoring and
the exact cache.

Each module used to build its own client without socket timeouts and, while Redis was
down, tried to reconnect (and ping) on every request. A hung Redis could therefore stall
the request path indefinitely. Connections now time out after REDIS_TIMEOUT_SECONDS and a
failed connect is retried at most every RECONNECT_INTERVAL_SECONDS.
"""
import threading
import time

try:
    import redis
except ImportError:  # pragma: no cover - optional in test environments
    redis = None

from app.core.config import REDIS_TIMEOUT_SECONDS, REDIS_URL
from app.core.logger import logger

RECONNECT_INTERVAL_SECONDS = 5.0

_client = None
_last_failure = 0.0
_lock = threading.Lock()


def get_redis():
    """The shared client, or None if Redis is unavailable right now."""
    global _client, _last_failure
    if _client is not None:
        return _client
    if redis is None:
        return None
    if time.monotonic() - _last_failure < RECONNECT_INTERVAL_SECONDS:
        return None
    with _lock:
        if _client is not None:
            return _client
        try:
            client = redis.Redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                health_check_interval=30,
            )
            client.ping()
            _client = client
            logger.info("Redis connection established")
        except Exception as exc:
            _last_failure = time.monotonic()
            logger.warning(f"Redis unavailable: {exc}")
            return None
    return _client


def reset_redis(exc: BaseException = None) -> None:
    """Drop the client after a connection error so the next call reconnects (with backoff)."""
    global _client, _last_failure
    if exc is not None and redis is not None and not isinstance(
        exc, (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError)
    ):
        return
    with _lock:
        _client = None
        _last_failure = time.monotonic()


def ping() -> bool:
    client = get_redis()
    if client is None:
        return False
    try:
        return bool(client.ping())
    except Exception as exc:
        reset_redis(exc)
        return False
