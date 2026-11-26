from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")

# Upstream statuses that are worth retrying: rate limited, or a transient server error.
RETRYABLE_STATUS_CODES = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})


class CircuitOpenError(RuntimeError):
    pass


@dataclass
class CircuitBreaker:
    failure_threshold: int
    reset_timeout_seconds: float
    failure_count: int = 0
    opened_at: float | None = None

    def allow(self) -> bool:
        if self.opened_at is None:
            return True
        if (time.time() - self.opened_at) >= self.reset_timeout_seconds:
            self.failure_count = 0
            self.opened_at = None
            return True
        return False

    def record_success(self) -> None:
        self.failure_count = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.opened_at = time.time()


def _httpx():
    try:
        import httpx
        return httpx
    except ImportError:  # pragma: no cover
        return None


def is_transient_error(exc: BaseException) -> bool:
    """True for failures worth retrying or counting against a provider's health:
    network errors and timeouts, and 408/429/5xx responses.

    The retry list used to be (TimeoutError, ConnectionError, OSError), but httpx's
    ConnectError / ReadTimeout derive from httpx.HTTPError, not from those, and status
    errors were never retried either, so no provider call was ever retried.
    """
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, ConnectionError)):
        return True
    httpx = _httpx()
    if httpx is not None:
        if isinstance(exc, httpx.TransportError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in RETRYABLE_STATUS_CODES
    return False


def is_client_error(exc: BaseException) -> bool:
    """A non-retryable 4xx: the caller's request was wrong (bad schema, bad parameter).
    It must not count against the provider's circuit breaker, or one tenant sending bad
    requests would open the breaker for everyone."""
    status = getattr(exc, "status_code", None)
    if exc.__class__.__name__ == "HTTPException" and isinstance(status, int):
        return 400 <= status < 500  # raised by the proxy itself, e.g. a missing BYOK key
    httpx = _httpx()
    return (
        httpx is not None
        and isinstance(exc, httpx.HTTPStatusError)
        and 400 <= exc.response.status_code < 500
        and exc.response.status_code not in RETRYABLE_STATUS_CODES
    )


def _retry_after_seconds(exc: BaseException) -> Optional[float]:
    httpx = _httpx()
    if httpx is None or not isinstance(exc, httpx.HTTPStatusError):
        return None
    value = exc.response.headers.get("retry-after")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


async def retry_async(
    func: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    base_delay_seconds: float,
    retry_exceptions: tuple[type[BaseException], ...] = (),
    should_retry: Optional[Callable[[BaseException], bool]] = None,
    max_delay_seconds: float = 4.0,
) -> T:
    """Call ``func`` up to ``attempts + 1`` times with exponential backoff and jitter.

    An exception is retried if it is an instance of ``retry_exceptions`` or
    ``should_retry(exc)`` is true. A provider's Retry-After is honoured up to
    ``max_delay_seconds``; longer waits are not worth holding the request for.
    """
    last_exc: BaseException | None = None
    for attempt in range(attempts + 1):
        try:
            return await func()
        except BaseException as exc:  # noqa: B902 - filtered below
            retryable = isinstance(exc, retry_exceptions) if retry_exceptions else False
            if not retryable and should_retry is not None and isinstance(exc, Exception):
                retryable = should_retry(exc)
            if not retryable:
                raise
            last_exc = exc
            if attempt >= attempts:
                break
            retry_after = _retry_after_seconds(exc)
            if retry_after is not None and retry_after > max_delay_seconds:
                break  # the provider asked for a longer pause: fail over instead
            sleep_for = base_delay_seconds * (2 ** attempt) + random.uniform(0, base_delay_seconds)
            if retry_after is not None:
                sleep_for = max(sleep_for, retry_after)
            await asyncio.sleep(min(sleep_for, max_delay_seconds))
    assert last_exc is not None
    raise last_exc
