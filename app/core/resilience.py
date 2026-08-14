import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


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


async def retry_async(
    func: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    base_delay_seconds: float,
    retry_exceptions: tuple[type[BaseException], ...],
) -> T:
    last_exc: BaseException | None = None
    for attempt in range(attempts + 1):
        try:
            return await func()
        except retry_exceptions as exc:
            last_exc = exc
            if attempt >= attempts:
                break
            sleep_for = base_delay_seconds * (2 ** attempt)
            sleep_for += random.uniform(0, base_delay_seconds)
            await asyncio.sleep(sleep_for)
    assert last_exc is not None
    raise last_exc
