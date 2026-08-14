import asyncio

from app.core.resilience import CircuitBreaker, CircuitOpenError, retry_async


def test_retry_async_retries_then_succeeds():
    attempts = {"count": 0}

    async def flaky():
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise TimeoutError("try again")
        return "ok"

    result = asyncio.run(
        retry_async(
            flaky,
            attempts=2,
            base_delay_seconds=0.0,
            retry_exceptions=(TimeoutError,),
        )
    )

    assert result == "ok"
    assert attempts["count"] == 3


def test_circuit_breaker_opens_after_threshold():
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout_seconds=60)

    assert breaker.allow() is True
    breaker.record_failure()
    assert breaker.allow() is True
    breaker.record_failure()
    assert breaker.allow() is False


def test_circuit_breaker_raises_for_open_circuit():
    breaker = CircuitBreaker(failure_threshold=1, reset_timeout_seconds=60)
    breaker.record_failure()

    assert breaker.allow() is False
    try:
        raise CircuitOpenError("circuit is open")
    except CircuitOpenError as exc:
        assert "open" in str(exc)
