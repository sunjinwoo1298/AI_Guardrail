import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Tuple

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

from app.core.config import (
    BEHAVIOR_RISK_WINDOW_SECONDS,
    REDIS_URL,
)
from app.core.logger import logger

RPM_WINDOW_SECONDS = 60
TPM_WINDOW_SECONDS = 60
DEFAULT_REQUEST_WEIGHT = 1
_redis_client = None

_RATE_LIMIT_LUA = """
local rpm_key = KEYS[1]
local tpm_key = KEYS[2]
local rpm_limit = tonumber(ARGV[1])
local tpm_limit = tonumber(ARGV[2])
local rpm_window = tonumber(ARGV[3])
local tpm_window = tonumber(ARGV[4])
local request_weight = tonumber(ARGV[5])
local token_weight = tonumber(ARGV[6])

local rpm_used = tonumber(redis.call('GET', rpm_key) or '0')
local tpm_used = tonumber(redis.call('GET', tpm_key) or '0')

if (rpm_used + request_weight) > rpm_limit then
    return {0, 'rpm_exceeded', rpm_used, tpm_used}
end

if (tpm_used + token_weight) > tpm_limit then
    return {0, 'tpm_exceeded', rpm_used, tpm_used}
end

rpm_used = redis.call('INCRBY', rpm_key, request_weight)
if rpm_used == request_weight then
    redis.call('EXPIRE', rpm_key, rpm_window)
end

tpm_used = redis.call('INCRBY', tpm_key, token_weight)
if tpm_used == token_weight then
    redis.call('EXPIRE', tpm_key, tpm_window)
end

return {1, 'allowed', rpm_used, tpm_used}
"""

_REFUND_LUA = """
local tpm_key = KEYS[1]
local refund = tonumber(ARGV[1])
local tpm_window = tonumber(ARGV[2])
local current = tonumber(redis.call('GET', tpm_key) or '0')
local next_value = current - refund
if next_value < 0 then
    next_value = 0
end
redis.call('SET', tpm_key, next_value)
redis.call('EXPIRE', tpm_key, tpm_window)
return next_value
"""


@dataclass
class RateLimitResult:
    allowed: bool
    reason: Optional[str] = None
    rpm_used: int = 0
    tpm_used: int = 0
    rpm_limit: int = 0
    tpm_limit: int = 0


def _get_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if redis is None:
        return None
    try:
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
    except Exception as exc:
        logger.warning(f"Rate limiter Redis unavailable: {exc}")
        _redis_client = None
    return _redis_client


def _eval(client, script: str, keys: list[str], args: list[object]):
    if hasattr(client, "evalsha"):
        try:
            sha = hashlib.sha1(script.encode("utf-8")).hexdigest()
            return client.evalsha(sha, len(keys), *keys, *args)
        except Exception:
            pass
    return client.eval(script, len(keys), *keys, *args)


def _key(api_key: str, kind: str, window: int) -> str:
    fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    bucket = int(time.time() // window)
    return f"ai_proxy:rl:{kind}:{fingerprint}:{bucket}"


def _default_limits(api_key: str) -> Tuple[int, int]:
    # Lightweight defaults; can be moved to config later.
    return 120, 12000


def check_and_consume(api_key: str, request_tokens: int, rpm_limit: int = 120, tpm_limit: int = 12000) -> RateLimitResult:
    client = _get_client()
    if client is None:
        return RateLimitResult(allowed=True, rpm_limit=rpm_limit, tpm_limit=tpm_limit)

    rpm_key = _key(api_key, "rpm", RPM_WINDOW_SECONDS)
    tpm_key = _key(api_key, "tpm", TPM_WINDOW_SECONDS)

    try:
        allowed, reason, rpm_used, tpm_used = _eval(
            client,
            _RATE_LIMIT_LUA,
            [rpm_key, tpm_key],
            [
                rpm_limit,
                tpm_limit,
                RPM_WINDOW_SECONDS,
                TPM_WINDOW_SECONDS,
                DEFAULT_REQUEST_WEIGHT,
                max(0, request_tokens),
            ],
        )
        allowed = int(allowed) == 1
        rpm_used = int(rpm_used)
        tpm_used = int(tpm_used)
        reason = str(reason)
        if not allowed:
            return RateLimitResult(
                allowed=False,
                reason=reason,
                rpm_used=rpm_used,
                tpm_used=tpm_used,
                rpm_limit=rpm_limit,
                tpm_limit=tpm_limit,
            )

        return RateLimitResult(
            allowed=True,
            rpm_used=rpm_used,
            tpm_used=tpm_used,
            rpm_limit=rpm_limit,
            tpm_limit=tpm_limit,
        )
    except Exception as exc:
        logger.warning(f"Rate limiter failed open: {exc}")
        return RateLimitResult(allowed=True, rpm_limit=rpm_limit, tpm_limit=tpm_limit)


def refund_tokens(api_key: str, tokens: int):
    client = _get_client()
    if client is None or tokens <= 0:
        return
    try:
        tpm_key = _key(api_key, "tpm", TPM_WINDOW_SECONDS)
        _eval(client, _REFUND_LUA, [tpm_key], [max(0, tokens), TPM_WINDOW_SECONDS])
    except Exception as exc:
        logger.warning(f"Failed to refund token usage: {exc}")


def settle_tokens(api_key: str, reserved_tokens: int, actual_tokens: int):
    reserved_tokens = max(0, reserved_tokens)
    actual_tokens = max(0, actual_tokens)
    if actual_tokens > reserved_tokens:
        record_token_usage(api_key, actual_tokens - reserved_tokens)
    elif reserved_tokens > actual_tokens:
        refund_tokens(api_key, reserved_tokens - actual_tokens)


def record_token_usage(api_key: str, tokens: int):
    client = _get_client()
    if client is None:
        return
    try:
        tpm_key = _key(api_key, "tpm", TPM_WINDOW_SECONDS)
        client.incrby(tpm_key, max(0, tokens))
        client.expire(tpm_key, TPM_WINDOW_SECONDS)
    except Exception as exc:
        logger.warning(f"Failed to record token usage: {exc}")
