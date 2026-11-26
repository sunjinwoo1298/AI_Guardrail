"""Escalation across one agent session (policy.session).

Per-request scoring sees each message alone, so an attacker can try one variant after
another. Here every flagged or blocked request counts against its session; after
``max_events`` within ``window_seconds`` the whole session is refused for
``block_seconds``. Counters live in Redis (shared by all replicas), scoped per tenant.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from app.control.policy import Policy
from app.core.context import app_context
from app.core.logger import logger
from app.core.redis_client import get_redis, reset_redis

SESSION_HEADER = "x-guardrail-session"


def session_id_from(headers, payload: Optional[dict]) -> Optional[str]:
    """The client's session id: the x-guardrail-session header, else the OpenAI ``user``
    field or Anthropic ``metadata.user_id``."""
    value = headers.get(SESSION_HEADER) if headers is not None else None
    if not value and isinstance(payload, dict):
        value = payload.get("user")
        metadata = payload.get("metadata")
        if not value and isinstance(metadata, dict):
            value = metadata.get("user_id")
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:200]


def _keys(session_id: str):
    tenant = hashlib.sha256(app_context.get().encode("utf-8")).hexdigest()[:12]
    sid = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:24]
    return f"ai_proxy:session:{tenant}:{sid}:events", f"ai_proxy:session:{tenant}:{sid}:blocked"


def is_locked(policy: Policy, session_id: Optional[str]) -> bool:
    if not policy.session.enabled or not session_id:
        return False
    client = get_redis()
    if client is None:
        return False
    try:
        return bool(client.exists(_keys(session_id)[1]))
    except Exception as exc:
        reset_redis(exc)
        logger.warning(f"Session risk check unavailable: {exc}")
        return False


def record_event(policy: Policy, session_id: Optional[str]) -> bool:
    """Count one flagged / blocked request; returns True when this locks the session."""
    if not policy.session.enabled or not session_id:
        return False
    client = get_redis()
    if client is None:
        return False
    events_key, blocked_key = _keys(session_id)
    try:
        count = client.incr(events_key)
        if count == 1:
            client.expire(events_key, policy.session.window_seconds)
        if count >= policy.session.max_events:
            client.set(blocked_key, "1", ex=policy.session.block_seconds)
            client.delete(events_key)
            return True
    except Exception as exc:
        reset_redis(exc)
        logger.warning(f"Session risk tracking unavailable: {exc}")
    return False
