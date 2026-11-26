"""Signed event webhooks (per organization) and the operator-wide SIEM feed.

Every audit event that is persisted is offered to the webhooks of its organization whose
``event_types`` patterns match (e.g. ``request.block``, ``admin.*``, ``budget.*``), and to
AUDIT_SIEM_WEBHOOK_URL when configured. Payloads contain the audit event only: never
prompt or response text.

Signing (Stripe-style), so receivers can reject forged or replayed calls::

    X-Guardrail-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, f"{t}.{body}")>

Deliveries run on a background thread with retries (1 s, 5 s, 30 s); a webhook is
disabled after 20 consecutive failed events. Targets must be public HTTPS URLs (SSRF
protection) unless WEBHOOK_ALLOW_PRIVATE_TARGETS is set for local development.
"""
from __future__ import annotations

import hashlib
import heapq
import hmac
import ipaddress
import json
import secrets
import socket
import threading
import time
import uuid
from fnmatch import fnmatchcase
from typing import Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import select

from app.control import db
from app.control.crypto import decrypt_secret, encrypt_secret
from app.control.models import Webhook, utcnow
from app.core import config
from app.core.logger import logger

RETRY_DELAYS = [1.0, 5.0, 30.0]
DISABLE_AFTER_FAILURES = 20
DELIVERY_TIMEOUT_SECONDS = 5.0
SIEM = "siem"

_queue: list = []  # heap of (due_at, seq, delivery)
_queue_lock = threading.Condition()
_seq = {"n": 0}
_worker: Optional[threading.Thread] = None
_cache: Dict[str, tuple] = {}  # org_id -> (fetched_at, [webhook dicts])
_CACHE_TTL = 30.0


class InvalidTarget(ValueError):
    pass


# --- signing ---------------------------------------------------------------------------------

def sign(secret: str, body: bytes, timestamp: Optional[int] = None) -> str:
    timestamp = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def verify_signature(secret: str, header: str, body: bytes, tolerance_seconds: int = 300) -> bool:
    """Receiver-side check (also documented for customers)."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs(time.time() - timestamp) > tolerance_seconds:
        return False
    expected = sign(secret, body, timestamp).split("v1=", 1)[1]
    return hmac.compare_digest(expected, parts.get("v1", ""))


# --- target validation -------------------------------------------------------------------------

def check_target(url: str) -> None:
    parsed = urlparse(url)
    if config.WEBHOOK_ALLOW_PRIVATE_TARGETS:
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise InvalidTarget("webhook url must be an http(s) URL")
        return
    if parsed.scheme != "https" or not parsed.hostname:
        raise InvalidTarget("webhook url must be an https URL")
    if parsed.username or parsed.password:
        raise InvalidTarget("webhook url must not contain credentials")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, 0, socket.SOCK_STREAM)
    except OSError as exc:
        raise InvalidTarget(f"cannot resolve {parsed.hostname}") from exc
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise InvalidTarget(f"{parsed.hostname} resolves to a non-public address")


# --- management -------------------------------------------------------------------------------

def _out(row: Webhook) -> dict:
    from app.control.service import _iso

    return {"id": row.id, "org_id": row.org_id, "url": row.url, "event_types": row.event_types, "active": row.active,
            "consecutive_failures": row.consecutive_failures, "last_status": row.last_status,
            "last_delivery_at": _iso(row.last_delivery_at), "created_at": _iso(row.created_at)}


def _patterns(event_types: List[str]) -> List[str]:
    cleaned = [e.strip() for e in event_types or [] if e and e.strip()]
    if not cleaned or len(cleaned) > 50 or any(len(e) > 60 for e in cleaned):
        raise ValueError("event_types must list 1-50 event type patterns, e.g. ['request.block', 'admin.*']")
    return cleaned


def create(org_id: str, url: str, event_types: List[str], actor: str) -> dict:
    from app.control import audit

    check_target(url)
    patterns = _patterns(event_types)
    secret = "whsec_" + secrets.token_urlsafe(32)
    ciphertext = encrypt_secret(secret)  # EncryptionUnavailable if not configured
    with db.session_scope() as session:
        row = Webhook(org_id=org_id, url=url, event_types=patterns, secret_ciphertext=ciphertext)
        session.add(row)
        session.flush()
        out = _out(row)
    invalidate(org_id)
    audit.record("admin.webhook_created", actor=actor, org_id=org_id, details={"webhook_id": out["id"], "url": url,
                                                                                 "event_types": patterns})
    return dict(out, secret=secret)


def list_for(org_id: str) -> List[dict]:
    with db.session_scope() as session:
        rows = session.execute(select(Webhook).where(Webhook.org_id == org_id).order_by(Webhook.created_at)).scalars()
        return [_out(r) for r in rows]


def _get(session, org_id: str, webhook_id: str) -> Webhook:
    row = session.get(Webhook, webhook_id)
    if row is None or row.org_id != org_id:
        from app.control.service import NotFound

        raise NotFound(f"webhook '{webhook_id}' not found")
    return row


def update(org_id: str, webhook_id: str, actor: str, *, active: Optional[bool] = None,
           event_types: Optional[List[str]] = None) -> dict:
    from app.control import audit

    with db.session_scope() as session:
        row = _get(session, org_id, webhook_id)
        if event_types is not None:
            row.event_types = _patterns(event_types)
        if active is not None:
            row.active = active
            if active:
                row.consecutive_failures = 0
        out = _out(row)
    invalidate(org_id)
    audit.record("admin.webhook_updated", actor=actor, org_id=org_id, details={"webhook_id": webhook_id,
                                                                                 "active": out["active"]})
    return out


def delete(org_id: str, webhook_id: str, actor: str) -> None:
    from app.control import audit

    with db.session_scope() as session:
        session.delete(_get(session, org_id, webhook_id))
    invalidate(org_id)
    audit.record("admin.webhook_deleted", actor=actor, org_id=org_id, details={"webhook_id": webhook_id})


def send_test(org_id: str, webhook_id: str) -> dict:
    """Deliver a ``webhook.test`` event synchronously and report the outcome."""
    with db.session_scope() as session:
        row = _get(session, org_id, webhook_id)
        url, secret = row.url, decrypt_secret(row.secret_ciphertext)
    event = {"id": str(uuid.uuid4()), "event_type": "webhook.test", "org_id": org_id, "created_at": utcnow().isoformat()}
    ok, status = _post(url, secret, event)
    return {"delivered": ok, "status": status}


def invalidate(org_id: Optional[str] = None) -> None:
    if org_id is None:
        _cache.clear()
    else:
        _cache.pop(org_id, None)


def _webhooks_for(org_id: str) -> List[dict]:
    hit = _cache.get(org_id)
    if hit is not None and time.monotonic() - hit[0] < _CACHE_TTL:
        return hit[1]
    with db.session_scope() as session:
        rows = session.execute(select(Webhook).where(Webhook.org_id == org_id, Webhook.active.is_(True))).scalars()
        hooks = [{"id": r.id, "url": r.url, "event_types": list(r.event_types), "ciphertext": r.secret_ciphertext}
                 for r in rows]
    _cache[org_id] = (time.monotonic(), hooks)
    return hooks


# --- dispatch ---------------------------------------------------------------------------------

def dispatch(events: List[dict]) -> None:
    """Queue deliveries for persisted audit events (called by the audit writer)."""
    for event in events:
        try:
            if config.AUDIT_SIEM_WEBHOOK_URL:
                _enqueue({"target": SIEM, "url": config.AUDIT_SIEM_WEBHOOK_URL,
                          "secret": config.AUDIT_SIEM_WEBHOOK_SECRET, "event": event, "attempt": 0})
            org_id = event.get("org_id")
            if not org_id or not db.enabled():
                continue
            for hook in _webhooks_for(org_id):
                if any(fnmatchcase(event.get("event_type", ""), p) for p in hook["event_types"]):
                    _enqueue({"target": hook["id"], "url": hook["url"], "ciphertext": hook["ciphertext"],
                              "event": event, "attempt": 0})
        except Exception as exc:
            logger.warning(f"Webhook dispatch failed: {exc!r}")


def _enqueue(delivery: dict, delay: float = 0.0) -> None:
    global _worker
    with _queue_lock:
        _seq["n"] += 1
        heapq.heappush(_queue, (time.monotonic() + delay, _seq["n"], delivery))
        _queue_lock.notify()
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, name="webhook-delivery", daemon=True)
            _worker.start()


def _post(url: str, secret: str, event: dict):
    import httpx

    body = json.dumps({"type": event.get("event_type"), "data": event}, sort_keys=True, default=str).encode("utf-8")
    headers = {"content-type": "application/json", "user-agent": "ai-guardrail-proxy-webhooks/1",
               "x-guardrail-event": str(event.get("event_type")), "x-guardrail-delivery": str(event.get("id")),
               "x-guardrail-signature": sign(secret, body)}
    try:
        check_target(url)
        response = httpx.post(url, content=body, headers=headers, timeout=DELIVERY_TIMEOUT_SECONDS,
                              follow_redirects=False)
        return 200 <= response.status_code < 300, f"HTTP {response.status_code}"
    except InvalidTarget as exc:
        return False, f"rejected target: {exc}"
    except Exception as exc:
        return False, type(exc).__name__


def _deliver(delivery: dict) -> None:
    secret = delivery.get("secret") or decrypt_secret(delivery["ciphertext"])
    ok, status = _post(delivery["url"], secret, delivery["event"])
    retry = not ok and delivery["attempt"] < len(RETRY_DELAYS)
    if retry:
        delivery = dict(delivery, attempt=delivery["attempt"] + 1)
        _enqueue(delivery, RETRY_DELAYS[delivery["attempt"] - 1])
    if delivery["target"] != SIEM and db.enabled() and (ok or not retry):
        _record_outcome(delivery["target"], ok, status)
    if not ok and not retry:
        logger.warning(f"Webhook delivery to {delivery['target']} failed permanently: {status}")


def _record_outcome(webhook_id: str, ok: bool, status: str) -> None:
    try:
        with db.session_scope() as session:
            row = session.get(Webhook, webhook_id)
            if row is None:
                return
            row.last_delivery_at, row.last_status = utcnow(), status[:200]
            row.consecutive_failures = 0 if ok else row.consecutive_failures + 1
            if row.consecutive_failures >= DISABLE_AFTER_FAILURES:
                row.active = False
                logger.warning(f"Webhook {webhook_id} disabled after {DISABLE_AFTER_FAILURES} failed events")
            org_id = row.org_id
        invalidate(org_id)
    except Exception as exc:
        logger.warning(f"Could not record webhook outcome: {exc!r}")


def _run() -> None:
    while True:
        with _queue_lock:
            while not _queue or _queue[0][0] > time.monotonic():
                timeout = None if not _queue else max(0.0, _queue[0][0] - time.monotonic())
                _queue_lock.wait(timeout)
            _, _, delivery = heapq.heappop(_queue)
        try:
            _deliver(delivery)
        except Exception as exc:
            logger.warning(f"Webhook delivery crashed: {exc!r}")


def drain(include_delayed: bool = False) -> int:
    """Deliver queued items on the calling thread (tests, shutdown). Returns deliveries made."""
    done = 0
    while True:
        with _queue_lock:
            if not _queue or (not include_delayed and _queue[0][0] > time.monotonic()):
                return done
            _, _, delivery = heapq.heappop(_queue)
        _deliver(delivery)
        done += 1
