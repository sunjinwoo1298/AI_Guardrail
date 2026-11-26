"""Audit log: who did what, which detector fired, what the proxy decided.

Events are queued in memory and written in batches by one background thread, so the
request path never waits for the database. No prompt or response text is stored: only
the decision, its reasons (detector names, entity types), risk score and identifiers.

Tamper evidence: each writer process owns a chain (``chain_id``). Every row stores a
SHA-256 over its own content plus the previous row's hash, so editing or deleting a row
breaks the chain, which verify_chains() reports.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import delete, select

from app.control import db
from app.control.models import AuditEvent
from app.core import config
from app.core.logger import logger

_QUEUE_MAX = 50_000
_BATCH = 500
_FLUSH_INTERVAL_SECONDS = 1.0

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=_QUEUE_MAX)
_chain = {"id": f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}", "seq": 0, "prev": None}
_chain_lock = threading.Lock()
_worker: Optional[threading.Thread] = None
_stop = threading.Event()
_dropped = {"count": 0}

# Fields covered by the row hash, in a fixed order.
_HASHED_FIELDS = ("id", "created_at", "event_type", "org_id", "project_id", "app", "actor", "key_prefix",
                  "request_id", "action", "reasons", "risk_score", "details", "chain_id", "seq", "prev_hash", "monitor")


def _row_hash(values: dict) -> str:
    material = {}
    for name in _HASHED_FIELDS:
        value = values.get(name)
        if isinstance(value, datetime):
            value = _aware(value).isoformat()
        material[name] = value
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def record(event_type: str, *, action: Optional[str] = None, reasons: Optional[List[str]] = None,
           risk_score: Optional[float] = None, details: Optional[dict] = None, actor: Optional[str] = None,
           tenant=None, app: Optional[str] = None, request_id: Optional[str] = None,
           key_prefix: Optional[str] = None, monitor: bool = False, org_id: Optional[str] = None,
           project_id: Optional[str] = None) -> None:
    """Queue an event. Never raises and never blocks; when the queue is full the event is
    dropped and counted (ai_proxy_audit_dropped_total)."""
    if not config.AUDIT_ENABLED or not db.enabled():
        return
    event = {
        "event_type": event_type, "action": action, "reasons": reasons or None,
        "risk_score": None if risk_score is None else round(float(risk_score), 4),
        "details": details or None, "actor": actor, "request_id": request_id, "monitor": monitor,
        "org_id": org_id or (tenant.org_id if tenant else None),
        "project_id": project_id or (tenant.project_id if tenant else None),
        "app": app or (tenant.app_name if tenant else None),
        "key_prefix": key_prefix or (tenant.key_prefix if tenant else None),
        "created_at": datetime.now(timezone.utc),
    }
    try:
        _queue.put_nowait(event)
    except queue.Full:
        _dropped["count"] += 1
        try:
            from app.observability.metrics import record_audit_dropped

            record_audit_dropped()
        except Exception:
            pass
    _ensure_worker()


def _ensure_worker() -> None:
    global _worker
    if _worker is not None and _worker.is_alive():
        return
    with _chain_lock:
        if _worker is not None and _worker.is_alive():
            return
        _stop.clear()
        _worker = threading.Thread(target=_run, name="audit-writer", daemon=True)
        _worker.start()


def _drain(limit: int) -> List[dict]:
    batch = []
    while len(batch) < limit:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    return batch


def _write(batch: List[dict]) -> None:
    if not batch or not db.enabled():
        return
    with _chain_lock:
        rows = []
        seq, prev = _chain["seq"], _chain["prev"]
        for event in batch:
            seq += 1
            values = dict(event, id=str(uuid.uuid4()), chain_id=_chain["id"], seq=seq, prev_hash=prev)
            values["hash"] = _row_hash(values)
            prev = values["hash"]
            rows.append(AuditEvent(**values))
        try:
            with db.session_scope() as session:
                session.add_all(rows)
        except Exception as exc:
            logger.error(f"Audit write failed, {len(rows)} events lost: {exc}")
            return  # the chain keeps its last persisted head
        _chain["seq"], _chain["prev"] = seq, prev
        persisted = [_to_dict(r) for r in rows]
    # Offer the persisted events to webhooks / the SIEM feed (never blocks this thread long:
    # deliveries are queued for the webhook worker).
    try:
        from app.control import webhooks

        webhooks.dispatch(persisted)
    except Exception as exc:
        logger.warning(f"Webhook dispatch failed: {exc!r}")


def _run() -> None:
    last_usage_flush = time.monotonic()
    while not _stop.is_set():
        try:
            first = _queue.get(timeout=_FLUSH_INTERVAL_SECONDS)
        except queue.Empty:
            first = None
        batch = ([first] if first else []) + _drain(_BATCH - 1)
        _write(batch)
        if time.monotonic() - last_usage_flush > 30:
            from app.control.tenancy import flush_key_usage

            flush_key_usage()
            last_usage_flush = time.monotonic()


def flush() -> None:
    """Write everything queued so far (tests, shutdown)."""
    while True:
        batch = _drain(_BATCH)
        if not batch:
            break
        _write(batch)


def shutdown() -> None:
    _stop.set()
    flush()
    from app.control.tenancy import flush_key_usage

    flush_key_usage()


# --- reading ---------------------------------------------------------------------------------

def _to_dict(row: AuditEvent) -> dict:
    return {
        "id": row.id, "created_at": _aware(row.created_at).isoformat(), "event_type": row.event_type,
        "org_id": row.org_id, "project_id": row.project_id, "app": row.app, "actor": row.actor,
        "key_prefix": row.key_prefix, "request_id": row.request_id, "action": row.action,
        "reasons": row.reasons or [], "risk_score": row.risk_score, "details": row.details or {},
        "monitor": row.monitor,
    }


def query(*, org_id: Optional[str] = None, project_id: Optional[str] = None, event_type: Optional[str] = None,
          action: Optional[str] = None, since: Optional[datetime] = None, until: Optional[datetime] = None,
          limit: int = 100) -> List[dict]:
    flush()
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.seq.desc())
    if org_id:
        stmt = stmt.where(AuditEvent.org_id == org_id)
    if project_id:
        stmt = stmt.where(AuditEvent.project_id == project_id)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if since:
        stmt = stmt.where(AuditEvent.created_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.created_at < until)
    with db.session_scope() as session:
        return [_to_dict(r) for r in session.execute(stmt.limit(max(1, min(limit, 1000)))).scalars()]


def verify_chains() -> Dict[str, dict]:
    """Recompute every chain. A chain is intact when each row's hash matches its content
    and links to its predecessor; retention purges cut chains at the front only, which is
    reported as ``starts_at_seq`` rather than as tampering."""
    flush()
    results: Dict[str, dict] = {}
    with db.session_scope() as session:
        rows = session.execute(select(AuditEvent).order_by(AuditEvent.chain_id, AuditEvent.seq)).scalars().all()
    for row in rows:
        state = results.setdefault(row.chain_id, {"rows": 0, "intact": True, "problems": [],
                                                  "starts_at_seq": row.seq, "_prev": None, "_seq": None})
        values = {name: getattr(row, name) for name in _HASHED_FIELDS}
        if _row_hash(values) != row.hash:
            state["intact"] = False
            state["problems"].append(f"seq {row.seq}: content does not match its hash")
        if state["_seq"] is not None:
            if row.seq != state["_seq"] + 1:
                state["intact"] = False
                state["problems"].append(f"seq {state['_seq'] + 1}..{row.seq - 1} missing")
            if row.prev_hash != state["_prev"]:
                state["intact"] = False
                state["problems"].append(f"seq {row.seq}: does not link to the previous row")
        state["rows"] += 1
        state["_prev"], state["_seq"] = row.hash, row.seq
    for state in results.values():
        state.pop("_prev"), state.pop("_seq")
    return results


def purge_expired(retention_days: Optional[int] = None) -> int:
    days = config.AUDIT_RETENTION_DAYS if retention_days is None else retention_days
    if days <= 0 or not db.enabled():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with db.session_scope() as session:
        result = session.execute(delete(AuditEvent).where(AuditEvent.created_at < cutoff))
        return result.rowcount or 0


def encode_cursor(created_at: str, event_id: str) -> str:
    import base64

    return base64.urlsafe_b64encode(f"{created_at}|{event_id}".encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str):
    import base64

    try:
        created_at, event_id = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8").split("|", 1)
        return datetime.fromisoformat(created_at), event_id
    except Exception as exc:
        raise ValueError("invalid cursor") from exc


def export(*, org_id: Optional[str], after: Optional[str] = None, limit: int = 1000) -> tuple:
    """Events in ascending (created_at, id) order after ``after`` (an opaque cursor), for
    SIEM pull ingestion. Returns (events, next cursor or None). org_id None = all orgs."""
    from sqlalchemy import and_, or_

    flush()
    stmt = select(AuditEvent).order_by(AuditEvent.created_at, AuditEvent.id)
    if org_id is not None:
        stmt = stmt.where(AuditEvent.org_id == org_id)
    if after:
        created_at, event_id = decode_cursor(after)
        stmt = stmt.where(or_(AuditEvent.created_at > created_at,
                              and_(AuditEvent.created_at == created_at, AuditEvent.id > event_id)))
    limit = max(1, min(limit, 5000))
    with db.session_scope() as session:
        rows = session.execute(stmt.limit(limit)).scalars().all()
        events = [_to_dict(r) for r in rows]
    if not events:
        return [], after
    return events, encode_cursor(events[-1]["created_at"], events[-1]["id"])
