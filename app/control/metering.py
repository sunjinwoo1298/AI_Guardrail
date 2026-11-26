"""Usage metering and monthly budgets.

* Every model call, cache hit, block / flag and guard scan is counted per app and UTC day.
  Counts accumulate in memory and a background thread adds them to ``usage_daily``
  every USAGE_FLUSH_SECONDS with ``UPDATE … SET n = n + :delta``, so several replicas
  can write the same row safely.
* Month-to-date cost and tokens are also kept in Redis, shared by all replicas, which is
  what budget enforcement reads on each request.
* Crossing a budget alert threshold emits one ``budget.threshold`` audit event per month
  (and so a webhook).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.control import db
from app.core import config
from app.core.context import app_context, tenant_context
from app.core.logger import logger

COUNTERS = ("requests", "blocked", "flagged", "cache_hits", "guard_scans", "input_tokens", "output_tokens", "cost_usd")
_MICRO = 1_000_000  # cost is kept in Redis as integer micro-dollars

_pending: Dict[Tuple[str, str], dict] = {}
_lock = threading.Lock()
_worker: Optional[threading.Thread] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _subject() -> Tuple[str, Optional[str], Optional[str], str]:
    """(subject, org_id, project_id, app) for the current request."""
    tenant = tenant_context.get()
    if tenant is not None:
        return tenant.project_id, tenant.org_id, tenant.project_id, tenant.app_name
    app = app_context.get()
    return f"env:{app}", None, None, app


def record(*, requests: int = 0, blocked: int = 0, flagged: int = 0, cache_hits: int = 0, guard_scans: int = 0,
           input_tokens: int = 0, output_tokens: int = 0, cost_usd: float = 0.0) -> None:
    """Add to the current app's usage. Never raises."""
    try:
        subject, org_id, project_id, app = _subject()
        if app == "anonymous" and tenant_context.get() is None:
            return
        day = _now().strftime("%Y-%m-%d")
        deltas = {"requests": requests, "blocked": blocked, "flagged": flagged, "cache_hits": cache_hits,
                  "guard_scans": guard_scans, "input_tokens": input_tokens, "output_tokens": output_tokens,
                  "cost_usd": cost_usd}
        with _lock:
            row = _pending.setdefault((subject, day), {"org_id": org_id, "project_id": project_id, "app": app,
                                                       **{c: 0 for c in COUNTERS}})
            for name, value in deltas.items():
                row[name] += value
        if input_tokens or output_tokens or cost_usd:
            _add_month_to_date(subject, input_tokens + output_tokens, cost_usd)
        _ensure_worker()
    except Exception as exc:
        logger.warning(f"Usage metering failed: {exc!r}")


def record_model_call(*, cache_hit: bool, cache_type: Optional[str], prompt_tokens: int, completion_tokens: int,
                      cost: float) -> None:
    if cache_type in ("degraded", "error"):
        return
    record(requests=1, cache_hits=1 if cache_hit else 0,
           input_tokens=0 if cache_hit else int(prompt_tokens or 0),
           output_tokens=0 if cache_hit else int(completion_tokens or 0),
           cost_usd=0.0 if cache_hit else float(cost or 0.0))


def record_decision(action: str) -> None:
    if action == "block":
        record(blocked=1)
    elif action in ("flag", "would_block"):
        record(flagged=1)


# --- persistence ------------------------------------------------------------------------------

def _ensure_worker() -> None:
    global _worker
    if not db.enabled() or (_worker is not None and _worker.is_alive()):
        return
    with _lock:
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(target=_run, name="usage-flush", daemon=True)
        _worker.start()


def _run() -> None:
    while True:
        time.sleep(config.USAGE_FLUSH_SECONDS)
        flush()


def flush() -> int:
    """Write pending counters to usage_daily; returns rows touched. Failed rows are
    put back and retried on the next flush."""
    from app.control.models import UsageDaily

    if not db.enabled():
        return 0
    with _lock:
        batch = dict(_pending)
        _pending.clear()
    written = 0
    for (subject, day), row in batch.items():
        deltas = {c: row[c] for c in COUNTERS}
        if not any(deltas.values()):
            continue
        try:
            for attempt in range(2):
                with db.session_scope() as session:
                    result = session.execute(
                        update(UsageDaily).where(UsageDaily.subject == subject, UsageDaily.day == day)
                        .values(updated_at=_now(), **{c: getattr(UsageDaily, c) + v for c, v in deltas.items()})
                    )
                    if result.rowcount:
                        break
                    try:
                        with session.begin_nested():
                            session.add(UsageDaily(subject=subject, day=day, org_id=row["org_id"],
                                                   project_id=row["project_id"], app=row["app"], **deltas))
                        break
                    except IntegrityError:
                        continue  # another replica inserted it first: update on the next attempt
            written += 1
        except Exception as exc:
            logger.warning(f"Usage flush failed for {subject} {day}: {exc!r}")
            with _lock:
                pending = _pending.setdefault((subject, day), {k: row[k] for k in ("org_id", "project_id", "app")}
                                              | {c: 0 for c in COUNTERS})
                for c in COUNTERS:
                    pending[c] += row[c]
    return written


# --- month to date and budgets -------------------------------------------------------------------

def _month() -> str:
    return _now().strftime("%Y%m")


def _redis():
    from app.core.redis_client import get_redis

    return get_redis()


def _keys(subject: str, month: Optional[str] = None) -> Tuple[str, str]:
    month = month or _month()
    return f"ai_proxy:usage:{subject}:{month}:cost_micro", f"ai_proxy:usage:{subject}:{month}:tokens"


def _add_month_to_date(subject: str, tokens: int, cost: float) -> None:
    client = _redis()
    if client is None:
        return
    cost_key, token_key = _keys(subject)
    try:
        pipe = client.pipeline()
        pipe.incrby(cost_key, int(round(cost * _MICRO)))
        pipe.incrby(token_key, int(tokens))
        pipe.expire(cost_key, 40 * 86400)
        pipe.expire(token_key, 40 * 86400)
        cost_micro, total_tokens, _, _ = pipe.execute()
    except Exception as exc:
        logger.warning(f"Month-to-date usage unavailable: {exc!r}")
        return
    _check_thresholds(subject, int(cost_micro) / _MICRO, int(total_tokens))


def month_to_date(subject: str) -> Tuple[float, int, str]:
    """(cost USD, tokens, source) for the current month. Redis first; the database
    (plus not-yet-flushed counters) when Redis is unavailable."""
    client = _redis()
    if client is not None:
        try:
            cost_micro, tokens = client.mget(*_keys(subject))
            return int(cost_micro or 0) / _MICRO, int(tokens or 0), "redis"
        except Exception:
            pass
    cost, tokens = 0.0, 0
    if db.enabled():
        from app.control.models import UsageDaily

        prefix = _now().strftime("%Y-%m-")
        with db.session_scope() as session:
            row = session.execute(select(func.coalesce(func.sum(UsageDaily.cost_usd), 0.0),
                                         func.coalesce(func.sum(UsageDaily.input_tokens + UsageDaily.output_tokens), 0))
                                  .where(UsageDaily.subject == subject, UsageDaily.day.like(prefix + "%"))).one()
            cost, tokens = float(row[0]), int(row[1])
    with _lock:
        for (s, day), row in _pending.items():
            if s == subject and day.startswith(_now().strftime("%Y-%m-")):
                cost += row["cost_usd"]
                tokens += row["input_tokens"] + row["output_tokens"]
    return cost, tokens, "database"


def _policy_budget():
    from app.control.policy import policy_for

    return policy_for(app_context.get()).budget


def budget_status(subject: Optional[str] = None, budget=None) -> dict:
    budget = budget if budget is not None else _policy_budget()
    subject = subject or _subject()[0]
    cost, tokens, source = month_to_date(subject)
    exceeded = []
    if budget.monthly_usd is not None and cost >= budget.monthly_usd:
        exceeded.append("monthly_usd")
    if budget.monthly_tokens is not None and tokens >= budget.monthly_tokens:
        exceeded.append("monthly_tokens")
    return {"month": _now().strftime("%Y-%m"), "cost_usd": round(cost, 6), "tokens": tokens,
            "monthly_usd": budget.monthly_usd, "monthly_tokens": budget.monthly_tokens,
            "action": budget.action, "exceeded": exceeded, "source": source}


def check_budget() -> Optional[dict]:
    """Budget status when the current app has an active budget, else None."""
    budget = _policy_budget()
    if not budget.active:
        return None
    return budget_status(budget=budget)


def _check_thresholds(subject: str, cost: float, tokens: int) -> None:
    try:
        budget = _policy_budget()
    except Exception:
        return
    if not budget.active:
        return
    client = _redis()
    for limit_name, used, limit in (("monthly_usd", cost, budget.monthly_usd), ("monthly_tokens", tokens, budget.monthly_tokens)):
        if not limit:
            continue
        for threshold in budget.alert_thresholds:
            if used < limit * threshold:
                continue
            key = f"ai_proxy:budget_alert:{subject}:{_month()}:{limit_name}:{threshold}"
            try:
                first = client.set(key, "1", nx=True, ex=40 * 86400) if client is not None else True
            except Exception:
                first = False
            if first:
                from app.control import audit

                tenant = tenant_context.get()
                audit.record("budget.threshold", action="alert", tenant=tenant, app=app_context.get(),
                             reasons=[f"{limit_name}:{int(threshold * 100)}%"],
                             details={"limit": limit_name, "threshold": threshold, "used": round(used, 6),
                                      "cap": limit, "month": _now().strftime("%Y-%m")})


# --- reporting ------------------------------------------------------------------------------------

def usage_rows(*, org_id: Optional[str] = None, project_id: Optional[str] = None, since: Optional[str] = None,
               until: Optional[str] = None, all_orgs: bool = False) -> list:
    from app.control.models import UsageDaily

    flush()
    stmt = select(UsageDaily).order_by(UsageDaily.day, UsageDaily.app)
    if not all_orgs:
        stmt = stmt.where(UsageDaily.org_id == org_id)
    if project_id:
        stmt = stmt.where(UsageDaily.project_id == project_id)
    if since:
        stmt = stmt.where(UsageDaily.day >= since)
    if until:
        stmt = stmt.where(UsageDaily.day <= until)
    with db.session_scope() as session:
        return [{"day": r.day, "org_id": r.org_id, "project_id": r.project_id, "app": r.app,
                 **{c: (round(getattr(r, c), 6) if c == "cost_usd" else getattr(r, c)) for c in COUNTERS}}
                for r in session.execute(stmt).scalars()]


def totals(rows: list) -> dict:
    out = defaultdict(float)
    for row in rows:
        for c in COUNTERS:
            out[c] += row[c]
    return {c: (round(out[c], 6) if c == "cost_usd" else int(out[c])) for c in COUNTERS}
