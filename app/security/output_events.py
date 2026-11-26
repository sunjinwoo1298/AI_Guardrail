"""Collects findings about model output during one request, so the code that finishes the
response (orchestrator, native endpoints) can audit them once.

Redaction runs deep inside helpers (sanitize_response is called per streamed sentence),
which have no request handle; they report here instead.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import List, Optional

_findings: ContextVar[Optional[List[str]]] = ContextVar("output_findings", default=None)


def begin() -> List[str]:
    """Start collecting for the current request; returns the (mutable) list."""
    findings: List[str] = []
    _findings.set(findings)
    return findings


def note(reasons: List[str]) -> None:
    if not reasons:
        return
    try:
        from app.observability.metrics import record_output_finding

        for reason in reasons:
            record_output_finding(reason.split(":", 1)[0])
    except Exception:
        pass
    findings = _findings.get()
    if findings is not None:
        findings.extend(r for r in reasons if r not in findings)
