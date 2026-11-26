"""Resolve an issued API key to its tenant (organization, project, scopes, policy, BYOK
credentials) without a database round trip per request.

Resolved tenants are cached in memory for CONTROL_CACHE_TTL_SECONDS. Every admin write
bumps a version counter in Redis; each replica checks it at most every
CONTROL_VERSION_CHECK_SECONDS and drops its cache when it changed, so revoking a key or
publishing a policy takes effect within seconds everywhere.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Optional, Tuple

from sqlalchemy import select

from app.control import db
from app.control.crypto import decrypt_secret, hash_api_key
from app.control.models import ApiKey, Organization, PolicyVersion, Project, ProviderCredential
from app.control.policy import Policy, PolicyError, parse_policy
from app.core import config
from app.core.logger import logger

ALL_SCOPES = frozenset({"chat", "guard", "models"})
_VERSION_KEY = "ai_proxy:control:version"


@dataclass(frozen=True)
class TenantContext:
    org_id: str
    org_slug: str
    project_id: str
    project_slug: str
    key_id: str
    key_prefix: str
    scopes: FrozenSet[str]
    policy: Policy
    policy_version: int
    # provider -> Fernet ciphertext (decrypted only when a call needs it)
    provider_ciphertexts: Dict[str, str] = field(default_factory=dict)

    @property
    def app_name(self) -> str:
        return f"{self.org_slug}/{self.project_slug}"

    @property
    def policy_dict(self) -> dict:
        return self.policy.as_dict()

    @property
    def limit_key(self) -> str:
        """Rate limits, cache scope and budgets follow the project, not the key, so rotating
        a key neither resets its quota nor empties its cache."""
        return f"project:{self.project_id}"

    def provider_key(self, provider: str) -> Optional[str]:
        ciphertext = self.provider_ciphertexts.get(provider)
        return decrypt_secret(ciphertext) if ciphertext else None


class KeyRejected(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# --- cache --------------------------------------------------------------------------------

_cache: Dict[str, Tuple[float, object]] = {}
_cache_lock = threading.Lock()
_version_state = {"value": None, "checked_at": 0.0}


def _redis():
    from app.core.redis_client import get_redis

    return get_redis()


def bump_version() -> None:
    """Call after any control-plane write. Clears this replica now and the others within
    CONTROL_VERSION_CHECK_SECONDS."""
    clear_cache()
    client = _redis()
    if client is not None:
        try:
            client.incr(_VERSION_KEY)
        except Exception as exc:
            logger.warning(f"Could not publish control-plane change: {exc}")


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _check_version() -> None:
    now = time.monotonic()
    if now - _version_state["checked_at"] < config.CONTROL_VERSION_CHECK_SECONDS:
        return
    _version_state["checked_at"] = now
    client = _redis()
    if client is None:
        return
    try:
        current = client.get(_VERSION_KEY)
    except Exception:
        return
    if current != _version_state["value"]:
        _version_state["value"] = current
        clear_cache()


# --- resolution -----------------------------------------------------------------------------

def _active_policy(session, project_id: str) -> Tuple[Policy, int]:
    row = session.execute(
        select(PolicyVersion).where(PolicyVersion.project_id == project_id)
        .order_by(PolicyVersion.version.desc()).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return Policy(), 0
    try:
        return parse_policy(row.document), row.version
    except PolicyError as exc:
        # Documents are validated on write; if one still fails (schema change), fall back
        # to defaults rather than serving the tenant with no policy at all.
        logger.error(f"Stored policy v{row.version} of project {project_id} is invalid: {exc}")
        return Policy(), row.version


def _credentials(session, org_id: str, project_id: str) -> Dict[str, str]:
    rows = session.execute(
        select(ProviderCredential).where(
            ProviderCredential.org_id == org_id,
            (ProviderCredential.project_id == project_id) | (ProviderCredential.project_id.is_(None)),
        )
    ).scalars().all()
    creds: Dict[str, str] = {}
    for row in sorted(rows, key=lambda r: r.project_id is not None):  # project keys override org keys
        creds[row.provider] = row.ciphertext
    return creds


def _load(key_hash: str):
    with db.session_scope() as session:
        row = session.execute(
            select(ApiKey, Project, Organization)
            .join(Project, ApiKey.project_id == Project.id)
            .join(Organization, Project.org_id == Organization.id)
            .where(ApiKey.key_hash == key_hash)
        ).first()
        if row is None:
            return None
        key, project, org = row
        policy, version = _active_policy(session, project.id)
        return {
            "tenant": TenantContext(
                org_id=org.id, org_slug=org.slug, project_id=project.id, project_slug=project.slug,
                key_id=key.id, key_prefix=key.prefix,
                scopes=frozenset(key.scopes or ALL_SCOPES) & ALL_SCOPES,
                policy=policy, policy_version=version,
                provider_ciphertexts=_credentials(session, org.id, project.id),
            ),
            "org_status": org.status,
            "expires_at": key.expires_at,
            "revoked_at": key.revoked_at,
        }


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)  # SQLite returns naive datetimes
    return value


def resolve_key(provided_key: str) -> TenantContext:
    """The tenant of an issued key, or KeyRejected (401 unknown / revoked / expired,
    403 suspended organization)."""
    if not db.enabled():
        raise KeyRejected(401, "invalid_api_key", "Unauthorized")
    _check_version()
    key_hash = hash_api_key(provided_key)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key_hash)
    if cached is not None and now - cached[0] < config.CONTROL_CACHE_TTL_SECONDS:
        record = cached[1]
    else:
        record = _load(key_hash)
        with _cache_lock:
            _cache[key_hash] = (now, record)  # negative results are cached too (key spraying)
    if record is None:
        raise KeyRejected(401, "invalid_api_key", "Unauthorized")
    utc_now = datetime.now(timezone.utc)
    if record["revoked_at"] is not None:
        raise KeyRejected(401, "api_key_revoked", "This API key has been revoked")
    expires_at = _aware(record["expires_at"])
    if expires_at is not None and expires_at <= utc_now:
        raise KeyRejected(401, "api_key_expired", "This API key has expired")
    if record["org_status"] != "active":
        raise KeyRejected(403, "organization_suspended", "This organization is suspended")
    _note_usage(record["tenant"].key_id)
    return record["tenant"]


# --- last-used tracking (batched, off the request path) ------------------------------------

_usage: Dict[str, datetime] = {}
_usage_lock = threading.Lock()


def _note_usage(key_id: str) -> None:
    with _usage_lock:
        _usage[key_id] = datetime.now(timezone.utc)


def flush_key_usage() -> int:
    """Persist last_used_at for keys seen since the last flush (called by the audit worker)."""
    with _usage_lock:
        pending = dict(_usage)
        _usage.clear()
    if not pending or not db.enabled():
        return 0
    try:
        with db.session_scope() as session:
            for key_id, used_at in pending.items():
                key = session.get(ApiKey, key_id)
                if key is not None:
                    key.last_used_at = used_at
    except Exception as exc:
        logger.warning(f"Could not record API key usage: {exc}")
        return 0
    return len(pending)


# --- scopes ---------------------------------------------------------------------------------

def required_scope(path: str) -> Optional[str]:
    if path.startswith("/v1/guard"):
        return "guard"
    if path.startswith("/v1/models"):
        return "models"
    if path.startswith(("/v1/chat/completions", "/generate", "/stream", "/v1/messages", "/v1/responses", "/mcp/")):
        return "chat"
    return None
