"""Control-plane operations used by the admin API and the bootstrap CLI.

Every write is audited (event types ``admin.*``) and bumps the cache version, so all
replicas apply it within CONTROL_VERSION_CHECK_SECONDS.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.control import audit, db
from app.control.crypto import (
    encrypt_secret,
    generate_api_key,
    hash_api_key,
    key_display_prefix,
    secret_hint,
)
from app.control.models import ApiKey, Organization, PolicyVersion, Project, ProviderCredential, utcnow
from app.control.policy import parse_policy
from app.control.tenancy import ALL_SCOPES, bump_version

PROVIDERS = frozenset({"groq", "openai", "anthropic", "gemini", "openrouter"})
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")


class NotFound(LookupError):
    pass


class Conflict(ValueError):
    pass


class Invalid(ValueError):
    pass


def _slug(value: str) -> str:
    value = (value or "").strip().lower()
    if not _SLUG.fullmatch(value):
        raise Invalid("slug must be 1-40 lowercase letters, digits or '-', not starting or ending with '-'")
    return value


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()


# --- serialisation ----------------------------------------------------------------------------

def org_out(org: Organization) -> dict:
    return {"id": org.id, "slug": org.slug, "name": org.name, "status": org.status, "created_at": _iso(org.created_at)}


def project_out(project: Project, org_slug: Optional[str] = None) -> dict:
    out = {"id": project.id, "org_id": project.org_id, "slug": project.slug, "name": project.name,
           "created_at": _iso(project.created_at)}
    if org_slug:
        out["app_name"] = f"{org_slug}/{project.slug}"
    return out


def key_out(key: ApiKey) -> dict:
    return {"id": key.id, "project_id": key.project_id, "name": key.name, "prefix": key.prefix,
            "scopes": sorted(key.scopes or []), "created_at": _iso(key.created_at),
            "expires_at": _iso(key.expires_at), "revoked_at": _iso(key.revoked_at),
            "last_used_at": _iso(key.last_used_at), "active": key.revoked_at is None}


def policy_out(row: PolicyVersion) -> dict:
    return {"project_id": row.project_id, "version": row.version, "document": row.document,
            "comment": row.comment, "created_by": row.created_by, "created_at": _iso(row.created_at)}


def credential_out(row: ProviderCredential) -> dict:
    return {"id": row.id, "provider": row.provider, "scope": "project" if row.project_id else "organization",
            "project_id": row.project_id, "hint": row.hint, "updated_at": _iso(row.updated_at)}


# --- organizations and projects ---------------------------------------------------------------

def create_org(slug: str, name: str, actor: str) -> dict:
    slug = _slug(slug)
    try:
        with db.session_scope() as session:
            org = Organization(slug=slug, name=(name or slug).strip()[:200])
            session.add(org)
            session.flush()
            out = org_out(org)
    except IntegrityError as exc:
        raise Conflict(f"organization '{slug}' already exists") from exc
    audit.record("admin.org_created", actor=actor, org_id=out["id"], details={"slug": slug})
    return out


def list_orgs() -> List[dict]:
    with db.session_scope() as session:
        return [org_out(o) for o in session.execute(select(Organization).order_by(Organization.slug)).scalars()]


def _org(session, org_ref: str) -> Organization:
    org = session.execute(
        select(Organization).where((Organization.id == org_ref) | (Organization.slug == org_ref))
    ).scalar_one_or_none()
    if org is None:
        raise NotFound(f"organization '{org_ref}' not found")
    return org


def get_org(org_ref: str) -> dict:
    with db.session_scope() as session:
        return org_out(_org(session, org_ref))


def set_org_status(org_ref: str, status: str, actor: str) -> dict:
    if status not in {"active", "suspended"}:
        raise Invalid("status must be 'active' or 'suspended'")
    with db.session_scope() as session:
        org = _org(session, org_ref)
        org.status = status
        out = org_out(org)
    bump_version()
    audit.record(f"admin.org_{'suspended' if status == 'suspended' else 'reactivated'}", actor=actor, org_id=out["id"])
    return out


def create_project(org_ref: str, slug: str, name: str, actor: str, policy: Optional[dict] = None) -> dict:
    slug = _slug(slug)
    document = parse_policy(policy).model_dump(exclude_defaults=True) if policy is not None else None
    try:
        with db.session_scope() as session:
            org = _org(session, org_ref)
            project = Project(org_id=org.id, slug=slug, name=(name or slug).strip()[:200])
            session.add(project)
            session.flush()
            if document is not None:
                session.add(PolicyVersion(project_id=project.id, version=1, document=document,
                                          comment="initial policy", created_by=actor))
            out = project_out(project, org.slug)
    except IntegrityError as exc:
        raise Conflict(f"project '{slug}' already exists in this organization") from exc
    audit.record("admin.project_created", actor=actor, org_id=out["org_id"], project_id=out["id"],
                 app=out["app_name"], details={"slug": slug})
    return out


def list_projects(org_ref: str) -> List[dict]:
    with db.session_scope() as session:
        org = _org(session, org_ref)
        rows = session.execute(select(Project).where(Project.org_id == org.id).order_by(Project.slug)).scalars()
        return [project_out(p, org.slug) for p in rows]


def _project(session, project_id: str) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise NotFound(f"project '{project_id}' not found")
    return project


def get_project(project_id: str) -> dict:
    with db.session_scope() as session:
        project = _project(session, project_id)
        return project_out(project, project.organization.slug)


# --- API keys ---------------------------------------------------------------------------------

def _scopes(scopes: Optional[Iterable[str]]) -> List[str]:
    chosen = set(scopes) if scopes else set(ALL_SCOPES)
    unknown = chosen - ALL_SCOPES
    if unknown:
        raise Invalid(f"unknown scopes {sorted(unknown)}; allowed: {sorted(ALL_SCOPES)}")
    return sorted(chosen)


def create_key(project_id: str, actor: str, name: str = "default", scopes: Optional[Iterable[str]] = None,
               expires_in_days: Optional[int] = None) -> dict:
    """Issue a key. The plaintext is in the result only; it cannot be retrieved later."""
    if expires_in_days is not None and expires_in_days <= 0:
        raise Invalid("expires_in_days must be positive")
    plaintext = generate_api_key()
    with db.session_scope() as session:
        project = _project(session, project_id)
        key = ApiKey(project_id=project.id, name=(name or "default")[:100], key_hash=hash_api_key(plaintext),
                     prefix=key_display_prefix(plaintext), scopes=_scopes(scopes),
                     expires_at=utcnow() + timedelta(days=expires_in_days) if expires_in_days else None)
        session.add(key)
        session.flush()
        out = key_out(key)
        org_id = project.org_id
    audit.record("admin.key_created", actor=actor, org_id=org_id, project_id=project_id, key_prefix=out["prefix"],
                 details={"key_id": out["id"], "scopes": out["scopes"], "expires_at": out["expires_at"]})
    return dict(out, key=plaintext)


def list_keys(project_id: str) -> List[dict]:
    with db.session_scope() as session:
        _project(session, project_id)
        rows = session.execute(select(ApiKey).where(ApiKey.project_id == project_id)
                               .order_by(ApiKey.created_at)).scalars()
        return [key_out(k) for k in rows]


def _key(session, project_id: str, key_id: str) -> ApiKey:
    key = session.get(ApiKey, key_id)
    if key is None or key.project_id != project_id:
        raise NotFound(f"key '{key_id}' not found in project '{project_id}'")
    return key


def revoke_key(project_id: str, key_id: str, actor: str) -> dict:
    with db.session_scope() as session:
        key = _key(session, project_id, key_id)
        if key.revoked_at is None:
            key.revoked_at = utcnow()
        out = key_out(key)
        org_id = _project(session, project_id).org_id
    bump_version()
    audit.record("admin.key_revoked", actor=actor, org_id=org_id, project_id=project_id, key_prefix=out["prefix"],
                 details={"key_id": key_id})
    return out


def rotate_key(project_id: str, key_id: str, actor: str, grace_hours: float = 24) -> dict:
    """Issue a replacement with the same name and scopes. The old key keeps working for
    ``grace_hours`` (0 = revoke now) so clients can roll over without downtime."""
    if grace_hours < 0:
        raise Invalid("grace_hours must be zero or positive")
    with db.session_scope() as session:
        old = _key(session, project_id, key_id)
        if old.revoked_at is not None:
            raise Conflict("cannot rotate a revoked key")
        name, scopes = old.name, list(old.scopes or ALL_SCOPES)
        if grace_hours == 0:
            old.revoked_at = utcnow()
        else:
            deadline = utcnow() + timedelta(hours=grace_hours)
            current = old.expires_at.replace(tzinfo=timezone.utc) if old.expires_at and old.expires_at.tzinfo is None else old.expires_at
            old.expires_at = deadline if current is None or current > deadline else current
        old_prefix = old.prefix
    new = create_key(project_id, actor, name=name, scopes=scopes)
    bump_version()
    audit.record("admin.key_rotated", actor=actor, project_id=project_id, key_prefix=old_prefix,
                 details={"old_key_id": key_id, "new_key_id": new["id"], "grace_hours": grace_hours})
    return {"new_key": new, "old_key_id": key_id, "old_key_valid_for_hours": grace_hours}


# --- policies ---------------------------------------------------------------------------------

def get_policy(project_id: str) -> dict:
    with db.session_scope() as session:
        _project(session, project_id)
        row = session.execute(select(PolicyVersion).where(PolicyVersion.project_id == project_id)
                              .order_by(PolicyVersion.version.desc()).limit(1)).scalar_one_or_none()
        if row is None:
            return {"project_id": project_id, "version": 0, "document": {}, "comment": "defaults",
                    "created_by": None, "created_at": None}
        return policy_out(row)


def list_policy_versions(project_id: str) -> List[dict]:
    with db.session_scope() as session:
        _project(session, project_id)
        rows = session.execute(select(PolicyVersion).where(PolicyVersion.project_id == project_id)
                               .order_by(PolicyVersion.version.desc())).scalars()
        return [policy_out(r) for r in rows]


def _publish(session, project_id: str, document: dict, actor: str, comment: Optional[str]) -> PolicyVersion:
    current = session.execute(select(func.max(PolicyVersion.version))
                              .where(PolicyVersion.project_id == project_id)).scalar() or 0
    row = PolicyVersion(project_id=project_id, version=current + 1, document=document,
                        comment=(comment or None) and comment[:500], created_by=actor)
    session.add(row)
    session.flush()
    return row


def put_policy(project_id: str, document: dict, actor: str, comment: Optional[str] = None) -> dict:
    """Validate and publish a new version (raises PolicyError on an invalid document)."""
    normalized = parse_policy(document).model_dump(exclude_defaults=True)
    with db.session_scope() as session:
        project = _project(session, project_id)
        out = policy_out(_publish(session, project_id, normalized, actor, comment))
        org_id = project.org_id
    bump_version()
    audit.record("admin.policy_published", actor=actor, org_id=org_id, project_id=project_id,
                 details={"version": out["version"], "comment": comment})
    return out


def rollback_policy(project_id: str, version: int, actor: str) -> dict:
    with db.session_scope() as session:
        project = _project(session, project_id)
        source = session.execute(select(PolicyVersion).where(PolicyVersion.project_id == project_id,
                                                             PolicyVersion.version == version)).scalar_one_or_none()
        if source is None:
            raise NotFound(f"policy version {version} not found")
        parse_policy(source.document)  # still valid under the current schema
        out = policy_out(_publish(session, project_id, dict(source.document), actor, f"rollback to v{version}"))
        org_id = project.org_id
    bump_version()
    audit.record("admin.policy_rolled_back", actor=actor, org_id=org_id, project_id=project_id,
                 details={"from_version": version, "new_version": out["version"]})
    return out


# --- provider credentials (BYOK) --------------------------------------------------------------

def put_credential(org_ref: str, provider: str, secret: str, actor: str, project_id: Optional[str] = None) -> dict:
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        raise Invalid(f"provider must be one of {sorted(PROVIDERS)}")
    secret = (secret or "").strip()
    if len(secret) < 8:
        raise Invalid("api_key looks too short")
    ciphertext = encrypt_secret(secret)  # EncryptionUnavailable if not configured
    with db.session_scope() as session:
        org = _org(session, org_ref)
        if project_id is not None and _project(session, project_id).org_id != org.id:
            raise NotFound(f"project '{project_id}' is not in organization '{org_ref}'")
        row = session.execute(select(ProviderCredential).where(
            ProviderCredential.org_id == org.id, ProviderCredential.provider == provider,
            ProviderCredential.project_id.is_(None) if project_id is None else ProviderCredential.project_id == project_id,
        )).scalar_one_or_none()
        if row is None:
            row = ProviderCredential(org_id=org.id, project_id=project_id, provider=provider,
                                     ciphertext=ciphertext, hint=secret_hint(secret))
            session.add(row)
        else:
            row.ciphertext, row.hint, row.updated_at = ciphertext, secret_hint(secret), utcnow()
        session.flush()
        out = credential_out(row)
        org_id = org.id
    bump_version()
    audit.record("admin.provider_key_set", actor=actor, org_id=org_id, project_id=project_id,
                 details={"provider": provider, "scope": out["scope"], "hint": out["hint"]})
    return out


def list_credentials(org_ref: str) -> List[dict]:
    with db.session_scope() as session:
        org = _org(session, org_ref)
        rows = session.execute(select(ProviderCredential).where(ProviderCredential.org_id == org.id)
                               .order_by(ProviderCredential.provider)).scalars()
        return [credential_out(r) for r in rows]


def delete_credential(org_ref: str, credential_id: str, actor: str) -> None:
    with db.session_scope() as session:
        org = _org(session, org_ref)
        row = session.get(ProviderCredential, credential_id)
        if row is None or row.org_id != org.id:
            raise NotFound(f"provider key '{credential_id}' not found")
        details = {"provider": row.provider, "scope": "project" if row.project_id else "organization"}
        project_id = row.project_id
        session.delete(row)
        org_id = org.id
    bump_version()
    audit.record("admin.provider_key_deleted", actor=actor, org_id=org_id, project_id=project_id, details=details)
