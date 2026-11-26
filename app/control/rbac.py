"""Who may do what in the admin API.

Principals:
  * the bootstrap ``ADMIN_API_TOKEN`` (platform admin; for the operator's first steps
    and break-glass access);
  * admin tokens (``gpa_…``), hashed service-account credentials bound to one org and
    role, or platform-wide;
  * SSO users (OIDC JWT): their e-mail's org memberships, or platform admin when listed
    in PLATFORM_ADMIN_EMAILS.

Roles per organization: ``viewer`` < ``admin`` < ``owner``. Platform admins can do
everything, including creating and suspending organizations and verifying / purging the
audit log.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import select

from app.control import db, oidc
from app.control.models import AdminToken, OrgMember, utcnow
from app.core import config

ROLES = ("viewer", "admin", "owner")

_VIEWER = {"org.read", "project.read", "key.read", "policy.read", "audit.read", "usage.read",
           "webhook.read", "credential.read", "member.read"}
_ADMIN = _VIEWER | {"project.write", "key.write", "policy.write", "credential.write", "webhook.write"}
_OWNER = _ADMIN | {"member.write", "admin_token.read", "admin_token.write"}
PERMISSIONS = {"viewer": frozenset(_VIEWER), "admin": frozenset(_ADMIN), "owner": frozenset(_OWNER)}
PLATFORM_ONLY = frozenset({"org.create", "org.status", "audit.verify", "audit.purge", "platform.admin_token"})


class AuthError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass
class Principal:
    actor: str  # recorded in the audit log: "platform-token", "token:gpa_ab12…", "user:a@b.com"
    platform: bool = False
    roles: Dict[str, str] = field(default_factory=dict)  # org_id -> role

    def can(self, permission: str, org_id: Optional[str]) -> bool:
        if self.platform:
            return True
        if permission in PLATFORM_ONLY or org_id is None:
            return False
        role = self.roles.get(org_id)
        return role is not None and permission in PERMISSIONS[role]

    def require(self, permission: str, org_id: Optional[str]) -> None:
        if not self.can(permission, org_id):
            raise AuthError(403, "forbidden", f"Missing permission '{permission}' for this organization")

    @property
    def org_ids(self):
        return set(self.roles)


def generate_admin_token() -> str:
    import secrets

    return f"{config.ADMIN_TOKEN_PREFIX}_{secrets.token_urlsafe(32)}"


def hash_admin_token(token: str) -> str:
    return hmac.new(config.KEY_HASH_SECRET.encode("utf-8"), b"admin:" + token.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def _from_admin_token(token: str) -> Principal:
    with db.session_scope() as session:
        row = session.execute(select(AdminToken).where(AdminToken.token_hash == hash_admin_token(token))).scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            raise AuthError(401, "unauthorized", "Admin authentication required")
        expires = _aware(row.expires_at)
        if expires is not None and expires <= datetime.now(timezone.utc):
            raise AuthError(401, "token_expired", "This admin token has expired")
        row.last_used_at = utcnow()
        actor = f"token:{row.prefix}"
        if row.org_id is None:
            return Principal(actor=actor, platform=True)
        return Principal(actor=actor, roles={row.org_id: row.role})


def _from_sso(token: str) -> Principal:
    try:
        email = oidc.verify(token)
    except oidc.OidcError as exc:
        raise AuthError(401, "invalid_sso_token", str(exc))
    if email in config.PLATFORM_ADMIN_EMAILS:
        return Principal(actor=f"user:{email}", platform=True)
    roles = {}
    if db.enabled():
        with db.session_scope() as session:
            for member in session.execute(select(OrgMember).where(OrgMember.email == email)).scalars():
                roles[member.org_id] = member.role
    if not roles:
        raise AuthError(403, "no_membership", f"{email} is not a member of any organization")
    return Principal(actor=f"user:{email}", roles=roles)


def admin_api_enabled() -> bool:
    return bool(config.ADMIN_API_TOKEN) or oidc.enabled() or db.enabled()


def authenticate(authorization: str) -> Principal:
    """Resolve the ``Authorization`` header to a Principal (blocking: run in a thread)."""
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if not token:
        raise AuthError(401, "unauthorized", "Admin authentication required")
    if config.ADMIN_API_TOKEN and hmac.compare_digest(token.encode("utf-8"), config.ADMIN_API_TOKEN.encode("utf-8")):
        return Principal(actor="platform-token", platform=True)
    if token.startswith(f"{config.ADMIN_TOKEN_PREFIX}_") and db.enabled():
        return _from_admin_token(token)
    if oidc.enabled() and oidc.looks_like_jwt(token):
        return _from_sso(token)
    raise AuthError(401, "unauthorized", "Admin authentication required")
