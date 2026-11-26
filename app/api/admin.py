"""Admin API (/admin/v1): organizations, members, admin tokens, projects, API keys,
policies, provider keys, webhooks, usage and the audit log.

Authentication (see app/control/rbac.py): the bootstrap ``ADMIN_API_TOKEN`` (platform
admin), admin tokens (``gpa_…``, bound to one org and role, or platform-wide), or an SSO
user's OIDC token. Every endpoint checks a permission against the organization it acts
on, so customers can manage their own organization and nothing else.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from app.control import audit, db, metering, rbac, service, webhooks
from app.control.crypto import EncryptionUnavailable
from app.control.policy import PolicyError, parse_policy
from app.core import config

router = APIRouter(prefix="/admin/v1", tags=["admin"])


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"message": message, "type": "admin_error", "code": code})


async def require_admin(request: Request) -> rbac.Principal:
    if not rbac.admin_api_enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    try:
        principal = await asyncio.to_thread(rbac.authenticate, request.headers.get("authorization", ""))
    except rbac.AuthError as exc:
        raise _err(exc.status, exc.code, exc.message)
    if not db.enabled():
        raise _err(503, "control_plane_disabled", "Control plane database is not configured (DATABASE_URL)")
    return principal


async def _run(func, *args, **kwargs):
    """Run a blocking control-plane operation in a worker thread, mapping its errors."""
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except service.NotFound as exc:
        raise _err(404, "not_found", str(exc))
    except service.Conflict as exc:
        raise _err(409, "conflict", str(exc))
    except (service.Invalid, PolicyError, webhooks.InvalidTarget, ValueError) as exc:
        raise _err(422, "invalid", str(exc))
    except EncryptionUnavailable as exc:
        raise _err(503, "encryption_unavailable", f"{exc}; secrets cannot be stored")


def _require(principal: rbac.Principal, permission: str, org_id: Optional[str]) -> None:
    try:
        principal.require(permission, org_id)
    except rbac.AuthError as exc:
        raise _err(exc.status, exc.code, exc.message)


async def _org(principal: rbac.Principal, org: str, permission: str) -> str:
    """Resolve an org slug/id and check the permission; unknown orgs and orgs the principal
    cannot see both answer 404, so org names cannot be probed."""
    try:
        org_id = await asyncio.to_thread(service.org_id_for, org)
    except service.NotFound:
        raise _err(404, "not_found", f"organization '{org}' not found")
    if not principal.can("org.read", org_id):
        raise _err(404, "not_found", f"organization '{org}' not found")
    _require(principal, permission, org_id)
    return org_id


async def _project(principal: rbac.Principal, project_id: str, permission: str) -> str:
    try:
        org_id = await asyncio.to_thread(service.project_org_id, project_id)
    except service.NotFound:
        raise _err(404, "not_found", f"project '{project_id}' not found")
    if not principal.can("project.read", org_id):
        raise _err(404, "not_found", f"project '{project_id}' not found")
    _require(principal, permission, org_id)
    return org_id


# --- request bodies ---------------------------------------------------------------------------

class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrgCreate(_Body):
    slug: str
    name: Optional[str] = None
    owner_email: Optional[str] = None


class OrgStatus(_Body):
    status: str


class ProjectCreate(_Body):
    slug: str
    name: Optional[str] = None
    policy: Optional[Dict[str, Any]] = None


class KeyCreate(_Body):
    name: str = "default"
    scopes: Optional[List[str]] = None
    expires_in_days: Optional[int] = Field(default=None, gt=0, le=3650)


class KeyRotate(_Body):
    grace_hours: float = Field(default=24, ge=0, le=24 * 30)


class PolicyPut(_Body):
    document: Dict[str, Any]
    comment: Optional[str] = None


class CredentialPut(_Body):
    api_key: str = Field(min_length=8, max_length=500)
    project_id: Optional[str] = None


class MemberCreate(_Body):
    email: str
    role: str = "viewer"


class MemberUpdate(_Body):
    role: str


class AdminTokenCreate(_Body):
    name: str = "automation"
    role: str = "admin"
    expires_in_days: Optional[int] = Field(default=None, gt=0, le=3650)


class WebhookCreate(_Body):
    url: str = Field(min_length=8, max_length=500)
    event_types: List[str] = Field(default_factory=lambda: ["request.block", "budget.*"])


class WebhookUpdate(_Body):
    active: Optional[bool] = None
    event_types: Optional[List[str]] = None


# --- identity -----------------------------------------------------------------------------------

@router.get("/me")
async def me(principal: rbac.Principal = Depends(require_admin)):
    return {"actor": principal.actor, "platform_admin": principal.platform, "roles": principal.roles}


# --- organizations -----------------------------------------------------------------------------

@router.post("/orgs", status_code=201)
async def create_org(body: OrgCreate, principal: rbac.Principal = Depends(require_admin)):
    _require(principal, "org.create", None)
    org = await _run(service.create_org, body.slug, body.name or body.slug, principal.actor)
    if body.owner_email:
        await _run(service.add_member, org["id"], body.owner_email, "owner", principal.actor)
    return org


@router.get("/orgs")
async def list_orgs(principal: rbac.Principal = Depends(require_admin)):
    orgs = await _run(service.list_orgs)
    return {"data": [o for o in orgs if principal.platform or o["id"] in principal.org_ids]}


@router.get("/orgs/{org}")
async def get_org(org: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "org.read")
    return await _run(service.get_org, org)


@router.patch("/orgs/{org}")
async def set_org_status(org: str, body: OrgStatus, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "org.status")
    return await _run(service.set_org_status, org, body.status, principal.actor)


# --- members (SSO) and admin tokens --------------------------------------------------------------

@router.get("/orgs/{org}/members")
async def list_members(org: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "member.read")
    return {"data": await _run(service.list_members, org)}


@router.post("/orgs/{org}/members", status_code=201)
async def add_member(org: str, body: MemberCreate, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "member.write")
    return await _run(service.add_member, org, body.email, body.role, principal.actor)


@router.patch("/orgs/{org}/members/{email}")
async def update_member(org: str, email: str, body: MemberUpdate, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "member.write")
    return await _run(service.set_member_role, org, email, body.role, principal.actor)


@router.delete("/orgs/{org}/members/{email}", status_code=204)
async def remove_member(org: str, email: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "member.write")
    await _run(service.remove_member, org, email, principal.actor)


@router.post("/orgs/{org}/admin-tokens", status_code=201)
async def create_org_admin_token(org: str, body: AdminTokenCreate, principal: rbac.Principal = Depends(require_admin)):
    """The response's ``token`` is shown once. A token can't grant more than its creator has."""
    org_id = await _org(principal, org, "admin_token.write")
    if not principal.platform and rbac.ROLES.index(body.role if body.role in rbac.ROLES else "owner") > \
            rbac.ROLES.index(principal.roles.get(org_id, "viewer")):
        raise _err(403, "forbidden", "Cannot create a token with a higher role than your own")
    return await _run(service.create_admin_token, org, body.name, body.role, principal.actor, body.expires_in_days)


@router.get("/orgs/{org}/admin-tokens")
async def list_org_admin_tokens(org: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "admin_token.read")
    return {"data": await _run(service.list_admin_tokens, org)}


@router.post("/orgs/{org}/admin-tokens/{token_id}/revoke")
async def revoke_org_admin_token(org: str, token_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "admin_token.write")
    return await _run(service.revoke_admin_token, org, token_id, principal.actor)


@router.post("/admin-tokens", status_code=201)
async def create_platform_token(body: AdminTokenCreate, principal: rbac.Principal = Depends(require_admin)):
    _require(principal, "platform.admin_token", None)
    return await _run(service.create_admin_token, None, body.name, "platform", principal.actor, body.expires_in_days)


@router.get("/admin-tokens")
async def list_platform_tokens(principal: rbac.Principal = Depends(require_admin)):
    _require(principal, "platform.admin_token", None)
    return {"data": await _run(service.list_admin_tokens, None)}


@router.post("/admin-tokens/{token_id}/revoke")
async def revoke_platform_token(token_id: str, principal: rbac.Principal = Depends(require_admin)):
    _require(principal, "platform.admin_token", None)
    return await _run(service.revoke_admin_token, None, token_id, principal.actor)


# --- projects ----------------------------------------------------------------------------------

@router.post("/orgs/{org}/projects", status_code=201)
async def create_project(org: str, body: ProjectCreate, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "project.write")
    return await _run(service.create_project, org, body.slug, body.name or body.slug, principal.actor, body.policy)


@router.get("/orgs/{org}/projects")
async def list_projects(org: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "project.read")
    return {"data": await _run(service.list_projects, org)}


@router.get("/projects/{project_id}")
async def get_project(project_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "project.read")
    return await _run(service.get_project, project_id)


# --- API keys ----------------------------------------------------------------------------------

@router.post("/projects/{project_id}/keys", status_code=201)
async def create_key(project_id: str, body: KeyCreate, principal: rbac.Principal = Depends(require_admin)):
    """The response's ``key`` is the only time the plaintext key is ever shown."""
    await _project(principal, project_id, "key.write")
    return await _run(service.create_key, project_id, principal.actor, body.name, body.scopes, body.expires_in_days)


@router.get("/projects/{project_id}/keys")
async def list_keys(project_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "key.read")
    return {"data": await _run(service.list_keys, project_id)}


@router.post("/projects/{project_id}/keys/{key_id}/revoke")
async def revoke_key(project_id: str, key_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "key.write")
    return await _run(service.revoke_key, project_id, key_id, principal.actor)


@router.post("/projects/{project_id}/keys/{key_id}/rotate", status_code=201)
async def rotate_key(project_id: str, key_id: str, body: Optional[KeyRotate] = None,
                     principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "key.write")
    return await _run(service.rotate_key, project_id, key_id, principal.actor, (body or KeyRotate()).grace_hours)


# --- policies ----------------------------------------------------------------------------------

@router.get("/projects/{project_id}/policy")
async def get_policy(project_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "policy.read")
    return await _run(service.get_policy, project_id)


@router.put("/projects/{project_id}/policy")
async def put_policy(project_id: str, body: PolicyPut, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "policy.write")
    return await _run(service.put_policy, project_id, body.document, principal.actor, body.comment)


@router.get("/projects/{project_id}/policy/versions")
async def list_policy_versions(project_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "policy.read")
    return {"data": await _run(service.list_policy_versions, project_id)}


@router.post("/projects/{project_id}/policy/rollback/{version}")
async def rollback_policy(project_id: str, version: int, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "policy.write")
    return await _run(service.rollback_policy, project_id, version, principal.actor)


@router.post("/policy/validate")
async def validate_policy(document: Dict[str, Any], principal: rbac.Principal = Depends(require_admin)):
    """Dry-run validation of a policy document, without publishing it."""
    try:
        return {"valid": True, "normalized": parse_policy(document).model_dump(exclude_defaults=True)}
    except PolicyError as exc:
        return {"valid": False, "error": str(exc)}


# --- provider keys (BYOK) ----------------------------------------------------------------------

@router.put("/orgs/{org}/provider-keys/{provider}")
async def put_provider_key(org: str, provider: str, body: CredentialPut, principal: rbac.Principal = Depends(require_admin)):
    """Store (or replace) the organization's key for ``provider``; with ``project_id``,
    a key for that project only. The key is encrypted at rest and never returned."""
    await _org(principal, org, "credential.write")
    return await _run(service.put_credential, org, provider, body.api_key, principal.actor, body.project_id)


@router.get("/orgs/{org}/provider-keys")
async def list_provider_keys(org: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "credential.read")
    return {"data": await _run(service.list_credentials, org)}


@router.delete("/orgs/{org}/provider-keys/{credential_id}", status_code=204)
async def delete_provider_key(org: str, credential_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _org(principal, org, "credential.write")
    await _run(service.delete_credential, org, credential_id, principal.actor)


# --- webhooks ----------------------------------------------------------------------------------

@router.post("/orgs/{org}/webhooks", status_code=201)
async def create_webhook(org: str, body: WebhookCreate, principal: rbac.Principal = Depends(require_admin)):
    """The response's ``secret`` (for verifying X-Guardrail-Signature) is shown once."""
    org_id = await _org(principal, org, "webhook.write")
    return await _run(webhooks.create, org_id, body.url, body.event_types, principal.actor)


@router.get("/orgs/{org}/webhooks")
async def list_webhooks(org: str, principal: rbac.Principal = Depends(require_admin)):
    org_id = await _org(principal, org, "webhook.read")
    return {"data": await _run(webhooks.list_for, org_id)}


@router.patch("/orgs/{org}/webhooks/{webhook_id}")
async def update_webhook(org: str, webhook_id: str, body: WebhookUpdate, principal: rbac.Principal = Depends(require_admin)):
    org_id = await _org(principal, org, "webhook.write")
    return await _run(webhooks.update, org_id, webhook_id, principal.actor, active=body.active,
                      event_types=body.event_types)


@router.delete("/orgs/{org}/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(org: str, webhook_id: str, principal: rbac.Principal = Depends(require_admin)):
    org_id = await _org(principal, org, "webhook.write")
    await _run(webhooks.delete, org_id, webhook_id, principal.actor)


@router.post("/orgs/{org}/webhooks/{webhook_id}/test")
async def test_webhook(org: str, webhook_id: str, principal: rbac.Principal = Depends(require_admin)):
    org_id = await _org(principal, org, "webhook.write")
    return await _run(webhooks.send_test, org_id, webhook_id)


# --- usage and budgets -------------------------------------------------------------------------

def _day(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        raise _err(422, "invalid", "dates must be YYYY-MM-DD")


@router.get("/orgs/{org}/usage")
async def org_usage(org: str, principal: rbac.Principal = Depends(require_admin), since: Optional[str] = None,
                    until: Optional[str] = None, project_id: Optional[str] = None):
    org_id = await _org(principal, org, "usage.read")
    rows = await _run(metering.usage_rows, org_id=org_id, project_id=project_id, since=_day(since), until=_day(until))
    return {"data": rows, "totals": metering.totals(rows)}


@router.get("/orgs/{org}/usage.csv")
async def org_usage_csv(org: str, principal: rbac.Principal = Depends(require_admin), since: Optional[str] = None,
                        until: Optional[str] = None):
    """Daily usage per project as CSV, for billing systems."""
    org_id = await _org(principal, org, "usage.read")
    rows = await _run(metering.usage_rows, org_id=org_id, since=_day(since), until=_day(until))
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["day", "org_id", "project_id", "app", *metering.COUNTERS])
    writer.writeheader()
    writer.writerows(rows)
    return Response(buffer.getvalue(), media_type="text/csv",
                    headers={"content-disposition": f'attachment; filename="usage-{org}.csv"'})


@router.get("/usage")
async def platform_usage(principal: rbac.Principal = Depends(require_admin), since: Optional[str] = None,
                         until: Optional[str] = None):
    _require(principal, "platform.admin_token", None)
    rows = await _run(metering.usage_rows, all_orgs=True, since=_day(since), until=_day(until))
    return {"data": rows, "totals": metering.totals(rows)}


@router.get("/projects/{project_id}/budget")
async def project_budget(project_id: str, principal: rbac.Principal = Depends(require_admin)):
    await _project(principal, project_id, "usage.read")
    policy = await _run(service.get_policy, project_id)
    return await _run(metering.budget_status, project_id, parse_policy(policy["document"]).budget)


# --- audit -------------------------------------------------------------------------------------

@router.get("/audit")
async def list_audit(
    principal: rbac.Principal = Depends(require_admin),
    org_id: Optional[str] = None,
    project_id: Optional[str] = None,
    event_type: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    if not principal.platform:
        # Non-platform principals only see their own organizations' events.
        if org_id is None and len(principal.org_ids) == 1:
            org_id = next(iter(principal.org_ids))
        if org_id is None:
            raise _err(422, "invalid", "org_id is required")
        _require(principal, "audit.read", org_id)
        if project_id:
            await _project(principal, project_id, "audit.read")
    return {"data": await _run(audit.query, org_id=org_id, project_id=project_id, event_type=event_type,
                               action=action, since=since, until=until, limit=limit)}


@router.get("/orgs/{org}/audit/export")
async def export_org_audit(org: str, principal: rbac.Principal = Depends(require_admin), after: Optional[str] = None,
                           limit: int = Query(default=1000, ge=1, le=5000)):
    """NDJSON, oldest first, for SIEM ingestion. Pass the X-Next-Cursor header back as
    ``after`` to continue."""
    org_id = await _org(principal, org, "audit.read")
    return await _export(org_id, after, limit)


@router.get("/audit/export")
async def export_all_audit(principal: rbac.Principal = Depends(require_admin), after: Optional[str] = None,
                           limit: int = Query(default=1000, ge=1, le=5000)):
    _require(principal, "audit.verify", None)
    return await _export(None, after, limit)


async def _export(org_id: Optional[str], after: Optional[str], limit: int) -> Response:
    events, cursor = await _run(audit.export, org_id=org_id, after=after, limit=limit)
    body = "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
    headers = {"x-next-cursor": cursor} if cursor else {}
    return Response(body, media_type="application/x-ndjson", headers=headers)


@router.get("/audit/verify")
async def verify_audit(principal: rbac.Principal = Depends(require_admin)):
    _require(principal, "audit.verify", None)
    chains = await _run(audit.verify_chains)
    return {"intact": all(c["intact"] for c in chains.values()), "chains": chains}


@router.post("/audit/purge")
async def purge_audit(principal: rbac.Principal = Depends(require_admin),
                      retention_days: Optional[int] = Query(default=None, ge=1)):
    _require(principal, "audit.purge", None)
    deleted = await _run(audit.purge_expired, retention_days)
    audit.record("admin.audit_purged", actor=principal.actor,
                 details={"deleted": deleted, "retention_days": retention_days or config.AUDIT_RETENTION_DAYS})
    return {"deleted": deleted}
