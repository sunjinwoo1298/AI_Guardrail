"""Admin API (/admin/v1): organizations, projects, API keys, policies, provider keys,
and the audit log.

Authentication is a single bootstrap credential, ``Authorization: Bearer
<ADMIN_API_TOKEN>``, meant for the operator's own tooling. Per-user admin accounts with
SSO and roles are a later phase. With ADMIN_API_TOKEN unset the API is disabled (404),
and with no DATABASE_URL it returns 503.
"""
from __future__ import annotations

import asyncio
import hmac
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.control import audit, db, service
from app.control.crypto import EncryptionUnavailable
from app.control.policy import PolicyError
from app.core import config

router = APIRouter(prefix="/admin/v1", tags=["admin"])

ADMIN_ACTOR = "admin-token"


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"message": message, "type": "admin_error", "code": code})


async def require_admin(request: Request) -> str:
    if not config.ADMIN_API_TOKEN:
        raise HTTPException(status_code=404, detail="Not Found")
    header = request.headers.get("authorization", "")
    provided = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not provided or not hmac.compare_digest(provided.encode("utf-8"), config.ADMIN_API_TOKEN.encode("utf-8")):
        raise _err(401, "unauthorized", "Admin authentication required")
    if not db.enabled():
        raise _err(503, "control_plane_disabled", "Control plane database is not configured (DATABASE_URL)")
    return ADMIN_ACTOR


async def _run(func, *args, **kwargs):
    """Run a blocking control-plane operation in a worker thread, mapping its errors."""
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except service.NotFound as exc:
        raise _err(404, "not_found", str(exc))
    except service.Conflict as exc:
        raise _err(409, "conflict", str(exc))
    except (service.Invalid, PolicyError) as exc:
        raise _err(422, "invalid", str(exc))
    except EncryptionUnavailable as exc:
        raise _err(503, "encryption_unavailable", f"{exc}; provider keys cannot be stored")


# --- request bodies ---------------------------------------------------------------------------

class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrgCreate(_Body):
    slug: str
    name: Optional[str] = None


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


# --- organizations -----------------------------------------------------------------------------

@router.post("/orgs", status_code=201)
async def create_org(body: OrgCreate, actor: str = Depends(require_admin)):
    return await _run(service.create_org, body.slug, body.name or body.slug, actor)


@router.get("/orgs")
async def list_orgs(actor: str = Depends(require_admin)):
    return {"data": await _run(service.list_orgs)}


@router.get("/orgs/{org}")
async def get_org(org: str, actor: str = Depends(require_admin)):
    return await _run(service.get_org, org)


@router.patch("/orgs/{org}")
async def set_org_status(org: str, body: OrgStatus, actor: str = Depends(require_admin)):
    return await _run(service.set_org_status, org, body.status, actor)


# --- projects ----------------------------------------------------------------------------------

@router.post("/orgs/{org}/projects", status_code=201)
async def create_project(org: str, body: ProjectCreate, actor: str = Depends(require_admin)):
    return await _run(service.create_project, org, body.slug, body.name or body.slug, actor, body.policy)


@router.get("/orgs/{org}/projects")
async def list_projects(org: str, actor: str = Depends(require_admin)):
    return {"data": await _run(service.list_projects, org)}


@router.get("/projects/{project_id}")
async def get_project(project_id: str, actor: str = Depends(require_admin)):
    return await _run(service.get_project, project_id)


# --- API keys ----------------------------------------------------------------------------------

@router.post("/projects/{project_id}/keys", status_code=201)
async def create_key(project_id: str, body: KeyCreate, actor: str = Depends(require_admin)):
    """The response's ``key`` is the only time the plaintext key is ever shown."""
    return await _run(service.create_key, project_id, actor, body.name, body.scopes, body.expires_in_days)


@router.get("/projects/{project_id}/keys")
async def list_keys(project_id: str, actor: str = Depends(require_admin)):
    return {"data": await _run(service.list_keys, project_id)}


@router.post("/projects/{project_id}/keys/{key_id}/revoke")
async def revoke_key(project_id: str, key_id: str, actor: str = Depends(require_admin)):
    return await _run(service.revoke_key, project_id, key_id, actor)


@router.post("/projects/{project_id}/keys/{key_id}/rotate", status_code=201)
async def rotate_key(project_id: str, key_id: str, body: Optional[KeyRotate] = None,
                     actor: str = Depends(require_admin)):
    return await _run(service.rotate_key, project_id, key_id, actor, (body or KeyRotate()).grace_hours)


# --- policies ----------------------------------------------------------------------------------

@router.get("/projects/{project_id}/policy")
async def get_policy(project_id: str, actor: str = Depends(require_admin)):
    return await _run(service.get_policy, project_id)


@router.put("/projects/{project_id}/policy")
async def put_policy(project_id: str, body: PolicyPut, actor: str = Depends(require_admin)):
    return await _run(service.put_policy, project_id, body.document, actor, body.comment)


@router.get("/projects/{project_id}/policy/versions")
async def list_policy_versions(project_id: str, actor: str = Depends(require_admin)):
    return {"data": await _run(service.list_policy_versions, project_id)}


@router.post("/projects/{project_id}/policy/rollback/{version}")
async def rollback_policy(project_id: str, version: int, actor: str = Depends(require_admin)):
    return await _run(service.rollback_policy, project_id, version, actor)


@router.post("/policy/validate")
async def validate_policy(document: Dict[str, Any], actor: str = Depends(require_admin)):
    """Dry-run validation of a policy document, without publishing it."""
    from app.control.policy import parse_policy

    try:
        return {"valid": True, "normalized": parse_policy(document).model_dump(exclude_defaults=True)}
    except PolicyError as exc:
        return {"valid": False, "error": str(exc)}


# --- provider keys (BYOK) ----------------------------------------------------------------------

@router.put("/orgs/{org}/provider-keys/{provider}")
async def put_provider_key(org: str, provider: str, body: CredentialPut, actor: str = Depends(require_admin)):
    """Store (or replace) the organization's key for ``provider``; with ``project_id``,
    a key for that project only. The key is encrypted at rest and never returned."""
    return await _run(service.put_credential, org, provider, body.api_key, actor, body.project_id)


@router.get("/orgs/{org}/provider-keys")
async def list_provider_keys(org: str, actor: str = Depends(require_admin)):
    return {"data": await _run(service.list_credentials, org)}


@router.delete("/orgs/{org}/provider-keys/{credential_id}", status_code=204)
async def delete_provider_key(org: str, credential_id: str, actor: str = Depends(require_admin)):
    await _run(service.delete_credential, org, credential_id, actor)


# --- audit -------------------------------------------------------------------------------------

@router.get("/audit")
async def list_audit(
    actor: str = Depends(require_admin),
    org_id: Optional[str] = None,
    project_id: Optional[str] = None,
    event_type: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    return {"data": await _run(audit.query, org_id=org_id, project_id=project_id, event_type=event_type,
                               action=action, since=since, until=until, limit=limit)}


@router.get("/audit/verify")
async def verify_audit(actor: str = Depends(require_admin)):
    chains = await _run(audit.verify_chains)
    return {"intact": all(c["intact"] for c in chains.values()), "chains": chains}


@router.post("/audit/purge")
async def purge_audit(actor: str = Depends(require_admin), retention_days: Optional[int] = Query(default=None, ge=1)):
    deleted = await _run(audit.purge_expired, retention_days)
    audit.record("admin.audit_purged", actor=actor, details={"deleted": deleted, "retention_days": retention_days
                                                             or config.AUDIT_RETENTION_DAYS})
    return {"deleted": deleted}
