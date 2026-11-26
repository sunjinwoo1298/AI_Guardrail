# SOC 2 readiness: control mapping

This maps what the product already does to the SOC 2 Trust Services Criteria, and lists what
the company still has to put in place. It is a readiness aid for the auditor engagement,
**not** an attestation. Most SOC 2 controls are organisational (policies, HR, vendor
management, change management) and live outside the codebase.

Status: **In product** = implemented and tested in this repository. **Operator** = has to be
done by the team running the service. **Gap** = not yet built.

## Security (common criteria)

| Criterion | Control | Status |
|---|---|---|
| CC6.1 Logical access | API keys and admin tokens hashed; scoped keys; RBAC on the admin API; OIDC SSO | In product |
| CC6.1 | MFA for admins: enforced at the identity provider used for SSO | Operator |
| CC6.2 Provisioning and deprovisioning | Org members added and removed through the admin API (audited); the last owner can't be removed; tokens revocable and expiring | In product |
| CC6.2 | Quarterly access review (export members and admin tokens per org) | Operator |
| CC6.3 Least privilege | Viewer, admin, owner and platform roles; tokens can't exceed their creator's role | In product |
| CC6.6 Boundary protection | NetworkPolicy, ingress TLS, SSRF protection on outbound webhooks and MCP | In product + Operator (TLS at the ingress) |
| CC6.7 Data in transit and at rest | TLS to providers; customer secrets encrypted (Fernet); database encryption at rest | In product + Operator (managed-database encryption) |
| CC6.8 Malicious software | Minimal non-root image, read-only root filesystem; dependency ranges bounded; CI runs pip-audit and a Trivy image scan | In product; image signing is a **Gap** |
| CC7.1 Vulnerability detection | pip-audit and Trivy (fails on fixable critical/high) in CI | In product; continuous scanning of deployed images is Operator |
| CC7.2 Monitoring | Prometheus metrics, SLO burn-rate alerts, security-block and audit-drop alerts | In product |
| CC7.2 | Tamper-evident audit log with a verification API; SIEM feed and export | In product |
| CC7.3–7.5 Incident response | Runbook, on-call, post-mortems | Operator (`docs/OPERATIONS.md` is a starting point) |
| CC8.1 Change management | Versioned policies with rollback; migrations via Alembic; CI test suite (270+ tests) | In product; PR review rules and deploy approvals are Operator |
| CC9.2 Vendor management | Subprocessors listed in `docs/DATA_HANDLING.md` | Operator (DPAs with providers) |

## Availability

| Criterion | Control | Status |
|---|---|---|
| A1.1 Capacity | HPA, PDB, load-test results, per-pod capacity documented | In product |
| A1.2 Recovery | Postgres backups and point-in-time recovery; tested restore | Operator |
| A1.2 | Retries, circuit breaker, fallback model, readiness gating | In product |

## Confidentiality and privacy

| Criterion | Control | Status |
|---|---|---|
| C1.1 Confidential data | Prompts not stored; audit holds no text; PII masked before providers | In product |
| C1.2 Disposal | Audit retention purge; cache TTL; per-project cache off switch | In product |
| P-series | Data-subject requests (`docs/DATA_HANDLING.md`) | Operator |

## Before the audit window

1. Sign images (cosign) and scan deployed images continuously (CI already runs pip-audit and Trivy).
2. Enforce MFA at the IdP and switch admin access to SSO; keep `ADMIN_API_TOKEN` for break-glass
   only and rotate it.
3. Enable Postgres PITR backups and run a restore test.
4. Send the SIEM feed (`AUDIT_SIEM_WEBHOOK_URL`) to a store with retention of at least a year.
5. Write the organisational policies (access control, change management, incident response,
   vendor management) and collect evidence for the observation period.
