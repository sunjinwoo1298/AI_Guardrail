# Operations runbook

## Deploy (Kubernetes)

```bash
helm upgrade --install guardrail deploy/helm/ai-guardrail-proxy \
  --namespace guardrail --create-namespace \
  --set image.repository=<registry>/ai-guardrail-proxy --set image.tag=<version> \
  --set secrets.existingSecret=guardrail-secrets
```

The `guardrail-secrets` Secret needs: `DATABASE_URL`, `REDIS_URL`, `KEY_HASH_SECRET`,
`PROVIDER_KEY_ENCRYPTION_KEYS`, `SYSTEM_PROMPT_CANARY`, `METRICS_AUTH_TOKEN`, and the provider
keys you offer. Migrations run as a pre-upgrade job. New pods only receive traffic once `/ready`
passes.

## Alerts

| Alert | First checks |
|---|---|
| `AvailabilityErrorBudgetFastBurn` | Pod logs (JSON, `level=ERROR`) by `request_id`; recent deploy, so roll back with `helm rollback guardrail` |
| `UpstreamUnavailableHigh` | Provider status pages; circuit-breaker logs (`Primary model … failed`); Redis or database reachability if rate limits or auth fail closed |
| `GuardLatencySLOBurn` | CPU saturation (HPA at max?); raise `maxReplicas`; check `SECURITY_SCAN_THREADS` against the CPU request |
| `AuditEventsDropped` | Database latency and connections; audit events are queued in memory, up to 50k per pod |
| `SecurityBlockSpike` | `GET /admin/v1/audit?action=block`: one tenant under attack, or a bad policy publish (roll back with `…/policy/rollback/{v}`) |

## Routine tasks

| Task | How |
|---|---|
| Rotate `KEY_HASH_SECRET` | Invalidates **every** issued API key and admin token. Plan a re-issue window. |
| Rotate the provider-key encryption key | Put the new Fernet key **first** in `PROVIDER_KEY_ENCRYPTION_KEYS`, keep the old one after it, deploy; re-save secrets (or add a re-encryption job); then drop the old key |
| Purge the audit log | `POST /admin/v1/audit/purge` (platform admin) daily, e.g. from a CronJob |
| Verify the audit chain | `GET /admin/v1/audit/verify`; `intact: false` is a security incident |
| Suspend a tenant | `PATCH /admin/v1/orgs/{org}` with `{"status": "suspended"}`; every key stops within about 2 s |
| Investigate a block | `GET /admin/v1/audit?project_id=…&action=block`, then match `request_id` to the logs |
| Billing export | `GET /admin/v1/orgs/{org}/usage.csv?since=YYYY-MM-01` |

## Capacity

One worker per pod handles about 15 scanned requests/s on 8 vCPU (ONNX classifier bound). Plan
for roughly 1 vCPU per 2–3 requests/s of scanned traffic, plus headroom for the HPA.
