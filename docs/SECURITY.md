# Security

## Reporting a vulnerability

Email **security@your-company.example** (replace with the real address before launch) with
the steps to reproduce. Please don't open a public issue. We acknowledge within 2 business days
and aim to fix critical issues within 7 days.

In scope: the proxy API, the admin API, the MCP gateway, the Helm chart defaults and the
container image. Out of scope: denial-of-service volume testing against the hosted service,
social engineering, and third-party model providers.

## Architecture and trust boundaries

```
client app ──(gpk_ key)──▶ proxy ──(tenant or platform key)──▶ model provider
                              │
admin / SSO ──(gpa_ token or OIDC JWT)──▶ /admin/v1
                              │
                 Postgres (control plane)   Redis (limits, budgets, cache)   ONNX models (local)
```

- **Untrusted input:** user messages, tool and function results, MCP tool descriptions and
  results, and documents. All are scanned. System prompts and assistant history come from the
  customer's application and are treated as trusted.
- **Untrusted output:** model text, tool-call arguments and reasoning. PII, secrets, canaries
  and exfiltration channels are redacted, and tool calls are checked against the policy.

## Controls in the code

| Area | Control | Where |
|---|---|---|
| Authentication | API keys stored as HMAC-SHA256 with a server secret; shown once; scopes, expiry, revocation, rotation | `app/control/crypto.py`, `tenancy.py` |
| Admin access | Role-based (viewer, admin, owner, platform); OIDC SSO; hashed admin tokens; break-glass bootstrap token | `app/control/rbac.py`, `oidc.py` |
| Tenant isolation | Every admin action is checked against the target org; other orgs return 404; cache, rate limits, behaviour scores and budgets are scoped per project | `app/api/admin.py`, `llm_orchestrator.py` |
| Secrets at rest | Customers' provider keys and webhook secrets encrypted with MultiFernet (key rotation supported) | `app/control/crypto.py` |
| Input security | Injection tripwires (with invisible-character, homoglyph, base64 and multilingual handling), ONNX classifier over the full text in windows, optional verifier, PII masking | `app/security/` |
| Output security | PII, secret and canary redaction (streams included), exfiltration scrubbing, tool policy, optional Llama Guard moderation | `sanitizer.py`, `agent_guard.py`, `moderation.py` |
| Fail-safe behaviour | The security scan fails closed (503); rate limits fail closed in production; `/ready` keeps unscreened pods out of rotation | `security_middleware.py`, `rate_limiter.py`, `main.py` |
| Abuse limits | Body and input size limits, RPM/TPM, monthly budgets, session lock-out | `auth_middleware.py`, `metering.py`, `session_risk.py` |
| Outbound requests | MCP upstreams and webhook targets must be public HTTPS (SSRF protection) | `mcp_gateway.py`, `webhooks.py` |
| Audit | Append-only, hash-chained audit log with no prompt text; verification API; retention purge; signed webhooks and a SIEM feed | `app/control/audit.py`, `webhooks.py` |
| Observability | `/metrics` behind a bearer token in production; bounded metric labels | `main.py`, `logging_middleware.py` |
| Container and Kubernetes | Non-root, read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault, NetworkPolicy, no service-account token | `Dockerfile`, `deploy/helm/` |

## Known limitations

- Images, audio and files are not content-scanned; `multimodal.action` controls them.
- The ML injection classifier is English-only.
- The MCP gateway does not pin resolved IPs, so DNS rebinding between the check and the
  connection is possible.
- A prompt-injection guard reduces risk; it can't guarantee every attack is caught. Measured
  detection and false-positive rates are published (README, "Security evaluation"). Use
  `load_test/benchmark.py` on public datasets for independent numbers.
