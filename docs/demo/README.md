# Demo: end-to-end run on the Docker stack

Recorded on the full Docker Compose stack (proxy, console, Postgres, Redis, Prometheus,
Grafana, OpenTelemetry collector, Jaeger). Every screen shows a real request to the proxy;
nothing is mocked.

| File | What it shows |
|---|---|
| `guardrail-proxy-demo.mp4` | 3 min 49 s captioned walkthrough (kept out of git because of its size; regenerate with the command below) |
| `screenshots/01-inspect/` | Personal data masked; instruction override, tool-result injection and zero-width evasion blocked; ordinary question allowed; full request to Groq; exact-cache hit |
| `screenshots/02-tenants-policies/` | Tenant and key created; monitor mode ("would block"); enforce, version history, re-run result |
| `screenshots/03-agent-security/` | Tool-call verdicts; leaking image removed; session locked after repeated attacks |
| `screenshots/04-observability/` | Grafana dashboard (overview, by app and model), Prometheus guardrail decisions, Jaeger trace of a `/generate` request |
| `e2e-report.json` | The 38 automated end-to-end checks and the provider calls they used |

## Provider usage

Limits checked before testing: Groq free tier 1,000 requests/day and 8,000 tokens/minute;
OpenRouter free tier 50 requests/day. The whole session used **12 Groq calls** and
**2 OpenRouter calls**, all with small token budgets.

## Reproduce

```bat
docker compose -f docker-compose.observability.yml up -d --build
set ADMIN_API_TOKEN=<the proxy's ADMIN_API_TOKEN>
python load_test\e2e_check.py
python load_test\record_demo.py --out docs\demo
```

`e2e_check.py` caps real model calls (`GROQ_BUDGET`, default 6; `OPENROUTER_BUDGET`, default 1).
`record_demo.py` needs Playwright with Microsoft Edge and OpenCV; it makes one Groq call
(the repeat is served from cache). For a clean take, start with an empty control-plane
database and cleared caches so the console's "Create demo tenant" path and a fresh model
call are shown.

## Issues found by this run (fixed)

- Guard-scan blocks were not counted in `ai_proxy_security_blocks_total`, so Grafana's
  "Blocked Prompts" panels stayed empty.
- The console inferred output redaction by counting labels in the answer, but the model
  echoes labels from its masked prompt; the proxy now reports `output_redacted`.
- A Docker-only `REDIS_URL` (`redis:6379`) made every request outside Docker wait on a failing
  DNS lookup (about 7 s); use `redis://localhost:6379/0` when running the proxy on the host.
