# AI Guardrail Proxy — Project Context (for coding agents)

> Read this first. It describes what the project is, how a request flows through it, what each module does, and the non-obvious gotchas.
> Derived from the code on branch `upgrades-testing` (the README is partly outdated — where they conflict, **trust the code / this file**).

## 1. What this project is

A **FastAPI LLM gateway / guardrail proxy**. It sits between clients and LLM providers and adds:

- API-key auth + per-key rate limiting (RPM and TPM)
- Prompt-injection detection, PII detection, risk scoring, and prompt sanitization (PII masking) **before** the model sees the prompt
- Two-layer response cache (Redis exact + ChromaDB semantic)
- Multi-provider routing (Groq, OpenAI, Gemini, Anthropic) behind one OpenAI-compatible interface
- Resilience: retry w/ backoff, per-model circuit breaker, fallback model, graceful "degraded" response
- Output hardening (PII redaction, HTML escape, system-prompt canary redaction, length truncation)
- Observability: JSON logs, Prometheus metrics, OpenTelemetry traces, Grafana dashboards, alert rules
- A React web console, a Locust load test, and a pytest suite

Python 3.12, async throughout. Default provider/model: Groq, `groq/openai/gpt-oss-120b`.

## 2. Endpoints

| Method/Path | Purpose | Notes |
|---|---|---|
| `POST /generate` | Simple `{"prompt": "..."}` → returns the **metadata payload** (not the OpenAI completion) | Auth required |
| `POST /stream` | Same input, SSE stream: `data: <text delta>\n\n` chunks, then `data: {"__meta": {...}}` | Auth required |
| `POST /v1/chat/completions` | OpenAI-compatible (`model`, `messages`, `stream`, `temperature`, `max_tokens`) | Auth required; `stream=true` ends with `data: [DONE]`; non-stream returns the raw OpenAI-style completion dict (no `__meta`) |
| `GET /`, `/health`, `/ready` | Liveness/readiness (static responses, don't check dependencies) | Public |
| `GET /metrics` | Prometheus exposition | Public |

Auth header: `x-api-key`. Error codes: `401` bad/missing key, `403` blocked by security policy, `429` rate limited, `500` upstream error that escaped fallbacks (`HTTPException`). Total model outage returns **HTTP 200 with `status: "degraded"`** (for `/generate`).

## 3. Request lifecycle (actual order)

`app/main.py` registers middleware as Auth, Security, Logging. Starlette makes the **last added the outermost**, so the real execution order is:

```
Logging  →  Security  →  Auth  →  Route handler → llm_orchestrator
```

(The README diagram says Auth first; that is not what the code does. Consequence: an unauthenticated request is still scanned by Security and can get `403` before it would get `401`. Auth also re-reads the body and sets `request.state.raw_payload`, but Security runs earlier and so reads the body itself.)

1. **LoggingMiddleware** ([app/middleware/logging_middleware.py](../app/middleware/logging_middleware.py)): sets `request.state.request_id` (from `x-request-id` header or generated), tracks active-request gauge, records HTTP count/latency metrics, adds `x-request-id` response header.
2. **SecurityMiddleware** ([app/middleware/security_middleware.py](../app/middleware/security_middleware.py)): only for POST/PUT/PATCH to `/generate`, `/stream`, `/v1/chat/completions`. Extracts the prompt (`prompt` field, or concatenated `user` message contents), calls `calculate_risk_score`, builds sanitized prompt/messages, stores a `security_context` dict on `request.state`, and returns **403** if `should_block_prompt(...)`. **Fails open** on any unexpected exception (logs the error and continues); invalid JSON is also passed through.
3. **AuthMiddleware** ([app/middleware/auth_middleware.py](../app/middleware/auth_middleware.py)): skips `/`, `/health`, `/ready`, `/metrics`. If `REQUIRE_API_KEY`, validates `x-api-key` against `API_KEYS` (else 401). Estimates tokens as `len(text)//4` (min 1), then calls `check_and_consume` (Redis Lua, atomic RPM+TPM). `429` on exceed. Saves `request.state.api_key`, `reserved_tokens`.
4. **Routes** ([app/api/routes.py](../app/api/routes.py)): merge `api_key` + `reserved_tokens` into `security_context`, use `security_context["sanitized_prompt"]` (or `request.state.sanitized_messages` for chat completions), call the orchestrator.
5. **Orchestrator** ([app/services/llm_orchestrator.py](../app/services/llm_orchestrator.py)) `generate_response` / `stream_response`:
   1. Build messages; cache key query = last `user` message text.
   2. Cache lookup: Redis exact → Chroma semantic. On hit: re-sanitize cached text, record metrics, **settle** rate-limit tokens, return (for semantic hits it also writes a new cache entry for the new phrasing).
   3. Miss: `_create_completion(messages, model)` → provider resolution → circuit-breaker check → `retry_async` around `adapter.generate/stream`.
   4. On primary failure → try `SECONDARY_MODEL_NAME`. If that fails too → **refund** reserved tokens, return degraded payload (`status:"degraded"`, `reason:"model_unavailable"`; `/generate` body also becomes the metadata payload).
   5. Success: compute cost, `sanitize_response`, truncate to `MAX_RESPONSE_CHARS`, record metrics, write cache (Redis + Chroma), `settle_tokens(reserved, actual)`.
   6. Any other exception → refund (stream path) and `HTTPException(500)`.

## 4. Modules and how they work

### Security (`app/security/`)
- **pii_detector.py** — `detect_pii(text)`: NFKC-normalize, run Presidio `AnalyzerEngine` (spaCy `en_core_web_sm`) **plus** regex patterns (API keys `sk-/rk_/gsk_`, email, phone, SSN, credit card, IP, Aadhaar, PAN); regex hits not already covered by a Presidio span are added. If Presidio import/analysis fails → regex only. `PII_WEIGHTS` maps type → risk contribution (e.g. API_KEY 0.35, SSN/CC/AADHAAR 0.30, email/phone 0.20, IP 0.10).
- **prompt_guard.py** — `score_prompt_injection(text)`: normalize (NFKC, html-unescape, collapse whitespace); `fast_tripwire` regexes (phrases like "ignore all instructions", "reveal system prompt", "system override", plus structural tokens `<|im_start|>`, `[system]`, triple quotes, code fences); then the HF classifier `protectai/deberta-v3-base-prompt-injection-v2` (lazy-loaded; falls back to tripwire-only with confidence 1.0 if unavailable). A tripwire hit boosts classifier confidence by 0.15. Returns `{is_injection, confidence, signals, source}`. NOTE: `signals` are the **tripwire matches only** — classifier-only detections produce `is_injection=True` but empty `signals`.
- **risk_engine.py** — `calculate_risk_score(text)` → `(score, pii_detections, injection_signals)`. Score = Σ PII weights + injection confidence (if injection) + behavior risk (+0.05 for email/phone unless allowed), capped at 1.0. **Behavior risk**: Redis counter keyed by SHA-256 of the normalized prompt (`ai_proxy:prompt_probe:*`), window `BEHAVIOR_RISK_WINDOW_SECONDS`; repeated identical prompts add up to 0.35. `should_block_prompt`: block if `BLOCK_PROMPT_INJECTION` and any injection **signals** exist; or score ≥ `MAX_BEHAVIOR_RISK_SCORE` with signals; or `BLOCK_HIGH_RISK_PROMPTS` and score ≥ `MAX_RISK_SCORE` (0.8).
- **sanitizer.py** — `sanitize_text`: replaces detected spans (end→start) with labels like `[EMAIL]`, `[SSN]`, then re-runs regex patterns, then `html.escape`. `sanitize_response` = `sanitize_text` + replaces `SYSTEM_PROMPT_CANARY` with `[REDACTED_SYSTEM_PROMPT]`.
- **rate_limiter.py** — Redis fixed 60s window buckets keyed by SHA-256 prefix of API key. One Lua script atomically checks+increments RPM (weight 1) and TPM (estimated tokens). `refund_tokens` (Lua) on upstream failure; `settle_tokens(reserved, actual)` reconciles estimate vs. actual afterward. **Fails open** if Redis is unavailable.

### Providers (`app/providers/`)
- **base.py** `BaseLLMAdapter`: `generate(messages, model, ...)` → OpenAI-format dict; `stream(...)` → async generator of OpenAI-format chunk dicts.
- **groq_adapter.py / openai_adapter.py** — direct `httpx` calls to OpenAI-compatible REST APIs (Groq: `api.groq.com/openai/v1/chat/completions`). 30s httpx timeout.
- **anthropic_adapter.py / gemini_adapter.py** — translate OpenAI messages ↔ native formats and translate responses/stream chunks back to OpenAI shape.
- **factory.py** — `resolve_provider_and_model(name)` → `(provider, real_model)`: `groq/…`, `gemini/…`, `anthropic/…` prefixes; `openai/gpt-oss*` / `safeguard` are treated as Groq-hosted when `DEFAULT_PROVIDER=groq`; otherwise substring inference (`claude`→anthropic, `gemini`→gemini, `gpt-4`→openai, `llama/qwen/mixtral/gpt-oss…`→groq); fallback = `DEFAULT_PROVIDER`. `get_adapter(provider)` returns singleton adapters.

### Services (`app/services/`)
- **llm_orchestrator.py** — the core pipeline described in §3.5. Holds per-model `CircuitBreaker`s in `_breakers` (keyed by the model string as passed in, e.g. `groq/openai/gpt-oss-120b`; tests reset this dict). Default model `groq/openai/gpt-oss-120b`. Emits `("content", chunk)` and `("metadata", payload)` events for streaming. Response metadata includes `status, latency, model, cache_hit, cache_type, prompt/completion/total_tokens, estimated_cost, cache_saved_cost, request_id, response` plus the whole `security_context` (merged in — includes `original_prompt`, `sanitized_prompt`, `risk_score`, `pii_*`, `prompt_injection_*`, `blocked`, and the caller's `api_key`/`reserved_tokens`; see gotchas).
- **cache_service.py** — Redis exact cache (key `semantic_cache:exact:<sha256(normalized prompt)>`, JSON payload, TTL `CACHE_TTL_SECONDS`, `REDIS_TIMEOUT_SECONDS`) and ChromaDB semantic cache (in-memory `chromadb.Client()`, cosine space, embeddings from SentenceTransformer `BAAI/bge-small-en-v1.5`; a hit is cosine **distance** ≤ `CACHE_SIMILARITY_THRESHOLD` (0.15); `CHROMA_TIMEOUT_SECONDS`). All sync calls run via `asyncio.to_thread` with timeouts; failures degrade to cache-miss. Writes go to both layers.
- **groq_service.py** — **legacy**, older Groq-only (`AsyncGroq`) implementation. Not imported by `app/`. `resilient_groq_service.py` was deleted (still shown as `D` in git status). The tests import `llm_orchestrator` under the alias `groq_service`.

### Core (`app/core/`)
- **config.py** — all settings from env (`python-dotenv`), module-level constants; `validate_settings()` runs at app startup (lifespan) and raises `ValueError` on bad config (e.g. missing provider key for `DEFAULT_PROVIDER`, empty `API_KEYS` while `REQUIRE_API_KEY`).
- **resilience.py** — `CircuitBreaker` (opens after N consecutive failures, auto-resets after timeout; no half-open state tracking beyond reset), `retry_async` (exponential backoff + jitter; retries only timeout/connection/OS errors — HTTP status errors from `httpx` are NOT retried), `CircuitOpenError`.
- **pricing.py / cost_calculator.py** — per-1k-token price table keyed by bare model name; unknown model → cost 0.0 with a warning. Provider prefix is stripped before lookup.
- **logger.py / context.py / request_id.py** — JSON-formatted logging with a request-id contextvar; request-id generation.

### Observability (`app/observability/`, `observability/`)
- **metrics.py** — Prometheus metrics (`ai_proxy_http_requests_total`, `…_http_request_duration_seconds`, `…_active_requests`, `…_cache_lookups_total{layer,result}`, `…_cache_writes_total`, `…_model_requests_total`, `…_model_latency_seconds`, `…_model_tokens_total`, `…_model_cost_total`, `…_stream_duration_seconds`, `…_security_events_total`, `…_security_blocks_total`, `…_security_risk_score`).
- **tracing.py** — OpenTelemetry setup (OTLP HTTP exporter, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`), FastAPI instrumentation. Optional import; code uses `trace.get_tracer("ai_guardrail_proxy")` spans such as `cache.lookup`, `model.call`, `response.redaction`, `middleware.security`, `security.risk_engine`.
- **observability/** — `prometheus/prometheus.yml` (scrapes `app:8000/metrics`) and `alerts.yml` (HighP95Latency, HighErrorRate, CacheFailureRateHigh, SecurityBlockSpike), `otel/otel-collector-config.yaml`, `grafana/` provisioning + dashboard JSON.
- **`prometheus_client/` at repo root** is a **local minimal shim** that shadows the real `prometheus-client` package (listed in requirements.txt). It implements Counter/Gauge/Histogram/`make_asgi_app`/`generate_latest`. Be aware when changing metrics code or adding features like Summary/multiprocess mode.

### Frontend (`frontend/`) — current UI
React 18 + Vite, plain CSS, no UI libraries. Views: Playground, Security Lab, Test cases, Metrics (`src/components/`). `src/api.js` is the proxy client (incl. SSE parsing for `/stream`, whose events are `data: <delta>\n\n` then `data: {"__meta":…}`, and a Prometheus text parser). Dev: `npm run dev` on :5173 with Vite proxying `/api` → `localhost:8000`. Docker: `frontend/Dockerfile` (nginx, proxies `/api/` → `app:8000`), exposed on host port 5173 as the `frontend` compose service. Backend has no CORS middleware, so the UI relies on the `/api` proxy.

## 5. Infrastructure

- **Dockerfile**: `python:3.12-slim`, CPU-only torch, `pip install -r requirements.txt`, spaCy `en_core_web_sm`; runs `uvicorn app.main:app` on 8000.
- **docker-compose.observability.yml** services: `app` (8000, `.env`, mounts `./app`), `redis` (7-alpine, 6379, AOF), `prometheus` (9090), `grafana` (3000, admin/admin), `otel-collector` (4317/4318), `frontend` (React/nginx, host port 5173).
- **CI** (`.github/workflows/ci.yml`): `pytest -q` on PR/push; optional Locust job if `LOAD_TEST_TARGET` secret is set.
- **Load test**: `load_test/locustfile.py` (sequential `/generate` then `/stream`), results CSVs in `load_test/` (gitignored `*.csv`).

## 6. Configuration (env vars; see `app/core/config.py` for all defaults)

Providers: `DEFAULT_PROVIDER` (groq|openai|gemini|anthropic), `GROQ_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `SECONDARY_MODEL_NAME` (fallback; default `openai/gpt-oss-20b`).
Auth/limits: `API_KEYS` (comma-separated), `REQUIRE_API_KEY`, `RPM_LIMIT_PER_MINUTE` (120), `TPM_LIMIT_PER_MINUTE` (12000).
Security: `ENABLE_PII_MASKING`, `BLOCK_PROMPT_INJECTION`, `BLOCK_HIGH_RISK_PROMPTS`, `MAX_RISK_SCORE` (0.8), `MAX_BEHAVIOR_RISK_SCORE` (0.35), `BEHAVIOR_RISK_WINDOW_SECONDS`, `BEHAVIOR_RISK_RATE_THRESHOLD`, `PROMPT_INJECTION_MODEL_NAME`, `SYSTEM_PROMPT_CANARY`, `ALLOW_EMAILS`, `ALLOW_PHONE_NUMBERS`, `MAX_PROMPT_CHARS` (4000), `MAX_RESPONSE_CHARS` (12000).
Cache: `REDIS_URL`, `CACHE_TTL_SECONDS`, `CACHE_SIMILARITY_THRESHOLD`, `EMBEDDING_MODEL_NAME`, `CHROMA_COLLECTION_NAME`.
Resilience: `REQUEST_TIMEOUT_SECONDS`, `REDIS_TIMEOUT_SECONDS`, `CHROMA_TIMEOUT_SECONDS`, `GROQ_TIMEOUT_SECONDS`, `GROQ_RETRY_ATTEMPTS`, `GROQ_RETRY_BASE_DELAY_SECONDS`, `GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD`, `GROQ_CIRCUIT_BREAKER_RESET_SECONDS` (the `GROQ_` names apply to **all** providers now).
Tracing: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`.

## 7. Tests (`tests/`)

`conftest.py` sets test env (`GROQ_API_KEY`, `API_KEYS=test-api-key`, `SECONDARY_MODEL_NAME=fallback-model`), adds repo root to `sys.path`, and resets `llm_orchestrator._breakers` before each test. Files: `test_auth.py`, `test_security.py`, `test_red_team_prompts.py` (adversarial prompts), `test_groq_service.py` (orchestrator behavior: cache, fallback, degraded), `test_failure_modes.py`, `test_resilience.py` (breaker/retry). Run: `python -m pytest -q`. Tests monkeypatch the orchestrator/cache/adapter layers, so they don't need live Groq/Redis.

## 8. Run it

```bash
# full stack
docker compose -f docker-compose.observability.yml up -d --build
# app only (needs .env with GROQ_API_KEY, API_KEYS; Redis optional)
uvicorn app.main:app --reload --port 8000
cd frontend && npm install && npm run dev
python -m pytest -q
curl -X POST localhost:8000/generate -H "Content-Type: application/json" -H "x-api-key: test-api-key" -d '{"prompt":"hello"}'
```

Redis, Chroma, Presidio, and the injection classifier are all **optional at runtime**: each degrades (cache miss / regex-only / tripwire-only / no rate limiting) rather than crashing.

## 9. Gotchas and known issues (verify before relying on them)

- **Middleware order** is Logging → Security → Auth (see §3), contrary to the README.
- **Fail-open design**: Security middleware errors and Redis-less rate limiting allow traffic through. This is intentional for availability but is a security tradeoff.
- **Sensitive data in response metadata**: Fixed: `public_security_metadata` (`app/security/sanitizer.py`) strips `api_key`, `reserved_tokens` and `original_prompt`, and reduces `pii_detections` to `type/score/source` (no values/offsets), for both the response metadata and cached `security_metadata`. `sanitized_prompt` (masked) is still returned.
- **Cache key / content**: the cache query is the *sanitized* prompt (routes pass the sanitized prompt in), but semantic-hit re-writes and the `/v1/chat/completions` path use messages that were sanitized separately; the cache is global across API keys/tenants (not partitioned).
- **Injection blocking relies on `signals`**: classifier-only detections (no tripwire regex match) do not trigger the hard block via `BLOCK_PROMPT_INJECTION`; they only raise the risk score.
- **Retry scope**: only timeouts/connection/OS errors retry; `httpx.HTTPStatusError` (429/5xx) fails immediately into the circuit breaker/fallback.
- **Circuit breaker** is per-process and in-memory (not shared across workers); keyed by the model string the caller passed.
- **Streaming** token counts are estimated by whitespace splitting when the provider gives no usage; the streaming path can't un-send chunks, so streamed content is not redacted chunk-by-chunk (only the cached/final copy is sanitized).
- **`/ready`** doesn't verify Redis/Chroma/provider connectivity.
- **README drift**: still references `resilient_groq_service`, Groq-only flow, Auth-first order, and `SECONDARY_MODEL_NAME=llama-3.1-8b-instant`; `requirements.txt` is unpinned and includes `groq` (unused by the adapters) and `locust`/`pytest`.
- Chroma is in-memory (`chromadb.Client()`): the semantic cache is lost on restart and not shared across replicas.

## 10. Directory map

```
app/
  main.py                  FastAPI app, middleware wiring, health endpoints, /metrics mount
  api/routes.py            /generate, /stream, /v1/chat/completions
  core/                    config, logger, request id, pricing/cost, resilience (retry+breaker)
  middleware/              auth (+rate limit), security (guardrails), logging (metrics)
  models/request_models.py Pydantic PromptRequest, ChatCompletionRequest
  observability/           metrics.py, tracing.py
  providers/               base, factory, groq/openai/gemini/anthropic adapters
  security/                pii_detector, prompt_guard, risk_engine, sanitizer, rate_limiter
  services/                llm_orchestrator (active), cache_service, groq_service (legacy)
prometheus_client/         local shim of the prometheus_client package (shadows the real one)
frontend/                  React + Vite web console (nginx in Docker)
observability/             prometheus, grafana, otel configs
load_test/                 Locust harness + results
tests/                     pytest suite
context/                   (this folder) agent-facing documentation
```
