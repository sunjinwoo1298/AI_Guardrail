# AI Guardrail Proxy

This project is a FastAPI proxy around Groq with request tracing, token usage and cost tracking, streaming responses, and a hybrid cache layer.

## Phase 4: Semantic Cache

The cache pipeline works like this:

1. A prompt arrives at `/generate` or `/stream`.
2. Redis is checked first for an exact prompt match.
3. If Redis misses, the prompt is embedded with `BAAI/bge-small-en-v1.5`.
4. ChromaDB searches for the closest cached prompt by vector similarity.
5. If the distance is below the similarity threshold, the cached answer is returned.
6. Otherwise Groq is called, token usage and estimated cost are computed, and the result is stored in both Redis and ChromaDB.

## Required Services

- Groq API key in `.env`
- Redis running locally at `redis://localhost:6379/0` or override `REDIS_URL`

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload
```

## Endpoints

- `POST /generate` - returns a full JSON response with token usage, estimated cost, cache metadata, and request ID.
- `POST /stream` - streams SSE chunks and ends with a final `__meta` event containing cache and cost metadata.

## Phase 5: PII Guardrails + Security Middleware

The request flow now is:

1. Security middleware inspects the incoming prompt.
2. PII is detected with regex patterns for emails, phone numbers, IPs, credit cards, SSNs, Aadhaar-like numbers, API keys, and addresses.
3. Prompt injection patterns are checked with keyword and regex rules.
4. A risk score is computed from the findings.
5. The prompt is sanitized before it can reach cache or Groq.
6. High-risk or injection-heavy prompts can be blocked with a `403` response.
7. Only the sanitized prompt is sent to the cache layer and model layer.

### Security Metadata

Responses include:

- `risk_score`
- `pii_detected`
- `prompt_injection_detected`
- `sanitized`
- `blocked` when the request is denied by policy

### Policy Flags

These can be configured in `.env`:

- `ENABLE_PII_MASKING=true`
- `BLOCK_PROMPT_INJECTION=true`
- `BLOCK_HIGH_RISK_PROMPTS=true`
- `MAX_RISK_SCORE=0.8`
- `ALLOW_EMAILS=false`
- `ALLOW_PHONE_NUMBERS=false`

### Why the order matters

Security runs before cache so raw sensitive data never gets stored in Redis or ChromaDB. The cache layer only sees the sanitized prompt.

## Observability Dashboard

The project now exposes Prometheus metrics at `GET /metrics` and ships a Grafana dashboard that tracks:

- request analytics
- cache hit charts
- security events
- latency dashboards

### Metrics exposed

- `ai_proxy_http_requests_total`
- `ai_proxy_http_request_duration_seconds`
- `ai_proxy_cache_lookups_total`
- `ai_proxy_cache_writes_total`
- `ai_proxy_model_requests_total`
- `ai_proxy_model_latency_seconds`
- `ai_proxy_model_tokens_total`
- `ai_proxy_model_cost_total`
- `ai_proxy_security_events_total`
- `ai_proxy_security_blocks_total`
- `ai_proxy_security_risk_score`

### Run the observability stack

Run the app normally with FastAPI, then start Prometheus and Grafana with:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Prometheus scrapes the app from `host.docker.internal:8000/metrics`, which works well on Windows with Docker Desktop.

Grafana is available at `http://localhost:3000` with:

- username: `admin`
- password: `admin`

The dashboard is provisioned automatically from `observability/grafana/dashboards/ai-guardrail-observability.json`.
