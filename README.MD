# AI Guardrail Proxy

AI Guardrail Proxy is a FastAPI-based proxy for LLM traffic that adds security guardrails, request observability, cost tracking, streaming responses, and a hybrid cache layer in front of Groq.

The goal of the project is to provide a practical reference implementation for safer and more cost-efficient LLM integrations.

## Highlights

- Security guardrails for prompt injection and common PII patterns
- Prompt sanitization before model execution and cache writes
- Exact-match Redis caching plus semantic ChromaDB caching
- Request, latency, token, cost, cache, and security metrics via Prometheus
- Grafana dashboard provisioning for local observability
- Standard JSON and SSE streaming response modes

## Architecture

```text
Client -> Security Middleware -> Cache Layer (Redis -> ChromaDB) -> Groq API
                     \-> Metrics / Prometheus
```

Security runs before cache lookup so sensitive input is screened before it can be reused or stored.

## Request Flow

1. A client sends a request to `POST /generate` or `POST /stream`.
2. Security middleware extracts the prompt and evaluates it for PII and prompt-injection signals.
3. If the policy threshold is exceeded, the request is blocked with HTTP `403`.
4. If the prompt is allowed, the route handler uses the sanitized prompt.
5. The service checks the Redis exact cache first.
6. If there is no exact hit, it checks the ChromaDB semantic cache.
7. If both caches miss, the request is sent to Groq.
8. The response, cost, latency, and security metadata are recorded and cached.

## Key Features

### Security

- Regex-based PII detection for:
  - email addresses
  - phone numbers
  - IP addresses
  - credit card numbers
  - SSNs
  - Aadhaar numbers
  - API keys
  - addresses
- Prompt-injection pattern detection
- Risk scoring with policy-based blocking
- Optional sanitization via environment flag

### Caching

- Redis exact cache for repeated prompts
- ChromaDB semantic cache for near-duplicate prompts
- SHA-256-based normalized cache keys
- Cache metadata includes request id, tokens, cost, and security context

### Observability

- Prometheus metrics exposed at `/metrics`
- Grafana dashboards provisioned from the repo
- Metrics for:
  - HTTP request count and latency
  - cache lookups and cache writes
  - model and cache latency
  - token and cost usage
  - security events and blocks
  - streaming duration

## Requirements

- Python 3.9+
- Redis
- Docker, if you want to run Prometheus and Grafana locally
- A Groq API key

## Installation

Create and activate a virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root and set at least:

```env
GROQ_API_KEY=your_groq_api_key_here
REDIS_URL=redis://localhost:6379/0
ENABLE_PII_MASKING=true
BLOCK_PROMPT_INJECTION=true
BLOCK_HIGH_RISK_PROMPTS=true
MAX_RISK_SCORE=0.8
EMBEDDING_MODEL_NAME=BAAI/bge-small-en-v1.5
CACHE_SIMILARITY_THRESHOLD=0.15
CACHE_TTL_SECONDS=3600
CHROMA_COLLECTION_NAME=semantic_cache
```

## Run the API

Start the FastAPI server from the project root:

```bash
uvicorn app.main:app --reload
```

Useful endpoints:

- `GET /` basic root response
- `GET /health` liveness check
- `GET /ready` readiness check
- `GET /metrics` Prometheus metrics

## API Usage

### Generate

```bash
curl -s -X POST http://127.0.0.1:8000/generate \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Explain transformer architecture in simple terms\"}"
```

Expected response fields include:

- `status`
- `response`
- `request_id`
- `cache_hit`
- `prompt_tokens`
- `completion_tokens`
- `total_tokens`
- `estimated_cost`
- security metadata such as `risk_score`, `pii_detected`, and `prompt_injection_detected`

### Stream

```bash
curl -N -X POST http://127.0.0.1:8000/stream \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Explain transformers briefly\"}"
```

The stream emits SSE `data:` chunks and ends with a final `__meta` event.

## Observability Stack

Start Prometheus and Grafana:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Services:

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

Grafana default credentials:

- Username: `admin`
- Password: `admin`

Prometheus scrapes the API at:

```text
host.docker.internal:8000
```

## Useful PromQL Queries

```promql
sum(ai_proxy_http_requests_total)
```

```promql
sum by (endpoint) (ai_proxy_http_requests_total)
```

```promql
sum by (layer, result) (ai_proxy_cache_lookups_total)
```

```promql
sum by (event, action) (ai_proxy_security_events_total)
```

```promql
histogram_quantile(0.95, sum(rate(ai_proxy_http_request_duration_seconds_bucket[5m])) by (le, endpoint))
```

## Tests

Run the test suite:

```bash
python -m pytest -q
```

The current test suite covers:

- blocked prompt handling
- health and readiness endpoints
- exact-cache hit behavior
- live model response behavior

## Production Notes

- The guardrails are intentionally conservative and regex-based.
- For stronger detection, consider adding a model-based or Presidio-backed PII layer.
- Tune the semantic cache threshold against real traffic before broad rollout.
- If you deploy this beyond local development, use proper secret management instead of a plain `.env` file.
- Consider persistent storage and explicit retention policies for cache data in production.

## Project Structure

```text
app/
  api/              FastAPI routes
  core/             Configuration, logging, pricing, request IDs
  middleware/       Security and logging middleware
  models/           Pydantic request models
  observability/    Prometheus metrics helpers
  security/         PII detection, prompt guard, sanitization, risk scoring
  services/         Groq integration and hybrid cache
observability/
  prometheus/       Prometheus config
  grafana/          Grafana provisioning and dashboard JSON
tests/              Minimal regression tests
```
