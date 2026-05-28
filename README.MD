# AI Guardrail Proxy

AI Guardrail Proxy is a production-focused FastAPI proxy for LLM traffic. It adds security guardrails, cost & token tracking, streaming support, and a hybrid caching layer (Redis + ChromaDB) in front of the Groq inference API — enabling safe, observable, and cost‑efficient AI integrations.

Key objectives:
- Prevent sensitive data leakage (PII detection & sanitization)
- Reduce inference cost with semantic caching
- Provide observability (Prometheus + Grafana)
- Support streaming responses with final metadata and metrics

---

Core features
- Security middleware: regex-based PII detection, prompt-injection detection, risk scoring, optional blocking, and sanitization.
- Hybrid cache: exact-match Redis cache + semantic vector search in ChromaDB using embeddings from `BAAI/bge-small-en-v1.5`.
- Token and cost tracking: token usage and estimated cost returned for each request and aggregated as Prometheus metrics.
- Streaming: SSE streaming endpoint that yields chunks and a final `__meta` event containing tokens, cost, request id, and security metadata.
- Observability: Prometheus-compatible metrics endpoint at `/metrics` and a Grafana dashboard (provisioned) for request analytics, cache hit rates, security events, and latency/cost charts.

---

Architecture (high level)

Client -> Security Middleware -> Cache Layer (Redis -> Chroma) -> Groq API
													\-> Observability (Prometheus)

Security middleware runs before cache to ensure raw sensitive data never gets stored.

---

Getting started (Quickstart)

Prerequisites
- Python 3.10+
- Redis (local or Docker)
- Docker (for Prometheus + Grafana stack)

Install dependencies

```bash
pip install -r requirements.txt
```

Environment variables (.env)
Create a `.env` file in the project root and set at minimum:

```
GROQ_API_KEY="your_groq_api_key_here"
REDIS_URL=redis://localhost:6379/0
ENABLE_PII_MASKING=true
BLOCK_PROMPT_INJECTION=true
BLOCK_HIGH_RISK_PROMPTS=true
MAX_RISK_SCORE=0.8
EMBEDDING_MODEL_NAME=BAAI/bge-small-en-v1.5
CACHE_SIMILARITY_THRESHOLD=0.15
```

Run the API server

```bash
uvicorn app.main:app --reload
```

API endpoints

- POST /generate
	- JSON body: `{ "prompt": "..." }`
	- Response: full JSON including `response`, `request_id`, token and cost fields, and security metadata.

Example:

```bash
curl -s -X POST http://127.0.0.1:8000/generate \
	-H "Content-Type: application/json" \
	-d '{"prompt":"Explain transformer architecture"}' | jq
```

- POST /stream
	- JSON body: `{ "prompt": "..." }`
	- Streams SSE `data: <chunk>` events and finishes with `data: {"__meta": {...}}` containing tokens, cost, and security metadata.

Example consumer (simple):

```bash
curl -N -X POST http://127.0.0.1:8000/stream -H "Content-Type: application/json" -d '{"prompt":"Explain transformers"}'
```

Observability (Prometheus + Grafana)

Prometheus metrics are exposed at `GET /metrics`.

To run Prometheus and Grafana locally (provisioned dashboards included):

```bash
docker compose -f docker-compose.observability.yml up -d
```

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

The provided Grafana dashboard highlights:
- Request rate and per-endpoint latency
- Cache hit rate and semantic vs exact cache breakdown
- Security events and blocked prompt counts
- Model latency and estimated cost trends

Security & policy

This project implements a conservative, regex-based PII detector and prompt-injection detector for demonstration and early production use. Key points:

- Security executes before cache to prevent storing raw sensitive text.
- PII is masked by default (`ENABLE_PII_MASKING=true`) and policy flags allow blocking high-risk prompts.
- Risk scoring combines PII and injection signals; blocked requests return HTTP 403 with a short reason and the risk score.

For enterprise deployments, replace the regex detector with Microsoft Presidio or another NER-based PII detector for better accuracy.

Caching behavior

- Exact cache (Redis): fast path; uses a normalized SHA-256 key of the prompt.
- Semantic cache (ChromaDB): stores prompt embeddings and responses; query embeddings are matched by cosine distance with a configurable `CACHE_SIMILARITY_THRESHOLD`.
- Cache writes store sanitized prompts and metadata (request id, tokens, cost, security metadata).

Observability metrics (selection)

- `ai_proxy_http_requests_total` — total HTTP requests by method/endpoint/status
- `ai_proxy_http_request_duration_seconds` — per-endpoint request latency
- `ai_proxy_cache_lookups_total` / `ai_proxy_cache_writes_total` — cache ops
- `ai_proxy_model_requests_total` / `ai_proxy_model_latency_seconds` — model vs cache latencies
- `ai_proxy_model_tokens_total` / `ai_proxy_model_cost_total` — token & cost accounting
- `ai_proxy_security_events_total` / `ai_proxy_security_blocks_total` — security telemetry

Development & testing

- Add unit tests under `tests/` and run with `pytest`.
- Run linter/formatter: `black .` and `ruff .` (install first).

Extending & production notes

- Replace regex PII detection with Presidio for higher accuracy.
- Secure `.env` and secrets using environment managers or secret stores in production.
- Tune `CACHE_SIMILARITY_THRESHOLD` to balance freshness vs reuse.
- Consider a TTL strategy and eviction policy for ChromaDB and Redis in heavy workloads.

Contributing

Contributions welcome — please open issues or PRs. Follow the repository's coding conventions and add tests for new features.

License

MIT License — copy as appropriate for your organization.

