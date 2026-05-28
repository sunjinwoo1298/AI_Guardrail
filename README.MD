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
