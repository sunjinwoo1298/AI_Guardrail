# Data handling

What the proxy stores, where, and for how long. Use this for customer DPAs, security
questionnaires and the GDPR records of processing.

| Data | Stored? | Where | Retention |
|---|---|---|---|
| Prompts and responses | **Not stored** by default; only in transit and in memory | n/a | n/a |
| Cached answers (optional) | Masked response text, keyed by a hash of app, context and query | Redis (exact) and ChromaDB (semantic) | `CACHE_TTL_SECONDS` (default 1 hour). Turn off per project with `policy.cache` |
| Audit events | Decision, reasons (detector names, PII **types**), risk score, tenant, key prefix, request ID. **No prompt or response text, and no PII values** | Postgres `audit_events` | `AUDIT_RETENTION_DAYS` (default 90), then `POST /admin/v1/audit/purge` |
| Usage | Daily counts, tokens and cost per project | Postgres `usage_daily` | Kept for billing; delete per contract |
| API keys and admin tokens | HMAC hash plus a 12-character display prefix | Postgres | Until deleted |
| Customers' provider keys and webhook secrets | Fernet-encrypted ciphertext plus last 4 characters | Postgres | Until deleted |
| Org members | E-mail address and role | Postgres `org_members` | Until removed |
| Application logs | Request ID, app, decision summaries, PII **types**; tracebacks on error | stdout (collected by your log pipeline) | Per your log pipeline |
| Rate-limit, behaviour and session counters | Hashed identifiers and counts | Redis | Minutes to days (auto-expiring) |

## Subprocessors

- **Model providers** chosen per request (Groq, OpenAI, Anthropic, Google, OpenRouter) receive the
  **masked** prompt. With bring-your-own-key, the customer's own provider account is used.
- **Groq** also receives text for the optional verifier (Llama Prompt Guard 2) and moderation
  (Llama Guard), only when a policy enables them.
- The PII detector, injection classifier and embeddings run **locally**; no third party sees
  text for scanning.

## Data subject requests

Prompts aren't stored, so there is usually nothing to export or delete beyond org-member
e-mails (admin API) and cached answers. Caches expire on their own; to flush one tenant's
cache, delete its Redis keys and Chroma entries.
