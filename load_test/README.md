# Load test and security evaluation

Results and explanations are in the main [README](../README.MD#load-test-results).

## Load test (Locust)

[`locustfile.py`](locustfile.py) simulates applications using the gateway's OpenAI-compatible API:
- cache hits, paraphrases, PII prompts and streams;
- blocked attacks, including one hidden in a tool result;
- bad keys;
- a small, paced number of live model calls.

Every response is checked: a cache-hit request fails if it wasn't served from cache, and an attack fails if it wasn't blocked.

Live calls are capped so the free tiers are never exceeded:

| Setting | Default | Meaning |
|---|---|---|
| `LIVE_BUDGET` / `LIVE_INTERVAL_SECONDS` | `40` / `6` | Max live Groq calls per run, and minimum spacing between them (Groq free tier: 1,000 requests/day, 8,000 tokens/minute) |
| `LIVE_MAX_TOKENS` | `200` | Completion cap per live call (`reasoning_effort: low` is sent to gpt-oss) |
| `OPENROUTER_BUDGET` / `OPENROUTER_INTERVAL_SECONDS` | `4` / `30` | OpenRouter free models (50 requests/day without credit) |
| `WAIT_MIN` / `WAIT_MAX` | `0.5` / `2` | Think time between a user's requests |

A warm-up step fills the caches first (about 12 live calls) and keeps only the paraphrases that really hit the semantic cache.

Run it with Locust in Docker on the stack's network, from the project folder in Command Prompt. The key must be in `API_KEYS`; raise its limits with `APP_POLICIES` or the proxy's own rate limit will answer `429`:

```bash
docker run --rm --network ai_guardrail_proxy_default -v "%cd%\load_test:/mnt/load_test" -e LOAD_TEST_API_KEY=<proxy key> locustio/locust:2.37.11 -f /mnt/load_test/locustfile.py --headless -u 20 -r 5 -t 5m --host http://ai-guardrail-app:8000 --csv /mnt/load_test/results
```

For a capacity test that never calls a model:

```bash
docker run --rm --network ai_guardrail_proxy_default -v "%cd%\load_test:/mnt/load_test" -e LOAD_TEST_API_KEY=<proxy key> -e LIVE_BUDGET=0 -e OPENROUTER_BUDGET=0 -e WAIT_MIN=0 -e WAIT_MAX=0.05 locustio/locust:2.37.11 -f /mnt/load_test/locustfile.py --headless -u 50 -r 10 -t 2m --host http://ai-guardrail-app:8000 --csv /mnt/load_test/capacity
```

The run writes `results_stats.csv`, `results_stats_history.csv`, `results_failures.csv` and `results_exceptions.csv`.

## Security evaluation

[`security_eval.py`](security_eval.py) runs the proxy's block decision on labelled attack and harmless prompts. It has a tuning set and a held-out set, each measured with and without the optional verifier. No answering model is called.

```bash
docker cp load_test\security_eval.py ai-guardrail-app:/tmp/security_eval.py
```

```bash
docker exec -w /app -e PYTHONPATH=/app ai-guardrail-app python /tmp/security_eval.py
```

The latest output is in [`security_eval_results.txt`](security_eval_results.txt).
