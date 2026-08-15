# Load Testing

Run against a deployed instance of the proxy.

## Locust

```bash
locust -f load_test/locustfile.py --headless \
  -u 20 -r 5 -t 5m \
  --host http://127.0.0.1:8000 \
  --csv load_test/results
```

This will emit:
- `load_test/results_stats.csv`
- `load_test/results_stats_history.csv`
- `load_test/results_failures.csv`

Use the CSV files to publish p50/p95/p99 and error-rate numbers.
