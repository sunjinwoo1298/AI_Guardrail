# Service levels

This is the proposed service-level framework for the hosted AI Guardrail Proxy. The **SLOs**
are what engineering measures and alerts on (`observability/prometheus/slo_rules.yml`). The
**SLA** is the contractual commitment derived from them, set deliberately below the SLO so
there is room to act before customers are owed credits. Commercial terms (credit
percentages, claim process) need legal review before publication.

## Service level objectives

| SLO | Target | Window | SLI (Prometheus) |
|---|---|---|---|
| API availability | 99.9% | 30 days | `1 - (5xx except 503) / all requests` on `/v1/*`, `/generate`, `/stream` (`slo:api_availability:ratio30d`) |
| Guard scan latency | 99% of `/v1/guard/scan` requests under 250 ms | 30 days | `slo:guard_slow_ratio:*` |
| Audit completeness | No dropped audit events | continuous | `ai_proxy_audit_dropped_total` stays 0 |

**Why 503 is excluded from availability.** The proxy returns 503 when every upstream model is
unavailable (provider outage, after retries and fallback) or when it deliberately fails closed
(security scan unavailable, rate limiter down in production). Those are tracked by their own
alert (`UpstreamUnavailableHigh`) and reported separately, because a provider outage is outside
the proxy's control. Failing closed is a security property, not an availability bug.

**Error budget.** 99.9% leaves 0.1%, about 43 minutes of total unavailability per 30 days. The
burn-rate alerts page at 14.4× (budget gone in about 2 days) and open a ticket at 6× (about 5
days).

**What latency SLOs don't cover.** End-to-end latency of `/v1/chat/completions` is dominated by
the model provider. The proxy's own overhead is measured on `/v1/guard/scan`, which runs the
same scanning without a model call. Measured locally: 20–45 ms per classifier pass, about 90 ms
median under load on one 8-vCPU worker (README, "Load test results").

## Proposed SLA (draft)

| Tier | Monthly uptime commitment | Support response (P1) |
|---|---|---|
| Standard | 99.5% | Next business day |
| Enterprise | 99.9% | 1 hour, 24×7 |

Measured on the availability SLI above. Scheduled maintenance announced 72 hours in advance is
excluded. Upstream model-provider outages are excluded, except where the customer has
configured a fallback model on another provider and both fail because of the proxy.

## Running the SLOs

- Rules: `observability/prometheus/slo_rules.yml`, loaded by Docker Compose and usable with the
  Prometheus Operator through the Helm chart's `ServiceMonitor`.
- Grafana: add panels for `slo:api_availability:ratio30d` and the burn-rate series to the
  provisioned dashboard.
- Each pod runs one worker, so Prometheus counters are complete per pod. Scale with replicas
  (Helm `autoscaling`), not with `WEB_CONCURRENCY`.
