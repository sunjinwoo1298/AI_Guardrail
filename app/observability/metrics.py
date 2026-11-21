from typing import Optional

from prometheus_client import Counter, Gauge, Histogram

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0)
RISK_BUCKETS = (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)

HTTP_REQUESTS_TOTAL = Counter(
    "ai_proxy_http_requests_total",
    "Total HTTP requests processed by the AI proxy",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "ai_proxy_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=LATENCY_BUCKETS,
)

ACTIVE_REQUESTS = Gauge(
    "ai_proxy_active_requests",
    "Current in-flight HTTP requests",
)

CACHE_LOOKUPS_TOTAL = Counter(
    "ai_proxy_cache_lookups_total",
    "Cache lookup attempts",
    ["layer", "result"],
)

CACHE_WRITES_TOTAL = Counter(
    "ai_proxy_cache_writes_total",
    "Cache write attempts",
    ["layer", "result"],
)

MODEL_REQUESTS_TOTAL = Counter(
    "ai_proxy_model_requests_total",
    "Requests that reached the model or were satisfied from cache",
    ["endpoint", "cache_hit", "cache_type"],
)

MODEL_LATENCY_SECONDS = Histogram(
    "ai_proxy_model_latency_seconds",
    "Model or cache response latency in seconds",
    ["endpoint", "cache_hit", "cache_type"],
    buckets=LATENCY_BUCKETS,
)

MODEL_TOKENS_TOTAL = Counter(
    "ai_proxy_model_tokens_total",
    "Token usage observed by the proxy",
    ["endpoint", "kind", "cache_hit", "cache_type"],
)

MODEL_COST_TOTAL = Counter(
    "ai_proxy_model_cost_total",
    "Estimated model cost accumulated by the proxy",
    ["endpoint", "cache_hit", "cache_type"],
)

STREAM_DURATION_SECONDS = Histogram(
    "ai_proxy_stream_duration_seconds",
    "Total time to serve streaming responses",
    ["cache_hit", "cache_type"],
    buckets=LATENCY_BUCKETS,
)

SECURITY_EVENTS_TOTAL = Counter(
    "ai_proxy_security_events_total",
    "Security guardrail events",
    ["event", "action"],
)

SECURITY_BLOCKS_TOTAL = Counter(
    "ai_proxy_security_blocks_total",
    "Requests blocked by security policies",
    ["reason"],
)

SECURITY_RISK_SCORE = Histogram(
    "ai_proxy_security_risk_score",
    "Observed security risk scores",
    buckets=RISK_BUCKETS,
)

CACHE_SAVED_COST_TOTAL = Counter(
    "ai_proxy_cache_saved_cost_total",
    "Estimated USD cost avoided by serving responses from cache",
    ["cache_type"],
)

UNPRICED_REQUESTS_TOTAL = Counter(
    "ai_proxy_unpriced_requests_total",
    "Requests served by a model with no price entry (cost reported as 0)",
    ["model"],
)

USAGE_SOURCE_TOTAL = Counter(
    "ai_proxy_usage_source_total",
    "Whether token counts came from the provider or were estimated",
    ["source"],
)


def set_active_request_count(delta: int):
    if delta > 0:
        ACTIVE_REQUESTS.inc(delta)
    elif delta < 0:
        ACTIVE_REQUESTS.dec(abs(delta))


def record_http_request(method: str, endpoint: str, status: int, duration_seconds: float):
    HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(duration_seconds)


def record_cache_lookup(layer: str, result: str):
    CACHE_LOOKUPS_TOTAL.labels(layer=layer, result=result).inc()


def record_cache_write(layer: str, result: str = "success"):
    CACHE_WRITES_TOTAL.labels(layer=layer, result=result).inc()


def record_model_observation(
    *,
    endpoint: str,
    cache_hit: bool,
    cache_type: Optional[str],
    latency_seconds: float,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    estimated_cost: float,
):
    cache_hit_label = "true" if cache_hit else "false"
    cache_type_label = cache_type or "none"

    MODEL_REQUESTS_TOTAL.labels(
        endpoint=endpoint,
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).inc()
    MODEL_LATENCY_SECONDS.labels(
        endpoint=endpoint,
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).observe(latency_seconds)
    MODEL_TOKENS_TOTAL.labels(
        endpoint=endpoint,
        kind="prompt",
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).inc(prompt_tokens)
    MODEL_TOKENS_TOTAL.labels(
        endpoint=endpoint,
        kind="completion",
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).inc(completion_tokens)
    MODEL_TOKENS_TOTAL.labels(
        endpoint=endpoint,
        kind="total",
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).inc(total_tokens)
    MODEL_COST_TOTAL.labels(
        endpoint=endpoint,
        cache_hit=cache_hit_label,
        cache_type=cache_type_label,
    ).inc(estimated_cost)


def record_stream_duration(cache_hit: bool, cache_type: Optional[str], duration_seconds: float):
    STREAM_DURATION_SECONDS.labels(
        cache_hit="true" if cache_hit else "false",
        cache_type=cache_type or "none",
    ).observe(duration_seconds)


def record_security_risk(risk_score: float):
    SECURITY_RISK_SCORE.observe(risk_score)


def record_security_event(event: str, action: str = "detected"):
    SECURITY_EVENTS_TOTAL.labels(event=event, action=action).inc()


def record_security_block(reason: str):
    SECURITY_BLOCKS_TOTAL.labels(reason=reason).inc()


def record_cache_saved_cost(cache_type: str, saved_cost: float):
    if saved_cost > 0:
        CACHE_SAVED_COST_TOTAL.labels(cache_type=cache_type).inc(saved_cost)


def record_unpriced_model(model: str):
    UNPRICED_REQUESTS_TOTAL.labels(model=model).inc()


def record_usage_source(source: str):
    USAGE_SOURCE_TOTAL.labels(source=source).inc()
