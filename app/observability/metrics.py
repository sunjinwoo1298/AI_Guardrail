from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "ai_proxy_http_requests_total",
    "Total HTTP requests processed by the AI proxy",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "ai_proxy_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
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
    cache_type: str | None,
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


def record_stream_duration(cache_hit: bool, cache_type: str | None, duration_seconds: float):
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