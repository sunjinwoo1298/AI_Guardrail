import asyncio
import hmac
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from app.api.routes import router
from app.core.config import (
    DEFAULT_SYSTEM_PROMPT_CANARY,
    ENABLE_DOCS,
    ENVIRONMENT,
    IS_PRODUCTION,
    METRICS_AUTH_TOKEN,
    RATE_LIMIT_FAIL_MODE,
    SYSTEM_PROMPT_CANARY,
    validate_settings,
)
from app.core.logger import logger
from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.logging_middleware import LoggingMiddleware
from app.middleware.security_middleware import SecurityMiddleware
from app.observability.tracing import instrument_fastapi, setup_tracing

_warmup_done = threading.Event()


def _warm_models():
    """Load the ONNX models up front so the first requests don't time out on
    semantic-cache lookups or skip the injection classifier while they load."""
    from app.security.prompt_guard import _get_classifier
    from app.services.cache_service import get_chroma_collection, get_embedding_model, get_redis_client

    for name, loader in (
        ("prompt-injection classifier", _get_classifier),
        ("embedding model", get_embedding_model),
        # Open cache connections up front too, so the first request isn't slowed by it.
        ("Redis connection", get_redis_client),
        ("Chroma collection", get_chroma_collection),
    ):
        try:
            loader()
        except Exception as exc:
            logger.warning(f"Warm-up of {name} failed: {exc}")
    _warmup_done.set()
    logger.info("Model warm-up finished")


def _startup_warnings():
    if not IS_PRODUCTION:
        if SYSTEM_PROMPT_CANARY == DEFAULT_SYSTEM_PROMPT_CANARY:
            logger.warning("SYSTEM_PROMPT_CANARY is the public default; set a private value before going live")
        if not METRICS_AUTH_TOKEN:
            logger.warning("/metrics is unauthenticated; set METRICS_AUTH_TOKEN before going live")
        if RATE_LIMIT_FAIL_MODE == "open":
            logger.warning("RATE_LIMIT_FAIL_MODE=open: a Redis outage disables all rate limits")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_settings()
    _startup_warnings()
    logger.info(f"Starting AI Guardrail Proxy (environment={ENVIRONMENT})")
    threading.Thread(target=_warm_models, name="model-warmup", daemon=True).start()
    yield
    from app.providers.http import close_http_clients

    await close_http_clients()


app = FastAPI(
    title="AI Guardrail Proxy",
    version="1.0.0",
    lifespan=lifespan,
    # Interactive docs advertise every endpoint and parameter; off in production
    # unless ENABLE_DOCS=true.
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)
setup_tracing(app.title)
# Starlette runs the middleware added LAST first. Order on a request:
#   Logging -> Auth (key + rate limit) -> Security scan -> route.
# Auth used to run after the security scan, so unauthenticated callers could make the
# proxy run its ML classifier, and security events could not be attributed to an app.
app.add_middleware(SecurityMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(LoggingMiddleware)
app.include_router(router)


def _protected_metrics_app(metrics_app, token: str):
    """/metrics labels traffic, cost and blocks by app name, so outside development it
    needs ``Authorization: Bearer <METRICS_AUTH_TOKEN>`` (Prometheus: ``authorization``)."""
    expected = f"Bearer {token}".encode("utf-8")

    async def guarded(scope, receive, send):
        if scope["type"] == "http":
            provided = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(provided, expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b'{"error":"Unauthorized"}'})
                return
        await metrics_app(scope, receive, send)

    return guarded


_metrics_app = make_asgi_app()
app.mount("/metrics", _protected_metrics_app(_metrics_app, METRICS_AUTH_TOKEN) if METRICS_AUTH_TOKEN else _metrics_app)
instrument_fastapi(app)


@app.exception_handler(HTTPException)
async def openai_style_http_errors(request, exc: HTTPException):
    # Structured errors (e.g. a provider's 4xx) use OpenAI's {"error": {...}} shape so
    # SDK clients surface the real message; plain errors keep FastAPI's default shape.
    if isinstance(exc.detail, dict) and "message" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)


@app.get("/")
async def root():
    return {"message": "AI Guardrail Proxy running"}


@app.get("/health")
async def health():
    """Liveness: the process is up. Use /ready for traffic decisions."""
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    """Readiness: the dependencies the security guarantees rely on.

    It used to return "ready" unconditionally, so a load balancer sent traffic to
    replicas whose injection classifier had not loaded (tripwire-only scanning) or whose
    Redis was down (no rate limits). In production those make the replica not ready
    (503); in development the same report is returned with 200.
    """
    from app.core.redis_client import ping
    from app.security import prompt_guard

    redis_ok = await asyncio.to_thread(ping)
    checks = {
        "warmup_complete": _warmup_done.is_set(),
        "injection_classifier": prompt_guard._classifier is not None,
        "redis": redis_ok,
    }
    required = ["warmup_complete", "injection_classifier"]
    if RATE_LIMIT_FAIL_MODE == "closed":
        required.append("redis")
    is_ready = all(checks[name] for name in required)
    status_code = 200 if is_ready or not IS_PRODUCTION else 503
    return JSONResponse(
        {"status": "ready" if is_ready else "not_ready", "checks": checks, "required": required},
        status_code=status_code,
    )
