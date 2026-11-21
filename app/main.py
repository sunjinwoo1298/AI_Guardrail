import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from app.api.routes import router
from app.core.config import validate_settings
from app.core.logger import logger
from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.logging_middleware import LoggingMiddleware
from app.middleware.security_middleware import SecurityMiddleware
from app.observability.tracing import instrument_fastapi, setup_tracing

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
    logger.info("Model warm-up finished")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_settings()
    threading.Thread(target=_warm_models, name="model-warmup", daemon=True).start()
    yield


app = FastAPI(
    title="AI Guardrail Proxy",
    version="1.0.0",
    lifespan=lifespan,
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
app.mount("/metrics", make_asgi_app())
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
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    return JSONResponse({"status": "ready"})



