import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
    from app.services.cache_service import get_embedding_model

    for name, loader in (("prompt-injection classifier", _get_classifier), ("embedding model", get_embedding_model)):
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
app.add_middleware(AuthMiddleware)
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.include_router(router)
app.mount("/metrics", make_asgi_app())
instrument_fastapi(app)

@app.get("/")
async def root():
    return {"message": "AI Guardrail Proxy running"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    return JSONResponse({"status": "ready"})



