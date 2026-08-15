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

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_settings()
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



