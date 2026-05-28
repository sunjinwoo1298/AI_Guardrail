from fastapi import FastAPI
from prometheus_client import make_asgi_app
from app.api.routes import router
from app.middleware.logging_middleware import LoggingMiddleware
from app.middleware.security_middleware import SecurityMiddleware

app = FastAPI()
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.include_router(router)
app.mount("/metrics", make_asgi_app())

@app.get("/")
async def root():
    return {"message": "AI Gaurdrail proxt running"}



