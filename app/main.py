from fastapi import FastAPI
from app.api.routes import router
from app.middleware.logging_middleware import LoggingMiddleware
from app.middleware.security_middleware import SecurityMiddleware

app = FastAPI()
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.include_router(router)

@app.get("/")
async def root():
    return {"message": "AI Gaurdrail proxt running"}



