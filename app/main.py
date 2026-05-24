from fastapi import FastAPI
from app.api.routes import router
from app.middleware.logging_middleware import LoggingMiddleware

app = FastAPI()
app.add_middleware(LoggingMiddleware)
app.include_router(router)

@app.get("/")
async def root():
    return {"message": "AI Gaurdrail proxt running"}



