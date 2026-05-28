from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from app.models.request_models import PromptRequest
from app.services.groq_service import generate_response, stream_response


router = APIRouter()

@router.post("/generate")
async def generate(request: Request, payload: PromptRequest):
    security_context = getattr(request.state, "security_context", {})
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)
    result = await generate_response(sanitized_prompt, security_context=security_context)
    return result

@router.post("/stream")
async def stream(request: Request, payload: PromptRequest):
    security_context = getattr(request.state, "security_context", {})
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)
    return StreamingResponse(
        stream_response(sanitized_prompt, security_context=security_context),
        media_type="text/event-stream"
    )