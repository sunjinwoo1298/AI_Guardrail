import json
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from app.models.request_models import PromptRequest, ChatCompletionRequest
from app.services.llm_orchestrator import generate_response, stream_response


router = APIRouter()

@router.post("/generate")
async def generate(request: Request, payload: PromptRequest):
    security_context = getattr(request.state, "security_context", {})
    if getattr(request.state, "api_key", None):
        security_context = {
            **security_context,
            "api_key": request.state.api_key,
            "reserved_tokens": getattr(request.state, "reserved_tokens", 0),
        }
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)
    _, result = await generate_response(sanitized_prompt, security_context=security_context)
    return result

@router.post("/stream")
async def stream(request: Request, payload: PromptRequest):
    security_context = getattr(request.state, "security_context", {})
    if getattr(request.state, "api_key", None):
        security_context = {
            **security_context,
            "api_key": request.state.api_key,
            "reserved_tokens": getattr(request.state, "reserved_tokens", 0),
        }
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)
    
    async def legacy_stream_generator():
        async for event_type, event_data in stream_response(sanitized_prompt, security_context=security_context):
            if event_type == "content":
                delta_content = event_data["choices"][0]["delta"].get("content", "")
                yield f"data: {delta_content}\n\n"
            elif event_type == "metadata":
                yield f"data: {json.dumps({'__meta': event_data})}\n\n"

    return StreamingResponse(
        legacy_stream_generator(),
        media_type="text/event-stream"
    )

@router.post("/v1/chat/completions")
async def chat_completions(request: Request, payload: ChatCompletionRequest):
    security_context = getattr(request.state, "security_context", {})
    if getattr(request.state, "api_key", None):
        security_context = {
            **security_context,
            "api_key": request.state.api_key,
            "reserved_tokens": getattr(request.state, "reserved_tokens", 0),
        }
        
    sanitized_messages = getattr(request.state, "sanitized_messages", None) or payload.messages

    if payload.stream:
        async def event_generator():
            async for event_type, event_data in stream_response(
                sanitized_messages,
                model=payload.model,
                security_context=security_context
            ):
                if event_type == "content":
                    yield f"data: {json.dumps(event_data)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")
    else:
        completion, _ = await generate_response(
            sanitized_messages,
            model=payload.model,
            security_context=security_context
        )
        return completion
