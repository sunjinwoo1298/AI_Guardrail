import json
from typing import AsyncIterator, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.core.config import DEGRADED_RETRY_AFTER_SECONDS
from app.models.request_models import PromptRequest, ChatCompletionRequest
from app.services.llm_orchestrator import generate_response, stream_response


router = APIRouter()

DEGRADED_MESSAGE = "Service temporarily degraded: all upstream models are unavailable. Please retry shortly."


def _security_context(request: Request) -> dict:
    security_context = getattr(request.state, "security_context", {})
    if getattr(request.state, "api_key", None):
        security_context = {
            **security_context,
            "api_key": request.state.api_key,
            "reserved_tokens": getattr(request.state, "reserved_tokens", 0),
        }
    return security_context


def _is_degraded(metadata: Optional[dict]) -> bool:
    return isinstance(metadata, dict) and metadata.get("status") == "degraded"


def _degraded_response(body: dict) -> JSONResponse:
    # A failed upstream used to come back as HTTP 200, so clients could not tell it
    # apart from a real answer. 503 + Retry-After is what retrying clients expect.
    return JSONResponse(
        status_code=503,
        content=body,
        headers={"Retry-After": str(DEGRADED_RETRY_AFTER_SECONDS)},
    )


async def _peek(events: AsyncIterator[Tuple[str, dict]]):
    """Read the first event before the response starts, so a stream that is degraded
    from the outset can still be answered with a real 503 status."""
    try:
        first = await events.__anext__()
    except StopAsyncIteration:
        first = None

    async def replay():
        if first is not None:
            yield first
        async for event in events:
            yield event

    return first, replay()


@router.post("/generate")
async def generate(request: Request, payload: PromptRequest):
    security_context = _security_context(request)
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)
    _, result = await generate_response(sanitized_prompt, security_context=security_context)
    if _is_degraded(result):
        return _degraded_response({"error": DEGRADED_MESSAGE, **result})
    return result


@router.post("/stream")
async def stream(request: Request, payload: PromptRequest):
    security_context = _security_context(request)
    sanitized_prompt = security_context.get("sanitized_prompt", payload.prompt)

    first, events = await _peek(stream_response(sanitized_prompt, security_context=security_context))
    if first and first[0] == "metadata" and _is_degraded(first[1]):
        return _degraded_response({"error": DEGRADED_MESSAGE, **first[1]})

    async def legacy_stream_generator():
        async for event_type, event_data in events:
            if event_type == "content":
                delta_content = event_data["choices"][0]["delta"].get("content", "")
                # SSE: every line of a multi-line chunk needs its own "data:" prefix.
                yield "".join(f"data: {line}\n" for line in delta_content.split("\n")) + "\n"
            elif event_type == "metadata":
                yield f"data: {json.dumps({'__meta': event_data})}\n\n"

    return StreamingResponse(legacy_stream_generator(), media_type="text/event-stream")


@router.post("/v1/chat/completions")
async def chat_completions(request: Request, payload: ChatCompletionRequest):
    security_context = _security_context(request)
    sanitized_messages = getattr(request.state, "sanitized_messages", None) or payload.messages

    if payload.stream:
        first, events = await _peek(
            stream_response(sanitized_messages, model=payload.model, security_context=security_context)
        )
        if first and first[0] == "metadata" and _is_degraded(first[1]):
            return _degraded_response(
                {"error": {"message": DEGRADED_MESSAGE, "type": "service_unavailable", "code": "model_unavailable"}}
            )

        async def event_generator():
            async for event_type, event_data in events:
                if event_type == "content":
                    yield f"data: {json.dumps(event_data)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    completion, metadata = await generate_response(
        sanitized_messages,
        model=payload.model,
        security_context=security_context
    )
    if _is_degraded(metadata):
        # OpenAI-style error body so SDK clients raise a proper APIError.
        return _degraded_response(
            {"error": {"message": DEGRADED_MESSAGE, "type": "service_unavailable", "code": "model_unavailable"}}
        )
    return completion
