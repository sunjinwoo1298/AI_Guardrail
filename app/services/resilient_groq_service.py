import asyncio
import json
import time
from typing import Optional

from fastapi import HTTPException

from app.core.config import (
    GROQ_API_KEY,
    GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    GROQ_CIRCUIT_BREAKER_RESET_SECONDS,
    GROQ_RETRY_ATTEMPTS,
    GROQ_RETRY_BASE_DELAY_SECONDS,
    GROQ_TIMEOUT_SECONDS,
    MAX_RESPONSE_CHARS,
    SECONDARY_MODEL_NAME,
)
from app.core.cost_calculator import calculate_cost
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.core.resilience import CircuitBreaker, CircuitOpenError, retry_async
from app.observability.metrics import record_model_observation, record_stream_duration
from app.observability.tracing import trace
from app.security.sanitizer import sanitize_response
from app.services.cache_service import cache_response, get_exact_cache, search_semantic_cache

client = None
MODEL_NAME = "llama-3.1-8b-instant"
SECONDARY_MODEL = SECONDARY_MODEL_NAME
BREAKERS = {
    MODEL_NAME: CircuitBreaker(GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD, GROQ_CIRCUIT_BREAKER_RESET_SECONDS),
    SECONDARY_MODEL: CircuitBreaker(GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD, GROQ_CIRCUIT_BREAKER_RESET_SECONDS),
}


def get_groq_client():
    global client
    if client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY is required")
        from groq import AsyncGroq

        client = AsyncGroq(api_key=GROQ_API_KEY)
    return client


def _truncate_response(text: str):
    return text if len(text) <= MAX_RESPONSE_CHARS else text[:MAX_RESPONSE_CHARS] + "..."


def _build_response_payload(**kwargs):
    payload = {
        "status": kwargs.get("status", "success"),
        "latency": round(kwargs["latency"], 2),
        "model": kwargs.get("model"),
        "cache_hit": kwargs.get("cache_hit", False),
        "cache_type": kwargs.get("cache_type"),
        "prompt_tokens": kwargs.get("prompt_tokens", 0),
        "completion_tokens": kwargs.get("completion_tokens", 0),
        "total_tokens": kwargs.get("total_tokens", 0),
        "estimated_cost": kwargs.get("estimated_cost", 0.0),
        "cache_saved_cost": kwargs.get("cache_saved_cost", 0.0),
        "request_id": kwargs["request_id"],
        "response": kwargs["response"],
    }
    if kwargs.get("similarity_distance") is not None:
        payload["similarity_distance"] = kwargs["similarity_distance"]
    if kwargs.get("source_prompt") is not None:
        payload["source_prompt"] = kwargs["source_prompt"]
    if kwargs.get("security_metadata"):
        payload.update(kwargs["security_metadata"])
    if kwargs.get("reason"):
        payload["reason"] = kwargs["reason"]
    return payload


async def _lookup_cache(query: str):
    exact_cache = await get_exact_cache(query)
    if exact_cache is not None:
        return "exact", exact_cache
    semantic_cache = await search_semantic_cache(query)
    if semantic_cache is not None:
        return "semantic", semantic_cache
    return None, None


async def _create_completion(query: str, model: str, stream: bool = False):
    breaker = BREAKERS[model]
    if not breaker.allow():
        raise CircuitOpenError(f"Circuit open for model={model}")

    groq_client = get_groq_client()

    async def _call():
        return await asyncio.wait_for(
            groq_client.chat.completions.create(
                messages=[{"role": "user", "content": query}],
                model=model,
                stream=stream,
            ),
            timeout=GROQ_TIMEOUT_SECONDS,
        )

    try:
        result = await retry_async(
            _call,
            attempts=GROQ_RETRY_ATTEMPTS,
            base_delay_seconds=GROQ_RETRY_BASE_DELAY_SECONDS,
            retry_exceptions=(asyncio.TimeoutError, TimeoutError, ConnectionError, OSError),
        )
        breaker.record_success()
        return result
    except Exception:
        breaker.record_failure()
        raise


def _current_tracer():
    return trace.get_tracer("ai_guardrail_proxy") if trace else None


def _degraded_payload(*, request_id: str, latency: float, security_metadata: Optional[dict] = None, reason: str):
    return _build_response_payload(
        request_id=request_id,
        latency=latency,
        model=None,
        response="Service temporarily degraded. Please retry shortly.",
        cache_hit=False,
        cache_type=None,
        estimated_cost=0.0,
        cache_saved_cost=0.0,
        prompt_tokens=0,
        completion_tokens=0,
        total_tokens=0,
        security_metadata=security_metadata,
        reason=reason,
        status="degraded",
    )


async def generate_response(query: str, security_context: Optional[dict] = None):
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query)
        finally:
            if cache_span:
                cache_span.__exit__(None, None, None)

        if cache_type == "exact":
            span = tracer.start_as_current_span("response.redaction") if tracer else None
            if span:
                span.__enter__()
            try:
                latency = time.time() - start_time
                response = _truncate_response(sanitize_response(cached.get("response", "")))
                prompt_tokens = int(cached.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached.get("completion_tokens", 0) or 0)
                total_tokens = int(cached.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached.get("estimated_cost", 0.0) or 0.0)
                record_model_observation(endpoint="generate", cache_hit=True, cache_type="exact", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0)
                return _build_response_payload(request_id=request_id, latency=latency, model=MODEL_NAME, response=response, cache_hit=True, cache_type="exact", prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_saved_cost=cache_saved_cost, security_metadata=security_metadata)
            finally:
                if span:
                    span.__exit__(None, None, None)

        if cache_type == "semantic":
            span = tracer.start_as_current_span("response.redaction") if tracer else None
            if span:
                span.__enter__()
            try:
                latency = time.time() - start_time
                response = _truncate_response(sanitize_response(cached.get("response", "")))
                source_prompt = cached.get("source_prompt")
                similarity_distance = cached.get("distance")
                cached_entry = cached.get("cached_entry", {}) or {}
                prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
                total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)
                record_model_observation(endpoint="generate", cache_hit=True, cache_type="semantic", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0)
                await cache_response(prompt=query, response=response, request_id=request_id, model_name=MODEL_NAME, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=cache_saved_cost, cache_type="semantic", source_prompt=source_prompt, similarity_distance=similarity_distance, security_metadata=security_metadata)
                return _build_response_payload(request_id=request_id, latency=latency, model=MODEL_NAME, response=response, cache_hit=True, cache_type="semantic", prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_saved_cost=cache_saved_cost, similarity_distance=similarity_distance, source_prompt=source_prompt, security_metadata=security_metadata)
            finally:
                if span:
                    span.__exit__(None, None, None)

        model_span = tracer.start_as_current_span("model.call") if tracer else None
        if model_span:
            model_span.__enter__()
        try:
            try:
                chat_completion = await _create_completion(query, MODEL_NAME)
                active_model = MODEL_NAME
            except Exception as primary_exc:
                logger.warning(f"Primary model failed, trying fallback model: {primary_exc}")
                try:
                    chat_completion = await _create_completion(query, SECONDARY_MODEL)
                    active_model = SECONDARY_MODEL
                except Exception as secondary_exc:
                    logger.error(f"Both model attempts failed: primary={primary_exc} secondary={secondary_exc}")
                    latency = time.time() - start_time
                    record_model_observation(endpoint="generate", cache_hit=False, cache_type="degraded", latency_seconds=latency, prompt_tokens=0, completion_tokens=0, total_tokens=0, estimated_cost=0.0)
                    return _degraded_payload(request_id=request_id, latency=latency, security_metadata=security_metadata, reason="model_unavailable")
        finally:
            if model_span:
                model_span.__exit__(None, None, None)

        usage = chat_completion.usage
        prompt_tokens = usage.prompt_tokens
        completion_tokens = usage.completion_tokens
        total_tokens = usage.total_tokens
        estimated_cost = calculate_cost(active_model, prompt_tokens, completion_tokens)
        redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
        if redaction_span:
            redaction_span.__enter__()
        try:
            response = _truncate_response(sanitize_response(chat_completion.choices[0].message.content))
        finally:
            if redaction_span:
                redaction_span.__exit__(None, None, None)
        latency = time.time() - start_time
        record_model_observation(endpoint="generate", cache_hit=False, cache_type="generated", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost)
        await cache_response(prompt=query, response=response, request_id=request_id, model_name=active_model, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost, cache_type="generated", security_metadata=security_metadata)
        return _build_response_payload(request_id=request_id, latency=latency, model=active_model, response=response, cache_hit=False, cache_type=None, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost, cache_saved_cost=0.0, security_metadata=security_metadata)
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Groq API Error: {str(e)}")


async def stream_response(query: str, security_context: Optional[dict] = None):
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query)
        finally:
            if cache_span:
                cache_span.__exit__(None, None, None)

        if cache_type == "exact":
            redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
            if redaction_span:
                redaction_span.__enter__()
            try:
                latency = time.time() - start_time
                response = _truncate_response(sanitize_response(cached.get("response", "")))
                prompt_tokens = int(cached.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached.get("completion_tokens", 0) or 0)
                total_tokens = int(cached.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached.get("estimated_cost", 0.0) or 0.0)
                record_model_observation(endpoint="stream", cache_hit=True, cache_type="exact", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0)
                yield f"data: {response}\n\n"
                yield f"data: {json.dumps({'__meta': _build_response_payload(request_id=request_id, latency=latency, model=MODEL_NAME, response=response, cache_hit=True, cache_type='exact', prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_saved_cost=cache_saved_cost, security_metadata=security_metadata)})}\n\n"
            finally:
                if redaction_span:
                    redaction_span.__exit__(None, None, None)
            return

        if cache_type == "semantic":
            redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
            if redaction_span:
                redaction_span.__enter__()
            try:
                latency = time.time() - start_time
                response = _truncate_response(sanitize_response(cached.get("response", "")))
                source_prompt = cached.get("source_prompt")
                similarity_distance = cached.get("distance")
                cached_entry = cached.get("cached_entry", {}) or {}
                prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
                total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)
                record_model_observation(endpoint="stream", cache_hit=True, cache_type="semantic", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0)
                await cache_response(prompt=query, response=response, request_id=request_id, model_name=MODEL_NAME, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=cache_saved_cost, cache_type="semantic", source_prompt=source_prompt, similarity_distance=similarity_distance, security_metadata=security_metadata)
                yield f"data: {response}\n\n"
                yield f"data: {json.dumps({'__meta': _build_response_payload(request_id=request_id, latency=latency, model=MODEL_NAME, response=response, cache_hit=True, cache_type='semantic', prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_saved_cost=cache_saved_cost, similarity_distance=similarity_distance, source_prompt=source_prompt, security_metadata=security_metadata)})}\n\n"
            finally:
                if redaction_span:
                    redaction_span.__exit__(None, None, None)
            return

        model_span = tracer.start_as_current_span("model.call") if tracer else None
        if model_span:
            model_span.__enter__()
        try:
            try:
                stream = await _create_completion(query=query, model=MODEL_NAME, stream=True)
                active_model = MODEL_NAME
            except Exception as primary_exc:
                logger.warning(f"Primary stream model failed, trying fallback model: {primary_exc}")
                try:
                    stream = await _create_completion(query=query, model=SECONDARY_MODEL, stream=True)
                    active_model = SECONDARY_MODEL
                except Exception as secondary_exc:
                    logger.error(f"Stream degraded: primary={primary_exc} secondary={secondary_exc}")
                    latency = time.time() - start_time
                    yield f"data: {json.dumps({'__meta': _degraded_payload(request_id=request_id, latency=latency, security_metadata=security_metadata, reason='model_unavailable')})}\n\n"
                    return
        finally:
            if model_span:
                model_span.__exit__(None, None, None)

        full_response = ""
        prompt_tokens = len(query.split())
        async for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                full_response += content
                yield f"data: {content}\n\n"

        latency = time.time() - start_time
        completion_tokens = len(full_response.split())
        total_tokens = prompt_tokens + completion_tokens
        estimated_cost = calculate_cost(active_model, prompt_tokens, completion_tokens)
        record_model_observation(endpoint="stream", cache_hit=False, cache_type="generated", latency_seconds=latency, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost)
        record_stream_duration(cache_hit=False, cache_type="generated", duration_seconds=latency)
        redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
        if redaction_span:
            redaction_span.__enter__()
        try:
            sanitized_full_response = _truncate_response(sanitize_response(full_response))
        finally:
            if redaction_span:
                redaction_span.__exit__(None, None, None)
        await cache_response(prompt=query, response=sanitized_full_response, request_id=request_id, model_name=active_model, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost, cache_type="generated", security_metadata=security_metadata)
        yield f"data: {json.dumps({'__meta': _build_response_payload(request_id=request_id, latency=latency, model=active_model, response=sanitized_full_response, cache_hit=False, cache_type=None, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=estimated_cost, cache_saved_cost=0.0, security_metadata=security_metadata)})}\n\n"
    except Exception as e:
        logger.error(f"Error streaming response: {str(e)}")
        record_stream_duration(cache_hit=False, cache_type="error", duration_seconds=time.time() - start_time)
        raise HTTPException(status_code=500, detail=f"Groq API Stream Error: {str(e)}")
