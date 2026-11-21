from __future__ import annotations

import asyncio
import json
import time
import uuid
import threading
from typing import Optional, AsyncGenerator

from fastapi import HTTPException

from app.core.config import (
    GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    GROQ_CIRCUIT_BREAKER_RESET_SECONDS,
    GROQ_RETRY_ATTEMPTS,
    GROQ_RETRY_BASE_DELAY_SECONDS,
    GROQ_TIMEOUT_SECONDS,
    MAX_RESPONSE_CHARS,
    SECONDARY_MODEL_NAME,
    DEFAULT_PROVIDER,
)
from app.core.cost_calculator import calculate_cost, is_priced
from app.core.tokens import estimate_messages_tokens, estimate_text_tokens
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.core.resilience import CircuitBreaker, CircuitOpenError, retry_async
from app.observability.metrics import (
    record_cache_saved_cost,
    record_model_observation,
    record_stream_duration,
    record_unpriced_model,
    record_usage_source,
)
from app.observability.tracing import trace
from app.security.sanitizer import public_security_metadata, sanitize_response
from app.security.rate_limiter import refund_tokens, settle_tokens
from app.services.cache_service import cache_response, get_exact_cache, search_semantic_cache
from app.providers.factory import resolve_provider_and_model, get_adapter

# Dynamically managed circuit breakers per model
_breakers = {}
_breakers_lock = threading.Lock()

def get_circuit_breaker(model_name: str) -> CircuitBreaker:
    with _breakers_lock:
        if model_name not in _breakers:
            _breakers[model_name] = CircuitBreaker(
                GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
                GROQ_CIRCUIT_BREAKER_RESET_SECONDS
            )
        return _breakers[model_name]


def _resolve_usage(usage: Optional[dict], messages: list[dict], completion_text: str) -> tuple[int, int, int, str]:
    """Token counts as (prompt, completion, total, source).

    Uses provider-reported usage when present; otherwise falls back to an
    estimate over the full conversation and flags it as "estimated".
    """
    usage = usage or {}
    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)
    total = int(usage.get("total_tokens") or 0)
    if prompt or completion or total:
        record_usage_source("provider")
        return prompt, completion, total or (prompt + completion), "provider"
    prompt = estimate_messages_tokens(messages)
    completion = estimate_text_tokens(completion_text)
    record_usage_source("estimated")
    return prompt, completion, prompt + completion, "estimated"


def _priced_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    if not is_priced(model):
        record_unpriced_model(model)
    return calculate_cost(model, prompt_tokens, completion_tokens)


def _truncate_response(text: str):
    return text if len(text) <= MAX_RESPONSE_CHARS else text[:MAX_RESPONSE_CHARS] + "..."


def _build_metadata_payload(**kwargs) -> dict:
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
    if kwargs.get("usage_source"):
        payload["usage_source"] = kwargs["usage_source"]
    if kwargs.get("similarity_distance") is not None:
        payload["similarity_distance"] = kwargs["similarity_distance"]
    if kwargs.get("source_prompt") is not None:
        payload["source_prompt"] = kwargs["source_prompt"]
    if kwargs.get("security_metadata"):
        payload.update(public_security_metadata(kwargs["security_metadata"]))
    if kwargs.get("reason"):
        payload["reason"] = kwargs["reason"]
    return payload


def extract_cache_query(messages: list[dict]) -> str:
    for msg in reversed(messages):
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content")
            if isinstance(content, str):
                return content
            elif isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
                return "".join(text_parts)
    return ""


def prepare_messages(query_or_messages: str | list[dict]) -> list[dict]:
    if isinstance(query_or_messages, str):
        return [{"role": "user", "content": query_or_messages}]
    return query_or_messages


async def _lookup_cache(query: str, model: str):
    if not query:
        return None, None
    exact_cache = await get_exact_cache(query, model)
    if exact_cache is not None:
        return "exact", exact_cache
    semantic_cache = await search_semantic_cache(query, model)
    if semantic_cache is not None:
        return "semantic", semantic_cache
    return None, None


async def _create_completion(messages: list[dict], model: str, stream: bool = False):
    provider, real_model = resolve_provider_and_model(model)
    breaker = get_circuit_breaker(model)

    if not breaker.allow():
        raise CircuitOpenError(f"Circuit open for model={model} (provider={provider})")

    adapter = get_adapter(provider)

    async def _call():
        if stream:
            return await adapter.stream(messages=messages, model=real_model)
        else:
            return await adapter.generate(messages=messages, model=real_model)

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
    return _build_metadata_payload(
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


def _api_key_from_context(security_context: Optional[dict]) -> Optional[str]:
    if not security_context:
        return None
    return security_context.get("api_key")


def _reserved_tokens_from_context(security_context: Optional[dict]) -> int:
    if not security_context:
        return 0
    try:
        return int(security_context.get("reserved_tokens", 0) or 0)
    except Exception:
        return 0


async def generate_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None
) -> tuple[dict, dict]:
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    messages = prepare_messages(query_or_messages)
    query = extract_cache_query(messages)

    # Resolve default model if not provided
    active_model = model or "groq/openai/gpt-oss-120b"

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query, active_model)
        finally:
            if cache_span:
                cache_span.__exit__(None, None, None)

        if cache_type == "exact":
            span = tracer.start_as_current_span("response.redaction") if tracer else None
            if span:
                span.__enter__()
            try:
                latency = time.time() - start_time
                response_text = _truncate_response(sanitize_response(cached.get("response", "")))
                prompt_tokens = int(cached.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached.get("completion_tokens", 0) or 0)
                total_tokens = int(cached.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached.get("estimated_cost", 0.0) or 0.0)
                record_cache_saved_cost("exact", cache_saved_cost)

                record_model_observation(
                    endpoint="generate",
                    cache_hit=True,
                    cache_type="exact",
                    latency_seconds=latency,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0
                )

                api_key = _api_key_from_context(security_metadata)
                if api_key:
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

                openai_response = {
                    "id": f"chatcmpl-cache-{uuid_id()}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": active_model,
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": response_text},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens
                    }
                }

                metadata_payload = _build_metadata_payload(
                    request_id=request_id,
                    latency=latency,
                    model=active_model,
                    response=response_text,
                    cache_hit=True,
                    cache_type="exact",
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0,
                    cache_saved_cost=cache_saved_cost,
                    security_metadata=security_metadata
                )

                return openai_response, metadata_payload
            finally:
                if span:
                    span.__exit__(None, None, None)

        if cache_type == "semantic":
            span = tracer.start_as_current_span("response.redaction") if tracer else None
            if span:
                span.__enter__()
            try:
                latency = time.time() - start_time
                response_text = _truncate_response(sanitize_response(cached.get("response", "")))
                source_prompt = cached.get("source_prompt")
                similarity_distance = cached.get("distance")
                cached_entry = cached.get("cached_entry", {}) or {}
                prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
                total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)
                record_cache_saved_cost("semantic", cache_saved_cost)

                record_model_observation(
                    endpoint="generate",
                    cache_hit=True,
                    cache_type="semantic",
                    latency_seconds=latency,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0
                )

                await cache_response(
                    prompt=query,
                    cache_model=active_model,
                    response=response_text,
                    request_id=request_id,
                    model_name=active_model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=cache_saved_cost,
                    cache_type="semantic",
                    source_prompt=source_prompt,
                    similarity_distance=similarity_distance,
                    security_metadata=security_metadata
                )

                api_key = _api_key_from_context(security_metadata)
                if api_key:
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

                openai_response = {
                    "id": f"chatcmpl-cache-{uuid_id()}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": active_model,
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": response_text},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens
                    }
                }

                metadata_payload = _build_metadata_payload(
                    request_id=request_id,
                    latency=latency,
                    model=active_model,
                    response=response_text,
                    cache_hit=True,
                    cache_type="semantic",
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0,
                    cache_saved_cost=cache_saved_cost,
                    similarity_distance=similarity_distance,
                    source_prompt=source_prompt,
                    security_metadata=security_metadata
                )

                return openai_response, metadata_payload
            finally:
                if span:
                    span.__exit__(None, None, None)

        model_span = tracer.start_as_current_span("model.call") if tracer else None
        if model_span:
            model_span.__enter__()
        try:
            try:
                chat_completion = await _create_completion(messages, active_model, stream=False)
                used_model = active_model
            except Exception as primary_exc:
                logger.warning(f"Primary model {active_model} failed, trying fallback: {primary_exc}")
                try:
                    fallback_model = SECONDARY_MODEL_NAME
                    chat_completion = await _create_completion(messages, fallback_model, stream=False)
                    used_model = fallback_model
                except Exception as secondary_exc:
                    logger.error(f"Both model attempts failed: primary={primary_exc} secondary={secondary_exc}")
                    latency = time.time() - start_time
                    api_key = _api_key_from_context(security_metadata)
                    if api_key:
                        refund_tokens(api_key, _reserved_tokens_from_context(security_metadata))
                    record_model_observation(
                        endpoint="generate",
                        cache_hit=False,
                        cache_type="degraded",
                        latency_seconds=latency,
                        prompt_tokens=0,
                        completion_tokens=0,
                        total_tokens=0,
                        estimated_cost=0.0
                    )
                    degraded_meta = _degraded_payload(
                        request_id=request_id,
                        latency=latency,
                        security_metadata=security_metadata,
                        reason="model_unavailable"
                    )
                    return {"error": "service degraded"}, degraded_meta
        finally:
            if model_span:
                model_span.__exit__(None, None, None)

        prompt_tokens, completion_tokens, total_tokens, usage_source = _resolve_usage(
            chat_completion.get("usage"),
            messages,
            chat_completion["choices"][0]["message"]["content"],
        )
        estimated_cost = _priced_cost(used_model, prompt_tokens, completion_tokens)

        redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
        if redaction_span:
            redaction_span.__enter__()
        try:
            raw_response_text = chat_completion["choices"][0]["message"]["content"]
            response_text = _truncate_response(sanitize_response(raw_response_text))
        finally:
            if redaction_span:
                redaction_span.__exit__(None, None, None)

        latency = time.time() - start_time
        record_model_observation(
            endpoint="generate",
            cache_hit=False,
            cache_type="generated",
            latency_seconds=latency,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost
        )

        if query:
            await cache_response(
                prompt=query,
                cache_model=active_model,
                response=response_text,
                request_id=request_id,
                model_name=used_model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=estimated_cost,
                cache_type="generated",
                security_metadata=security_metadata
            )

        api_key = _api_key_from_context(security_metadata)
        if api_key:
            settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

        # Update content in original completion response
        chat_completion["choices"][0]["message"]["content"] = response_text

        metadata_payload = _build_metadata_payload(
            request_id=request_id,
            latency=latency,
            model=used_model,
            response=response_text,
            cache_hit=False,
            cache_type=None,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            cache_saved_cost=0.0,
            usage_source=usage_source,
            security_metadata=security_metadata
        )

        return chat_completion, metadata_payload

    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise HTTPException(status_code=500, detail=f"LLM API Error: {str(e)}")


async def stream_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None
) -> AsyncGenerator[tuple[str, dict], None]:
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    messages = prepare_messages(query_or_messages)
    query = extract_cache_query(messages)

    active_model = model or "groq/openai/gpt-oss-120b"

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query, active_model)
        finally:
            if cache_span:
                cache_span.__exit__(None, None, None)

        if cache_type == "exact":
            redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
            if redaction_span:
                redaction_span.__enter__()
            try:
                latency = time.time() - start_time
                response_text = _truncate_response(sanitize_response(cached.get("response", "")))
                prompt_tokens = int(cached.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached.get("completion_tokens", 0) or 0)
                total_tokens = int(cached.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached.get("estimated_cost", 0.0) or 0.0)
                record_cache_saved_cost("exact", cache_saved_cost)

                record_model_observation(
                    endpoint="stream",
                    cache_hit=True,
                    cache_type="exact",
                    latency_seconds=latency,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0
                )

                api_key = _api_key_from_context(security_metadata)
                if api_key:
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

                chunk_id = f"chatcmpl-cache-{uuid_id()}"
                yield "content", {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": active_model,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": response_text},
                        "finish_reason": "stop"
                    }]
                }

                metadata_payload = _build_metadata_payload(
                    request_id=request_id,
                    latency=latency,
                    model=active_model,
                    response=response_text,
                    cache_hit=True,
                    cache_type="exact",
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0,
                    cache_saved_cost=cache_saved_cost,
                    security_metadata=security_metadata
                )
                yield "metadata", metadata_payload
                return
            finally:
                if redaction_span:
                    redaction_span.__exit__(None, None, None)

        if cache_type == "semantic":
            redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
            if redaction_span:
                redaction_span.__enter__()
            try:
                latency = time.time() - start_time
                response_text = _truncate_response(sanitize_response(cached.get("response", "")))
                source_prompt = cached.get("source_prompt")
                similarity_distance = cached.get("distance")
                cached_entry = cached.get("cached_entry", {}) or {}
                prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
                completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
                total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
                cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)
                record_cache_saved_cost("semantic", cache_saved_cost)

                record_model_observation(
                    endpoint="stream",
                    cache_hit=True,
                    cache_type="semantic",
                    latency_seconds=latency,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0
                )

                await cache_response(
                    prompt=query,
                    cache_model=active_model,
                    response=response_text,
                    request_id=request_id,
                    model_name=active_model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=cache_saved_cost,
                    cache_type="semantic",
                    source_prompt=source_prompt,
                    similarity_distance=similarity_distance,
                    security_metadata=security_metadata
                )

                api_key = _api_key_from_context(security_metadata)
                if api_key:
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

                chunk_id = f"chatcmpl-cache-{uuid_id()}"
                yield "content", {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": active_model,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": response_text},
                        "finish_reason": "stop"
                    }]
                }

                metadata_payload = _build_metadata_payload(
                    request_id=request_id,
                    latency=latency,
                    model=active_model,
                    response=response_text,
                    cache_hit=True,
                    cache_type="semantic",
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=0.0,
                    cache_saved_cost=cache_saved_cost,
                    similarity_distance=similarity_distance,
                    source_prompt=source_prompt,
                    security_metadata=security_metadata
                )
                yield "metadata", metadata_payload
                return
            finally:
                if redaction_span:
                    redaction_span.__exit__(None, None, None)

        model_span = tracer.start_as_current_span("model.call") if tracer else None
        if model_span:
            model_span.__enter__()
        try:
            try:
                stream = await _create_completion(messages, active_model, stream=True)
                used_model = active_model
            except Exception as primary_exc:
                logger.warning(f"Primary stream model {active_model} failed, trying fallback: {primary_exc}")
                try:
                    fallback_model = SECONDARY_MODEL_NAME
                    stream = await _create_completion(messages, fallback_model, stream=True)
                    used_model = fallback_model
                except Exception as secondary_exc:
                    logger.error(f"Stream degraded: primary={primary_exc} secondary={secondary_exc}")
                    latency = time.time() - start_time
                    api_key = _api_key_from_context(security_metadata)
                    if api_key:
                        refund_tokens(api_key, _reserved_tokens_from_context(security_metadata))

                    record_model_observation(
                        endpoint="stream",
                        cache_hit=False,
                        cache_type="degraded",
                        latency_seconds=latency,
                        prompt_tokens=0,
                        completion_tokens=0,
                        total_tokens=0,
                        estimated_cost=0.0
                    )
                    degraded_meta = _degraded_payload(
                        request_id=request_id,
                        latency=latency,
                        security_metadata=security_metadata,
                        reason="model_unavailable"
                    )
                    yield "metadata", degraded_meta
                    return
        finally:
            if model_span:
                model_span.__exit__(None, None, None)

        full_response = ""
        provider_usage = None

        async for chunk in stream:
            choices = chunk.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    full_response += content
                    yield "content", chunk

            # Providers report real usage in a final chunk (Groq may nest it under x_groq).
            chunk_usage = chunk.get("usage") or (chunk.get("x_groq") or {}).get("usage")
            if chunk_usage:
                provider_usage = chunk_usage

        latency = time.time() - start_time

        prompt_tokens, completion_tokens, total_tokens, usage_source = _resolve_usage(
            provider_usage, messages, full_response
        )
        estimated_cost = _priced_cost(used_model, prompt_tokens, completion_tokens)
        record_model_observation(
            endpoint="stream",
            cache_hit=False,
            cache_type="generated",
            latency_seconds=latency,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost
        )
        record_stream_duration(cache_hit=False, cache_type="generated", duration_seconds=latency)

        redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
        if redaction_span:
            redaction_span.__enter__()
        try:
            sanitized_full_response = _truncate_response(sanitize_response(full_response))
        finally:
            if redaction_span:
                redaction_span.__exit__(None, None, None)

        if query:
            await cache_response(
                prompt=query,
                cache_model=active_model,
                response=sanitized_full_response,
                request_id=request_id,
                model_name=used_model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=estimated_cost,
                cache_type="generated",
                security_metadata=security_metadata
            )

        api_key = _api_key_from_context(security_metadata)
        if api_key:
            settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), total_tokens)

        metadata_payload = _build_metadata_payload(
            request_id=request_id,
            latency=latency,
            model=used_model,
            response=sanitized_full_response,
            cache_hit=False,
            cache_type=None,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            cache_saved_cost=0.0,
            usage_source=usage_source,
            security_metadata=security_metadata
        )
        yield "metadata", metadata_payload

    except Exception as e:
        logger.error(f"Error streaming response: {str(e)}")
        api_key = _api_key_from_context(security_metadata)
        if api_key:
            refund_tokens(api_key, _reserved_tokens_from_context(security_metadata))
        record_stream_duration(cache_hit=False, cache_type="error", duration_seconds=time.time() - start_time)
        raise HTTPException(status_code=500, detail=f"LLM API Stream Error: {str(e)}")


def uuid_id() -> str:
    return str(uuid.uuid4())
