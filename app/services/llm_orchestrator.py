from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
import threading
from typing import Optional, AsyncGenerator

import httpx
from fastapi import HTTPException

from app.core.config import (
    GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    GROQ_CIRCUIT_BREAKER_RESET_SECONDS,
    GROQ_RETRY_ATTEMPTS,
    GROQ_RETRY_BASE_DELAY_SECONDS,
    MAX_RESPONSE_CHARS,
    REDACT_TOOL_CALL_ARGUMENTS,
    RETRY_MAX_DELAY_SECONDS,
    SECONDARY_MODEL_NAME,
    DEFAULT_PROVIDER,
    EXPOSE_REASONING,
    STREAM_REDACTION_HOLDBACK_CHARS,
)

_REASONING_KEYS = ("reasoning", "reasoning_content", "reasoning_details")


def _scrub_reasoning(message: Optional[dict]) -> None:
    """Drop (or, if EXPOSE_REASONING, redact) provider chain-of-thought fields in
    place. They bypassed response redaction and can echo system-prompt content."""
    if not isinstance(message, dict):
        return
    for key in _REASONING_KEYS:
        if key not in message:
            continue
        if EXPOSE_REASONING and isinstance(message[key], str):
            message[key] = sanitize_response(message[key])
        else:
            message.pop(key)


class _StreamRedactor:
    """Redacts streamed text before it reaches the client.

    Chunks are buffered and released only up to a sentence or line boundary that is
    at least ``holdback`` characters from the end, so an email, key, phone number or
    the canary split across chunks is still seen whole by the redactor.
    """

    _BOUNDARIES = ("\n", ". ", "! ", "? ")

    def __init__(self, holdback: int = STREAM_REDACTION_HOLDBACK_CHARS):
        self.holdback = max(0, holdback)
        self.buffer = ""

    def feed(self, text: str) -> str:
        self.buffer += text
        limit = len(self.buffer) - self.holdback
        if limit <= 0:
            return ""
        cut = -1
        for boundary in self._BOUNDARIES:
            pos = self.buffer.rfind(boundary, 0, limit)
            if pos != -1:
                cut = max(cut, pos + len(boundary))
        if cut <= 0:
            return ""
        ready, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return sanitize_response(ready)

    def flush(self) -> str:
        ready, self.buffer = self.buffer, ""
        return sanitize_response(ready) if ready else ""
from app.core.cost_calculator import calculate_cost, is_priced
from app.core.tokens import estimate_messages_tokens, estimate_text_tokens
from app.core.context import model_context
from app.core.logger import logger
from app.core.request_id import generate_request_id
from app.core.resilience import CircuitBreaker, CircuitOpenError, is_client_error, is_transient_error, retry_async
from app.observability.metrics import (
    record_cache_saved_cost,
    record_model_observation,
    record_stream_duration,
    record_unpriced_model,
    record_usage_source,
)
from app.observability.tracing import trace
from app.control.policy import policy_for
from app.core.context import app_context
from app.security import moderation, output_events
from app.security.agent_guard import audit_output, check_openai_tool_calls
from app.security.decision import output_decision
from app.security.sanitizer import public_security_metadata, sanitize_response, sanitize_tool_calls
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


_MASK_TOKEN = re.compile(r"\[(?:REDACTED_SYSTEM_PROMPT|image removed[^\]]*|[A-Z][A-Z_]{1,30})\]")


def _redaction_count(raw: Optional[str], redacted: Optional[str]) -> int:
    """Values the output redaction replaced. Labels the model itself wrote (it may echo
    "[EMAIL]" from its masked prompt) are present in both texts and not counted."""
    return max(0, len(_MASK_TOKEN.findall(redacted or "")) - len(_MASK_TOKEN.findall(raw or "")))


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
    if kwargs.get("output_redacted") is not None:
        payload["output_redacted"] = kwargs["output_redacted"]
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


# OpenAI parameters the proxy forwards to the provider. Routing/transport fields
# (model, messages, stream) are handled by the proxy itself.
_PROXY_OWNED_PARAMS = {"model", "messages", "stream"}


def clean_params(params: Optional[dict]) -> dict:
    return {k: v for k, v in (params or {}).items() if k not in _PROXY_OWNED_PARAMS and v is not None}


def _cache_policy() -> tuple:
    """(exact, semantic) caching switches from the current app's policy. A project
    handling per-user data can turn sharing of answers between its users off."""
    from app.core.config import get_app_policy
    from app.core.context import app_context

    cache = get_app_policy(app_context.get()).get("cache") or {}
    return bool(cache.get("exact", True)), bool(cache.get("semantic", True))


def _app_fingerprint(security_metadata: Optional[dict]) -> str:
    api_key = _api_key_from_context(security_metadata)
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16] if api_key else "anonymous"


def _cache_namespace(model: str, messages: list[dict], params: dict, security_metadata: Optional[dict]) -> str:
    """Scope cached answers to one app (API key), one conversation context and one set
    of request parameters.

    The cache used to be keyed only by model + last user message, so an app with a
    different system prompt, or a user in a different conversation, was served
    another app's / user's answer. The last user message's text stays out of the
    scope (it is the lookup query), so paraphrases within the same app and context
    can still hit the semantic cache.
    """
    last_user = None
    for i, msg in enumerate(messages):
        if isinstance(msg, dict) and msg.get("role") == "user":
            last_user = i
    context = [{"role": "user", "content": "<query>"} if i == last_user else m for i, m in enumerate(messages)]
    material = json.dumps(
        {"app": _app_fingerprint(security_metadata), "context": context, "params": params},
        sort_keys=True,
        default=str,
    )
    return f"{model}#{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"


def _upstream_client_error(exc: BaseException) -> Optional[HTTPException]:
    """A 4xx from the provider (bad tool schema, unsupported parameter, ...) is the
    caller's error: return it to them instead of trying the fallback model and
    reporting a misleading 503."""
    if isinstance(exc, HTTPException) and 400 <= exc.status_code < 500:
        return exc  # the proxy's own refusal (e.g. provider_key_missing): no fallback
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if 400 <= status < 500 and status not in (408, 429):
            try:
                body = exc.response.json()
                message = (body.get("error") or {}).get("message") if isinstance(body, dict) else None
            except Exception:
                message = None
            return HTTPException(status_code=status, detail={
                "message": message or f"Upstream provider rejected the request ({status})",
                "type": "invalid_request_error",
                "code": "upstream_client_error",
            })
    return None


async def _lookup_cache(query: str, model: str, semantic: bool = True):
    if not query:
        return None, None
    exact_cache = await get_exact_cache(query, model)
    if exact_cache is not None:
        return "exact", exact_cache
    if not semantic:
        return None, None
    semantic_cache = await search_semantic_cache(query, model)
    if semantic_cache is not None:
        return "semantic", semantic_cache
    return None, None


async def _create_completion(messages: list[dict], model: str, stream: bool = False, params: Optional[dict] = None):
    provider, real_model = resolve_provider_and_model(model)
    breaker = get_circuit_breaker(model)

    if not breaker.allow():
        raise CircuitOpenError(f"Circuit open for model={model} (provider={provider})")

    adapter = get_adapter(provider)

    async def _call():
        if stream:
            # A provider stream only sends its request (and raises 429/5xx/connect
            # errors) when first read, so read the first chunk inside the retried call.
            upstream = await adapter.stream(messages=messages, model=real_model, **(params or {}))
            return await _prefetch_first(upstream)
        else:
            return await adapter.generate(messages=messages, model=real_model, **(params or {}))

    try:
        result = await retry_async(
            _call,
            attempts=GROQ_RETRY_ATTEMPTS,
            base_delay_seconds=GROQ_RETRY_BASE_DELAY_SECONDS,
            should_retry=is_transient_error,
            max_delay_seconds=RETRY_MAX_DELAY_SECONDS,
        )
        breaker.record_success()
        return result
    except Exception as exc:
        # The caller's own bad request (a non-retryable 4xx) says nothing about the
        # provider's health and must not open the breaker for every tenant.
        if not is_client_error(exc):
            breaker.record_failure()
        raise


def _accumulate_tool_calls(buffer: dict, deltas) -> None:
    """Merge OpenAI streaming tool-call deltas (keyed by ``index``) into whole calls."""
    for position, delta in enumerate(deltas or []):
        if not isinstance(delta, dict):
            continue
        index = delta.get("index", position)
        call = buffer.setdefault(index, {"index": index, "type": "function",
                                         "function": {"name": "", "arguments": ""}})
        if delta.get("id"):
            call["id"] = delta["id"]
        if delta.get("type"):
            call["type"] = delta["type"]
        function = delta.get("function") or {}
        if function.get("name"):
            call["function"]["name"] += function["name"]
        if function.get("arguments"):
            call["function"]["arguments"] += function["arguments"]


async def _prefetch_first(upstream):
    """Read the first chunk of an async iterator and return an iterator that replays it."""
    try:
        first = await upstream.__anext__()
    except StopAsyncIteration:
        first = None

    async def replay():
        if first is not None:
            yield first
        async for chunk in upstream:
            yield chunk

    return replay()


async def _open_stream(messages: list[dict], model: str, params: Optional[dict] = None):
    """Start a provider stream and read its first chunk before returning.

    Provider errors (429 rate limits, 5xx) only surface once a stream is read, which
    happened after the primary/fallback decision, so they became a 500 instead of
    falling back. Reading the first chunk here lets the caller fall back properly.
    """
    stream = await _create_completion(messages, model, stream=True, params=params)
    try:
        first = await stream.__anext__()
    except StopAsyncIteration:
        first = None
    except Exception as exc:
        if not is_client_error(exc):
            get_circuit_breaker(model).record_failure()
        raise

    async def replay():
        if first is not None:
            yield first
        async for chunk in stream:
            yield chunk

    return replay()


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


async def _generate_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None,
    params: Optional[dict] = None,
) -> tuple[dict, dict]:
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    messages = prepare_messages(query_or_messages)
    query = extract_cache_query(messages)
    output_findings = output_events.begin()
    policy = policy_for(app_context.get())

    # Resolve default model if not provided
    active_model = model or "groq/openai/gpt-oss-120b"
    params = clean_params(params)
    cache_ns = _cache_namespace(active_model, messages, params, security_metadata)
    # A paraphrase must not stand in for a tool-calling turn.
    allow_semantic = "tools" not in params and "functions" not in params
    exact_on, semantic_on = _cache_policy()
    if not exact_on:
        query = ""  # no lookups and no writes for this project
    allow_semantic = allow_semantic and semantic_on
    model_context.set(active_model)

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query, cache_ns, semantic=allow_semantic)
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
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), 0)  # cache hit: no upstream tokens used

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
                    cache_model=cache_ns,
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
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), 0)  # cache hit: no upstream tokens used

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
                chat_completion = await _create_completion(messages, active_model, stream=False, params=params)
                used_model = active_model
            except Exception as primary_exc:
                client_error = _upstream_client_error(primary_exc)
                if client_error:
                    raise client_error
                logger.warning(f"Primary model {active_model} failed, trying fallback: {primary_exc}")
                try:
                    fallback_model = SECONDARY_MODEL_NAME
                    chat_completion = await _create_completion(messages, fallback_model, stream=False, params=params)
                    used_model = fallback_model
                    model_context.set(used_model)
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
            chat_completion["choices"][0]["message"].get("content") or "",
        )
        estimated_cost = _priced_cost(used_model, prompt_tokens, completion_tokens)

        redaction_span = tracer.start_as_current_span("response.redaction") if tracer else None
        if redaction_span:
            redaction_span.__enter__()
        try:
            first_message = chat_completion["choices"][0]["message"]
            raw_response_text = first_message.get("content")
            response_text = _truncate_response(sanitize_response(raw_response_text)) if raw_response_text else raw_response_text
            # Tool calls are per-conversation actions, not reusable answers: never cache them.
            cacheable = bool(raw_response_text) and not first_message.get("tool_calls")
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

        if query and cacheable:
            await cache_response(
                prompt=query,
                cache_model=cache_ns,
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
        tool_reasons: list = []
        for index, choice in enumerate(chat_completion.get("choices", [])):
            message = choice.get("message")
            if not isinstance(message, dict):
                continue
            # Only choices[0] used to be redacted, so n>1 returned the other choices raw.
            if index > 0 and isinstance(message.get("content"), str):
                message["content"] = _truncate_response(sanitize_response(message["content"]))
            if REDACT_TOOL_CALL_ARGUMENTS:
                sanitize_tool_calls(message.get("tool_calls"))
            tool_reasons.extend(check_openai_tool_calls(policy, message.get("tool_calls")))
            _scrub_reasoning(message)

        tool_verdict = output_decision(policy, tool_reasons, policy.tools.action)
        audit_output(policy, surface="chat.completions", decision=tool_verdict, findings=output_findings)
        if tool_verdict.blocked:
            raise HTTPException(status_code=403, detail={
                "message": "The model's tool call was blocked by the guardrail policy",
                "type": "permission_error", "code": "tool_call_blocked", "reasons": tool_verdict.reasons,
            })

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
            output_redacted=_redaction_count(raw_response_text, response_text),
            security_metadata=security_metadata
        )

        return chat_completion, metadata_payload

    except HTTPException:
        raise
    except Exception as e:
        client_error = _upstream_client_error(e)
        if client_error:
            raise client_error
        logger.exception(f"Error generating response: {e!r}")
        # Don't echo internal exception text (provider URLs, stack details) to clients;
        # the request ID links the client's error to the logged traceback.
        raise HTTPException(status_code=500, detail={
            "message": f"Internal error while generating the response (request_id {request_id})",
            "type": "internal_error",
            "code": "internal_error",
        })


async def _stream_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None,
    params: Optional[dict] = None,
) -> AsyncGenerator[tuple[str, dict], None]:
    start_time = time.time()
    request_id = generate_request_id()
    security_metadata = security_context or {}
    tracer = _current_tracer()

    messages = prepare_messages(query_or_messages)
    query = extract_cache_query(messages)
    output_findings = output_events.begin()
    policy = policy_for(app_context.get())

    active_model = model or "groq/openai/gpt-oss-120b"
    params = clean_params(params)
    cache_ns = _cache_namespace(active_model, messages, params, security_metadata)
    # A paraphrase must not stand in for a tool-calling turn.
    allow_semantic = "tools" not in params and "functions" not in params
    exact_on, semantic_on = _cache_policy()
    if not exact_on:
        query = ""  # no lookups and no writes for this project
    allow_semantic = allow_semantic and semantic_on
    model_context.set(active_model)

    try:
        cache_span = tracer.start_as_current_span("cache.lookup") if tracer else None
        if cache_span:
            cache_span.__enter__()
        try:
            cache_type, cached = await _lookup_cache(query, cache_ns, semantic=allow_semantic)
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
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), 0)  # cache hit: no upstream tokens used

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
                    cache_model=cache_ns,
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
                    settle_tokens(api_key, _reserved_tokens_from_context(security_metadata), 0)  # cache hit: no upstream tokens used

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
                stream = await _open_stream(messages, active_model, params=params)
                used_model = active_model
            except Exception as primary_exc:
                client_error = _upstream_client_error(primary_exc)
                if client_error:
                    raise client_error
                logger.warning(f"Primary stream model {active_model} failed, trying fallback: {primary_exc}")
                try:
                    fallback_model = SECONDARY_MODEL_NAME
                    stream = await _open_stream(messages, fallback_model, params=params)
                    used_model = fallback_model
                    model_context.set(used_model)
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
        # Streamed text used to reach the client raw; only the cached copy was redacted.
        redactor = _StreamRedactor()
        emitted_chars = 0
        last_chunk: Optional[dict] = None

        def _redacted_chunk(template: dict, text: str) -> dict:
            out = {k: v for k, v in template.items() if k not in ("usage", "x_groq")}
            choice = dict((template.get("choices") or [{}])[0])
            delta = {k: v for k, v in (choice.get("delta") or {}).items() if k not in _REASONING_KEYS}
            delta.pop("tool_calls", None)
            delta["content"] = text
            choice["delta"] = delta
            choice["finish_reason"] = None  # sent once, after all text, by the finish chunk
            choice.setdefault("index", 0)
            out["choices"] = [choice]
            return out

        def _within_limit(text: str) -> str:
            nonlocal emitted_chars
            room = max(0, MAX_RESPONSE_CHARS - emitted_chars)
            text = text[:room]
            emitted_chars += len(text)
            return text

        finish_chunk: Optional[dict] = None
        streamed_tool_calls = False
        tool_call_buffer: dict = {}
        tool_call_template: Optional[dict] = None

        def _passthrough_chunk(template: dict, finish_reason=None) -> dict:
            """Forward a non-text chunk (tool-call deltas, the finish marker) without
            reasoning fields and without text, which goes through the redactor."""
            out = {k: v for k, v in template.items() if k not in ("usage", "x_groq")}
            choice = dict((template.get("choices") or [{}])[0])
            choice["delta"] = {k: v for k, v in (choice.get("delta") or {}).items()
                               if k not in _REASONING_KEYS and k != "content"}
            choice["finish_reason"] = finish_reason
            choice.setdefault("index", 0)
            out["choices"] = [choice]
            return out

        async for chunk in stream:
            choices = chunk.get("choices", [])
            if choices:
                last_chunk = chunk
                choice0 = choices[0]
                delta = choice0.get("delta") or {}
                content = delta.get("content") or ""
                if content:
                    full_response += content
                    ready = _within_limit(redactor.feed(content))
                    if ready:
                        yield "content", _redacted_chunk(chunk, ready)
                if delta.get("tool_calls"):
                    # Tool-call deltas used to be dropped, breaking agent apps. Flush any
                    # held-back text first so order is preserved.
                    streamed_tool_calls = True
                    pending = _within_limit(redactor.flush())
                    if pending:
                        yield "content", _redacted_chunk(chunk, pending)
                    if REDACT_TOOL_CALL_ARGUMENTS or policy.tools.active:
                        # Argument fragments can split a secret across chunks, so collect
                        # the calls and send each one whole, redacted, at the end.
                        _accumulate_tool_calls(tool_call_buffer, delta["tool_calls"])
                        tool_call_template = chunk
                    else:
                        yield "content", _passthrough_chunk(chunk)
                if choice0.get("finish_reason"):
                    finish_chunk = chunk

            # Providers report real usage in a final chunk (Groq may nest it under x_groq).
            chunk_usage = chunk.get("usage") or (chunk.get("x_groq") or {}).get("usage")
            if chunk_usage:
                provider_usage = chunk_usage

        tail = _within_limit(redactor.flush())
        if tail:
            yield "content", _redacted_chunk(last_chunk or {"object": "chat.completion.chunk", "model": used_model}, tail)
        tool_verdict = None
        if tool_call_buffer:
            calls = [tool_call_buffer[i] for i in sorted(tool_call_buffer)]
            if REDACT_TOOL_CALL_ARGUMENTS:
                sanitize_tool_calls(calls)
            tool_verdict = output_decision(policy, check_openai_tool_calls(policy, calls), policy.tools.action)
            if not tool_verdict.blocked:
                out = _passthrough_chunk(tool_call_template or last_chunk or {"object": "chat.completion.chunk"})
                out["choices"][0]["delta"] = {"tool_calls": calls}
                yield "content", out
        audit_output(policy, surface="chat.completions.stream", decision=tool_verdict, findings=output_findings)
        if tool_verdict is not None and tool_verdict.blocked:
            # Headers are already sent; withhold the calls and end the way OpenAI ends
            # filtered output, so clients see why the turn stopped.
            yield "content", _passthrough_chunk(finish_chunk or last_chunk or {"object": "chat.completion.chunk"},
                                                "content_filter")
        elif finish_chunk is not None:
            yield "content", _passthrough_chunk(finish_chunk, finish_chunk["choices"][0].get("finish_reason"))

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

        # A streamed tool call is a per-conversation action, not a reusable answer.
        if query and full_response and not streamed_tool_calls:
            await cache_response(
                prompt=query,
                cache_model=cache_ns,
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
            output_redacted=_redaction_count(full_response, sanitized_full_response),
            security_metadata=security_metadata
        )
        yield "metadata", metadata_payload

    except Exception as e:
        logger.exception(f"Error streaming response: {e!r}")
        api_key = _api_key_from_context(security_metadata)
        if api_key:
            refund_tokens(api_key, _reserved_tokens_from_context(security_metadata))
        record_stream_duration(cache_hit=False, cache_type="error", duration_seconds=time.time() - start_time)
        client_error = _upstream_client_error(e)
        if client_error:
            raise client_error
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail={
            "message": f"Internal error while streaming the response (request_id {request_id})",
            "type": "internal_error",
            "code": "internal_error",
        })


# --- output moderation (policy.moderation, opt-in) ---------------------------------------------

_WITHHELD = "[Response withheld by the guardrail policy.]"


async def _moderate_output(query_or_messages, response_text: str):
    """Decision for the model's answer, or None when output moderation is off."""
    policy = policy_for(app_context.get())
    if not moderation.wants(policy, "output") or not response_text:
        return None
    question = extract_cache_query(prepare_messages(query_or_messages))
    verdict = await moderation.moderate([{"role": "user", "content": question},
                                         {"role": "assistant", "content": response_text}])
    blocks, flags = moderation.verdict_reasons(policy, verdict)
    decision = output_decision(policy, blocks, "block") if blocks else output_decision(policy, flags, "flag")
    audit_output(policy, surface="moderation", decision=decision)
    return decision


async def generate_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None,
    params: Optional[dict] = None,
) -> tuple[dict, dict]:
    completion, metadata = await _generate_response(query_or_messages, model, security_context, params)
    if isinstance(metadata, dict) and metadata.get("status") != "degraded":
        decision = await _moderate_output(query_or_messages, metadata.get("response") or "")
        if decision is not None and decision.blocked:
            raise HTTPException(status_code=403, detail={
                "message": "The model's response was blocked by the guardrail policy",
                "type": "permission_error", "code": "output_blocked", "reasons": decision.reasons,
            })
    return completion, metadata


async def stream_response(
    query_or_messages: str | list[dict],
    model: str | None = None,
    security_context: Optional[dict] = None,
    params: Optional[dict] = None,
) -> AsyncGenerator[tuple[str, dict], None]:
    policy = policy_for(app_context.get())
    inner = _stream_response(query_or_messages, model, security_context, params)
    if not moderation.wants(policy, "output"):
        async for event in inner:
            yield event
        return
    if policy.moderation.action != "block":
        # Flag only: stream normally, judge the full answer afterwards (audited).
        async for event in inner:
            if event[0] == "metadata" and event[1].get("status") != "degraded":
                await _moderate_output(query_or_messages, event[1].get("response") or "")
            yield event
        return
    # Block: hold the whole answer until it has been judged; text already sent to a
    # client cannot be taken back. This costs time-to-first-token.
    held, metadata = [], None
    async for event in inner:
        if event[0] == "metadata":
            metadata = event
        else:
            held.append(event)
    if metadata is not None and metadata[1].get("status") != "degraded":
        decision = await _moderate_output(query_or_messages, metadata[1].get("response") or "")
        if decision is not None and decision.blocked:
            template = next((e[1] for e in held), {"object": "chat.completion.chunk"})
            base = {k: v for k, v in template.items() if k not in ("choices", "usage", "x_groq")}
            yield "content", {**base, "choices": [{"index": 0, "delta": {"content": _WITHHELD}, "finish_reason": None}]}
            yield "content", {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "content_filter"}]}
            yield "metadata", {**metadata[1], "response": _WITHHELD, "guardrail_action": "block",
                               "guardrail_reasons": decision.reasons}
            return
    for event in held:
        yield event
    if metadata is not None:
        yield metadata


def uuid_id() -> str:
    return str(uuid.uuid4())
