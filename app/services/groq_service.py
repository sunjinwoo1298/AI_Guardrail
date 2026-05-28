import json
import time

from groq import AsyncGroq
from app.core.config import GROQ_API_KEY
from fastapi import HTTPException
from app.core.logger import logger
from app.core.cost_calculator import calculate_cost
from app.core.request_id import generate_request_id
from app.observability.metrics import record_model_observation, record_stream_duration
from app.services.cache_service import cache_response, get_exact_cache, search_semantic_cache

client = AsyncGroq(api_key=GROQ_API_KEY)
MODEL_NAME = "llama3-8b-8192"


def _build_response_payload(
    *,
    request_id: str,
    latency: float,
    response: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    estimated_cost: float,
    cache_hit: bool,
    cache_type: str | None,
    cache_saved_cost: float = 0.0,
    similarity_distance: float | None = None,
    source_prompt: str | None = None,
    security_metadata: dict | None = None,
):
    payload = {
        "status": "success",
        "latency": round(latency, 2),
        "model": MODEL_NAME,
        "cache_hit": cache_hit,
        "cache_type": cache_type,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "estimated_cost": estimated_cost,
        "cache_saved_cost": cache_saved_cost,
        "request_id": request_id,
        "response": response,
    }

    if similarity_distance is not None:
        payload["similarity_distance"] = similarity_distance

    if source_prompt is not None:
        payload["source_prompt"] = source_prompt

    if security_metadata is not None:
        payload.update(security_metadata)

    return payload


async def generate_response(query: str, security_context: dict | None = None):
    try:
        start_time = time.time()
        request_id = generate_request_id()
        security_metadata = security_context or {}

        exact_cache = get_exact_cache(query)
        if exact_cache is not None:
            latency = time.time() - start_time
            logger.info("Redis cache hit")
            cached_response = exact_cache.get("response", "")
            prompt_tokens = int(exact_cache.get("prompt_tokens", 0) or 0)
            completion_tokens = int(exact_cache.get("completion_tokens", 0) or 0)
            total_tokens = int(exact_cache.get("total_tokens", 0) or 0)
            cache_saved_cost = float(exact_cache.get("estimated_cost", 0.0) or 0.0)

            record_model_observation(
                endpoint="generate",
                cache_hit=True,
                cache_type="exact",
                latency_seconds=latency,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
            )

            return _build_response_payload(
                request_id=request_id,
                latency=latency,
                response=cached_response,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
                cache_hit=True,
                cache_type="exact",
                cache_saved_cost=cache_saved_cost,
                security_metadata=security_metadata,
            )

        semantic_cache = search_semantic_cache(query)
        if semantic_cache is not None:
            latency = time.time() - start_time
            logger.info("Semantic cache hit")
            cached_response = semantic_cache.get("response", "")
            source_prompt = semantic_cache.get("source_prompt")
            similarity_distance = semantic_cache.get("distance")
            cached_entry = semantic_cache.get("cached_entry", {}) or {}
            prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
            completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
            total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
            cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)

            record_model_observation(
                endpoint="generate",
                cache_hit=True,
                cache_type="semantic",
                latency_seconds=latency,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
            )

            cache_response(
                prompt=query,
                response=cached_response,
                request_id=request_id,
                model_name=MODEL_NAME,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=cache_saved_cost,
                cache_type="semantic",
                source_prompt=source_prompt,
                similarity_distance=similarity_distance,
                security_metadata=security_metadata,
            )

            return _build_response_payload(
                request_id=request_id,
                latency=latency,
                response=cached_response,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
                cache_hit=True,
                cache_type="semantic",
                cache_saved_cost=cache_saved_cost,
                similarity_distance=similarity_distance,
                source_prompt=source_prompt,
                security_metadata=security_metadata,
            )

        chat_completion = await client.chat.completions.create(
            messages=[{"role": "user", "content": query}],
            model=MODEL_NAME,
        )

        usage = chat_completion.usage
        prompt_tokens = usage.prompt_tokens
        completion_tokens = usage.completion_tokens
        total_tokens = usage.total_tokens
        estimated_cost = calculate_cost(MODEL_NAME, prompt_tokens, completion_tokens)
        response = chat_completion.choices[0].message.content

        logger.info(f"Generated Response: {response}")

        latency = time.time() - start_time
        logger.info(f"Groq API Latency: {latency:.2f} seconds")
        logger.info(
            f"Token Usage - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}"
        )
        logger.info(f"Estimated Cost for this request: ${estimated_cost:.6f}")
        logger.info(f"Request ID: {request_id}")

        record_model_observation(
            endpoint="generate",
            cache_hit=False,
            cache_type="generated",
            latency_seconds=latency,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
        )

        cache_response(
            prompt=query,
            response=response,
            request_id=request_id,
            model_name=MODEL_NAME,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            cache_type="generated",
            security_metadata=security_metadata,
        )

        return {
            "status": "success",
            "latency": latency,
            "model": MODEL_NAME,
            "cache_hit": False,
            "cache_type": None,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost": estimated_cost,
            "cache_saved_cost": 0.0,
            "request_id": request_id,
            "response": response,
            **security_metadata,
        }

    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Groq API Error: {str(e)}"
        )


async def stream_response(query: str, security_context: dict | None = None):
    try:
        start_time = time.time()
        request_id = generate_request_id()
        security_metadata = security_context or {}

        exact_cache = get_exact_cache(query)
        if exact_cache is not None:
            latency = time.time() - start_time
            logger.info("Redis cache hit for stream")
            cached_response = exact_cache.get("response", "")
            prompt_tokens = int(exact_cache.get("prompt_tokens", 0) or 0)
            completion_tokens = int(exact_cache.get("completion_tokens", 0) or 0)
            total_tokens = int(exact_cache.get("total_tokens", 0) or 0)
            cache_saved_cost = float(exact_cache.get("estimated_cost", 0.0) or 0.0)

            record_model_observation(
                endpoint="stream",
                cache_hit=True,
                cache_type="exact",
                latency_seconds=latency,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
            )

            yield f"data: {cached_response}\n\n"
            yield f"data: {json.dumps({'__meta': _build_response_payload(request_id=request_id, latency=latency, response=cached_response, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_hit=True, cache_type='exact', cache_saved_cost=cache_saved_cost, security_metadata=security_metadata)})}\n\n"
            return

        semantic_cache = search_semantic_cache(query)
        if semantic_cache is not None:
            latency = time.time() - start_time
            logger.info("Semantic cache hit for stream")
            cached_response = semantic_cache.get("response", "")
            source_prompt = semantic_cache.get("source_prompt")
            similarity_distance = semantic_cache.get("distance")
            cached_entry = semantic_cache.get("cached_entry", {}) or {}
            prompt_tokens = int(cached_entry.get("prompt_tokens", 0) or 0)
            completion_tokens = int(cached_entry.get("completion_tokens", 0) or 0)
            total_tokens = int(cached_entry.get("total_tokens", 0) or 0)
            cache_saved_cost = float(cached_entry.get("estimated_cost", 0.0) or 0.0)

            record_model_observation(
                endpoint="stream",
                cache_hit=True,
                cache_type="semantic",
                latency_seconds=latency,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=0.0,
            )

            cache_response(
                prompt=query,
                response=cached_response,
                request_id=request_id,
                model_name=MODEL_NAME,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                estimated_cost=cache_saved_cost,
                cache_type="semantic",
                source_prompt=source_prompt,
                similarity_distance=similarity_distance,
                security_metadata=security_metadata,
            )

            yield f"data: {cached_response}\n\n"
            yield f"data: {json.dumps({'__meta': _build_response_payload(request_id=request_id, latency=latency, response=cached_response, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens, estimated_cost=0.0, cache_hit=True, cache_type='semantic', cache_saved_cost=cache_saved_cost, similarity_distance=similarity_distance, source_prompt=source_prompt, security_metadata=security_metadata)})}\n\n"
            return

        stream = await client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": query
                }
            ],
            model=MODEL_NAME,
            stream=True
        )

        full_response = ""
        total_prompt_tokens = len(query.split())

        async for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                full_response += content
                yield f"data: {content}\n\n"

        latency = time.time() - start_time
        logger.info(f"Groq API Stream Latency: {latency:.2f} seconds")

        estimated_prompt_tokens = total_prompt_tokens
        estimated_completion_tokens = len(full_response.split())
        estimated_total_tokens = estimated_prompt_tokens + estimated_completion_tokens
        estimated_cost = calculate_cost(
            MODEL_NAME,
            estimated_prompt_tokens,
            estimated_completion_tokens
        )

        logger.info(
            f"""
            Request ID: {request_id}
            Prompt Tokens: {estimated_prompt_tokens}
            Completion Tokens: {estimated_completion_tokens}
            Total Tokens: {estimated_total_tokens}
            Estimated Cost: ${estimated_cost}
            """
        )

        record_model_observation(
            endpoint="stream",
            cache_hit=False,
            cache_type="generated",
            latency_seconds=latency,
            prompt_tokens=estimated_prompt_tokens,
            completion_tokens=estimated_completion_tokens,
            total_tokens=estimated_total_tokens,
            estimated_cost=estimated_cost,
        )

        record_stream_duration(cache_hit=False, cache_type="generated", duration_seconds=latency)

        cache_response(
            prompt=query,
            response=full_response,
            request_id=request_id,
            model_name=MODEL_NAME,
            prompt_tokens=estimated_prompt_tokens,
            completion_tokens=estimated_completion_tokens,
            total_tokens=estimated_total_tokens,
            estimated_cost=estimated_cost,
            cache_type="generated",
            security_metadata=security_metadata,
        )

        metadata = {
            "status": "success",
            "latency": round(latency, 2),
            "model": MODEL_NAME,
            "cache_hit": False,
            "cache_type": None,
            "prompt_tokens": estimated_prompt_tokens,
            "completion_tokens": estimated_completion_tokens,
            "total_tokens": estimated_total_tokens,
            "estimated_cost": estimated_cost,
            "cache_saved_cost": 0.0,
            "request_id": request_id
            ,**security_metadata
        }

        yield f"data: {json.dumps({'__meta': metadata})}\n\n"

    except Exception as e:
        logger.error(
            f"Error streaming response: {str(e)}"
        )

        record_stream_duration(cache_hit=False, cache_type="error", duration_seconds=time.time() - start_time)

        raise HTTPException(
            status_code=500,
            detail=f"Groq API Stream Error: {str(e)}"
        )