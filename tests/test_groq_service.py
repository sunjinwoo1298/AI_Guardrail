import asyncio
import pytest

from app.services import llm_orchestrator as groq_service


def test_generate_response_uses_exact_cache(monkeypatch):
    async def fake_exact_cache(query):
        return {
            "response": "cached answer",
            "prompt_tokens": 10,
            "completion_tokens": 12,
            "total_tokens": 22,
            "estimated_cost": 0.0001,
        }

    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_exact_cache)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)

    observed = {}

    def fake_record_model_observation(**kwargs):
        observed.update(kwargs)

    monkeypatch.setattr(groq_service, "record_model_observation", fake_record_model_observation)
    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)

    _, result = asyncio.run(groq_service.generate_response("hello"))

    assert result["cache_hit"] is True
    assert result["response"] == "cached answer"
    assert result["cache_type"] == "exact"
    assert observed["cache_hit"] is True


def test_generate_response_uses_live_model(monkeypatch):
    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)
    monkeypatch.setattr(groq_service, "calculate_cost", lambda model, prompt_tokens, completion_tokens: 0.123)

    async def fake_create_completion(messages, model, stream=False):
        return {
            "choices": [{"message": {"role": "assistant", "content": "live answer"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
        }

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)
    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)

    _, result = asyncio.run(groq_service.generate_response("hello"))

    assert result["cache_hit"] is False
    assert result["response"] == "live answer"
    assert result["estimated_cost"] == 0.123


def test_generate_response_falls_back_to_secondary_model(monkeypatch):
    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)
    monkeypatch.setattr(groq_service, "SECONDARY_MODEL_NAME", "fallback-model")
    
    from app.core.resilience import CircuitBreaker
    groq_service._breakers["fallback-model"] = CircuitBreaker(failure_threshold=3, reset_timeout_seconds=30)

    calls = []

    async def fake_create_completion(messages, model, stream=False):
        calls.append(model)
        if model == "groq/openai/gpt-oss-120b":
            raise TimeoutError("primary timed out")
        return {
            "choices": [{"message": {"role": "assistant", "content": "secondary answer"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        }

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
    monkeypatch.setattr(groq_service, "calculate_cost", lambda model, prompt_tokens, completion_tokens: 0.456)

    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)

    _, result = asyncio.run(groq_service.generate_response("hello"))

    assert calls == ["groq/openai/gpt-oss-120b", "fallback-model"]
    assert result["model"] == "fallback-model"
    assert result["response"] == "secondary answer"
    assert result["cache_hit"] is False


def test_generate_response_degrades_when_all_models_fail(monkeypatch):
    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)

    async def fake_create_completion(messages, model, stream=False):
        raise TimeoutError("down")

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)

    _, result = asyncio.run(groq_service.generate_response("hello"))

    assert result["status"] == "degraded"
    assert result["reason"] == "model_unavailable"
