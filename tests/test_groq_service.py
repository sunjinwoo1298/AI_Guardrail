import asyncio

from app.services import resilient_groq_service as groq_service


def test_generate_response_uses_exact_cache(monkeypatch):
    async def fake_exact_cache(query):
        return {
            "response": "cached answer",
            "prompt_tokens": 10,
            "completion_tokens": 12,
            "total_tokens": 22,
            "estimated_cost": 0.0001,
        }

    async def fake_semantic_cache(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_exact_cache)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_semantic_cache)

    observed = {}

    def fake_record_model_observation(**kwargs):
        observed.update(kwargs)

    monkeypatch.setattr(groq_service, "record_model_observation", fake_record_model_observation)
    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)

    result = asyncio.run(groq_service.generate_response("hello"))

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

    class FakeUsage:
        prompt_tokens = 3
        completion_tokens = 4
        total_tokens = 7

    class FakeMessage:
        content = "live answer"

    class FakeChoice:
        message = FakeMessage()

    class FakeCompletion:
        usage = FakeUsage()
        choices = [FakeChoice()]

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                async def create(**kwargs):
                    return FakeCompletion()

    monkeypatch.setattr(groq_service, "get_groq_client", lambda: FakeClient())
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)
    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert result["cache_hit"] is False
    assert result["response"] == "live answer"
    assert result["estimated_cost"] == 0.123


def test_generate_response_falls_back_to_secondary_model(monkeypatch):
    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)
    monkeypatch.setattr(groq_service, "SECONDARY_MODEL", "fallback-model")
    from app.core.resilience import CircuitBreaker
    groq_service.BREAKERS["fallback-model"] = CircuitBreaker(failure_threshold=3, reset_timeout_seconds=30)

    class FakeUsage:
        prompt_tokens = 2
        completion_tokens = 3
        total_tokens = 5

    class FakeMessage:
        content = "secondary answer"

    class FakeChoice:
        message = FakeMessage()

    class FakeCompletion:
        usage = FakeUsage()
        choices = [FakeChoice()]

    calls = []

    async def fake_create_completion(query, model, stream=False):
        calls.append(model)
        if model == groq_service.MODEL_NAME:
            raise TimeoutError("primary timed out")
        return FakeCompletion()

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
    monkeypatch.setattr(groq_service, "calculate_cost", lambda model, prompt_tokens, completion_tokens: 0.456)

    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert calls == [groq_service.MODEL_NAME, groq_service.SECONDARY_MODEL]
    assert result["model"] == groq_service.SECONDARY_MODEL
    assert result["response"] == "secondary answer"
    assert result["cache_hit"] is False


def test_generate_response_degrades_when_all_models_fail(monkeypatch):
    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)

    async def fake_create_completion(query, model, stream=False):
        raise TimeoutError("down")

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert result["status"] == "degraded"
    assert result["reason"] == "model_unavailable"
