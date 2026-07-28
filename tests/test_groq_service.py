import asyncio

from app.services import groq_service


def test_generate_response_uses_exact_cache(monkeypatch):
    monkeypatch.setattr(groq_service, "get_exact_cache", lambda query: {
        "response": "cached answer",
        "prompt_tokens": 10,
        "completion_tokens": 12,
        "total_tokens": 22,
        "estimated_cost": 0.0001,
    })
    monkeypatch.setattr(groq_service, "search_semantic_cache", lambda query: None)

    observed = {}

    def fake_record_model_observation(**kwargs):
        observed.update(kwargs)

    monkeypatch.setattr(groq_service, "record_model_observation", fake_record_model_observation)
    monkeypatch.setattr(groq_service, "cache_response", lambda **kwargs: None)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert result["cache_hit"] is True
    assert result["response"] == "cached answer"
    assert result["cache_type"] == "exact"
    assert observed["cache_hit"] is True


def test_generate_response_uses_live_model(monkeypatch):
    monkeypatch.setattr(groq_service, "get_exact_cache", lambda query: None)
    monkeypatch.setattr(groq_service, "search_semantic_cache", lambda query: None)
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
    monkeypatch.setattr(groq_service, "cache_response", lambda **kwargs: None)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert result["cache_hit"] is False
    assert result["response"] == "live answer"
    assert result["estimated_cost"] == 0.123
