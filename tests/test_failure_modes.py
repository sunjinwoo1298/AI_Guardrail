import asyncio

from app.services import resilient_groq_service as groq_service


def test_generate_response_degrades_when_all_cache_and_model_paths_fail(monkeypatch):
    async def fake_none(query):
        return None

    async def fake_fail(*args, **kwargs):
        raise TimeoutError("down")

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)
    monkeypatch.setattr(groq_service, "_create_completion", fake_fail)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)

    result = asyncio.run(groq_service.generate_response("hello"))

    assert result["status"] == "degraded"
    assert result["reason"] == "model_unavailable"


def test_stream_response_degrades_when_all_models_fail(monkeypatch):
    async def fake_none(query):
        return None

    async def fake_fail(*args, **kwargs):
        raise TimeoutError("down")

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)
    monkeypatch.setattr(groq_service, "_create_completion", fake_fail)
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)
    monkeypatch.setattr(groq_service, "record_stream_duration", lambda **kwargs: None)

    chunks = list(asyncio.run(_collect_stream(groq_service.stream_response("hello"))))
    assert any("__meta" in chunk for chunk in chunks)


async def _collect_stream(generator):
    items = []
    async for chunk in generator:
        items.append(chunk)
    return items
