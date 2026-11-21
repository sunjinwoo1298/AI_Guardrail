import asyncio

from app.services import cache_service, llm_orchestrator as orchestrator


def test_exact_key_differs_by_model_and_ignores_prompt_formatting():
    a = cache_service.build_exact_cache_key("  Hello   World ", "groq/openai/gpt-oss-120b")
    assert a == cache_service.build_exact_cache_key("hello world", "GROQ/openai/gpt-oss-120b")
    assert a != cache_service.build_exact_cache_key("hello world", "groq/openai/gpt-oss-20b")


def test_chroma_metadata_is_flat():
    meta = cache_service._chroma_metadata(
        {"a": "x", "b": 1, "c": None, "d": {"k": [1, 2]}, "e": True}
    )
    assert meta == {"a": "x", "b": 1, "d": '{"k": [1, 2]}', "e": True}


def test_exact_cache_is_not_shared_across_models(monkeypatch):
    store = {}

    class FakeRedis:
        def get(self, key):
            return store.get(key)

        def setex(self, key, ttl, value):
            store[key] = value

    monkeypatch.setattr(cache_service, "get_redis_client", lambda: FakeRedis())
    monkeypatch.setattr(cache_service, "get_chroma_collection", lambda: (_ for _ in ()).throw(RuntimeError("no chroma")))

    async def run():
        await cache_service.cache_response(
            prompt="What is 2+2?",
            response="4",
            request_id="r1",
            model_name="groq/openai/gpt-oss-20b",  # model that actually answered (e.g. fallback)
            cache_model="groq/openai/gpt-oss-120b",  # model that was requested
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
            estimated_cost=0.0,
            cache_type="generated",
        )
        same = await cache_service.get_exact_cache("what is 2+2?", "groq/openai/gpt-oss-120b")
        other = await cache_service.get_exact_cache("what is 2+2?", "groq/openai/gpt-oss-20b")
        return same, other

    same, other = asyncio.run(run())
    assert same is not None and same["response"] == "4"
    assert other is None


def test_orchestrator_looks_up_cache_with_requested_model(monkeypatch):
    seen = {}

    async def fake_exact(query, model):
        seen["exact"] = model
        return None

    async def fake_semantic(query, model):
        seen["semantic"] = model
        return None

    monkeypatch.setattr(orchestrator, "get_exact_cache", fake_exact)
    monkeypatch.setattr(orchestrator, "search_semantic_cache", fake_semantic)
    asyncio.run(orchestrator._lookup_cache("hi", "anthropic/claude-3-5-sonnet-20241022"))
    assert seen == {
        "exact": "anthropic/claude-3-5-sonnet-20241022",
        "semantic": "anthropic/claude-3-5-sonnet-20241022",
    }
