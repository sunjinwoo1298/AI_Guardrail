import asyncio

import pytest

from app.core.cost_calculator import calculate_cost, is_priced
from app.core.tokens import estimate_messages_tokens, estimate_text_tokens
from app.services import llm_orchestrator as orchestrator


def test_default_model_is_priced_with_routing_prefix():
    # Regression: "groq/openai/gpt-oss-120b" used to miss the table and cost 0.0.
    assert is_priced("groq/openai/gpt-oss-120b")
    cost = calculate_cost("groq/openai/gpt-oss-120b", 1_000_000, 1_000_000)
    assert cost == pytest.approx(0.15 + 0.60)


def test_cost_uses_per_million_prices():
    assert calculate_cost("gpt-4o", 2_000, 1_000) == pytest.approx(2 * 0.0025 + 1 * 0.010)
    assert calculate_cost("groq/openai/gpt-oss-20b", 1_000_000, 0) == pytest.approx(0.075)


def test_unknown_model_is_flagged_unpriced():
    assert not is_priced("some/unknown-model")
    assert calculate_cost("some/unknown-model", 1000, 1000) == 0.0


def test_token_estimates():
    assert estimate_text_tokens("") == 0
    assert estimate_text_tokens("abcd") == 1
    assert estimate_text_tokens("abcde") == 2
    msgs = [{"role": "system", "content": "abcd"}, {"role": "user", "content": [{"type": "text", "text": "abcdefgh"}]}]
    assert estimate_messages_tokens(msgs) == (4 + 1) + (4 + 2)


def test_resolve_usage_prefers_provider_values():
    p, c, t, source = orchestrator._resolve_usage(
        {"prompt_tokens": 10, "completion_tokens": 5}, [{"role": "user", "content": "hi"}], "ignored"
    )
    assert (p, c, t, source) == (10, 5, 15, "provider")


def test_resolve_usage_falls_back_to_estimate():
    p, c, t, source = orchestrator._resolve_usage(None, [{"role": "user", "content": "abcdefgh"}], "abcd")
    assert source == "estimated"
    assert (p, c, t) == (6, 1, 7)


def test_stream_uses_provider_usage_chunk(monkeypatch):
    async def fake_stream():
        yield {"choices": [{"delta": {"content": "Hello"}}]}
        yield {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}}

    async def fake_create(messages, model, stream=False):
        return fake_stream()

    async def no_cache(*args, **kwargs):
        return None, None

    async def noop_cache_response(**kwargs):
        return None

    monkeypatch.setattr(orchestrator, "_create_completion", fake_create)
    monkeypatch.setattr(orchestrator, "_lookup_cache", no_cache)
    monkeypatch.setattr(orchestrator, "cache_response", noop_cache_response)

    async def run():
        return [event async for event in orchestrator.stream_response("hi")]

    events = asyncio.run(run())
    meta = next(data for kind, data in events if kind == "metadata")
    assert (meta["prompt_tokens"], meta["completion_tokens"], meta["total_tokens"]) == (12, 3, 15)
    assert meta["usage_source"] == "provider"
    assert meta["estimated_cost"] == pytest.approx(12 / 1e6 * 0.15 + 3 / 1e6 * 0.60)
