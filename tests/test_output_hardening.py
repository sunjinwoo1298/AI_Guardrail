import asyncio

from app.services import llm_orchestrator as orch


def test_stream_redactor_masks_pii_split_across_chunks():
    redactor = orch._StreamRedactor(holdback=16)
    pieces = ["Contact me at bob.sm", "ith@example.com please. ", "Thanks for waiting. " * 3, "Bye."]
    out = "".join(redactor.feed(p) for p in pieces) + redactor.flush()
    assert "bob.smith@example.com" not in out
    assert "[EMAIL]" in out
    assert out.endswith("Bye.")


def test_stream_redactor_holds_text_until_sentence_boundary():
    redactor = orch._StreamRedactor(holdback=8)
    assert redactor.feed("no boundary yet") == ""
    assert redactor.flush() == "no boundary yet"


def test_reasoning_is_dropped_by_default():
    message = {"role": "assistant", "content": "OK", "reasoning": "secret chain of thought"}
    orch._scrub_reasoning(message)
    assert "reasoning" not in message and message["content"] == "OK"


def test_reasoning_is_redacted_when_exposed(monkeypatch):
    monkeypatch.setattr(orch, "EXPOSE_REASONING", True)
    message = {"content": "OK", "reasoning": "user is alice@corp.com"}
    orch._scrub_reasoning(message)
    assert message["reasoning"] == "user is [EMAIL]"


def test_live_stream_chunks_are_redacted(monkeypatch):
    async def fake_lookup(query, model, **_kwargs):
        return None, None

    async def fake_stream():
        for text in ["Write to alice@", "corp.com today. ", "Done."]:
            yield {"choices": [{"index": 0, "delta": {"content": text, "reasoning": "x"}}]}

    async def fake_create(messages, model, stream=False, **_kwargs):
        return fake_stream()

    async def fake_cache(**kwargs):
        return None

    monkeypatch.setattr(orch, "_lookup_cache", fake_lookup)
    monkeypatch.setattr(orch, "_create_completion", fake_create)
    monkeypatch.setattr(orch, "cache_response", fake_cache)

    async def collect():
        return [e async for e in orch.stream_response("hi")]

    events = asyncio.run(collect())
    content = [e[1] for e in events if e[0] == "content"]
    text = "".join(c["choices"][0]["delta"]["content"] for c in content)
    assert "alice@corp.com" not in text and "[EMAIL]" in text
    assert all("reasoning" not in c["choices"][0]["delta"] for c in content)
