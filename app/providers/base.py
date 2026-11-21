from __future__ import annotations

from typing import AsyncGenerator

class BaseLLMAdapter:
    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        """
        Accepts OpenAI-compatible messages and model parameter, returns standard OpenAI response dict.
        """
        raise NotImplementedError()

    async def stream(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> AsyncGenerator[dict, None]:
        """
        Accepts OpenAI-compatible messages and model parameter, yields standard OpenAI stream chunk dicts.
        """
        raise NotImplementedError()
        yield  # to satisfy compiler/linter that this is a generator
