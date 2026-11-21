from __future__ import annotations

import httpx
from typing import AsyncGenerator
from app.providers.base import BaseLLMAdapter
from app.core.config import OPENAI_API_KEY

class OpenAIAdapter(BaseLLMAdapter):
    """Any OpenAI-compatible chat-completions API (OpenAI itself, OpenRouter, ...)."""

    chat_url = "https://api.openai.com/v1/chat/completions"
    key_name = "OPENAI_API_KEY"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else OPENAI_API_KEY

    def extra_headers(self) -> dict:
        return {}

    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        if not self.api_key:
            raise ValueError(f"{self.key_name} is not configured")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers(),
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": False
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        
        for k, v in kwargs.items():
            if k not in payload:
                payload[k] = v

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.chat_url,
                headers=headers,
                json=payload,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    async def stream(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> AsyncGenerator[dict, None]:
        if not self.api_key:
            raise ValueError(f"{self.key_name} is not configured")
            
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers(),
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            # Ask the provider to append a final chunk with real token usage.
            "stream_options": {"include_usage": True},
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
            
        for k, v in kwargs.items():
            if k not in payload:
                payload[k] = v

        async def _stream_generator():
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    self.chat_url,
                    headers=headers,
                    json=payload,
                    timeout=30.0
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("data: "):
                            data_content = line[6:]
                            if data_content == "[DONE]":
                                break
                            import json
                            try:
                                chunk = json.loads(data_content)
                                yield chunk
                            except json.JSONDecodeError:
                                pass
        return _stream_generator()
