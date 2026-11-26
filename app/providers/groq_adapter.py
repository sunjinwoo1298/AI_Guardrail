from __future__ import annotations

import httpx
from typing import AsyncGenerator
from app.providers.base import BaseLLMAdapter
from app.providers.http import PROVIDER_TIMEOUT, provider_client
from app.core.config import GROQ_API_KEY

class GroqAdapter(BaseLLMAdapter):
    def __init__(self):
        self.api_key = GROQ_API_KEY

    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        if not self.api_key:
            raise ValueError("GROQ_API_KEY is not configured")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
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

        async with provider_client() as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=PROVIDER_TIMEOUT
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
            raise ValueError("GROQ_API_KEY is not configured")
            
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
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
            async with provider_client() as client:
                async with client.stream(
                    "POST",
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=PROVIDER_TIMEOUT
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
