from __future__ import annotations

import httpx
import json
import time
import uuid
from typing import AsyncGenerator
from app.providers.base import BaseLLMAdapter
from app.providers.http import PROVIDER_TIMEOUT, provider_client
from app.core.config import ANTHROPIC_API_KEY

def translate_messages_to_anthropic(messages: list[dict]) -> tuple[str | None, list[dict]]:
    system_prompt = None
    anth_messages = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content", "")
        
        if role == "system":
            system_prompt = content
        else:
            anth_role = "user" if role == "user" else "assistant"
            anth_messages.append({
                "role": anth_role,
                "content": content
            })
    return system_prompt, anth_messages

def translate_anthropic_response_to_openai(anth_resp: dict, model: str) -> dict:
    content = anth_resp.get("content", [])
    text = ""
    if content and isinstance(content, list):
        text = "".join([c.get("text", "") for c in content if c.get("type") == "text"])
    
    stop_reason = anth_resp.get("stop_reason")
    finish_reason = "stop"
    if stop_reason == "end_turn":
        finish_reason = "stop"
    elif stop_reason == "max_tokens":
        finish_reason = "length"
    elif stop_reason:
        finish_reason = stop_reason

    usage = anth_resp.get("usage", {})
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)
    total_tokens = input_tokens + output_tokens

    return {
        "id": anth_resp.get("id") or f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": text
            },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": total_tokens
        }
    }


class AnthropicAdapter(BaseLLMAdapter):
    def __init__(self):
        self.api_key = ANTHROPIC_API_KEY

    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured")
        
        system_prompt, anth_messages = translate_messages_to_anthropic(messages)
        
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        # Anthropic requires max_tokens
        limit_tokens = max_tokens if max_tokens is not None else 16000  # current Claude models always think; 1024 could be spent before any answer text
        
        payload = {
            "model": model,
            "messages": anth_messages,
            "max_tokens": limit_tokens,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt
        if temperature is not None:
            payload["temperature"] = temperature

        async with provider_client() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
                timeout=PROVIDER_TIMEOUT
            )
            response.raise_for_status()
            return translate_anthropic_response_to_openai(response.json(), model)

    async def stream(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> AsyncGenerator[dict, None]:
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured")
            
        system_prompt, anth_messages = translate_messages_to_anthropic(messages)
        
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        limit_tokens = max_tokens if max_tokens is not None else 16000  # current Claude models always think; 1024 could be spent before any answer text
        
        payload = {
            "model": model,
            "messages": anth_messages,
            "max_tokens": limit_tokens,
            "stream": True
        }
        if system_prompt:
            payload["system"] = system_prompt
        if temperature is not None:
            payload["temperature"] = temperature

        async def _stream_generator():
            chunk_id = f"chatcmpl-{uuid.uuid4()}"
            created_time = int(time.time())
            
            input_tokens = 0
            
            async with provider_client() as client:
                async with client.stream(
                    "POST",
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                    timeout=PROVIDER_TIMEOUT
                ) as response:
                    response.raise_for_status()
                    current_event = None
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("event: "):
                            current_event = line[7:]
                        elif line.startswith("data: "):
                            data_str = line[6:]
                            
                            if current_event == "message_start":
                                try:
                                    event_data = json.loads(data_str)
                                    input_tokens = event_data.get("message", {}).get("usage", {}).get("input_tokens", 0)
                                except Exception:
                                    pass
                                    
                            elif current_event == "content_block_delta":
                                try:
                                    event_data = json.loads(data_str)
                                    text_delta = event_data.get("delta", {}).get("text", "")
                                    yield {
                                        "id": chunk_id,
                                        "object": "chat.completion.chunk",
                                        "created": created_time,
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": {"content": text_delta},
                                            "finish_reason": None
                                        }]
                                    }
                                except Exception:
                                    pass
                                    
                            elif current_event == "message_delta":
                                try:
                                    event_data = json.loads(data_str)
                                    delta = event_data.get("delta", {})
                                    stop_reason = delta.get("stop_reason")
                                    finish_reason = None
                                    if stop_reason == "end_turn":
                                        finish_reason = "stop"
                                    elif stop_reason == "max_tokens":
                                        finish_reason = "length"
                                    elif stop_reason:
                                        finish_reason = stop_reason
                                    
                                    usage = event_data.get("usage", {})
                                    output_tokens = usage.get("output_tokens", 0)
                                    total_tokens = input_tokens + output_tokens
                                    
                                    chunk = {
                                        "id": chunk_id,
                                        "object": "chat.completion.chunk",
                                        "created": created_time,
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": {},
                                            "finish_reason": finish_reason
                                        }],
                                        "usage": {
                                            "prompt_tokens": input_tokens,
                                            "completion_tokens": output_tokens,
                                            "total_tokens": total_tokens
                                        }
                                    }
                                    yield chunk
                                except Exception:
                                    pass
        return _stream_generator()
