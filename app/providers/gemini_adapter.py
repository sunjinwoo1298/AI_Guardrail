from __future__ import annotations

import httpx
import json
import time
import uuid
from typing import AsyncGenerator
from app.providers.base import BaseLLMAdapter
from app.providers.http import PROVIDER_TIMEOUT, provider_client
from app.core.config import GEMINI_API_KEY

def translate_messages_to_gemini(messages: list[dict]) -> tuple[dict | None, list[dict]]:
    system_instruction = None
    contents = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content", "")
        
        if role == "system":
            system_instruction = {
                "parts": [{"text": content}]
            }
        else:
            gemini_role = "user" if role == "user" else "model"
            parts = []
            if isinstance(content, str):
                parts = [{"text": content}]
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        parts.append({"text": part.get("text", "")})
            contents.append({
                "role": gemini_role,
                "parts": parts
            })
    return system_instruction, contents

def translate_gemini_response_to_openai(gemini_resp: dict, model: str) -> dict:
    candidates = gemini_resp.get("candidates", [])
    text = ""
    finish_reason = "stop"
    if candidates:
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if parts:
            text = parts[0].get("text", "")
        gemini_finish = candidates[0].get("finishReason")
        if gemini_finish == "STOP":
            finish_reason = "stop"
        elif gemini_finish == "MAX_TOKENS":
            finish_reason = "length"
        elif gemini_finish:
            finish_reason = gemini_finish.lower()
    
    usage = gemini_resp.get("usageMetadata", {})
    prompt_tokens = usage.get("promptTokenCount", 0)
    completion_tokens = usage.get("candidatesTokenCount", 0)
    total_tokens = usage.get("totalTokenCount", 0)

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
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
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }
    }

def translate_gemini_chunk_to_openai(gemini_chunk: dict, model: str, chunk_id: str, created_time: int) -> dict:
    candidates = gemini_chunk.get("candidates", [])
    text = ""
    finish_reason = None
    if candidates:
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if parts:
            text = parts[0].get("text", "")
        gemini_finish = candidates[0].get("finishReason")
        if gemini_finish:
            if gemini_finish == "STOP":
                finish_reason = "stop"
            elif gemini_finish == "MAX_TOKENS":
                finish_reason = "length"
            else:
                finish_reason = gemini_finish.lower()
    
    usage = gemini_chunk.get("usageMetadata")
    usage_dict = None
    if usage:
        usage_dict = {
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "total_tokens": usage.get("totalTokenCount", 0)
        }
    
    chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created_time,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {
                "content": text
            },
            "finish_reason": finish_reason
        }]
    }
    if usage_dict:
        chunk["usage"] = usage_dict
    return chunk


class GeminiAdapter(BaseLLMAdapter):
    def __init__(self):
        self.api_key = GEMINI_API_KEY

    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured")
        
        system_instruction, contents = translate_messages_to_gemini(messages)
        
        generation_config = {}
        if temperature is not None:
            generation_config["temperature"] = temperature
        if max_tokens is not None:
            generation_config["maxOutputTokens"] = max_tokens
        
        payload = {
            "contents": contents
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction
        if generation_config:
            payload["generationConfig"] = generation_config

        # The key goes in a header, never the URL: httpx logs request URLs and
        # raise_for_status() errors include them, which leaked the key into logs.
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

        async with provider_client() as client:
            response = await client.post(
                url,
                json=payload,
                headers={"x-goog-api-key": self.api_key},
                timeout=PROVIDER_TIMEOUT
            )
            response.raise_for_status()
            return translate_gemini_response_to_openai(response.json(), model)

    async def stream(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> AsyncGenerator[dict, None]:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured")
            
        system_instruction, contents = translate_messages_to_gemini(messages)
        
        generation_config = {}
        if temperature is not None:
            generation_config["temperature"] = temperature
        if max_tokens is not None:
            generation_config["maxOutputTokens"] = max_tokens
            
        payload = {
            "contents": contents
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction
        if generation_config:
            payload["generationConfig"] = generation_config

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?alt=sse"

        async def _stream_generator():
            chunk_id = f"chatcmpl-{uuid.uuid4()}"
            created_time = int(time.time())
            async with provider_client() as client:
                async with client.stream(
                    "POST",
                    url,
                    json=payload,
                    headers={"x-goog-api-key": self.api_key},
                    timeout=PROVIDER_TIMEOUT
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("data: "):
                            data_content = line[6:]
                            try:
                                chunk_json = json.loads(data_content)
                                yield translate_gemini_chunk_to_openai(chunk_json, model, chunk_id, created_time)
                            except json.JSONDecodeError:
                                pass
        return _stream_generator()
