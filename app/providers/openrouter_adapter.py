from __future__ import annotations

from app.core.config import OPEN_ROUTER_API_KEY, OPENROUTER_FREE_ONLY
from app.providers.openai_adapter import OpenAIAdapter


def is_free_openrouter_model(model: str) -> bool:
    """Free OpenRouter models end in ":free"; "openrouter/free" routes to one of them."""
    return model.endswith(":free") or model == "openrouter/free"


class OpenRouterAdapter(OpenAIAdapter):
    """OpenRouter speaks the OpenAI chat-completions API, including tools and JSON mode.

    With OPENROUTER_FREE_ONLY (the default) only free models are allowed, so traffic
    through the proxy can never spend credits on the account.
    """

    chat_url = "https://openrouter.ai/api/v1/chat/completions"
    key_name = "OPEN_ROUTER_API_KEY"

    def __init__(self):
        super().__init__(api_key=OPEN_ROUTER_API_KEY or "")

    def extra_headers(self) -> dict:
        # Optional attribution header shown in the OpenRouter dashboard.
        return {"X-Title": "AI Guardrail Proxy"}

    def _check_model(self, model: str) -> None:
        if OPENROUTER_FREE_ONLY and not is_free_openrouter_model(model):
            raise ValueError(f"OpenRouter model '{model}' is not free and OPENROUTER_FREE_ONLY is enabled")

    async def generate(self, messages, model, temperature=None, max_tokens=None, **kwargs):
        self._check_model(model)
        return await super().generate(messages, model, temperature=temperature, max_tokens=max_tokens, **kwargs)

    async def stream(self, messages, model, temperature=None, max_tokens=None, **kwargs):
        self._check_model(model)
        return await super().stream(messages, model, temperature=temperature, max_tokens=max_tokens, **kwargs)
