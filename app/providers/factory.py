from app.providers.gemini_adapter import GeminiAdapter
from app.providers.groq_adapter import GroqAdapter
from app.providers.openai_adapter import OpenAIAdapter
from app.providers.anthropic_adapter import AnthropicAdapter
from app.core.config import DEFAULT_PROVIDER

_adapters = {
    "gemini": GeminiAdapter(),
    "groq": GroqAdapter(),
    "openai": OpenAIAdapter(),
    "anthropic": AnthropicAdapter(),
}

def resolve_provider_and_model(model_name: str) -> tuple[str, str]:
    if model_name.startswith("groq/"):
        return "groq", model_name[5:]
    elif model_name.startswith("gemini/"):
        return "gemini", model_name[7:]
    elif model_name.startswith("anthropic/"):
        return "anthropic", model_name[10:]
    elif model_name.startswith("openai/") and ("gpt-oss" in model_name or "safeguard" in model_name):
        # Groq hosted open-source models (e.g. openai/gpt-oss-120b)
        if DEFAULT_PROVIDER == "groq":
            return "groq", model_name
        return "openai", model_name[7:]
    elif "/" in model_name:
        provider, real_model = model_name.split("/", 1)
        provider = provider.lower()
        if provider in _adapters:
            return provider, real_model

    # Inference logic based on substrings
    model_lower = model_name.lower()
    if "gemini" in model_lower:
        return "gemini", model_name
    elif "claude" in model_lower:
        return "anthropic", model_name
    elif "gpt-4" in model_lower or "o1-" in model_lower or "text-embedding-" in model_lower:
        return "openai", model_name
    elif "gpt-oss" in model_lower or "qwen" in model_lower or "llama" in model_lower or "mixtral" in model_lower or "allam" in model_lower or "orpheus" in model_lower:
        return "groq", model_name

    return DEFAULT_PROVIDER, model_name

def get_adapter(provider: str):
    adapter = _adapters.get(provider.lower())
    if not adapter:
        raise ValueError(f"Unknown provider: {provider}")
    return adapter
