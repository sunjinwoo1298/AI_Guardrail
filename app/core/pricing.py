"""Model price table.

Prices are USD per 1,000,000 tokens, the unit providers publish. Keys are the
provider's model id without the proxy's routing prefix (e.g. "openai/gpt-oss-120b"
for Groq, "gpt-4o" for OpenAI).

Verified against provider pricing pages: Groq gpt-oss-120b / gpt-oss-20b
(console.groq.com/docs/models). The other entries were carried over from the
previous table and have NOT been re-verified; check them before relying on cost
numbers. Cached-input discounts and batch pricing are not modelled.
Models missing from this table are reported as unpriced, never silently as free.
"""

MODEL_PRICING_PER_MILLION = {
    "openai/gpt-oss-120b": {"input": 0.15, "output": 0.60},
    "openai/gpt-oss-20b": {"input": 0.075, "output": 0.30},
    "llama-3.1-8b-instant": {"input": 0.05, "output": 0.08},
    "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "claude-opus-5-5": {"input": 4.00, "output": 20.00},
}

PROVIDER_PREFIXES = ("groq/", "openai/", "gemini/", "anthropic/")


def get_pricing(model_name: str):
    """Resolve a model string (with or without routing prefix) to its price entry, or None."""
    candidates = [model_name]
    # Strip one routing prefix at a time: "groq/openai/gpt-oss-120b" -> "openai/gpt-oss-120b" -> "gpt-oss-120b"
    name = model_name
    while name.startswith(PROVIDER_PREFIXES):
        name = name.split("/", 1)[1]
        candidates.append(name)
    for candidate in candidates:
        if candidate in MODEL_PRICING_PER_MILLION:
            return MODEL_PRICING_PER_MILLION[candidate]
    return None
