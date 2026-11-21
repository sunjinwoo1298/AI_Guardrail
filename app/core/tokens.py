"""Token estimation.

Provider-reported usage is the source of truth for billing and metrics. These
helpers are only used when a provider does not return usage (or before the call,
to reserve rate-limit budget). They follow the common ~4 characters/token rule
with a small per-message overhead, as in OpenAI's token-counting guidance.
"""
import math

CHARS_PER_TOKEN = 4
PER_MESSAGE_OVERHEAD = 4


def estimate_text_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / CHARS_PER_TOKEN))


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def estimate_messages_tokens(messages: list[dict]) -> int:
    """Estimate prompt tokens for a whole conversation (all roles, not just the last turn)."""
    total = 0
    for msg in messages:
        if isinstance(msg, dict):
            total += PER_MESSAGE_OVERHEAD + estimate_text_tokens(_content_text(msg.get("content")))
    return max(1, total)
