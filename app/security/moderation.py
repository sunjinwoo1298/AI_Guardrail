"""Harmful-content moderation with Llama Guard (policy.moderation, opt-in).

Llama Guard classifies a conversation turn as ``safe`` or ``unsafe`` plus hazard
categories (S1 violent crimes … S14 code interpreter abuse). It runs on Groq with the
platform's key, or the tenant's own Groq key (BYOK). Input moderation looks at the
user's latest turn; output moderation looks at the model's answer in context.

Verdicts are cached by content hash, so a repeated text costs one call.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List, Optional

from app.control.policy import Policy
from app.core.config import GROQ_API_KEY
from app.core.logger import logger

MODERATION_MODEL = os.getenv("MODERATION_MODEL", "meta-llama/llama-guard-4-12b")
MODERATION_URL = os.getenv("MODERATION_URL", "https://api.groq.com/openai/v1/chat/completions")
MODERATION_TIMEOUT_SECONDS = float(os.getenv("MODERATION_TIMEOUT_SECONDS", "5"))
# Llama Guard's context is limited; long texts are judged on their last part, where an
# answer's harmful content usually is, and the first part.
MODERATION_MAX_CHARS = int(os.getenv("MODERATION_MAX_CHARS", "12000"))

CATEGORY_NAMES = {
    "S1": "violent_crimes", "S2": "non_violent_crimes", "S3": "sex_related_crimes",
    "S4": "child_sexual_exploitation", "S5": "defamation", "S6": "specialized_advice",
    "S7": "privacy", "S8": "intellectual_property", "S9": "indiscriminate_weapons",
    "S10": "hate", "S11": "suicide_self_harm", "S12": "sexual_content", "S13": "elections",
    "S14": "code_interpreter_abuse",
}

_cache: "OrderedDict[str, tuple]" = OrderedDict()
_cache_lock = threading.Lock()
_CACHE_TTL, _CACHE_MAX = 3600, 5000


@dataclass
class ModerationResult:
    safe: Optional[bool]  # None = moderation unavailable
    categories: List[str] = field(default_factory=list)
    error: Optional[str] = None


def _clip(text: str) -> str:
    if len(text) <= MODERATION_MAX_CHARS:
        return text
    half = MODERATION_MAX_CHARS // 2
    return text[:half] + "\n…\n" + text[-half:]


def _parse(content: str) -> ModerationResult:
    lines = [line.strip() for line in (content or "").strip().splitlines() if line.strip()]
    if not lines:
        return ModerationResult(None, error="empty moderation response")
    verdict = lines[0].lower()
    if verdict == "safe":
        return ModerationResult(True)
    if verdict == "unsafe":
        categories = []
        for line in lines[1:]:
            categories.extend(c.strip().upper() for c in line.split(",") if c.strip())
        return ModerationResult(False, categories)
    return ModerationResult(None, error=f"unexpected moderation response {lines[0][:40]!r}")


async def moderate(conversation: List[dict]) -> ModerationResult:
    """Classify the last turn of ``conversation`` (OpenAI-style role/content dicts)."""
    from app.providers.base import resolve_api_key
    from app.providers.http import get_http_client

    messages = [{"role": m["role"], "content": _clip(m["content"])} for m in conversation
                if m.get("content") and m.get("role") in {"user", "assistant"}]
    if not messages:
        return ModerationResult(True)
    key = hashlib.sha256(repr(messages).encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and now - hit[1] < _CACHE_TTL:
            return hit[0]
    try:
        api_key = resolve_api_key("groq", GROQ_API_KEY)
        if not api_key:
            return ModerationResult(None, error="no Groq key for moderation")
        response = await get_http_client().post(
            MODERATION_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": MODERATION_MODEL, "messages": messages, "temperature": 0},
            timeout=MODERATION_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        result = _parse(response.json()["choices"][0]["message"]["content"])
    except Exception as exc:  # network, 4xx/5xx, missing BYOK key, bad JSON
        logger.warning(f"Moderation unavailable: {exc!r}")
        return ModerationResult(None, error=type(exc).__name__)
    if result.safe is not None:
        with _cache_lock:
            _cache[key] = (result, now)
            _cache.move_to_end(key)
            while len(_cache) > _CACHE_MAX:
                _cache.popitem(last=False)
    return result


def verdict_reasons(policy: Policy, result: ModerationResult) -> tuple:
    """(block reasons, flag reasons) for a moderation result under the policy."""
    moderation = policy.moderation
    if result.safe is None:
        reason = "moderation_unavailable"
        return ([reason], []) if moderation.fail_mode == "closed" else ([], [reason])
    if result.safe:
        return [], []
    relevant = [c for c in result.categories if not moderation.categories or c in moderation.categories]
    if not relevant:
        return [], []
    reason = "moderation:" + ",".join(sorted(set(relevant)))
    return ([reason], []) if moderation.action == "block" else ([], [reason])


def wants(policy: Policy, direction: str) -> bool:
    m = policy.moderation
    return m.enabled and m.direction in (direction, "both")
