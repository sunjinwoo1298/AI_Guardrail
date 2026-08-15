import html
import re
import unicodedata
from typing import Dict, List

from app.core.config import PROMPT_INJECTION_MODEL_NAME, SYSTEM_PROMPT_CANARY
from app.core.logger import logger

INJECTION_PATTERNS = [
    r"ignore (?:all|previous|any) instructions",
    r"reveal (?:the )?(?:system|developer) prompt",
    r"show (?:me )?(?:the )?(?:system|developer) prompt",
    r"you are now (?:in )?admin(?:istrator)?",
    r"system override",
    r"bypass safety",
    r"act as administrator",
    r"disregard (?:the )?(?:rules|instructions)",
    r"prompt injection",
]

STRUCTURAL_PATTERNS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[system\]",
    r"\[assistant\]",
    r"\[developer\]",
    r'"""',
    r"```",
]

INJECTION_WEIGHTS = {
    "ignore": 0.35,
    "reveal": 0.45,
    "admin": 0.35,
    "override": 0.45,
    "bypass": 0.45,
}

_classifier = None


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = html.unescape(normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def fast_tripwire(text: str) -> List[str]:
    lowered_text = normalize_text(text).lower()
    matches = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered_text, flags=re.IGNORECASE):
            matches.append(pattern)
    for pattern in STRUCTURAL_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(pattern)
    return matches


def _get_classifier():
    global _classifier
    if _classifier is not None:
        return _classifier
    try:
        from transformers import pipeline

        _classifier = pipeline(
            "text-classification",
            model=PROMPT_INJECTION_MODEL_NAME,
            truncation=True,
            top_k=None,
        )
    except Exception as exc:
        logger.warning(f"Prompt injection classifier unavailable, falling back to tripwire only: {exc}")
        _classifier = None
    return _classifier


def score_prompt_injection(text: str) -> Dict[str, object]:
    normalized = normalize_text(text)
    tripwire_matches = fast_tripwire(normalized)
    classifier = _get_classifier()

    if classifier is None:
        return {
            "is_injection": bool(tripwire_matches),
            "confidence": 1.0 if tripwire_matches else 0.0,
            "signals": tripwire_matches,
            "source": "tripwire",
        }

    try:
        result = classifier(normalized)[0]
        label = str(result.get("label", "")).upper()
        score = float(result.get("score", 0.0))
        is_injection = label in {"INJECTION", "LABEL_1", "YES"}
        confidence = score if is_injection else 1.0 - score
        if tripwire_matches and not is_injection:
            confidence = min(1.0, confidence + 0.15)
            is_injection = confidence >= 0.5
        return {
            "is_injection": is_injection,
            "confidence": confidence,
            "signals": tripwire_matches,
            "label": label,
            "source": "classifier",
        }
    except Exception as exc:
        logger.warning(f"Prompt injection classifier failed, using tripwire only: {exc}")
        return {
            "is_injection": bool(tripwire_matches),
            "confidence": 1.0 if tripwire_matches else 0.0,
            "signals": tripwire_matches,
            "source": "tripwire",
        }


def detect_prompt_injection(text: str):
    return fast_tripwire(text)


def get_system_prompt_canary() -> str:
    return SYSTEM_PROMPT_CANARY
