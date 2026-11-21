import html
import re
from typing import Optional, List

from app.core.config import SYSTEM_PROMPT_CANARY
from app.security.pii_detector import PII_PATTERNS
from app.security.prompt_guard import get_system_prompt_canary

LABEL_MAP = {
    "EMAIL_ADDRESS": "[EMAIL]",
    "EMAIL": "[EMAIL]",
    "PHONE_NUMBER": "[PHONE]",
    "PHONE": "[PHONE]",
    "IP_ADDRESS": "[IP_ADDRESS]",
    "CREDIT_CARD": "[CREDIT_CARD]",
    "SSN": "[SSN]",
    "US_SSN": "[SSN]",
    "AADHAAR": "[AADHAAR]",
    "API_KEY": "[API_KEY]",
    "LOCATION": "[LOCATION]",
    "ADDRESS": "[ADDRESS]",
    "PAN": "[PAN]",
    "PERSON": "[PERSON]",
    "US_PASSPORT": "[PASSPORT]",
    "US_DRIVER_LICENSE": "[DRIVER_LICENSE]",
}


INTERNAL_CONTEXT_KEYS = frozenset({"api_key", "reserved_tokens", "original_prompt"})
_SAFE_PII_FIELDS = ("type", "score", "source")


def public_security_metadata(security_context: Optional[dict]) -> dict:
    """Return security context safe to expose or cache.

    Drops credentials, rate-limit bookkeeping and the raw prompt, and reduces
    PII detections to type/score/source (no matched values or offsets).
    """
    if not security_context:
        return {}
    result = {k: v for k, v in security_context.items() if k not in INTERNAL_CONTEXT_KEYS}
    if isinstance(result.get("pii_detections"), list):
        result["pii_detections"] = [
            {f: d[f] for f in _SAFE_PII_FIELDS if f in d}
            for d in result["pii_detections"]
            if isinstance(d, dict)
        ]
    return result


def sanitize_text(text: str, detections: Optional[List[dict]] = None) -> str:
    if not text:
        return text

    sanitized_text = text

    # 1. If detections are provided, redact detected spans from end to start
    if detections:
        sorted_detections = sorted(detections, key=lambda x: x.get("start", 0), reverse=True)
        for det in sorted_detections:
            start = det.get("start")
            end = det.get("end")
            entity_type = det.get("type", "")
            replacement = LABEL_MAP.get(entity_type, f"[{entity_type}]")
            if start is not None and end is not None and start < end and end <= len(sanitized_text):
                sanitized_text = sanitized_text[:start] + replacement + sanitized_text[end:]

    # 2. Run regex patterns for any remaining unmasked items
    for pii_type, pattern in PII_PATTERNS.items():
        replacement = LABEL_MAP.get(pii_type, f"[{pii_type}]")
        sanitized_text = re.sub(pattern, replacement, sanitized_text, flags=re.IGNORECASE)

    sanitized_text = html.escape(sanitized_text, quote=False)
    return sanitized_text


def sanitize_response(text: str) -> str:
    sanitized_text = sanitize_text(text)
    canary = get_system_prompt_canary() or SYSTEM_PROMPT_CANARY
    if canary and canary in sanitized_text:
        sanitized_text = sanitized_text.replace(canary, "[REDACTED_SYSTEM_PROMPT]")
    return sanitized_text
