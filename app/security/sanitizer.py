import html
import re

from app.core.config import SYSTEM_PROMPT_CANARY
from app.security.pii_detector import PII_PATTERNS
from app.security.prompt_guard import get_system_prompt_canary

SANITIZATION_LABELS = {
    "EMAIL": "[EMAIL]",
    "PHONE": "[PHONE]",
    "IP_ADDRESS": "[IP_ADDRESS]",
    "CREDIT_CARD": "[CREDIT_CARD]",
    "SSN": "[SSN]",
    "AADHAAR": "[AADHAAR]",
    "API_KEY": "[API_KEY]",
    "ADDRESS": "[ADDRESS]",
}


def sanitize_text(text: str):
    sanitized_text = text
    for pii_type, pattern in PII_PATTERNS.items():
        replacement = SANITIZATION_LABELS[pii_type]
        sanitized_text = re.sub(pattern, replacement, sanitized_text, flags=re.IGNORECASE)

    sanitized_text = html.escape(sanitized_text, quote=False)
    return sanitized_text


def sanitize_response(text: str):
    sanitized_text = sanitize_text(text)
    canary = get_system_prompt_canary() or SYSTEM_PROMPT_CANARY
    if canary and canary in sanitized_text:
        sanitized_text = sanitized_text.replace(canary, "[REDACTED_SYSTEM_PROMPT]")
    return sanitized_text
