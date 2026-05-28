import re

from app.security.pii_detector import PII_PATTERNS

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

    return sanitized_text