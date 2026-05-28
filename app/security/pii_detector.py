import re

PII_PATTERNS = {
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "PHONE": r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3}\)?[\s-]?)\d{3}[\s-]?\d{4}(?!\d)",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "AADHAAR": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "API_KEY": r"\b(?:sk-[A-Za-z0-9]{16,}|rk_[A-Za-z0-9]{16,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{12,})\b",
    "ADDRESS": r"\b\d{1,5}\s+[A-Za-z0-9#.,'\-\s]{3,80}\s+(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd|way|court|ct)\b",
}

PII_WEIGHTS = {
    "EMAIL": 0.20,
    "PHONE": 0.20,
    "IP_ADDRESS": 0.10,
    "CREDIT_CARD": 0.30,
    "SSN": 0.30,
    "AADHAAR": 0.30,
    "API_KEY": 0.35,
    "ADDRESS": 0.15,
}


def detect_pii(text: str):
    detections = []
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            detections.append(
                {
                    "type": pii_type,
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    return detections