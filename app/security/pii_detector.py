import re
import unicodedata
from typing import List

from app.core.logger import logger

PII_PATTERNS = {
    "API_KEY": r"\b(?:sk-[A-Za-z0-9]{16,}|rk_[A-Za-z0-9]{16,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{12,})\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
}

PII_WEIGHTS = {
    "EMAIL_ADDRESS": 0.20,
    "PHONE_NUMBER": 0.20,
    "IP_ADDRESS": 0.10,
    "CREDIT_CARD": 0.30,
    "SSN": 0.30,
    "AADHAAR": 0.30,
    "API_KEY": 0.35,
    "PAN": 0.20,
    "LOCATION": 0.15,
}

_analyzer = None


def normalize_text(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _get_analyzer():
    global _analyzer
    if _analyzer is not None:
        return _analyzer
    try:
        from presidio_analyzer import AnalyzerEngine

        _analyzer = AnalyzerEngine()
    except Exception as exc:
        logger.warning(f"Presidio unavailable, using regex fallback: {exc}")
        _analyzer = None
    return _analyzer


def _regex_fallback(text: str):
    detections = []
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            detections.append(
                {
                    "type": pii_type,
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0,
                    "source": "regex",
                }
            )
    return detections


def detect_pii(text: str):
    normalized = normalize_text(text)
    analyzer = _get_analyzer()
    if analyzer is None:
        return _regex_fallback(normalized)

    try:
        results = analyzer.analyze(text=normalized, language="en")
        detections = [
            {
                "type": result.entity_type,
                "value": normalized[result.start:result.end],
                "start": result.start,
                "end": result.end,
                "score": float(result.score),
                "source": "presidio",
            }
            for result in results
        ]
        return detections
    except Exception as exc:
        logger.warning(f"Presidio analysis failed, using regex fallback: {exc}")
        return _regex_fallback(normalized)
