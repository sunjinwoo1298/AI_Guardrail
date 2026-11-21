import re
import unicodedata
from typing import List

from app.core.config import PII_ENTITIES
from app.core.logger import logger

PII_PATTERNS = {
    "API_KEY": r"\b(?:sk-[A-Za-z0-9_-]{10,}|rk_[A-Za-z0-9_-]{10,}|gsk_[A-Za-z0-9_-]{10,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{10,})\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "AADHAAR": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
}

PII_WEIGHTS = {
    "EMAIL_ADDRESS": 0.20,
    "EMAIL": 0.20,
    "PHONE_NUMBER": 0.20,
    "PHONE": 0.20,
    "IP_ADDRESS": 0.10,
    "CREDIT_CARD": 0.30,
    "SSN": 0.30,
    "US_SSN": 0.30,
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
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            })
            nlp_engine = provider.create_engine()
            _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        except Exception:
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
    regex_detections = _regex_fallback(normalized)

    if analyzer is None:
        return regex_detections

    try:
        results = [
            r for r in analyzer.analyze(text=normalized, language="en")
            if r.entity_type in PII_ENTITIES
        ]
        presidio_detections = [
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

        # Combine Presidio detections with regex detections (deduplicating overlapping spans)
        all_detections = list(presidio_detections)
        for r_det in regex_detections:
            # check if already covered by presidio
            overlapping = any(
                p["start"] <= r_det["start"] and p["end"] >= r_det["end"]
                for p in presidio_detections
            )
            if not overlapping:
                all_detections.append(r_det)

        return all_detections
    except Exception as exc:
        logger.warning(f"Presidio analysis failed, using regex fallback: {exc}")
        return regex_detections
