from typing import List, Tuple

from app.core.config import (
    ALLOW_EMAILS,
    ALLOW_PHONE_NUMBERS,
    BLOCK_HIGH_RISK_PROMPTS,
    BLOCK_PROMPT_INJECTION,
    MAX_RISK_SCORE,
)
from app.security.pii_detector import PII_WEIGHTS, detect_pii
from app.security.prompt_guard import INJECTION_WEIGHTS, detect_prompt_injection


def calculate_risk_score(text: str) -> Tuple[float, list, list]:
    pii_detections = detect_pii(text)
    injection_detections = detect_prompt_injection(text)

    risk_score = 0.0
    pii_types = set()

    for detection in pii_detections:
        pii_type = detection["type"]
        pii_types.add(pii_type)
        risk_score += PII_WEIGHTS.get(pii_type, 0.0)

    if injection_detections:
        risk_score += 0.7
        for pattern in injection_detections:
            lowered_pattern = pattern.lower()
            if "ignore" in lowered_pattern:
                risk_score += INJECTION_WEIGHTS["ignore"]
            if "reveal" in lowered_pattern or "show" in lowered_pattern:
                risk_score += INJECTION_WEIGHTS["reveal"]
            if "admin" in lowered_pattern:
                risk_score += INJECTION_WEIGHTS["admin"]
            if "override" in lowered_pattern:
                risk_score += INJECTION_WEIGHTS["override"]
            if "bypass" in lowered_pattern:
                risk_score += INJECTION_WEIGHTS["bypass"]

    if not ALLOW_EMAILS and "EMAIL" in pii_types:
        risk_score += 0.05
    if not ALLOW_PHONE_NUMBERS and "PHONE" in pii_types:
        risk_score += 0.05

    return min(risk_score, 1.0), pii_detections, injection_detections


def should_block_prompt(risk_score: float, injection_detections: List[str]):
    if BLOCK_PROMPT_INJECTION and injection_detections:
        return True

    if BLOCK_HIGH_RISK_PROMPTS and risk_score >= MAX_RISK_SCORE:
        return True

    return False
