import hashlib
from typing import List, Tuple

from app.core.config import (
    ALLOW_EMAILS,
    ALLOW_PHONE_NUMBERS,
    BEHAVIOR_RISK_RATE_THRESHOLD,
    BEHAVIOR_RISK_WINDOW_SECONDS,
    BLOCK_HIGH_RISK_PROMPTS,
    BLOCK_PROMPT_INJECTION,
    MAX_BEHAVIOR_RISK_SCORE,
    MAX_RISK_SCORE,
)
from app.core.config import REDIS_URL
from app.core.logger import logger
from app.observability.metrics import record_security_event, record_security_risk
from app.observability.tracing import trace
from app.security.pii_detector import PII_WEIGHTS, detect_pii
from app.security.prompt_guard import score_prompt_injection
try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

_redis_client = None


def _get_redis_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if redis is None:
        return None
    try:
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
    except Exception:
        _redis_client = None
    return _redis_client


def _behavior_risk(prompt: str) -> Tuple[float, dict]:
    client = _get_redis_client()
    if client is None:
        return 0.0, {"behavior_count": 0, "behavior_risk": 0.0}

    normalized = " ".join(prompt.strip().split()).lower()
    fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    key = f"ai_proxy:prompt_probe:{fingerprint}"
    try:
        count = client.incr(key)
        client.expire(key, BEHAVIOR_RISK_WINDOW_SECONDS)
        # Clamp the score so repeated probing raises risk without dominating everything.
        behavior_risk = min(0.35, max(0.0, (count - 1) / max(1, BEHAVIOR_RISK_RATE_THRESHOLD) * 0.12))
        return behavior_risk, {"behavior_count": count, "behavior_risk": behavior_risk}
    except Exception as exc:
        logger.warning(f"Behavior-risk tracking unavailable: {exc}")
        return 0.0, {"behavior_count": 0, "behavior_risk": 0.0}


def calculate_risk_score(text: str) -> Tuple[float, list, list]:
    tracer = trace.get_tracer("ai_guardrail_proxy") if trace else None
    span_ctx = tracer.start_as_current_span("security.risk_engine") if tracer else None
    if span_ctx:
        span_ctx.__enter__()
    try:
        pii_detections = detect_pii(text)
        injection_result = score_prompt_injection(text)
        injection_detections = injection_result.get("signals", [])

        risk_score = 0.0
        pii_types = set()

        for detection in pii_detections:
            pii_type = detection["type"]
            pii_types.add(pii_type)
            risk_score += float(detection.get("score", PII_WEIGHTS.get(pii_type, 0.0)))

        injection_confidence = float(injection_result.get("confidence", 0.0))
        if injection_result.get("is_injection"):
            risk_score += injection_confidence

        behavior_risk, behavior_meta = _behavior_risk(text)
        risk_score += behavior_risk

        if not ALLOW_EMAILS and "EMAIL" in pii_types:
            risk_score += 0.05
        if not ALLOW_PHONE_NUMBERS and "PHONE" in pii_types:
            risk_score += 0.05

        risk_score = min(risk_score, 1.0)

        if span_ctx:
            span_ctx.set_attribute("risk_score", risk_score)
            span_ctx.set_attribute("pii_types", ",".join(sorted(pii_types)) if pii_types else "none")
            span_ctx.set_attribute("injection_confidence", injection_confidence)
            span_ctx.set_attribute("behavior_risk", behavior_meta["behavior_risk"])
            span_ctx.set_attribute("behavior_count", behavior_meta["behavior_count"])

        record_security_risk(risk_score)
        if pii_detections:
            record_security_event("pii", "detected")
        if injection_result.get("is_injection"):
            record_security_event("prompt_injection", "detected")

        return risk_score, pii_detections, injection_detections
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)


def should_block_prompt(risk_score: float, injection_detections: List[str]):
    if BLOCK_PROMPT_INJECTION and injection_detections:
        return True

    if risk_score >= MAX_BEHAVIOR_RISK_SCORE and injection_detections:
        return True

    if BLOCK_HIGH_RISK_PROMPTS and risk_score >= MAX_RISK_SCORE:
        return True

    return False
