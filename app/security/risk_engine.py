import hashlib
import re
from typing import List, Tuple

from app.core.config import (
    ALLOW_EMAILS,
    ALLOW_PHONE_NUMBERS,
    BEHAVIOR_RISK_RATE_THRESHOLD,
    BEHAVIOR_RISK_WINDOW_SECONDS,
    BLOCK_HIGH_RISK_PROMPTS,
    BLOCK_PROMPT_INJECTION,
    ENABLE_PII_MASKING,
    MASKED_PII_RISK_CAP,
    MAX_BEHAVIOR_RISK_SCORE,
    MAX_RISK_SCORE,
)
from app.core.context import app_context
from app.core.logger import logger
from app.core.redis_client import get_redis, reset_redis
from app.observability.metrics import record_security_event, record_security_risk
from app.observability.tracing import trace
from app.security.pii_detector import PII_WEIGHTS, detect_pii
from app.security.prompt_guard import score_prompt_injection
from app.security.sanitizer import mask_pii

# "my api key is [API_KEY]", "secret token: [API_KEY]", bare "[API_KEY]".
# The injection classifier scores any mention of sharing a key as an attack
# (~1.0 even after masking), so the classifier sees the prompt without that phrase.
# Only this fixed phrase is removed; the rest of the prompt is classified as-is.
_CREDENTIAL_PHRASE = re.compile(
    r"(?:\b(?:my|the|a|an|our|your|this|secret|api|access|private|auth)\s+)*"
    r"\b(?:key|token|secret|password|credential)s?\s*(?:is|was|=|:)?\s*\[API_KEY\]"
    r"|\[API_KEY\]",
    re.IGNORECASE,
)


def _injection_allow_patterns() -> list:
    from app.core.config import get_app_policy

    injection = get_app_policy(app_context.get()).get("injection") or {}
    return list(injection.get("allow_patterns") or [])


def _strip_allowed(text: str, patterns: list) -> str:
    for pattern in patterns:
        try:
            text = re.sub(pattern, " ", text, flags=re.IGNORECASE)
        except re.error:
            continue  # validated on write; never fail a scan over one pattern
    return text


def _classifier_view(text: str, pii_detections: list) -> str:
    masked = mask_pii(text, pii_detections)
    return re.sub(r"[ \t]{2,}", " ", _CREDENTIAL_PHRASE.sub("", masked))
try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

_redis_client = None


def _get_redis_client():
    return get_redis()


def _behavior_risk(prompt: str) -> Tuple[float, dict]:
    client = _get_redis_client()
    if client is None:
        return 0.0, {"behavior_count": 0, "behavior_risk": 0.0}

    normalized = " ".join(prompt.strip().split()).lower()
    fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    # Scoped per application: the counter used to be global, so one tenant repeating a
    # prompt raised the risk score of every other tenant sending the same text.
    tenant = hashlib.sha256(app_context.get().encode("utf-8")).hexdigest()[:12]
    key = f"ai_proxy:prompt_probe:{tenant}:{fingerprint}"
    try:
        count = client.incr(key)
        client.expire(key, BEHAVIOR_RISK_WINDOW_SECONDS)
        # Clamp the score so repeated probing raises risk without dominating everything.
        behavior_risk = min(0.35, max(0.0, (count - 1) / max(1, BEHAVIOR_RISK_RATE_THRESHOLD) * 0.12))
        return behavior_risk, {"behavior_count": count, "behavior_risk": behavior_risk}
    except Exception as exc:
        reset_redis(exc)
        logger.warning(f"Behavior-risk tracking unavailable: {exc}")
        return 0.0, {"behavior_count": 0, "behavior_risk": 0.0}


def calculate_risk_score(text: str) -> Tuple[float, list, list]:
    tracer = trace.get_tracer("ai_guardrail_proxy") if trace else None
    span_ctx = tracer.start_as_current_span("security.risk_engine") if tracer else None
    # start_as_current_span() returns a context manager; the span is what __enter__
    # returns. Calling set_attribute on the manager raised, which made the security
    # middleware fail open.
    span = span_ctx.__enter__() if span_ctx else None
    try:
        pii_detections = detect_pii(text)
        # A project's injection.allow_patterns (known false positives) are removed from
        # what the injection detectors see; PII detection still reads the full text.
        allow_patterns = _injection_allow_patterns()
        injection_text = _strip_allowed(text, allow_patterns)
        classifier_text = None
        if pii_detections:
            classifier_text = _strip_allowed(_classifier_view(text, pii_detections), allow_patterns)
        elif injection_text != text:
            classifier_text = injection_text
        injection_result = score_prompt_injection(injection_text, classifier_text=classifier_text)
        injection_detections = injection_result.get("signals", [])

        pii_risk = 0.0
        pii_types = set()

        for detection in pii_detections:
            pii_type = detection["type"]
            pii_types.add(pii_type)
            pii_risk += float(PII_WEIGHTS.get(pii_type, 0.20))

        if not ALLOW_EMAILS and pii_types & {"EMAIL", "EMAIL_ADDRESS"}:
            pii_risk += 0.05
        if not ALLOW_PHONE_NUMBERS and pii_types & {"PHONE", "PHONE_NUMBER"}:
            pii_risk += 0.05

        # When masking is on, PII never reaches the model, so PII alone must not push a
        # prompt over the block threshold; it still adds to injection/behaviour risk.
        if ENABLE_PII_MASKING:
            pii_risk = min(pii_risk, MASKED_PII_RISK_CAP)

        risk_score = pii_risk

        injection_confidence = float(injection_result.get("confidence", 0.0))
        if injection_result.get("is_injection"):
            risk_score += injection_confidence

        behavior_risk, behavior_meta = _behavior_risk(text)
        risk_score += behavior_risk

        risk_score = min(risk_score, 1.0)

        if span is not None and hasattr(span, "set_attribute"):
            span.set_attribute("risk_score", risk_score)
            span.set_attribute("pii_types", ",".join(sorted(pii_types)) if pii_types else "none")
            span.set_attribute("injection_confidence", injection_confidence)
            span.set_attribute("behavior_risk", behavior_meta["behavior_risk"])
            span.set_attribute("behavior_count", behavior_meta["behavior_count"])

        record_security_risk(risk_score)
        if pii_detections:
            record_security_event("pii", "detected")
        if injection_result.get("is_injection") or injection_detections:
            record_security_event("prompt_injection", "detected")

        return risk_score, pii_detections, injection_detections
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)


def should_block_prompt(risk_score: float, injection_detections: List[str], max_risk_score: float = None):
    """max_risk_score overrides MAX_RISK_SCORE for one app (APP_POLICIES)."""
    threshold = MAX_RISK_SCORE if max_risk_score is None else max_risk_score
    if BLOCK_PROMPT_INJECTION and injection_detections:
        return True

    if risk_score >= MAX_BEHAVIOR_RISK_SCORE and injection_detections:
        return True

    if BLOCK_HIGH_RISK_PROMPTS and risk_score >= threshold:
        return True

    return False
