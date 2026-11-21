import html
import re
import threading
import unicodedata
from typing import Dict, List, Optional

from app.core.config import (
    GROQ_API_KEY,
    INJECTION_VERIFIER_ENABLED,
    INJECTION_VERIFIER_MODEL,
    INJECTION_VERIFIER_THRESHOLD,
    INJECTION_VERIFIER_TIMEOUT_SECONDS,
    PROMPT_INJECTION_MODEL_NAME,
    SYSTEM_PROMPT_CANARY,
)
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
_classifier_lock = threading.Lock()


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
    with _classifier_lock:
        if _classifier is not None:
            return _classifier
        try:
            from app.core.onnx_models import OnnxTextClassifier

            _classifier = OnnxTextClassifier(PROMPT_INJECTION_MODEL_NAME)
        except Exception as exc:
            logger.warning(f"Prompt injection classifier unavailable, falling back to tripwire only: {exc}")
            _classifier = None
    return _classifier


def score_prompt_injection(text: str, classifier_text: Optional[str] = None) -> Dict[str, object]:
    """Tripwires always run on the original prompt. The ML classifier can be given a
    PII-masked copy (``classifier_text``) so that shared secrets don't read as
    injection attempts; the rest of the prompt is classified unchanged."""
    normalized = normalize_text(text)
    tripwire_matches = fast_tripwire(normalized)
    classifier = _get_classifier()
    classifier_input = normalize_text(classifier_text) if classifier_text is not None else normalized

    if classifier is None:
        return {
            "is_injection": bool(tripwire_matches),
            "confidence": 1.0 if tripwire_matches else 0.0,
            "signals": tripwire_matches,
            "source": "tripwire",
        }

    try:
        raw_output = classifier(classifier_input)
        if isinstance(raw_output, list) and raw_output and isinstance(raw_output[0], list):
            raw_output = raw_output[0]

        if isinstance(raw_output, list) and raw_output:
            injection_dict = next(
                (d for d in raw_output if isinstance(d, dict) and str(d.get("label", "")).upper() in {"INJECTION", "LABEL_1", "YES"}),
                None
            )
            result = injection_dict if injection_dict else (raw_output[0] if isinstance(raw_output[0], dict) else {})
        elif isinstance(raw_output, dict):
            result = raw_output
        else:
            result = {}

        label = str(result.get("label", "")).upper()
        score = float(result.get("score", 0.0))
        # `confidence` is the probability that the prompt is an injection. The INJECTION
        # entry is always selected above, so the label alone is not a verdict: it used to
        # flag every prompt (even at 0.2%) as an injection and inflate the metrics.
        is_injection_label = label in {"INJECTION", "LABEL_1", "YES"}
        confidence = score if is_injection_label else 1.0 - score
        is_injection = confidence >= 0.5
        if tripwire_matches and not is_injection:
            confidence = min(1.0, confidence + 0.15)
            is_injection = confidence >= 0.5
        source = "classifier"

        # The local DeBERTa model flags many harmless command-style prompts ("Reply with
        # exactly ...", "Print this ...") at ~1.0. When it is the ONLY signal (no regex
        # tripwire), ask a second, purpose-built model before blocking.
        if is_injection and not tripwire_matches:
            verifier_score = verify_injection(classifier_input)
            if verifier_score is not None:
                source = "classifier+verifier"
                if verifier_score < INJECTION_VERIFIER_THRESHOLD:
                    logger.info(
                        f"Injection verifier overruled classifier: classifier={confidence:.3f} verifier={verifier_score:.4f}"
                    )
                    is_injection, confidence = False, verifier_score
        return {
            "is_injection": is_injection,
            "confidence": confidence,
            "signals": tripwire_matches,
            "label": label,
            "source": source,
        }
    except Exception as exc:
        logger.warning(f"Prompt injection classifier failed, using tripwire only: {exc}")
        return {
            "is_injection": bool(tripwire_matches),
            "confidence": 1.0 if tripwire_matches else 0.0,
            "signals": tripwire_matches,
            "source": "tripwire",
        }


def verify_injection(text: str) -> Optional[float]:
    """Second opinion from Llama Prompt Guard 2 (served by Groq): probability that
    ``text`` is a prompt injection, or None if the verifier is off or unreachable
    (the caller then keeps the local classifier's verdict, i.e. fails closed).

    Measured on this project's cases: harmless prompts the local model flagged scored
    < 0.005; direct, role-play and tool-result injections scored > 0.99.
    """
    if not INJECTION_VERIFIER_ENABLED or not GROQ_API_KEY:
        return None
    try:
        import httpx

        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json={"model": INJECTION_VERIFIER_MODEL, "messages": [{"role": "user", "content": text}]},
            timeout=INJECTION_VERIFIER_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return float(response.json()["choices"][0]["message"]["content"].strip())
    except Exception as exc:
        logger.warning(f"Injection verifier unavailable, keeping classifier verdict: {exc!r}")
        return None


def detect_prompt_injection(text: str):
    return fast_tripwire(text)


def get_system_prompt_canary() -> str:
    return SYSTEM_PROMPT_CANARY
