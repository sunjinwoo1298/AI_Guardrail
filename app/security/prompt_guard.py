import hashlib
import html
import re
import threading
import time
from collections import OrderedDict
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
from app.core.config import get_app_policy
from app.core.context import app_context
from app.core.logger import logger

# Regex tripwires block immediately, before the ML classifier or the verifier. They cover
# attack styles the Llama Prompt Guard 2 verifier scores as safe (system-prompt
# extraction, authority claims, instructions planted in documents), measured with
# load_test/security_eval.py. Matched against lower-cased, whitespace-normalised text.
_LEAK_VERB = r"(?:print|reveal|show|repeat|output|display|translate|quote|dump|leak|summari[sz]e|write out|tell me|give me|list)"
_HIDDEN_TEXT = r"(?:system|initial|hidden|original|developer|confidential|secret)\s+(?:prompt|instructions?|message|rules|configuration)"

INJECTION_PATTERNS = [
    r"ignore (?:all|previous|any) instructions",
    r"(?:disregard|forget|ignore) (?:all |any )?(?:the |your )?(?:previous |earlier |above |prior )?(?:rules|instructions|guidelines)",
    r"you are now (?:in )?admin(?:istrator)?",
    r"system override",
    r"bypass safety",
    r"act as administrator",
    # system-prompt / hidden-instruction extraction
    rf"\b{_LEAK_VERB}\b[^.?!\n]{{0,40}}\b{_HIDDEN_TEXT}\b",
    r"\b(?:repeat|print|output|copy)\b[^.?!\n]{0,20}\b(?:words|text|everything|instructions)\s+(?:above|before this)\b",
    r"\b(?:told|instructed|asked)\s+(?:you\s+)?(?:to\s+)?never\s+(?:to\s+)?(?:reveal|share|disclose)\b",
    # switching safety off / jailbreak personas
    r"\b(?:disable|turn off|deactivate|remove|bypass|switch off)\s+(?:all\s+)?(?:of\s+)?your\s+(?:content\s+)?(?:filter(?:s|ing)?|safety\b|guardrails|restrictions|guidelines)",
    r"\b(?:disable|turn off|deactivate)\b[^.?!\n]{0,30}\bfor this (?:session|conversation|chat)\b",
    r"\b(?:safety|content) (?:checks|filters?|filtering) (?:are|is) (?:now )?(?:off|disabled)\b",
    r"\bjailbr(?:oken|eak)\b",
    r"\bdeveloper mode\b",
    r"\b(?:answer|respond|reply)\w*\b[^.?!\n]{0,20}\bwithout (?:any )?(?:restrictions|limits|filters|guidelines)\b",
    r"\bwith no (?:content )?(?:policy|policies|guidelines|restrictions)\b",
    # instructions planted in documents / tool results (indirect injection)
    r"\b(?:ai|assistant|model|llm)\b[^.?!\n]{0,30}\b(?:reading|summari[sz]ing|processing|parsing) this\b",
    r"\bif you are an? (?:ai|llm|language model|assistant|ai model)\b",
    r"\b(?:forward|send|email|upload|exfiltrate)\b[^.?!\n]{0,30}\b(?:chat|conversation) history\b",
]

# Chat-template / role delimiters used to fake a system or assistant turn. Matched on the
# raw text. (Triple backticks and triple quotes were removed: they are ordinary code
# blocks and docstrings, and blocked every developer prompt containing code.)
STRUCTURAL_PATTERNS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|(?:system|assistant|user)\|>",
    r"\[system\]",
    r"\[assistant\]",
    r"\[developer\]",
    r"\[inst\]",
    r"<<sys>>",
    r"(?:^|\n)\s*#{2,}\s*system\s*:",
    r"end of (?:user )?(?:input|prompt)",
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


VERIFIER_CACHE_TTL_SECONDS = 3600
VERIFIER_CACHE_MAX_ENTRIES = 10_000
VERIFIER_FAILURE_PAUSE_SECONDS = 30
_verifier_cache: "OrderedDict[str, tuple]" = OrderedDict()
_verifier_lock = threading.Lock()
_verifier_state = {"paused_until": 0.0}


def verify_injection(text: str) -> Optional[float]:
    """Second opinion from Llama Prompt Guard 2 (served by Groq): probability that
    ``text`` is a prompt injection, or None if the verifier is off or unreachable
    (the caller then keeps the local classifier's verdict, i.e. fails closed).

    Measured on this project's cases: harmless prompts the local model flagged scored
    < 0.005; direct, role-play and tool-result injections scored > 0.99.
    """
    # Global default, overridable per app: APP_POLICIES {"app": {"injection_verifier": true}}
    enabled = get_app_policy(app_context.get()).get("injection_verifier", INJECTION_VERIFIER_ENABLED)
    if not enabled or not GROQ_API_KEY:
        return None

    # Same text -> same verdict. Without this cache a repeated prompt called the verifier
    # on every request, exhausted Groq's rate limit under load (429) and then got
    # blocked because the verifier was "unavailable".
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _verifier_lock:
        cached = _verifier_cache.get(key)
        if cached is not None and now - cached[1] < VERIFIER_CACHE_TTL_SECONDS:
            _verifier_cache.move_to_end(key)
            return cached[0]
        if now < _verifier_state["paused_until"]:
            return None  # recently failing: don't hammer the API; caller fails closed
    try:
        import httpx

        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json={"model": INJECTION_VERIFIER_MODEL, "messages": [{"role": "user", "content": text}]},
            timeout=INJECTION_VERIFIER_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        score = float(response.json()["choices"][0]["message"]["content"].strip())
    except Exception as exc:
        with _verifier_lock:
            _verifier_state["paused_until"] = time.monotonic() + VERIFIER_FAILURE_PAUSE_SECONDS
        logger.warning(f"Injection verifier unavailable, keeping classifier verdict: {exc!r}")
        return None
    with _verifier_lock:
        _verifier_cache[key] = (score, now)
        _verifier_cache.move_to_end(key)
        while len(_verifier_cache) > VERIFIER_CACHE_MAX_ENTRIES:
            _verifier_cache.popitem(last=False)
    return score


def detect_prompt_injection(text: str):
    return fast_tripwire(text)


def get_system_prompt_canary() -> str:
    return SYSTEM_PROMPT_CANARY
