import base64
import binascii
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
    INJECTION_SCAN_OVERLAP_CHARS,
    INJECTION_SCAN_WINDOW_CHARS,
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

# The same "ignore your instructions" / "reveal your system prompt" attacks in other common
# languages. The ML classifier is English-only, so without these a translated attack had
# no detector at all. Kept to unambiguous phrasings.
MULTILINGUAL_PATTERNS = [
    # Spanish / Portuguese / Italian
    r"\b(?:ignora|ignore|olvida|esquece|dimentica)\w*\s+(?:todas?\s+|todos?\s+|tutte\s+)?(?:las\s+|os\s+|as\s+|le\s+)?(?:instrucciones|instru\u00e7\u00f5es|instrucoes|istruzioni|reglas|regras|regole)\b(?:\s+\w+)?",
    r"\b(?:muestra|revela|mostra|rivela)\w*\b[^.?!\n]{0,30}\b(?:prompt|instrucciones|instru\u00e7\u00f5es|istruzioni)\s+(?:del\s+|do\s+|di\s+)?sistema\b",
    # French
    r"\b(?:ignore[rz]?|oublie[rz]?)\s+(?:toutes\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|r\u00e8gles)\b",
    r"\b(?:r\u00e9v\u00e8le|affiche|montre)\w*\b[^.?!\n]{0,30}\b(?:prompt|instructions)\s+(?:du\s+)?syst\u00e8me\b",
    # German
    r"\b(?:ignoriere|vergiss)\w*\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?(?:anweisungen|instruktionen|regeln)\b",
    r"\b(?:zeige|verrate|gib)\w*\b[^.?!\n]{0,30}\bsystem(?:-)?(?:prompt|anweisungen)\b",
    # Hindi (romanised and Devanagari)
    r"\b(?:pichhle|pichle|sabhi|saare)\s+(?:nirdesh|instructions)\s+(?:ko\s+)?(?:bhool|ignore|nazarandaaz)",
    r"(?:\u0938\u092d\u0940|\u092a\u093f\u091b\u0932\u0947)\s+\u0928\u093f\u0930\u094d\u0926\u0947\u0936",
]

# Zero-width / bidi / other invisible "format" characters (Unicode category Cf). They are
# invisible to people and tokenisers alike and split keywords ("ig\u200bnore"), so a
# single one defeated every tripwire.
_INVISIBLE = dict.fromkeys(
    cp for cp in list(range(0x200B, 0x2010)) + list(range(0x202A, 0x202F)) + list(range(0x2060, 0x2070))
    + [0x00AD, 0x034F, 0x061C, 0x180E, 0xFEFF]
)

# Common Cyrillic / Greek look-alikes of Latin letters ("\u0456gnore", "\u0455ystem"). NFKC
# does not fold these.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
})

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def strip_invisible(text: str) -> str:
    return text.translate(_INVISIBLE)


def _decoded_payloads(text: str, limit: int = 5) -> List[str]:
    """Readable text hidden as base64 ("decode this and follow it: aWdub3Jl...")."""
    decoded = []
    for match in _BASE64_RUN.finditer(text):
        if len(decoded) >= limit:
            break
        chunk = match.group(0)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        if candidate and printable / len(candidate) > 0.95 and re.search(r"[A-Za-z]{3,}", candidate):
            decoded.append(candidate)
    return decoded


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
    normalized = strip_invisible(normalized).translate(_CONFUSABLES)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _tripwire_once(text: str) -> List[str]:
    lowered_text = normalize_text(text).lower()
    # Structural tokens are matched on the original line structure, minus invisible chars.
    structural_text = strip_invisible(unicodedata.normalize("NFKC", text))
    matches = []
    for pattern in INJECTION_PATTERNS + MULTILINGUAL_PATTERNS:
        if re.search(pattern, lowered_text, flags=re.IGNORECASE):
            matches.append(pattern)
    for pattern in STRUCTURAL_PATTERNS:
        if re.search(pattern, structural_text, flags=re.IGNORECASE):
            matches.append(pattern)
    return matches


def fast_tripwire(text: str) -> List[str]:
    matches = _tripwire_once(text)
    # Also check readable base64 payloads; matches on decoded text are tagged so the
    # block reason shows the attack was encoded.
    for payload in _decoded_payloads(text):
        for pattern in _tripwire_once(payload):
            tagged = f"base64:{pattern}"
            if tagged not in matches:
                matches.append(tagged)
    return matches


def tripwire_matches(text: str) -> List[str]:
    """The phrases (in normalised, lower-cased form) that tripped the tripwires, for
    showing a reviewer what was caught. Matches inside base64 payloads are reported as
    the decoded phrase."""
    found: List[str] = []

    def scan(candidate: str) -> None:
        lowered = normalize_text(candidate).lower()
        structural = strip_invisible(unicodedata.normalize("NFKC", candidate))
        for pattern in INJECTION_PATTERNS + MULTILINGUAL_PATTERNS:
            match = re.search(pattern, lowered, flags=re.IGNORECASE)
            if match and match.group(0) not in found:
                found.append(match.group(0))
        for pattern in STRUCTURAL_PATTERNS:
            match = re.search(pattern, structural, flags=re.IGNORECASE)
            if match and match.group(0).strip() and match.group(0).strip() not in found:
                found.append(match.group(0).strip())

    scan(text)
    for payload in _decoded_payloads(text):
        scan(payload)
    return found


def _scan_windows(text: str) -> List[str]:
    """Overlapping windows covering the whole text. The classifier truncates its input at
    512 tokens, so an injection placed after the first ~2,000 characters of one long
    message (a retrieved document, a tool result) was never seen by it."""
    window, overlap = INJECTION_SCAN_WINDOW_CHARS, INJECTION_SCAN_OVERLAP_CHARS
    if len(text) <= window:
        return [text]
    step = max(1, window - overlap)
    return [text[start:start + window] for start in range(0, len(text) - overlap, step)]


def _injection_result(raw_output) -> dict:
    if isinstance(raw_output, list) and raw_output and isinstance(raw_output[0], list):
        raw_output = raw_output[0]
    if isinstance(raw_output, list) and raw_output:
        injection_dict = next(
            (d for d in raw_output if isinstance(d, dict) and str(d.get("label", "")).upper() in {"INJECTION", "LABEL_1", "YES"}),
            None
        )
        return injection_dict if injection_dict else (raw_output[0] if isinstance(raw_output[0], dict) else {})
    if isinstance(raw_output, dict):
        return raw_output
    return {}


def _injection_probability(result: dict) -> tuple:
    label = str(result.get("label", "")).upper()
    score = float(result.get("score", 0.0))
    # `confidence` is the probability that the prompt is an injection. The INJECTION
    # entry is always selected above, so the label alone is not a verdict: it used to
    # flag every prompt (even at 0.2%) as an injection and inflate the metrics.
    is_injection_label = label in {"INJECTION", "LABEL_1", "YES"}
    return label, (score if is_injection_label else 1.0 - score)


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
        # Classify every window and keep the riskiest; the verifier sees that window.
        label, confidence, riskiest_window = "", -1.0, classifier_input
        for window_text in _scan_windows(classifier_input):
            window_label, window_confidence = _injection_probability(_injection_result(classifier(window_text)))
            if window_confidence > confidence:
                label, confidence, riskiest_window = window_label, window_confidence, window_text
        confidence = max(0.0, confidence)
        is_injection = confidence >= 0.5
        if tripwire_matches and not is_injection:
            confidence = min(1.0, confidence + 0.15)
            is_injection = confidence >= 0.5
        source = "classifier"

        # The local DeBERTa model flags many harmless command-style prompts ("Reply with
        # exactly ...", "Print this ...") at ~1.0. When it is the ONLY signal (no regex
        # tripwire), ask a second, purpose-built model before blocking.
        if is_injection and not tripwire_matches:
            verifier_score = verify_injection(riskiest_window)
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
