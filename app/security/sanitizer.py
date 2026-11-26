import html
import re
import unicodedata
from typing import Optional, List

from app.core.config import ESCAPE_HTML_RESPONSES, SYSTEM_PROMPT_CANARY, get_canaries
from app.core.context import app_context
from app.security.pii_detector import PII_PATTERNS
from app.security.prompt_guard import get_system_prompt_canary

LABEL_MAP = {
    "EMAIL_ADDRESS": "[EMAIL]",
    "EMAIL": "[EMAIL]",
    "PHONE_NUMBER": "[PHONE]",
    "PHONE": "[PHONE]",
    "IP_ADDRESS": "[IP_ADDRESS]",
    "CREDIT_CARD": "[CREDIT_CARD]",
    "SSN": "[SSN]",
    "US_SSN": "[SSN]",
    "AADHAAR": "[AADHAAR]",
    "API_KEY": "[API_KEY]",
    "LOCATION": "[LOCATION]",
    "ADDRESS": "[ADDRESS]",
    "PAN": "[PAN]",
    "PERSON": "[PERSON]",
    "US_PASSPORT": "[PASSPORT]",
    "US_DRIVER_LICENSE": "[DRIVER_LICENSE]",
}


INTERNAL_CONTEXT_KEYS = frozenset({"api_key", "reserved_tokens", "original_prompt"})
_SAFE_PII_FIELDS = ("type", "score", "source")


def public_security_metadata(security_context: Optional[dict]) -> dict:
    """Return security context safe to expose or cache.

    Drops credentials, rate-limit bookkeeping and the raw prompt, and reduces
    PII detections to type/score/source (no matched values or offsets).
    """
    if not security_context:
        return {}
    result = {k: v for k, v in security_context.items() if k not in INTERNAL_CONTEXT_KEYS}
    if isinstance(result.get("pii_detections"), list):
        result["pii_detections"] = [
            {f: d[f] for f in _SAFE_PII_FIELDS if f in d}
            for d in result["pii_detections"]
            if isinstance(d, dict)
        ]
    return result


def _merge_overlapping(detections: List[dict], text_length: int) -> List[dict]:
    """Collapse overlapping spans into one span covering their union.

    Presidio often reports nested entities (an EMAIL_ADDRESS plus the URL inside it,
    a PHONE_NUMBER plus a DATE_TIME). Replacing those one by one shifted the offsets
    of the outer span and produced corrupted text such as "[URL]]he meeting".
    The label of the widest (then highest-scoring) span in each cluster wins.
    """
    spans = []
    for det in detections:
        start, end = det.get("start"), det.get("end")
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= text_length:
            spans.append(det)
    spans.sort(key=lambda d: (d["start"], -d["end"]))

    merged: List[dict] = []
    for det in spans:
        if merged and det["start"] < merged[-1]["end"]:
            current = merged[-1]
            if (det["end"] - det["start"], det.get("score", 0)) > (current["_width"], current.get("score", 0)):
                current["type"], current["score"], current["_width"] = det.get("type", ""), det.get("score", 0), det["end"] - det["start"]
            current["end"] = max(current["end"], det["end"])
        else:
            merged.append({"start": det["start"], "end": det["end"], "type": det.get("type", ""),
                           "score": det.get("score", 0), "_width": det["end"] - det["start"]})
    return merged


def mask_pii(text: str, detections: Optional[List[dict]] = None) -> str:
    """Replace detected PII with labels such as [EMAIL]. No HTML escaping."""
    if not text:
        return text

    masked = text
    # 1. Replace detected spans right-to-left so earlier offsets stay valid.
    if detections:
        # detect_pii() reports offsets in the NFKC-normalised text. When normalisation
        # changes the text (full-width letters, ligatures), applying those offsets to the
        # original cut the wrong characters, so mask the normalised text instead.
        normalized = unicodedata.normalize("NFKC", masked)
        if normalized != masked:
            masked = normalized
        for det in reversed(_merge_overlapping(detections, len(masked))):
            replacement = LABEL_MAP.get(det["type"], f"[{det['type']}]")
            masked = masked[:det["start"]] + replacement + masked[det["end"]:]

    # 2. Regex pass for anything the detectors missed.
    for pii_type, pattern in PII_PATTERNS.items():
        replacement = LABEL_MAP.get(pii_type, f"[{pii_type}]")
        masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
    return masked


def sanitize_text(text: str, detections: Optional[List[dict]] = None) -> str:
    """Mask PII in a prompt. No HTML escaping: the model must see code such as
    ``a < b`` as written, and escaping here was the first of several layers that
    produced output like ``&amp;lt;br&amp;gt;``."""
    if not text:
        return text
    return mask_pii(text, detections)


def sanitize_response(text: str) -> str:
    """Mask PII and the system-prompt canary in model output.

    HTML escaping is opt-in (ESCAPE_HTML_RESPONSES) for clients that inject responses
    into HTML unescaped. It is idempotent, so text that was already escaped (for
    example, read back from the cache) is never escaped twice.
    """
    if not text:
        return text
    sanitized_text = _redact_plain(text)
    if ESCAPE_HTML_RESPONSES:
        sanitized_text = html.escape(html.unescape(sanitized_text), quote=False)
    return sanitized_text


def sanitize_tool_calls(tool_calls) -> None:
    """Redact PII, secrets and canaries in model-generated tool-call arguments, in place.

    Arguments are JSON strings; the masks ("[EMAIL]") contain no quotes or braces, so
    valid JSON stays valid. Without this, output redaction covered only message text
    and a model could pass a leaked key or canary straight into a tool call.
    """
    if not isinstance(tool_calls, list):
        return
    for call in tool_calls:
        function = call.get("function") if isinstance(call, dict) else None
        if isinstance(function, dict) and isinstance(function.get("arguments"), str):
            # No HTML escaping inside JSON arguments.
            function["arguments"] = _redact_plain(function["arguments"])


def _redact_plain(text: str) -> str:
    """PII/secret masking plus redaction of the global and the current app's canary."""
    if not text:
        return text
    redacted = mask_pii(text)
    canaries = get_canaries(app_context.get())
    global_canary = get_system_prompt_canary() or SYSTEM_PROMPT_CANARY
    if global_canary and global_canary not in canaries:
        canaries.append(global_canary)
    for canary in canaries:
        if canary and canary in redacted:
            redacted = redacted.replace(canary, "[REDACTED_SYSTEM_PROMPT]")
    return redacted
