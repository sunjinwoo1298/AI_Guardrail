"""Per-project guardrail policy: one validated document, versioned in the control plane.

Every field is optional, and an empty document means "global defaults". The legacy
APP_POLICIES keys (rpm, tpm, allowed_models, max_risk_score, injection_verifier, canary)
are part of this schema, so env-configured apps and control-plane projects share one
code path.

Example::

    {
      "mode": "enforce",                      # or "monitor": log what would be blocked, block nothing
      "rpm": 60, "tpm": 20000,
      "allowed_models": ["groq/*", "openrouter/*:free"],
      "max_risk_score": 0.85,
      "injection": {"action": "block", "verifier": false,
                    "allow_patterns": ["^reply with exactly"]},
      "pii": {"action": "mask", "allow_entities": ["EMAIL_ADDRESS"]},
      "deny": [{"name": "competitors", "keywords": ["acme corp"], "action": "flag"}],
      "cache": {"exact": true, "semantic": false},
      "max_input_chars": 16000,
      "canary": "my-private-canary-token",
      "allow_platform_provider_keys": true
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class PolicyError(ValueError):
    pass


_MAX_PATTERN_LENGTH = 200
# Nested quantifiers such as (a+)+ or (\w*)* make Python's backtracking regex engine take
# exponential time on crafted input (ReDoS). Tenant-supplied patterns run on every
# request, so they are refused.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")


def _check_regex(pattern: str) -> str:
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise ValueError(f"regex longer than {_MAX_PATTERN_LENGTH} characters")
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError(f"regex {pattern!r} has a nested quantifier (risk of catastrophic backtracking)")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
    return pattern


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InjectionPolicy(_Strict):
    action: Literal["block", "flag", "off"] = "block"
    # Llama Prompt Guard 2 second opinion (see INJECTION_VERIFIER_ENABLED).
    verifier: Optional[bool] = None
    # Text matching these is removed before injection scanning: a way to stop known
    # false positives ("reply with exactly ...") without turning detection off.
    allow_patterns: List[str] = Field(default_factory=list, max_length=50)

    @field_validator("allow_patterns")
    @classmethod
    def _patterns(cls, value):
        return [_check_regex(p) for p in value]


class PiiPolicy(_Strict):
    # mask: replace with [EMAIL] etc. (default); block: reject requests containing PII;
    # flag: forward unchanged but record it; off: no PII handling.
    action: Literal["mask", "block", "flag", "off"] = "mask"
    # Entity types this project may send unmasked (e.g. EMAIL_ADDRESS for a CRM assistant).
    allow_entities: List[str] = Field(default_factory=list, max_length=50)

    @field_validator("allow_entities")
    @classmethod
    def _upper(cls, value):
        return [v.strip().upper() for v in value if v.strip()]


class DenyRule(_Strict):
    name: str = Field(min_length=1, max_length=60)
    keywords: List[str] = Field(default_factory=list, max_length=200)
    regex: Optional[str] = None
    action: Literal["block", "flag"] = "block"

    @field_validator("regex")
    @classmethod
    def _regex(cls, value):
        return _check_regex(value) if value else value

    @field_validator("keywords")
    @classmethod
    def _keywords(cls, value):
        cleaned = [k.strip().lower() for k in value if k.strip()]
        if any(len(k) > 200 for k in cleaned):
            raise ValueError("keywords must be at most 200 characters")
        return cleaned

    @model_validator(mode="after")
    def _has_matcher(self):
        if not self.keywords and not self.regex:
            raise ValueError(f"deny rule {self.name!r} needs keywords or a regex")
        return self

    def matches(self, text: str) -> bool:
        lowered = text.lower()
        if any(k in lowered for k in self.keywords):
            return True
        return bool(self.regex and re.search(self.regex, text, flags=re.IGNORECASE))


class CachePolicy(_Strict):
    exact: bool = True
    semantic: bool = True


# --- Phase 2: agent-era controls -----------------------------------------------------------

class ToolRule(_Strict):
    # Tool name or fnmatch pattern ("crm_*").
    name: str = Field(min_length=1, max_length=100)
    # JSON Schema (draft 2020-12) the call's arguments must satisfy.
    arguments_schema: Optional[Dict[str, Any]] = None
    # Regexes that must not match the serialized arguments (e.g. "DROP\\s+TABLE", "rm -rf").
    deny_argument_patterns: List[str] = Field(default_factory=list, max_length=50)

    @field_validator("deny_argument_patterns")
    @classmethod
    def _patterns(cls, value):
        return [_check_regex(p) for p in value]

    @field_validator("arguments_schema")
    @classmethod
    def _schema(cls, value):
        if value is None:
            return value
        try:
            from jsonschema import Draft202012Validator

            Draft202012Validator.check_schema(value)
        except ImportError:  # pragma: no cover - jsonschema is a runtime dependency
            pass
        except Exception as exc:
            raise ValueError(f"invalid JSON schema: {getattr(exc, 'message', exc)}") from exc
        return value


class ToolsPolicy(_Strict):
    """Controls on the tools an agent may declare and the calls the model makes."""

    action: Literal["block", "flag", "off"] = "block"
    # Tool names / fnmatch patterns that may be declared and called. None = any tool.
    allowed: Optional[List[str]] = Field(default=None, max_length=500)
    rules: List[ToolRule] = Field(default_factory=list, max_length=200)

    @property
    def active(self) -> bool:
        return self.action != "off" and (self.allowed is not None or bool(self.rules))


class ExfiltrationPolicy(_Strict):
    """Model output that would leak data when rendered: a markdown / HTML image pointing at
    an outside server loads without a click, so anything in its URL (a summary of the
    conversation, a secret) is sent to that server."""

    # strip: remove the image / neutralise the link (default); flag: record only; off.
    action: Literal["strip", "flag", "off"] = "strip"
    # Domains (and their subdomains) whose images and links are trusted.
    allowed_domains: List[str] = Field(default_factory=list, max_length=200)

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, value):
        return [d.strip().lower().lstrip(".") for d in value if d.strip()]


class SessionPolicy(_Strict):
    """Escalation across an agent session (header x-guardrail-session, or the request's
    ``user`` field): after ``max_events`` flags / blocks within ``window_seconds`` the
    session is blocked for ``block_seconds``. Catches attackers probing one variant at a
    time, which per-request scoring cannot see."""

    enabled: bool = False
    max_events: int = Field(default=3, ge=1, le=1000)
    window_seconds: int = Field(default=900, ge=10, le=86400)
    block_seconds: int = Field(default=900, ge=10, le=86400 * 7)


class MultimodalPolicy(_Strict):
    """Images, audio and files are forwarded without content scanning (no OCR / ASR yet);
    this decides what to do with them."""

    action: Literal["allow", "flag", "block"] = "allow"


class ModerationPolicy(_Strict):
    """Harmful-content classification with Llama Guard (hazard categories S1-S14)."""

    enabled: bool = False
    direction: Literal["input", "output", "both"] = "output"
    action: Literal["block", "flag"] = "block"
    # Only these categories count (e.g. ["S1", "S10"]); empty = all categories.
    categories: List[str] = Field(default_factory=list, max_length=20)
    # When the moderation model is unreachable: open = allow and record, closed = reject.
    fail_mode: Literal["open", "closed"] = "open"

    @field_validator("categories")
    @classmethod
    def _categories(cls, value):
        cleaned = [c.strip().upper() for c in value if c.strip()]
        bad = [c for c in cleaned if not re.fullmatch(r"S(?:[1-9]|1[0-4])", c)]
        if bad:
            raise ValueError(f"unknown moderation categories {bad}; use S1..S14")
        return cleaned


class BudgetPolicy(_Strict):
    """Monthly spend / token caps (UTC calendar month) for the project.

    ``block`` refuses model calls with 429 ``budget_exceeded`` once a cap is reached;
    ``flag`` only records it. Crossing each of ``alert_thresholds`` (fractions of a cap)
    emits one ``budget.threshold`` event per month (audit log and webhooks).
    """

    monthly_usd: Optional[float] = Field(default=None, gt=0)
    monthly_tokens: Optional[int] = Field(default=None, gt=0)
    action: Literal["block", "flag"] = "block"
    alert_thresholds: List[float] = Field(default_factory=lambda: [0.8, 1.0], max_length=10)

    @field_validator("alert_thresholds")
    @classmethod
    def _thresholds(cls, value):
        if any(not 0 < t <= 1.0 for t in value):
            raise ValueError("alert_thresholds must be fractions in (0, 1]")
        return sorted(set(value))

    @property
    def active(self) -> bool:
        return self.monthly_usd is not None or self.monthly_tokens is not None


class McpServer(_Strict):
    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-z0-9][a-z0-9-]*$")
    url: str = Field(min_length=8, max_length=500)
    # Tools that may be listed and called through the gateway. None = all tools.
    allowed_tools: Optional[List[str]] = Field(default=None, max_length=500)
    # Scan tool descriptions for injected instructions ("tool poisoning") and drop them.
    scan_tool_descriptions: bool = True
    # Scan tool results for prompt injection and mask PII before they reach the agent.
    scan_results: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, value):
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("MCP server url must be an http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("MCP server url must not contain credentials; send them per request")
        return value


class Policy(_Strict):
    mode: Literal["enforce", "monitor"] = "enforce"
    rpm: Optional[int] = Field(default=None, gt=0)
    tpm: Optional[int] = Field(default=None, gt=0)
    allowed_models: Optional[List[str]] = None
    max_risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Legacy flat key, kept for APP_POLICIES compatibility; injection.verifier wins.
    injection_verifier: Optional[bool] = None
    injection: InjectionPolicy = Field(default_factory=InjectionPolicy)
    pii: PiiPolicy = Field(default_factory=PiiPolicy)
    deny: List[DenyRule] = Field(default_factory=list, max_length=50)
    cache: CachePolicy = Field(default_factory=CachePolicy)
    max_input_chars: Optional[int] = Field(default=None, gt=0)
    canary: Optional[str] = Field(default=None, min_length=12, max_length=200)
    # When false the project must bring its own provider keys (BYOK); requests for a
    # provider it has no key for are rejected instead of using the platform's key.
    allow_platform_provider_keys: bool = True
    tools: ToolsPolicy = Field(default_factory=ToolsPolicy)
    exfiltration: ExfiltrationPolicy = Field(default_factory=ExfiltrationPolicy)
    session: SessionPolicy = Field(default_factory=SessionPolicy)
    multimodal: MultimodalPolicy = Field(default_factory=MultimodalPolicy)
    moderation: ModerationPolicy = Field(default_factory=ModerationPolicy)
    mcp_servers: List[McpServer] = Field(default_factory=list, max_length=50)
    budget: BudgetPolicy = Field(default_factory=BudgetPolicy)

    @model_validator(mode="after")
    def _unique_mcp_names(self):
        names = [s.name for s in self.mcp_servers]
        if len(names) != len(set(names)):
            raise ValueError("mcp_servers names must be unique")
        return self

    def as_dict(self) -> Dict[str, Any]:
        """Flat view used by get_app_policy(): only explicitly meaningful values, plus the
        legacy keys the request path reads."""
        data = self.model_dump(exclude_none=True)
        verifier = self.injection.verifier if self.injection.verifier is not None else self.injection_verifier
        if verifier is not None:
            data["injection_verifier"] = verifier
        else:
            data.pop("injection_verifier", None)
        return data


def parse_policy(document: Optional[dict]) -> Policy:
    if document is None:
        return Policy()
    if not isinstance(document, dict):
        raise PolicyError("policy must be a JSON object")
    try:
        return Policy.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'policy'}: {err['msg']}" for err in exc.errors()
        )
        raise PolicyError(problems) from exc


def policy_for(app_name: str) -> Policy:
    """The Policy object for the current request's app (control-plane tenant or env)."""
    from app.core.config import get_app_policy

    try:
        return parse_policy(get_app_policy(app_name))
    except PolicyError:
        return Policy()
