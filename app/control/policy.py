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
