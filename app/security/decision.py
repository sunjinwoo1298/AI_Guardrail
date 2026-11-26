"""Turn scan results into one guardrail decision under the app's policy.

Actions:
    allow        nothing to report
    flag         forwarded, but recorded (a detector whose policy action is "flag")
    block        rejected with 403 (enforce mode)
    would_block  monitor mode: forwarded, recorded as what enforce mode would have done

Monitor mode lets a customer roll the proxy out in front of production traffic, watch the
audit log and tune the policy, and only then switch to enforce.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from app.control.policy import Policy
from app.security.sanitizer import canonical_type


@dataclass
class Decision:
    action: str = "allow"
    reasons: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def all_reasons(self) -> List[str]:
        return self.reasons + [f for f in self.flags if f not in self.reasons]


def deny_hits(policy: Policy, texts: Iterable[str]) -> List[tuple]:
    """(rule name, action) for each deny rule that matches any untrusted text."""
    texts = list(texts)
    return [(rule.name, rule.action) for rule in policy.deny if any(rule.matches(t) for t in texts)]


def relevant_pii(policy: Policy, pii_detections: list) -> List[str]:
    allowed = {canonical_type(t) for t in policy.pii.allow_entities}
    return sorted({canonical_type(d.get("type", "")) for d in pii_detections
                   if isinstance(d, dict) and canonical_type(d.get("type", "")) not in allowed})


def decide(policy: Policy, *, injection_blocked: bool, injection_signals: list, pii_detections: list,
           deny: Optional[List[tuple]] = None) -> Decision:
    """``injection_blocked`` is the risk engine's verdict (tripwires, classifier and risk
    threshold); this function applies the policy's actions and mode on top of it."""
    blocks: List[str] = []
    flags: List[str] = []

    if injection_blocked:
        reason = "prompt_injection" if injection_signals else "risk_score"
        if policy.injection.action == "block":
            blocks.append(reason)
        elif policy.injection.action == "flag":
            flags.append(reason)

    pii_types = relevant_pii(policy, pii_detections)
    if pii_types:
        reason = "pii:" + ",".join(pii_types)
        if policy.pii.action == "block":
            blocks.append(reason)
        elif policy.pii.action == "flag":
            flags.append(reason)

    for name, action in deny or []:
        (blocks if action == "block" else flags).append(f"deny:{name}")

    if blocks:
        return Decision("would_block" if policy.mode == "monitor" else "block", blocks, flags)
    if flags:
        return Decision("flag", [], flags)
    return Decision()


def masks_pii(policy: Policy) -> bool:
    """Prompt PII is masked for "mask", and for "block" too (monitor mode forwards
    would-be-blocked requests; they must not carry the PII the policy forbids)."""
    return policy.pii.action in {"mask", "block"}
