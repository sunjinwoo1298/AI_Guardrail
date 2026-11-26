"""``POST /v1/messages``: Anthropic's Messages API, guarded and forwarded natively.

Clients built on the Anthropic SDK (and Claude-based agents) set
``base_url=<proxy>`` and their proxy key, and keep every Anthropic feature: tool use,
extended thinking, prompt caching, PDFs, streaming. The proxy:

* scans untrusted content (user text, tool_result blocks, plain-text documents) and masks
  PII in place; ``system`` and assistant turns are the application's own and trusted;
* checks declared tools and every ``tool_use`` block against the policy;
* redacts PII, secrets, canaries and exfiltration channels in text blocks and tool inputs,
  in streams too (text is released sentence by sentence; a tool_use block is released
  whole when it completes);
* leaves ``thinking`` blocks untouched, because Anthropic verifies their signatures when
  they are sent back in the next turn, but blocks the response if they leak the canary.
"""
from __future__ import annotations

import copy
import json
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.api import native_common as nc
from app.api.routes import _model_not_allowed
from app.core.config import ANTHROPIC_API_KEY, REDACT_TOOL_CALL_ARGUMENTS, get_canaries
from app.core.context import app_context
from app.core.logger import logger
from app.providers.base import resolve_api_key
from app.security import output_events
from app.security.agent_guard import audit_output, check_tool_call
from app.security.decision import output_decision

router = APIRouter(tags=["anthropic"])

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_VERSION = "2023-06-01"
BLOCKED_TOOL_TEXT = "[Tool call blocked by the guardrail policy.]"
_MEDIA = {"image": "image", "document": "file", "search_result": None}


def collect_slots(payload: dict) -> nc.TextSlots:
    slots = nc.TextSlots()
    for message in payload.get("messages") or []:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            slots.add(message, "content")
            continue
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                slots.add(block, "text")
            elif kind == "tool_result":
                inner = block.get("content")
                if isinstance(inner, str):
                    slots.add(block, "content")
                for part in inner if isinstance(inner, list) else []:
                    if isinstance(part, dict) and part.get("type") == "text":
                        slots.add(part, "text")
                    elif isinstance(part, dict) and part.get("type") == "image":
                        slots.note_media("image")
            elif kind == "document" and isinstance(block.get("source"), dict) and block["source"].get("type") == "text":
                slots.add(block["source"], "data")
            elif kind in _MEDIA and _MEDIA[kind]:
                slots.note_media(_MEDIA[kind])
    return slots


def _last_user_text(payload: dict) -> str:
    for message in reversed(payload.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                return content
            return "\n".join(b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _upstream_headers(request: Request) -> Dict[str, str]:
    headers = {
        "x-api-key": resolve_api_key("anthropic", ANTHROPIC_API_KEY) or "",
        "anthropic-version": request.headers.get("anthropic-version", DEFAULT_VERSION),
        "content-type": "application/json",
    }
    if request.headers.get("anthropic-beta"):
        headers["anthropic-beta"] = request.headers["anthropic-beta"]
    return headers


def _canary_leaked(text: str) -> bool:
    return any(c and c in (text or "") for c in get_canaries(app_context.get()))


def _check_tool_block(policy, block: dict) -> list:
    return check_tool_call(policy, block.get("name", ""), block.get("input"))


@router.post("/v1/messages")
async def messages(request: Request):
    try:
        payload = await request.json()
    except ValueError:
        return nc.error_response(400, "invalid_json", "Request body must be JSON")
    if not isinstance(payload, dict) or not isinstance(payload.get("model"), str) or not isinstance(payload.get("messages"), list):
        return nc.error_response(400, "invalid_request", "'model' and 'messages' are required")
    model = payload["model"].removeprefix("anthropic/")
    denied = _model_not_allowed(request, f"anthropic/{model}")
    if denied:
        return denied

    body = copy.deepcopy(payload)
    body["model"] = model
    blocked, decision, policy = await nc.guard_input(request, body, collect_slots(body), tools_param=body.get("tools"),
                                                     surface="anthropic.messages")
    if blocked:
        return blocked
    findings = output_events.begin()
    question = _last_user_text(body)
    started = time.time()

    if body.get("stream"):
        upstream = await nc.open_stream(ANTHROPIC_URL, _upstream_headers(request), body)
        if upstream.status_code >= 400:
            nc.settle(request, model_label=f"anthropic/{model}", endpoint="anthropic.messages", started=started,
                      input_tokens=0, output_tokens=0, ok=False)
            return nc.upstream_error(upstream)
        stream = _relay_stream(request, upstream, policy, model, question, findings, started)
        return StreamingResponse(stream, media_type="text/event-stream", headers=nc.guardrail_headers(decision))

    response = await nc.post_json(ANTHROPIC_URL, _upstream_headers(request), body)
    if response.status_code >= 400:
        nc.settle(request, model_label=f"anthropic/{model}", endpoint="anthropic.messages", started=started,
                  input_tokens=0, output_tokens=0, ok=False)
        return nc.upstream_error(response)
    result = response.json()
    usage = result.get("usage") or {}
    nc.settle(request, model_label=f"anthropic/{model}", endpoint="anthropic.messages", started=started,
              input_tokens=int(usage.get("input_tokens") or 0), output_tokens=int(usage.get("output_tokens") or 0))

    tool_reasons, answer_parts = [], []
    for block in result.get("content") or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            block["text"] = nc._redact_plain(block.get("text", ""))
            answer_parts.append(block["text"])
        elif block.get("type") == "tool_use":
            tool_reasons += _check_tool_block(policy, block)
            if REDACT_TOOL_CALL_ARGUMENTS:
                block["input"] = nc.redact_value(block.get("input"))
        elif block.get("type") == "thinking" and _canary_leaked(block.get("thinking", "")):
            tool_reasons.append("canary_leak")
    verdict = output_decision(policy, tool_reasons, "block" if "canary_leak" in tool_reasons else policy.tools.action)
    audit_output(policy, surface="anthropic.messages", decision=verdict, findings=findings)
    if verdict.blocked:
        return nc.error_response(403, "tool_call_blocked" if "canary_leak" not in tool_reasons else "output_blocked",
                                 "The model's response was blocked by the guardrail policy", "permission_error",
                                 reasons=verdict.reasons)
    moderated = await nc.moderate_output(policy, question, "\n".join(answer_parts))
    if moderated is not None and moderated.blocked:
        return nc.error_response(403, "output_blocked", "The model's response was blocked by the guardrail policy",
                                 "permission_error", reasons=moderated.reasons)
    return JSONResponse(result, headers=nc.guardrail_headers(decision))


async def _relay_stream(request, upstream, policy, model, question, findings, started):
    """Re-emit Anthropic SSE with text redacted at sentence boundaries and tool_use blocks
    released whole once checked. With blocking output moderation, the whole answer is
    held until judged."""
    from app.services.llm_orchestrator import _StreamRedactor

    hold = nc.moderation.wants(policy, "output") and policy.moderation.action == "block"
    blocks: Dict[int, Dict[str, Any]] = {}
    held, answer = [], []
    input_tokens = output_tokens = 0
    blocked_tools = allowed_tools = 0
    tool_reasons: list = []
    ok = True

    def out(event, data):
        chunk = nc.sse(event, data)
        if hold:
            held.append(chunk)
            return None
        return chunk

    def text_delta(index, text):
        return out("content_block_delta", {"type": "content_block_delta", "index": index,
                                           "delta": {"type": "text_delta", "text": text}})

    try:
        async for event, raw in nc.sse_events(upstream):
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            kind = data.get("type") or event
            emitted = []
            if kind == "message_start":
                input_tokens = int(((data.get("message") or {}).get("usage") or {}).get("input_tokens") or 0)
                emitted.append(out(event, data))
            elif kind == "content_block_start":
                index, block = data.get("index"), data.get("content_block") or {}
                state = {"type": block.get("type"), "start": data}
                if block.get("type") == "text":
                    state["redactor"] = _StreamRedactor()
                    emitted.append(out(event, data))
                elif block.get("type") == "tool_use":
                    state["json"] = ""
                else:
                    emitted.append(out(event, data))  # thinking, redacted_thinking, server tools
                blocks[index] = state
            elif kind == "content_block_delta":
                index, delta = data.get("index"), data.get("delta") or {}
                state = blocks.get(index, {})
                if delta.get("type") == "text_delta" and "redactor" in state:
                    ready = state["redactor"].feed(delta.get("text", ""))
                    if ready:
                        answer.append(ready)
                        emitted.append(text_delta(index, ready))
                elif delta.get("type") == "input_json_delta" and "json" in state:
                    state["json"] += delta.get("partial_json", "")
                else:
                    emitted.append(out(event, data))
            elif kind == "content_block_stop":
                index = data.get("index")
                state = blocks.get(index, {})
                if "redactor" in state:
                    tail = state["redactor"].flush()
                    if tail:
                        answer.append(tail)
                        emitted.append(text_delta(index, tail))
                    emitted.append(out(event, data))
                elif "json" in state:
                    emitted += _release_tool_block(policy, index, state, out)
                    tool_reasons += state.get("reasons", [])
                    if state.get("blocked"):
                        blocked_tools += 1
                    else:
                        allowed_tools += 1
                else:
                    emitted.append(out(event, data))
            elif kind == "message_delta":
                output_tokens = int((data.get("usage") or {}).get("output_tokens") or 0)
                delta = data.get("delta") or {}
                if blocked_tools and not allowed_tools and delta.get("stop_reason") == "tool_use":
                    data = {**data, "delta": {**delta, "stop_reason": "end_turn"}}
                emitted.append(out(event, data))
            else:  # message_stop, ping, error
                emitted.append(out(event, data))
            for chunk in emitted:
                if chunk:
                    yield chunk
    except Exception as exc:
        ok = False
        logger.exception(f"Anthropic stream relay failed: {exc!r}")
        yield nc.sse("error", {"type": "error", "error": {"type": "api_error", "message": "Upstream stream failed"}})
    finally:
        await upstream.aclose()
        nc.settle(request, model_label=f"anthropic/{model}", endpoint="anthropic.messages.stream", started=started,
                  input_tokens=input_tokens, output_tokens=output_tokens, ok=ok)
        audit_output(policy, surface="anthropic.messages.stream",
                     decision=output_decision(policy, tool_reasons, policy.tools.action), findings=findings)

    if hold:
        verdict = await nc.moderate_output(policy, question, "".join(answer))
        if verdict is not None and verdict.blocked:
            yield nc.sse("error", {"type": "error", "error": {
                "type": "permission_error", "message": "The model's response was blocked by the guardrail policy",
                "reasons": verdict.reasons}})
            return
        for chunk in held:
            yield chunk


def _release_tool_block(policy, index, state, out):
    """Validate and redact a completed tool_use block, then emit it whole (start, one
    input delta, stop), or a text block saying it was blocked."""
    start = state["start"]
    block = dict(start.get("content_block") or {})
    try:
        arguments = json.loads(state["json"]) if state["json"].strip() else {}
    except ValueError:
        arguments = state["json"]
    reasons = check_tool_call(policy, block.get("name", ""), arguments)
    state["reasons"] = reasons
    verdict = output_decision(policy, reasons, policy.tools.action)
    if verdict.blocked:
        state["blocked"] = True
        return [
            out("content_block_start", {"type": "content_block_start", "index": index,
                                        "content_block": {"type": "text", "text": ""}}),
            out("content_block_delta", {"type": "content_block_delta", "index": index,
                                        "delta": {"type": "text_delta", "text": BLOCKED_TOOL_TEXT}}),
            out("content_block_stop", {"type": "content_block_stop", "index": index}),
        ]
    if REDACT_TOOL_CALL_ARGUMENTS and not isinstance(arguments, str):
        arguments = nc.redact_value(arguments)
    partial = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return [
        out("content_block_start", {**start, "content_block": {**block, "input": {}}}),
        out("content_block_delta", {"type": "content_block_delta", "index": index,
                                    "delta": {"type": "input_json_delta", "partial_json": partial}}),
        out("content_block_stop", {"type": "content_block_stop", "index": index}),
    ]
