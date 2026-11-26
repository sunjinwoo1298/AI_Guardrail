"""``POST /v1/responses``: OpenAI's Responses API, guarded and forwarded natively.

Lets clients on the Responses API (and the OpenAI Agents SDK) use the proxy without a
translation layer. Untrusted input (user messages and ``function_call_output`` items) is
scanned and masked; ``instructions``, system / developer messages and earlier model
items are trusted. Output text, reasoning summaries and function-call arguments are
redacted, and function calls are checked against the tool policy.

Limitation: with ``previous_response_id`` the earlier turns are stored at OpenAI and are
not visible to the proxy; only the new input items are scanned.
"""
from __future__ import annotations

import copy
import json
import time
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.api import native_common as nc
from app.api.routes import _model_not_allowed
from app.core.config import OPENAI_API_KEY, REDACT_TOOL_CALL_ARGUMENTS
from app.core.logger import logger
from app.providers.base import resolve_api_key
from app.security import output_events
from app.security.agent_guard import audit_output, check_tool_call
from app.security.decision import output_decision

router = APIRouter(tags=["responses"])

RESPONSES_URL = "https://api.openai.com/v1/responses"
_UNTRUSTED_ROLES = {"user"}
_MEDIA = {"input_image": "image", "input_file": "file", "input_audio": "audio"}


def collect_slots(payload: dict) -> nc.TextSlots:
    slots = nc.TextSlots()
    items = payload.get("input")
    if isinstance(items, str):
        slots.add(payload, "input")
        return slots
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "function_call_output":
            if isinstance(item.get("output"), str):
                slots.add(item, "output")
            for part in item.get("output") if isinstance(item.get("output"), list) else []:
                if isinstance(part, dict) and part.get("type") in ("input_text", "output_text", "text"):
                    slots.add(part, "text")
            continue
        if item.get("role") not in _UNTRUSTED_ROLES:
            continue
        content = item.get("content")
        if isinstance(content, str):
            slots.add(item, "content")
        for part in content if isinstance(content, list) else []:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "input_text":
                slots.add(part, "text")
            elif part.get("type") in _MEDIA:
                slots.note_media(_MEDIA[part["type"]])
    return slots


def _question(payload: dict) -> str:
    items = payload.get("input")
    if isinstance(items, str):
        return items
    for item in reversed(items if isinstance(items, list) else []):
        if isinstance(item, dict) and item.get("role") == "user":
            content = item.get("content")
            if isinstance(content, str):
                return content
            return "\n".join(p.get("text", "") for p in content or [] if isinstance(p, dict) and p.get("type") == "input_text")
    return ""


def _headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {resolve_api_key('openai', OPENAI_API_KEY) or ''}", "Content-Type": "application/json"}


def _redact_arguments(arguments: Any) -> Any:
    if not REDACT_TOOL_CALL_ARGUMENTS or not isinstance(arguments, str):
        return arguments
    try:
        return json.dumps(nc.redact_value(json.loads(arguments)))
    except ValueError:
        return nc._redact_plain(arguments)


def redact_item(item: dict, policy, reasons: list, answer: list) -> dict:
    """Redact one output item in place; appends tool-policy reasons and answer text."""
    kind = item.get("type")
    if kind == "message":
        for part in item.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "output_text":
                part["text"] = nc._redact_plain(part.get("text", ""))
                answer.append(part["text"])
    elif kind == "function_call":
        reasons.extend(check_tool_call(policy, item.get("name", ""), item.get("arguments")))
        item["arguments"] = _redact_arguments(item.get("arguments"))
    elif kind == "reasoning":
        for part in item.get("summary") or []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part["text"] = nc._redact_plain(part["text"])
    return item


def _redact_response(result: dict, policy, reasons: list, answer: list) -> dict:
    for item in result.get("output") or []:
        if isinstance(item, dict):
            redact_item(item, policy, reasons, answer)
    return result


@router.post("/v1/responses")
async def responses(request: Request):
    try:
        payload = await request.json()
    except ValueError:
        return nc.error_response(400, "invalid_json", "Request body must be JSON")
    if not isinstance(payload, dict) or not isinstance(payload.get("model"), str) or "input" not in payload:
        return nc.error_response(400, "invalid_request", "'model' and 'input' are required")
    model = payload["model"].removeprefix("openai/")
    denied = _model_not_allowed(request, f"openai/{model}")
    if denied:
        return denied

    body = copy.deepcopy(payload)
    body["model"] = model
    blocked, decision, policy = await nc.guard_input(request, body, collect_slots(body), tools_param=body.get("tools"),
                                                     surface="openai.responses")
    if blocked:
        return blocked
    findings = output_events.begin()
    question = _question(body)
    started = time.time()

    if body.get("stream"):
        upstream = await nc.open_stream(RESPONSES_URL, _headers(), body)
        if upstream.status_code >= 400:
            nc.settle(request, model_label=f"openai/{model}", endpoint="openai.responses", started=started,
                      input_tokens=0, output_tokens=0, ok=False)
            return nc.upstream_error(upstream)
        stream = _relay_stream(request, upstream, policy, model, question, findings, started)
        return StreamingResponse(stream, media_type="text/event-stream", headers=nc.guardrail_headers(decision))

    response = await nc.post_json(RESPONSES_URL, _headers(), body)
    if response.status_code >= 400:
        nc.settle(request, model_label=f"openai/{model}", endpoint="openai.responses", started=started,
                  input_tokens=0, output_tokens=0, ok=False)
        return nc.upstream_error(response)
    result = response.json()
    usage = result.get("usage") or {}
    nc.settle(request, model_label=f"openai/{model}", endpoint="openai.responses", started=started,
              input_tokens=int(usage.get("input_tokens") or 0), output_tokens=int(usage.get("output_tokens") or 0))
    reasons, answer = [], []
    _redact_response(result, policy, reasons, answer)
    verdict = output_decision(policy, reasons, policy.tools.action)
    audit_output(policy, surface="openai.responses", decision=verdict, findings=findings)
    if verdict.blocked:
        return nc.error_response(403, "tool_call_blocked", "The model's tool call was blocked by the guardrail policy",
                                 "permission_error", reasons=verdict.reasons)
    moderated = await nc.moderate_output(policy, question, "\n".join(answer))
    if moderated is not None and moderated.blocked:
        return nc.error_response(403, "output_blocked", "The model's response was blocked by the guardrail policy",
                                 "permission_error", reasons=moderated.reasons)
    return JSONResponse(result, headers=nc.guardrail_headers(decision))


_TEXT_DELTAS = {"response.output_text.delta": "content_index", "response.reasoning_summary_text.delta": "summary_index"}
_TEXT_DONES = {"response.output_text.done": "content_index", "response.reasoning_summary_text.done": "summary_index"}


async def _relay_stream(request, upstream, policy, model, question, findings, started):
    from app.services.llm_orchestrator import _StreamRedactor

    hold = nc.moderation.wants(policy, "output") and policy.moderation.action == "block"
    redactors: Dict[tuple, Any] = {}
    call_names: Dict[str, str] = {}
    held, answer, tool_reasons = [], [], []
    input_tokens = output_tokens = 0
    ok, stopped = True, False

    def out(event, data):
        chunk = nc.sse(event, data)
        if hold:
            held.append(chunk)
            return None
        return chunk

    try:
        async for event, raw in nc.sse_events(upstream):
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            kind = data.get("type") or event
            emitted = []
            if kind in _TEXT_DELTAS:
                key = (data.get("item_id"), data.get(_TEXT_DELTAS[kind]), kind)
                ready = redactors.setdefault(key, _StreamRedactor()).feed(data.get("delta", ""))
                if ready:
                    if kind == "response.output_text.delta":
                        answer.append(ready)
                    emitted.append(out(event, {**data, "delta": ready}))
            elif kind in _TEXT_DONES:
                delta_kind = kind.replace(".done", ".delta")
                key = (data.get("item_id"), data.get(_TEXT_DONES[kind]), delta_kind)
                redactor = redactors.pop(key, None)
                tail = redactor.flush() if redactor else ""
                if tail:
                    if delta_kind == "response.output_text.delta":
                        answer.append(tail)
                    emitted.append(out(delta_kind, {**{k: v for k, v in data.items() if k != "text"},
                                                    "type": delta_kind, "delta": tail}))
                emitted.append(out(event, {**data, "text": nc._redact_plain(data.get("text", ""))}))
            elif kind == "response.function_call_arguments.delta":
                continue  # released whole with .done, after the policy check
            elif kind == "response.function_call_arguments.done":
                name = data.get("name") or call_names.get(data.get("item_id"), "")
                reasons = check_tool_call(policy, name, data.get("arguments"))
                verdict = output_decision(policy, reasons, policy.tools.action)
                tool_reasons += reasons
                if verdict.blocked:
                    emitted.append(out("error", {"type": "error", "code": "tool_call_blocked",
                                                 "message": "The model's tool call was blocked by the guardrail policy",
                                                 "param": None, "reasons": verdict.reasons}))
                    stopped = True
                else:
                    arguments = _redact_arguments(data.get("arguments"))
                    emitted.append(out("response.function_call_arguments.delta", {
                        "type": "response.function_call_arguments.delta", "item_id": data.get("item_id"),
                        "output_index": data.get("output_index"), "delta": arguments}))
                    emitted.append(out(event, {**data, "arguments": arguments}))
            elif kind in ("response.output_item.added", "response.output_item.done"):
                item = data.get("item")
                if isinstance(item, dict):
                    if item.get("type") == "function_call" and item.get("id"):
                        call_names[item["id"]] = item.get("name", "")
                    if kind == "response.output_item.done" and item.get("type") == "function_call":
                        # .done carries the name, which the arguments events may not.
                        item_reasons = check_tool_call(policy, item.get("name", ""), item.get("arguments"))
                        tool_reasons += item_reasons
                        verdict = output_decision(policy, item_reasons, policy.tools.action)
                        if verdict.blocked and not stopped:
                            emitted.append(out("error", {"type": "error", "code": "tool_call_blocked",
                                                         "message": "The model's tool call was blocked by the guardrail policy",
                                                         "param": None, "reasons": verdict.reasons}))
                            stopped = True
                    redact_item(item, policy, [], [])
                emitted.append(out(event, data))
            elif kind in ("response.completed", "response.incomplete", "response.failed"):
                result = data.get("response") or {}
                usage = result.get("usage") or {}
                input_tokens = int(usage.get("input_tokens") or 0)
                output_tokens = int(usage.get("output_tokens") or 0)
                _redact_response(result, policy, [], [])
                emitted.append(out(event, data))
            else:
                emitted.append(out(event, data))
            for chunk in emitted:
                if chunk:
                    yield chunk
            if stopped:
                break
    except Exception as exc:
        ok = False
        logger.exception(f"Responses stream relay failed: {exc!r}")
        yield nc.sse("error", {"type": "error", "code": "upstream_error", "message": "Upstream stream failed", "param": None})
    finally:
        await upstream.aclose()
        nc.settle(request, model_label=f"openai/{model}", endpoint="openai.responses.stream", started=started,
                  input_tokens=input_tokens, output_tokens=output_tokens, ok=ok)
        audit_output(policy, surface="openai.responses.stream",
                     decision=output_decision(policy, sorted(set(tool_reasons)), policy.tools.action), findings=findings)

    if hold:
        verdict = await nc.moderate_output(policy, question, "".join(answer))
        if verdict is not None and verdict.blocked:
            yield nc.sse("error", {"type": "error", "code": "output_blocked",
                                   "message": "The model's response was blocked by the guardrail policy",
                                   "param": None, "reasons": verdict.reasons})
            return
        for chunk in held:
            yield chunk
