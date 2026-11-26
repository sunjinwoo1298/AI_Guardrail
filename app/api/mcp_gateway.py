"""MCP gateway: ``/mcp/{server}`` (Streamable HTTP transport).

An agent connects to ``<proxy>/mcp/<name>`` instead of the MCP server itself; the project
policy's ``mcp_servers`` maps the name to the real server. The gateway:

* refuses ``tools/call`` for tools the policy does not allow, or whose arguments break
  the tool rules (schema, denied patterns), without contacting the server;
* removes disallowed tools from ``tools/list``, and tools whose descriptions carry
  injected instructions ("tool poisoning": text in a tool description is read by the
  model as if it were trusted);
* scans ``tools/call`` and ``resources/read`` results for prompt injection (blocked
  results are replaced by an error result) and masks PII in them;
* only connects to public addresses (SSRF protection), unless
  MCP_ALLOW_PRIVATE_UPSTREAMS=true for local development.

Upstream credentials are not stored: the client sends them as
``X-MCP-Authorization``, forwarded as ``Authorization``.
"""
from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import os
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.api import native_common as nc
from app.control import audit
from app.control.policy import McpServer, Policy, policy_for
from app.core.config import ENABLE_PII_MASKING, get_app_policy
from app.core.context import app_context, tenant_context
from app.core.logger import logger
from app.middleware import security_middleware as sm
from app.observability.metrics import record_guardrail_decision
from app.providers.http import get_http_client
from app.security.agent_guard import check_tool_call, tool_allowed
from app.security.decision import masks_pii, output_decision

router = APIRouter(tags=["mcp"])

ALLOW_PRIVATE_UPSTREAMS = os.getenv("MCP_ALLOW_PRIVATE_UPSTREAMS", "false").lower() == "true"
_FORWARD_REQUEST_HEADERS = ("accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id")
_FORWARD_RESPONSE_HEADERS = ("content-type", "mcp-session-id", "mcp-protocol-version")
BLOCKED_RESULT_TEXT = "[Tool result blocked by the guardrail policy: it contains instructions aimed at the AI.]"
JSONRPC_POLICY_ERROR = -32001


class UpstreamRejected(Exception):
    pass


async def check_upstream(url: str) -> None:
    """Refuse upstreams that resolve to private, loopback, link-local or reserved
    addresses, so a tenant's policy cannot point the gateway at internal services.
    (Checked at connect time; DNS rebinding between this check and the connection is
    not prevented, which a pinned-resolution transport would add.)"""
    parsed = urlparse(url)
    if ALLOW_PRIVATE_UPSTREAMS:
        return
    if parsed.scheme != "https":
        raise UpstreamRejected("MCP upstreams must use https")
    host = parsed.hostname or ""
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, parsed.port or 443, 0, socket.SOCK_STREAM)
    except OSError as exc:
        raise UpstreamRejected(f"cannot resolve {host}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise UpstreamRejected(f"{host} resolves to a non-public address")


def _server(policy: Policy, name: str) -> Optional[McpServer]:
    return next((s for s in policy.mcp_servers if s.name == name), None)


def _upstream_headers(request: Request) -> Dict[str, str]:
    headers = {k: request.headers[k] for k in _FORWARD_REQUEST_HEADERS if k in request.headers}
    headers.setdefault("accept", "application/json, text/event-stream")
    if request.headers.get("x-mcp-authorization"):
        headers["authorization"] = request.headers["x-mcp-authorization"]
    return headers


def _response_headers(upstream) -> Dict[str, str]:
    return {k: upstream.headers[k] for k in _FORWARD_RESPONSE_HEADERS if k in upstream.headers}


def _jsonrpc_error(msg_id: Any, message: str, reasons: List[str]) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": JSONRPC_POLICY_ERROR, "message": message,
                                                      "data": {"reasons": reasons}}}


def _audit(event_type: str, policy: Policy, server: McpServer, action: str, reasons: List[str], **details) -> None:
    audit.record(event_type, action=action, reasons=reasons, details={"server": server.name, **details},
                 tenant=tenant_context.get(), app=app_context.get(), monitor=action == "would_block")


async def _scan(texts: List[str]) -> Tuple[bool, list, dict]:
    """(injection verdict, PII detections, detections per segment) for untrusted texts."""
    if not texts:
        return False, [], {}
    segments = [(k, None, t) for k, t in enumerate(texts)]
    loop = asyncio.get_running_loop()
    risk, pii, signals, by_segment = await loop.run_in_executor(
        sm._SCAN_EXECUTOR, contextvars.copy_context().run, sm._score_segments, segments)
    threshold = get_app_policy(app_context.get()).get("max_risk_score")
    blocked = (sm.should_block_prompt(risk, signals) if threshold is None
               else sm.should_block_prompt(risk, signals, max_risk_score=float(threshold)))
    return blocked, pii, by_segment


# --- request side ------------------------------------------------------------------------------

def _check_call(policy: Policy, server: McpServer, message: dict) -> List[str]:
    params = message.get("params") or {}
    name = params.get("name", "")
    if server.allowed_tools is not None and not any(_fn(name, p) for p in server.allowed_tools):
        return [f"tool_not_allowed:{name}"]
    return check_tool_call(policy, name, params.get("arguments"))


def _fn(name: str, pattern: str) -> bool:
    from fnmatch import fnmatchcase

    return fnmatchcase(name or "", pattern)


# --- response side -----------------------------------------------------------------------------

def _tool_texts(tool: dict) -> str:
    parts = [tool.get("description") or "", tool.get("title") or ""]
    schema = tool.get("inputSchema") or {}
    for prop in (schema.get("properties") or {}).values() if isinstance(schema, dict) else []:
        if isinstance(prop, dict) and isinstance(prop.get("description"), str):
            parts.append(prop["description"])
    return "\n".join(p for p in parts if p)


async def _filter_tools(policy: Policy, server: McpServer, result: dict) -> dict:
    tools = result.get("tools")
    if not isinstance(tools, list):
        return result
    kept = []
    for tool in tools:
        name = tool.get("name", "") if isinstance(tool, dict) else ""
        if (server.allowed_tools is not None and not any(_fn(name, p) for p in server.allowed_tools)) \
                or not tool_allowed(policy.tools, name):
            continue  # never advertise a tool the agent may not call
        if server.scan_tool_descriptions and policy.injection.action != "off":
            poisoned, _, _ = await _scan([_tool_texts(tool)])
            if poisoned:
                verdict = output_decision(policy, [f"tool_poisoning:{name}"],
                                          "block" if policy.injection.action == "block" else "flag")
                _audit(f"mcp.{verdict.action}", policy, server, verdict.action, verdict.all_reasons(), tool=name)
                if verdict.blocked:
                    logger.warning(f"MCP tool '{name}' from '{server.name}' removed: injected instructions in its description")
                    continue
        kept.append(tool)
    return {**result, "tools": kept}


def _result_text_slots(method: str, result: dict) -> List[Tuple[dict, str]]:
    slots = []
    items = result.get("content") if method == "tools/call" else result.get("contents")
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and isinstance(item.get("text"), str) and item["text"].strip():
            slots.append((item, "text"))
        resource = item.get("resource") if isinstance(item, dict) else None
        if isinstance(resource, dict) and isinstance(resource.get("text"), str) and resource["text"].strip():
            slots.append((resource, "text"))
    return slots


async def _guard_result(policy: Policy, server: McpServer, method: str, message: dict) -> dict:
    result = message.get("result")
    if not isinstance(result, dict) or not server.scan_results:
        return message
    slots = _result_text_slots(method, result)
    injected, pii, by_segment = await _scan([c[k] for c, k in slots])
    if injected and policy.injection.action != "off":
        verdict = output_decision(policy, ["prompt_injection_in_tool_result"],
                                  "block" if policy.injection.action == "block" else "flag")
        record_guardrail_decision(verdict.action, surface="mcp")
        _audit(f"mcp.{verdict.action}", policy, server, verdict.action, verdict.all_reasons(), method=method)
        if verdict.blocked:
            if method == "tools/call":
                return {**message, "result": {"content": [{"type": "text", "text": BLOCKED_RESULT_TEXT}], "isError": True}}
            return _jsonrpc_error(message.get("id"), "Resource content blocked by the guardrail policy", verdict.reasons)
    if ENABLE_PII_MASKING and masks_pii(policy):
        skip = frozenset(policy.pii.allow_entities)
        for k, (container, key) in enumerate(slots):
            detections = by_segment.get((k, None))
            container[key] = (nc.sanitize_text(container[key], detections, skip) if skip
                              else nc.sanitize_text(container[key], detections))
        if isinstance(result.get("structuredContent"), (dict, list)):
            result["structuredContent"] = nc.redact_value(result["structuredContent"])
    return message


async def _transform(policy: Policy, server: McpServer, methods: Dict[Any, str], message: Any) -> Any:
    if not isinstance(message, dict) or "id" not in message or "result" not in message:
        return message
    method = methods.get(message.get("id"))
    if method == "tools/list":
        return {**message, "result": await _filter_tools(policy, server, message["result"])}
    if method in ("tools/call", "resources/read"):
        return await _guard_result(policy, server, method, message)
    return message


async def _sse_with_ids(response):
    event, event_id, data = None, None, []
    async for line in response.aiter_lines():
        if line == "":
            if data or event_id:
                yield event, event_id, "\n".join(data)
            event, event_id, data = None, None, []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("id:"):
            event_id = line[3:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif line.startswith("retry:"):
            yield "__retry__", None, line[6:].strip()
    if data:
        yield event, event_id, "\n".join(data)


def _unreachable(server: McpServer, exc: Exception) -> JSONResponse:
    logger.warning(f"MCP server '{server.name}' unreachable: {exc!r}")
    return nc.error_response(502, "mcp_upstream_unreachable", f"MCP server '{server.name}' is unreachable", "upstream_error")


# --- endpoints ---------------------------------------------------------------------------------

async def _resolve(request: Request, name: str):
    policy = policy_for(app_context.get())
    server = _server(policy, name)
    if server is None:
        return None, None, nc.error_response(404, "mcp_server_not_found", f"No MCP server '{name}' in this project's policy")
    try:
        await check_upstream(server.url)
    except UpstreamRejected as exc:
        return None, None, nc.error_response(403, "mcp_upstream_rejected", str(exc), "permission_error")
    return policy, server, None


@router.post("/mcp/{name}")
async def mcp_post(name: str, request: Request):
    policy, server, error = await _resolve(request, name)
    if error:
        return error
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(status_code=400, content={"jsonrpc": "2.0", "id": None,
                                                      "error": {"code": -32700, "message": "Parse error"}})
    messages = body if isinstance(body, list) else [body]
    methods = {m.get("id"): m.get("method") for m in messages if isinstance(m, dict) and "id" in m and "method" in m}

    refusals = []
    for message in messages:
        if isinstance(message, dict) and message.get("method") == "tools/call":
            reasons = _check_call(policy, server, message)
            verdict = output_decision(policy, reasons, policy.tools.action if policy.tools.action != "off" else "block")
            if reasons:
                record_guardrail_decision(verdict.action, surface="mcp")
                _audit(f"mcp.{verdict.action}", policy, server, verdict.action, verdict.all_reasons(),
                       tool=(message.get("params") or {}).get("name"))
            if verdict.blocked:
                refusals.append(_jsonrpc_error(message.get("id"), "Tool call blocked by the guardrail policy", verdict.reasons))
    if refusals:
        return JSONResponse(refusals if isinstance(body, list) else refusals[0])

    client = get_http_client()
    try:
        upstream = await client.send(client.build_request("POST", server.url, headers=_upstream_headers(request),
                                                          content=json.dumps(body).encode("utf-8")), stream=True)
    except Exception as exc:
        return _unreachable(server, exc)
    content_type = upstream.headers.get("content-type", "")
    if upstream.status_code >= 400 or not methods or "text/event-stream" not in content_type:
        raw = await upstream.aread()
        await upstream.aclose()
        if upstream.status_code < 400 and methods and raw and "json" in content_type:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if parsed is not None:
                if isinstance(parsed, list):
                    parsed = [await _transform(policy, server, methods, m) for m in parsed]
                else:
                    parsed = await _transform(policy, server, methods, parsed)
                return JSONResponse(parsed, status_code=upstream.status_code, headers=_response_headers(upstream))
        return Response(raw, status_code=upstream.status_code, headers=_response_headers(upstream),
                        media_type=content_type or None)

    async def relay():
        try:
            async for event, event_id, data in _sse_with_ids(upstream):
                if event == "__retry__":
                    yield f"retry: {data}\n\n"
                    continue
                try:
                    message = await _transform(policy, server, methods, json.loads(data)) if data else None
                    data = json.dumps(message) if message is not None else data
                except ValueError:
                    pass
                yield (f"event: {event}\n" if event else "") + (f"id: {event_id}\n" if event_id else "") + \
                    "".join(f"data: {line}\n" for line in (data or "").split("\n")) + "\n"
        finally:
            await upstream.aclose()

    return StreamingResponse(relay(), status_code=upstream.status_code, headers=_response_headers(upstream),
                             media_type="text/event-stream")


@router.get("/mcp/{name}")
async def mcp_get(name: str, request: Request):
    """Server-to-client stream (notifications). Relayed as is."""
    policy, server, error = await _resolve(request, name)
    if error:
        return error
    client = get_http_client()
    try:
        upstream = await client.send(client.build_request("GET", server.url, headers=_upstream_headers(request)), stream=True)
    except Exception as exc:
        return _unreachable(server, exc)
    if upstream.status_code >= 400 or "text/event-stream" not in upstream.headers.get("content-type", ""):
        raw = await upstream.aread()
        await upstream.aclose()
        return Response(raw, status_code=upstream.status_code, headers=_response_headers(upstream))

    async def relay():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(relay(), status_code=upstream.status_code, headers=_response_headers(upstream),
                             media_type="text/event-stream")


@router.delete("/mcp/{name}")
async def mcp_delete(name: str, request: Request):
    policy, server, error = await _resolve(request, name)
    if error:
        return error
    try:
        upstream = await get_http_client().request("DELETE", server.url, headers=_upstream_headers(request))
    except Exception as exc:
        return _unreachable(server, exc)
    return Response(upstream.content, status_code=upstream.status_code, headers=_response_headers(upstream))
