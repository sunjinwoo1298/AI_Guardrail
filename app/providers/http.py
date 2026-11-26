"""Shared HTTP client for provider calls.

Every adapter call used to open a new ``httpx.AsyncClient``, so each request paid a fresh
TCP + TLS handshake and no connections were reused, and timeouts were a hardcoded 30 s.
One pooled client per event loop (an AsyncClient is bound to the loop it was created on)
fixes both; timeouts come from PROVIDER_CONNECT_TIMEOUT_SECONDS / PROVIDER_READ_TIMEOUT_SECONDS.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import httpx

from app.core.config import (
    PROVIDER_CONNECT_TIMEOUT_SECONDS,
    PROVIDER_MAX_CONNECTIONS,
    PROVIDER_READ_TIMEOUT_SECONDS,
)

PROVIDER_TIMEOUT = httpx.Timeout(
    connect=PROVIDER_CONNECT_TIMEOUT_SECONDS,
    read=PROVIDER_READ_TIMEOUT_SECONDS,
    write=PROVIDER_READ_TIMEOUT_SECONDS,
    pool=PROVIDER_CONNECT_TIMEOUT_SECONDS,
)

_clients: dict = {}


def get_http_client() -> httpx.AsyncClient:
    loop = asyncio.get_running_loop()
    entry = _clients.get(id(loop))
    if entry is not None and entry[0] is loop and not entry[1].is_closed:
        return entry[1]
    # Forget clients of loops that have closed (tests and asyncio.run create many).
    for key, (old_loop, _) in list(_clients.items()):
        if old_loop.is_closed():
            _clients.pop(key, None)
    client = httpx.AsyncClient(
        timeout=PROVIDER_TIMEOUT,
        limits=httpx.Limits(max_connections=PROVIDER_MAX_CONNECTIONS, max_keepalive_connections=50),
    )
    _clients[id(loop)] = (loop, client)
    return client


@asynccontextmanager
async def provider_client():
    """``async with provider_client() as client:`` yields the pooled client without
    closing it, so adapters keep their original structure."""
    yield get_http_client()


async def close_http_clients() -> None:
    loop = asyncio.get_running_loop()
    entry = _clients.pop(id(loop), None)
    if entry is not None:
        await entry[1].aclose()
