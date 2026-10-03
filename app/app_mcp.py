"""The app's own MCP server.

Exposes every control capability (layers, memory, MCP management, LLM config, checks)
over MCP so an external MCP client — including another AI assistant — can control this
app from outside. Transport: streamable SSE (mounted on the FastAPI app).

Access is protected by a bearer token (see `get_or_create_token`). Clients may pass it
either as an `Authorization: Bearer <token>` header or as a `?token=` query parameter.
"""
from __future__ import annotations

import json
import secrets

from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp import types

from . import database as db
from .agent import dispatch_sync, tool_definitions

TOKEN_KEY = "mcp_access_token"

server = Server("agent-control-assistant")


def get_or_create_token() -> str:
    token = db.get_setting(TOKEN_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        db.set_setting(TOKEN_KEY, token)
    return token


def regenerate_token() -> str:
    token = secrets.token_urlsafe(32)
    db.set_setting(TOKEN_KEY, token)
    return token


def _all_tools() -> list[dict]:
    return tool_definitions()


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=t["name"], description=t["description"], inputSchema=t["parameters"])
        for t in _all_tools()
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    import asyncio
    try:
        result = await asyncio.to_thread(dispatch_sync, name, arguments or {})
        text = json.dumps(result, default=str)
        return [types.TextContent(type="text", text=text)]
    except Exception as exc:  # noqa: BLE001
        return [types.TextContent(type="text", text=json.dumps({"ok": False, "error": str(exc)}))]


sse_transport = SseServerTransport("/mcp/messages")


def _token_ok(authorization: str | None, query_token: str | None) -> bool:
    expected = get_or_create_token()
    if query_token and secrets.compare_digest(query_token, expected):
        return True
    if authorization and authorization.lower().startswith("bearer "):
        return secrets.compare_digest(authorization[7:].strip(), expected)
    return False
