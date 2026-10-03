"""MCP client manager.

Runs a dedicated asyncio event loop in a background thread and keeps persistent
connections to configured MCP servers (stdio or SSE). Exposes sync wrappers so
the FastAPI request handlers can list and call tools.
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any

from .config import MCP_CALL_TIMEOUT
from . import database as db


@dataclass
class MCPServerState:
    id: int
    name: str
    transport: str
    status: str = "disconnected"  # disconnected|connecting|connected|error
    error: str = ""
    tools: list[dict] = field(default_factory=list)


class _Connection:
    """One live MCP session, kept alive by a dedicated task."""

    def __init__(self, manager: "MCPManager", config: dict) -> None:
        self.manager = manager
        self.config = config
        self.name = config["name"]
        self.sid = config["id"]
        self.status = "disconnected"
        self.error = ""
        self.tools: list[dict] = []
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._ready = asyncio.Event()

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        await self._ready.wait()

    async def _run(self) -> None:
        from mcp.client.session import ClientSession

        self.status = "connecting"
        try:
            async with self._open_transport() as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    self.tools = [
                        {
                            "name": t.name,
                            "description": (t.description or "").strip(),
                            "input_schema": t.inputSchema or {"type": "object", "properties": {}},
                        }
                        for t in result.tools
                    ]
                    self.status = "connected"
                    self.error = ""
                    self._ready.set()
                    await self._serve(session)
        except Exception as exc:  # noqa: BLE001
            self.status = "error"
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.status = "disconnected" if self.status != "error" else "error"
            self._ready.set()
            # Fail any pending futures so callers don't hang.
            while not self._queue.empty():
                op, payload, fut = self._queue.get_nowait()
                if not fut.done():
                    fut.set_exception(RuntimeError(f"MCP server '{self.name}' disconnected: {self.error}"))

    def _open_transport(self):
        from mcp.client.stdio import stdio_client, StdioServerParameters
        from mcp.client.sse import sse_client

        if self.config["transport"] == "stdio":
            params = StdioServerParameters(
                command=self.config["command"],
                args=self.config.get("args") or [],
                env={**(self.config.get("env") or {})} or None,
            )
            return stdio_client(params)
        if self.config["transport"] == "sse":
            return sse_client(self.config["url"], headers=self.config.get("headers") or None, timeout=10)
        raise ValueError(f"Unknown transport: {self.config['transport']}")

    async def _serve(self, session) -> None:
        while True:
            op, payload, fut = await self._queue.get()
            if op == "close":
                if not fut.done():
                    fut.set_result(None)
                return
            try:
                if op == "list_tools":
                    result = await session.list_tools()
                    tools = [
                        {"name": t.name, "description": (t.description or "").strip(),
                         "input_schema": t.inputSchema or {"type": "object", "properties": {}}}
                        for t in result.tools
                    ]
                    self.tools = tools
                    fut.set_result(tools)
                elif op == "call_tool":
                    name, arguments = payload
                    result = await asyncio.wait_for(
                        session.call_tool(name, arguments or {}), timeout=MCP_CALL_TIMEOUT
                    )
                    fut.set_result(_format_call_result(result))
                else:
                    fut.set_exception(ValueError(f"Unknown op {op}"))
            except Exception as exc:  # noqa: BLE001
                if not fut.done():
                    fut.set_exception(exc)

    async def request(self, op: str, payload: Any = None, timeout: float = MCP_CALL_TIMEOUT) -> Any:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        await self._queue.put((op, payload, fut))
        return await asyncio.wait_for(fut, timeout=timeout + 5)

    async def stop(self) -> None:
        if self._task and not self._task.done():
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            await self._queue.put(("close", None, fut))
            try:
                await asyncio.wait_for(fut, timeout=10)
            except Exception:  # noqa: BLE001
                pass
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except Exception:  # noqa: BLE001
                self._task.cancel()


def _format_call_result(result) -> dict:
    """Flatten an MCP CallToolResult into a JSON-serializable dict."""
    texts: list[str] = []
    for block in getattr(result, "content", []) or []:
        btype = getattr(block, "type", None)
        if btype == "text":
            texts.append(getattr(block, "text", ""))
        elif btype == "resource":
            res = getattr(block, "resource", None)
            texts.append(getattr(res, "text", "") or str(res))
        else:
            texts.append(str(block))
    return {
        "is_error": bool(getattr(result, "isError", False)),
        "content": "\n".join(t for t in texts if t),
        "structured": getattr(result, "structuredContent", None),
    }


class MCPManager:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._connections: dict[int, _Connection] = {}
        self._lock = threading.RLock()

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, name="mcp-loop", daemon=True)
            self._thread.start()

    def _run_loop(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def shutdown(self) -> None:
        with self._lock:
            if self._loop is None:
                return
            try:
                self._submit(self._close_all(), timeout=15)
            except Exception:  # noqa: BLE001
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)

    def _submit(self, coro, timeout: float = 30):
        assert self._loop is not None
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)

    # -- connect / disconnect ----------------------------------------------
    async def _close_all(self) -> None:
        for conn in list(self._connections.values()):
            try:
                await conn.stop()
            except Exception:  # noqa: BLE001
                pass
        self._connections.clear()

    def connect(self, sid: int) -> MCPServerState:
        self.start()
        config = db.get_mcp_server(sid, reveal=True)
        if not config:
            raise ValueError(f"MCP server id {sid} not found")
        with self._lock:
            return self._submit(self._connect(config), timeout=60)

    async def _connect(self, config: dict) -> MCPServerState:
        sid = config["id"]
        existing = self._connections.get(sid)
        if existing and existing.status == "connected":
            return MCPServerState(sid, config["name"], config["transport"], "connected", "", existing.tools)
        if existing:
            try:
                await existing.stop()
            except Exception:  # noqa: BLE001
                pass
            self._connections.pop(sid, None)
        conn = _Connection(self, config)
        self._connections[sid] = conn
        await conn.start()
        return MCPServerState(sid, config["name"], config["transport"], conn.status, conn.error, conn.tools)

    def disconnect(self, sid: int) -> None:
        with self._lock:
            conn = self._connections.pop(sid, None)
        if conn and self._loop:
            self._submit(conn.stop(), timeout=15)

    # -- queries ------------------------------------------------------------
    def states(self) -> list[dict]:
        out = []
        for srv in db.list_mcp_servers(reveal=False):
            conn = self._connections.get(srv["id"])
            out.append({
                "id": srv["id"],
                "name": srv["name"],
                "transport": srv["transport"],
                "enabled": srv["enabled"],
                "status": conn.status if conn else "disconnected",
                "error": conn.error if conn else "",
                "tool_count": len(conn.tools) if conn else 0,
                "tools": [t["name"] for t in conn.tools] if conn else [],
            })
        return out

    def all_tools(self) -> list[dict]:
        """Return every tool across connected servers, namespaced for the LLM."""
        out = []
        for sid, conn in self._connections.items():
            if conn.status != "connected":
                continue
            for t in conn.tools:
                out.append({
                    "server_id": sid,
                    "server": conn.name,
                    "name": t["name"],
                    "qualified": f"mcp__{conn.name}__{t['name']}",
                    "description": t["description"],
                    "input_schema": t["input_schema"],
                })
        return out

    def call_tool(self, sid: int, tool_name: str, arguments: dict) -> dict:
        conn = self._connections.get(sid)
        if not conn:
            raise ValueError("MCP server is not connected")
        return self._submit(conn.request("call_tool", (tool_name, arguments)), timeout=MCP_CALL_TIMEOUT + 10)

    def call_qualified(self, qualified: str, arguments: dict) -> dict:
        """Call a tool using its `mcp__<server>__<tool>` name."""
        parts = qualified.split("__", 2)
        if len(parts) != 3 or parts[0] != "mcp":
            raise ValueError(f"Not a qualified MCP tool name: {qualified}")
        _, server_name, tool_name = parts
        for sid, conn in self._connections.items():
            if conn.name == server_name and conn.status == "connected":
                return self.call_tool(sid, tool_name, arguments)
        raise ValueError(f"MCP server '{server_name}' is not connected")


manager = MCPManager()
