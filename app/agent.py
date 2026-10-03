"""The control assistant: system prompt, built-in tools, and the tool-calling loop.

This is NOT a coding agent. It is a control assistant that checks, tests and stores
API keys, MCP servers, links, code and notes in a number-letter layered registry, and
keeps a long-term memory layer.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, AsyncGenerator, Callable

import httpx

from . import database as db
from . import memory as memory_layer
from . import security_scan
from . import storage
from .llm import LLMError, get_runtime_config, make_client, parse_response, normalize_base_url
from .mcp_manager import manager as mcp_manager
from .rate_limit import llm_limiter

SYSTEM_PROMPT = """You are "Agent Control Assistant", a personal, private control assistant.
You are NOT a coding agent. You do not write software projects. You CONTROL and MANAGE the
owner's keys, MCP servers, links, code snippets, notes and settings through chat.

Your job, always step by step:
1. CHECK before you store. When the owner gives you an API key, a link, a code snippet or an
   MCP config, first VERIFY it and report the result:
   - API keys / tokens -> use `check_api_key`.
   - Links / endpoints -> use `check_link`.
   - Code / text -> use `scan_code` for safety and leaked secrets.
2. STORE in the number-letter system layer when asked. Everything saved gets a code like
   `A1`, `B2`, `C3`:
   - A = Credentials & API keys, B = MCP servers, C = Links & endpoints,
     D = Code & snippets, E = Notes & configs, F = Memory facts.
   - Use `save_item` with the right `kind` so the layer is chosen automatically, or pass an
     explicit `code`. Report the assigned code back to the owner.
   - Secrets are always stored encrypted. Never echo a secret in full; it is masked.
3. CONTROL on command. Use `list_items`, `search_items`, `get_item`, `delete_item`,
   `layers_overview`, and the MCP tools to control what is stored. Connect/disconnect MCP
   servers and call their tools yourself when asked.
4. REMEMBER. Use `remember` for durable facts about the owner's setup and preferences, and
   `recall` when context is needed. Keep memory tidy with `forget`.

Rules:
- Work autonomously, step by step, until the WHOLE task is done. Do not stop after a single
  tool call and do not ask for permission to continue an obvious sequence. If the owner says
  "check this key", check it AND report the result in full; if they say "check and save",
  do both without pausing in between.
- Show progress as a short numbered task list. After each step, state its status
  (✅ done / ⏳ running / ❌ failed) and then immediately continue to the next step.
- Only pause to ask the owner when a genuine decision is needed (e.g. which of two keys to
  keep, or whether to overwrite an existing item). Never pause just to confirm the next
  obvious step.
- Only save permanently when the owner says save / store / remember / connect. If they gave
  you something and asked to check it, check it; offer to save at the end of your report.
- When the owner gives you a key, a link or code, ALWAYS run the matching check tool and
  report the concrete result (status code, reachability, findings) — never reply with only
  "working" or an acknowledgement.
- Never store plaintext secrets anywhere except through the encrypted tools.
- If you detect a leaked secret in code, warn the owner and offer to save it to the vault.
- Be concise but complete. Report what you checked, the result, the code it was saved under,
  and the remaining next steps.

Available tools: your built-in tools plus any MCP tools named `mcp__<server>__<tool>`.
"""


# --------------------------------------------------------------------------
# Layer / vault tools
# --------------------------------------------------------------------------

def _tool_save_item(kind: str, name: str, value: str, description: str = "",
                    tags: str = "", code: str | None = None) -> dict:
    result = storage.add_item(kind=kind, name=name, value=value, description=description,
                              tags=tags, source="chat", code=code)
    result["stored_encrypted"] = True
    return result


def _tool_get_item(code: str, reveal: bool = False) -> dict:
    item = storage.get_item(code, reveal=reveal)
    if not item:
        return {"ok": False, "error": f"No item with code {code}"}
    return {"ok": True, "item": item}


def _tool_list_items(layer: str | None = None) -> dict:
    items = storage.list_items(layer, reveal=False)
    return {"count": len(items), "items": items}


def _tool_search_items(query: str) -> dict:
    items = storage.search_items(query, reveal=False)
    return {"count": len(items), "items": items}


def _tool_delete_item(code: str) -> dict:
    if storage.delete_item(code):
        return {"ok": True, "deleted": code.strip().upper()}
    return {"ok": False, "error": f"No item with code {code}"}


def _tool_layers_overview() -> dict:
    return {"layers": storage.layers_overview()}


# --------------------------------------------------------------------------
# Memory tools
# --------------------------------------------------------------------------

def _tool_remember(text: str, tags: str = "", importance: int = 3, pinned: bool = False) -> dict:
    return {"ok": True, "memory": memory_layer.remember(text, tags=tags, importance=importance,
                                                        pinned=pinned)}


def _tool_recall(query: str = "", limit: int = 8) -> dict:
    return {"memories": memory_layer.recall(query, limit=limit)}


def _tool_forget(memory_id: int) -> dict:
    return {"ok": memory_layer.forget(memory_id)}


# --------------------------------------------------------------------------
# Check / test tools
# --------------------------------------------------------------------------

def _tool_scan_code(code: str) -> dict:
    findings = security_scan.scan_code(code)
    return {"risk_level": security_scan.risk_level(findings), "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "secrets_detected": security_scan.detect_secrets(code)}


async def _tool_check_link(url: str, method: str = "GET") -> dict:
    """Check whether a link/endpoint is reachable and report status."""
    method = (method or "GET").upper()
    if method not in ("GET", "HEAD", "POST"):
        method = "GET"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            resp = await client.request(method, url, headers={"User-Agent": "AgentControlAssistant/1.0"})
        return {"ok": True, "reachable": True, "status": resp.status_code,
                "final_url": str(resp.url), "content_type": resp.headers.get("content-type", ""),
                "server": resp.headers.get("server", ""), "healthy": resp.status_code < 400}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reachable": False, "error": f"{type(exc).__name__}: {exc}"}


async def _tool_check_api_key(api_key: str, base_url: str | None = None,
                              model: str | None = None) -> dict:
    cfg = get_runtime_config()
    base_url = base_url or cfg["base_url"]
    model = model or cfg["model"] or "gpt-4o-mini"
    try:
        endpoint = normalize_base_url(base_url)
    except LLMError as exc:
        return {"ok": False, "error": str(exc)}
    payload = {"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    await asyncio.to_thread(llm_limiter.acquire)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(endpoint, headers=headers, json=payload)
        if resp.status_code < 400:
            return {"ok": True, "status": resp.status_code, "model": model,
                    "message": f"API key is valid and working (model: {model})."}
        if resp.status_code in (401, 403):
            return {"ok": False, "status": resp.status_code, "error": "API key rejected (invalid or unauthorized)."}
        if resp.status_code == 404:
            # Usually an unknown model on an otherwise valid key/endpoint.
            return {"ok": False, "status": 404, "model": model,
                    "error": f"Endpoint or model not found for model '{model}'. "
                             f"Try detect_best_model to find a working model.",
                    "hint": endpoint}
        if resp.status_code == 429:
            return {"ok": False, "status": 429, "error": "Key works but is rate limited right now."}
        return {"ok": False, "status": resp.status_code, "error": resp.text[:300]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def _tool_detect_best_model(base_url: str | None = None, api_key: str | None = None,
                                  apply: bool = False) -> dict:
    """Probe the provider's models and find one that actually works, then optionally set it."""
    cfg = get_runtime_config()
    base_url = base_url or cfg["base_url"]
    api_key = api_key or cfg["api_key"]
    if not api_key:
        return {"ok": False, "error": "No API key configured."}
    root = normalize_base_url(base_url)
    models_url = root.rsplit("/chat/completions", 1)[0] + "/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(models_url, headers=headers)
        if resp.status_code >= 400:
            return {"ok": False, "error": f"Could not list models ({resp.status_code}): {resp.text[:200]}"}
        ids = [m.get("id") for m in resp.json().get("data", []) if m.get("id")]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    preference = ["flash", "mini", "instant", "nano", "haiku", "lite", "small"]
    def rank(mid: str) -> tuple:
        low = mid.lower()
        return (0 if any(p in low for p in preference) else 1, len(mid))
    candidates = sorted(ids, key=rank)[:12]

    tested, working = [], []
    for mid in candidates:
        await asyncio.to_thread(llm_limiter.acquire)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(root, headers={**headers, "Content-Type": "application/json"},
                                      json={"model": mid, "messages": [{"role": "user", "content": "ping"}],
                                            "max_tokens": 1})
            status = r.status_code
            err = ""
            if status >= 400:
                try:
                    err = (r.json().get("error", {}) or {}).get("message", r.text[:120])
                except Exception:  # noqa: BLE001
                    err = r.text[:120]
            tested.append({"model": mid, "status": status, "error": err[:120]})
            if status < 400:
                working.append(mid)
                break
        except Exception as exc:  # noqa: BLE001
            tested.append({"model": mid, "status": None, "error": f"{type(exc).__name__}: {exc}"})

    if not working:
        return {"ok": False, "error": "No working model found. Check balance / deposit on the provider.",
                "tested": tested, "available_models": len(ids)}
    best = working[0]
    result = {"ok": True, "best_model": best, "tested": tested}
    if apply:
        cfg["model"] = best
        db.set_secret_setting("llm_config", cfg)
        result["applied"] = True
    return result


# --------------------------------------------------------------------------
# MCP tools
# --------------------------------------------------------------------------

def _tool_save_mcp_server(name: str, transport: str = "stdio", command: str = "",
                          args: list[str] | None = None, url: str = "",
                          headers: dict | None = None, env: dict | None = None,
                          enabled: bool = True) -> dict:
    if transport not in ("stdio", "sse"):
        return {"ok": False, "error": "transport must be 'stdio' or 'sse'"}
    if transport == "stdio" and not command:
        return {"ok": False, "error": "stdio transport requires a 'command'"}
    if transport == "sse" and not url:
        return {"ok": False, "error": "sse transport requires a 'url'"}
    sid = db.upsert_mcp_server(name, transport=transport, command=command, args=args or [],
                               env=env or {}, url=url, headers=headers or {}, enabled=enabled)
    code = storage.add_item("mcp", name, {"transport": transport, "command": command,
                                          "args": args or [], "url": url},
                            description="MCP server", source="agent")["code"]
    return {"ok": True, "id": sid, "name": name, "code": code,
            "note": "Secrets in env/headers are stored encrypted."}


def _tool_list_mcp_servers() -> dict:
    return {"servers": mcp_manager.states()}


def _tool_connect_mcp_server(name: str) -> dict:
    srv = db.get_mcp_server_by_name(name, reveal=False)
    if not srv:
        return {"ok": False, "error": f"No MCP server named '{name}'"}
    try:
        state = mcp_manager.connect(srv["id"])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    return {"ok": state.status == "connected", "status": state.status, "error": state.error,
            "tools": [t["name"] for t in state.tools]}


def _tool_disconnect_mcp_server(name: str) -> dict:
    srv = db.get_mcp_server_by_name(name, reveal=False)
    if not srv:
        return {"ok": False, "error": f"No MCP server named '{name}'"}
    mcp_manager.disconnect(srv["id"])
    return {"ok": True, "disconnected": name}


def _tool_delete_mcp_server(name: str) -> dict:
    srv = db.get_mcp_server_by_name(name, reveal=False)
    if not srv:
        return {"ok": False, "error": f"No MCP server named '{name}'"}
    mcp_manager.disconnect(srv["id"])
    db.delete_mcp_server(srv["id"])
    return {"ok": True, "deleted": name}


def _tool_list_mcp_tools(server: str | None = None) -> dict:
    tools = mcp_manager.all_tools()
    if server:
        tools = [t for t in tools if t["server"] == server]
    return {"count": len(tools),
            "tools": [{"qualified": t["qualified"], "server": t["server"], "name": t["name"],
                       "description": t["description"]} for t in tools]}


def _tool_call_mcp_tool(server: str, tool: str, arguments: dict | None = None) -> dict:
    srv = db.get_mcp_server_by_name(server, reveal=False)
    if not srv:
        return {"ok": False, "error": f"No MCP server named '{server}'"}
    try:
        return {"ok": True, "result": mcp_manager.call_tool(srv["id"], tool, arguments or {})}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------
# LLM config tools
# --------------------------------------------------------------------------

def _tool_get_llm_config() -> dict:
    cfg = get_runtime_config()
    safe = dict(cfg)
    safe["api_key"] = _mask(cfg["api_key"])
    safe["api_key_configured"] = bool(cfg["api_key"])
    safe["rate_limit_status"] = llm_limiter.snapshot()
    return safe


def _tool_set_llm_config(base_url: str | None = None, model: str | None = None,
                         rate_limit: int | None = None, temperature: float | None = None,
                         api_key: str | None = None) -> dict:
    cfg = db.get_secret_setting("llm_config") or {}
    if api_key:
        cfg["api_key"] = api_key
    if base_url:
        cfg["base_url"] = base_url
    if model:
        cfg["model"] = model
    if rate_limit is not None:
        llm_limiter.set_limit(rate_limit)
        cfg["rate_limit"] = llm_limiter.limit
    if temperature is not None:
        cfg["temperature"] = max(0.0, min(float(temperature), 2.0))
    db.set_secret_setting("llm_config", cfg)
    safe = dict(cfg)
    if "api_key" in safe:
        safe["api_key"] = _mask(safe["api_key"])
    return {"ok": True, "config": safe}


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


# --------------------------------------------------------------------------
# Session / health tools
# --------------------------------------------------------------------------

def _tool_health_report() -> dict:
    cfg = get_runtime_config()
    try:
        states = mcp_manager.states()
    except Exception:  # noqa: BLE001
        states = []
    layers = storage.layers_overview()
    mems = memory_layer.list_memories(limit=1000)
    return {
        "llm": {"configured": bool(cfg["api_key"]), "model": cfg["model"],
                "base_url": cfg["base_url"], "rate_limit_per_min": cfg["rate_limit"]},
        "rate_status": llm_limiter.snapshot(),
        "layers": {l["letter"]: l["count"] for l in layers},
        "items_total": sum(l["count"] for l in layers),
        "memories": len(mems),
        "mcp_servers": [{"name": s.get("name"), "status": s.get("status"),
                         "tools": len(s.get("tools") or [])} for s in states],
        "app_mcp": {"sse_path": "/mcp/sse", "exposed_tools": len(tool_definitions())},
        "healthy": bool(cfg["api_key"]),
    }


def _tool_list_chat_sessions() -> dict:
    return {"sessions": db.list_sessions()}


def _tool_read_chat_session(session_id: str, limit: int = 30) -> dict:
    msgs = db.get_messages(session_id, limit=limit)
    return {"session_id": session_id, "count": len(msgs),
            "messages": [{"role": m["role"], "content": m["content"][:800]} for m in msgs]}


# --------------------------------------------------------------------------
# Planner / verifier (multi-agent)
# --------------------------------------------------------------------------

PLANNER_PROMPT = (
    "You are the PLANNER of a control assistant. Break the owner's request into a short, "
    "ordered list of concrete steps (at most 6). Each step must be one action achievable "
    "with a tool (check a key, check a link, scan code, save an item, remember, connect MCP, "
    "call an MCP tool, update settings). Reply with ONLY a numbered list — no preamble, no "
    "explanation. If the request is a single action, return a single step."
)

VERIFIER_PROMPT = (
    "You are the VERIFIER of a control assistant. Given the owner's original request and the "
    "actions that were taken, decide whether the task is fully complete. Reply with ONLY a "
    "JSON object: {\"complete\": true|false, \"missing\": \"<short description or empty>\", "
    "\"next\": \"<one concrete next action, or empty>\"}. Be strict, but do not invent work "
    "the owner did not ask for. If everything the owner asked for is done, set complete=true."
)


async def _make_plan(client, user_message: str, cfg: dict) -> list[str]:
    try:
        raw = await client.chat(
            [{"role": "system", "content": PLANNER_PROMPT},
             {"role": "user", "content": user_message}],
            tools=None, temperature=0.0)
        text = parse_response(raw)["content"] or ""
    except Exception:  # noqa: BLE001
        return []
    plan = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^\s*(?:\d+[.)]|[-*])\s+(.*)$", line)
        if m:
            plan.append(m.group(1).strip())
    return plan[:6]


def _transcript_summary(messages: list[dict], limit: int = 40) -> str:
    lines = []
    for m in messages[-limit:]:
        role = m.get("role")
        if role == "tool":
            lines.append(f"tool result: {str(m.get('content',''))[:240]}")
        elif role == "assistant" and m.get("tool_calls"):
            names = [tc["function"]["name"] for tc in m["tool_calls"]]
            lines.append("called: " + ", ".join(names))
        elif role == "assistant" and m.get("content"):
            lines.append("said: " + str(m["content"])[:240])
    return "\n".join(lines) or "(no actions taken)"


async def _verify(client, user_message: str, messages: list[dict], cfg: dict) -> dict:
    try:
        raw = await client.chat(
            [{"role": "system", "content": VERIFIER_PROMPT},
             {"role": "user", "content":
              f"Owner request:\n{user_message}\n\nActions taken:\n{_transcript_summary(messages)}"}],
            tools=None, temperature=0.0)
        text = parse_response(raw)["content"] or ""
    except Exception:  # noqa: BLE001
        return {"complete": True, "missing": "", "next": ""}
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"complete": True, "missing": "", "next": ""}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"complete": True, "missing": "", "next": ""}
    return {"complete": bool(data.get("complete")),
            "missing": str(data.get("missing") or ""),
            "next": str(data.get("next") or "")}


# --------------------------------------------------------------------------
# Tool registry
# --------------------------------------------------------------------------

Tool = dict[str, Any]
_REGISTRY: dict[str, Callable[..., Any]] = {
    "save_item": _tool_save_item,
    "get_item": _tool_get_item,
    "list_items": _tool_list_items,
    "search_items": _tool_search_items,
    "delete_item": _tool_delete_item,
    "layers_overview": _tool_layers_overview,
    "remember": _tool_remember,
    "recall": _tool_recall,
    "forget": _tool_forget,
    "scan_code": _tool_scan_code,
    "check_link": _tool_check_link,
    "check_api_key": _tool_check_api_key,
    "detect_best_model": _tool_detect_best_model,
    "save_mcp_server": _tool_save_mcp_server,
    "list_mcp_servers": _tool_list_mcp_servers,
    "connect_mcp_server": _tool_connect_mcp_server,
    "disconnect_mcp_server": _tool_disconnect_mcp_server,
    "delete_mcp_server": _tool_delete_mcp_server,
    "list_mcp_tools": _tool_list_mcp_tools,
    "call_mcp_tool": _tool_call_mcp_tool,
    "get_llm_config": _tool_get_llm_config,
    "set_llm_config": _tool_set_llm_config,
    "health_report": _tool_health_report,
    "list_chat_sessions": _tool_list_chat_sessions,
    "read_chat_session": _tool_read_chat_session,
}

_OBJ = {"type": "object", "properties": {}}

BUILTIN_TOOLS: list[Tool] = [
    {"type": "function", "function": {
        "name": "save_item",
        "description": "Permanently store an item in the number-letter system layer (encrypted). "
                       "kind chooses the layer: api_key/token/password->A, mcp->B, link/url->C, "
                       "code->D, note/config->E, fact->F. Returns the assigned code like A1.",
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string"}, "name": {"type": "string"}, "value": {"type": "string"},
            "description": {"type": "string"}, "tags": {"type": "string"},
            "code": {"type": "string", "description": "Optional explicit code to overwrite."}},
            "required": ["kind", "name", "value"]}}},
    {"type": "function", "function": {
        "name": "get_item",
        "description": "Fetch a stored item by its code (e.g. A1). Secrets are masked unless reveal=true.",
        "parameters": {"type": "object", "properties": {
            "code": {"type": "string"}, "reveal": {"type": "boolean"}}, "required": ["code"]}}},
    {"type": "function", "function": {
        "name": "list_items",
        "description": "List stored items, optionally filtered by layer letter (A-F).",
        "parameters": {"type": "object", "properties": {"layer": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "search_items",
        "description": "Search stored items by name, description, tags or code.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}},
                       "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "delete_item",
        "description": "Delete a stored item by its code.",
        "parameters": {"type": "object", "properties": {"code": {"type": "string"}},
                       "required": ["code"]}}},
    {"type": "function", "function": {
        "name": "layers_overview",
        "description": "Show the number-letter layers (A-F) and how many items each holds.",
        "parameters": _OBJ}},
    {"type": "function", "function": {
        "name": "remember",
        "description": "Save a durable fact to long-term memory.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string"}, "tags": {"type": "string"},
            "importance": {"type": "integer", "description": "1-5"},
            "pinned": {"type": "boolean"}}, "required": ["text"]}}},
    {"type": "function", "function": {
        "name": "recall",
        "description": "Recall memories relevant to a query.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "forget",
        "description": "Delete a memory by id.",
        "parameters": {"type": "object", "properties": {"memory_id": {"type": "integer"}},
                       "required": ["memory_id"]}}},
    {"type": "function", "function": {
        "name": "scan_code",
        "description": "Security-scan code or text for leaked secrets and dangerous patterns.",
        "parameters": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}}},
    {"type": "function", "function": {
        "name": "check_link",
        "description": "Check whether a link/endpoint is reachable and report its HTTP status.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}, "method": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "check_api_key",
        "description": "Validate an API key with a minimal test request against an OpenAI-compatible endpoint.",
        "parameters": {"type": "object", "properties": {
            "api_key": {"type": "string"}, "base_url": {"type": "string"}, "model": {"type": "string"}},
            "required": ["api_key"]}}},
    {"type": "function", "function": {
        "name": "detect_best_model",
        "description": "List the provider's models, test which one works, and optionally apply the best one.",
        "parameters": {"type": "object", "properties": {
            "base_url": {"type": "string"}, "api_key": {"type": "string"},
            "apply": {"type": "boolean"}}}}},
    {"type": "function", "function": {
        "name": "save_mcp_server",
        "description": "Save an MCP server config (stdio or sse). env/headers are encrypted.",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string"}, "transport": {"type": "string", "enum": ["stdio", "sse"]},
            "command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}},
            "url": {"type": "string"}, "headers": {"type": "object"}, "env": {"type": "object"},
            "enabled": {"type": "boolean"}}, "required": ["name", "transport"]}}},
    {"type": "function", "function": {
        "name": "list_mcp_servers",
        "description": "List configured MCP servers with their connection status.", "parameters": _OBJ}},
    {"type": "function", "function": {
        "name": "connect_mcp_server",
        "description": "Connect to a configured MCP server and discover its tools.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "disconnect_mcp_server",
        "description": "Disconnect a connected MCP server.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "delete_mcp_server",
        "description": "Delete an MCP server configuration.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "list_mcp_tools",
        "description": "List tools exposed by connected MCP servers.",
        "parameters": {"type": "object", "properties": {"server": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "call_mcp_tool",
        "description": "Call a tool on a connected MCP server.",
        "parameters": {"type": "object", "properties": {
            "server": {"type": "string"}, "tool": {"type": "string"},
            "arguments": {"type": "object"}}, "required": ["server", "tool"]}}},
    {"type": "function", "function": {
        "name": "get_llm_config",
        "description": "Get the current AI model config (key masked) and rate-limit status.", "parameters": _OBJ}},
    {"type": "function", "function": {
        "name": "set_llm_config",
        "description": "Update base_url, model, per-minute rate limit, temperature or api_key.",
        "parameters": {"type": "object", "properties": {
            "base_url": {"type": "string"}, "model": {"type": "string"},
            "rate_limit": {"type": "integer"}, "temperature": {"type": "number"},
            "api_key": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "health_report",
        "description": "Full system health: LLM config, rate-limit status, layer item counts, "
                       "memory count, MCP servers and their status, and how many tools this app "
                       "exposes as an MCP server.", "parameters": _OBJ}},
    {"type": "function", "function": {
        "name": "list_chat_sessions",
        "description": "List all chat sessions.", "parameters": _OBJ}},
    {"type": "function", "function": {
        "name": "read_chat_session",
        "description": "Read the recent messages of a chat session by id.",
        "parameters": {"type": "object", "properties": {
            "session_id": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["session_id"]}}},
]


def _mcp_tool_schemas() -> list[Tool]:
    schemas = []
    for t in mcp_manager.all_tools():
        params = t["input_schema"] or {"type": "object", "properties": {}}
        if "type" not in params:
            params = {"type": "object", "properties": params.get("properties", {})}
        schemas.append({"type": "function", "function": {
            "name": t["qualified"],
            "description": f"[MCP:{t['server']}] {t['description']}"[:1024],
            "parameters": params,
        }})
    return schemas


async def _dispatch(name: str, arguments: dict) -> Any:
    if name.startswith("mcp__"):
        return mcp_manager.call_qualified(name, arguments)
    fn = _REGISTRY.get(name)
    if fn is None:
        raise ValueError(f"Unknown tool: {name}")
    if asyncio.iscoroutinefunction(fn):
        return await fn(**arguments)
    return await asyncio.to_thread(fn, **arguments)


def dispatch_sync(name: str, arguments: dict) -> Any:
    """Synchronous dispatch used by the app's own MCP server."""
    if name.startswith("mcp__"):
        return mcp_manager.call_qualified(name, arguments)
    fn = _REGISTRY.get(name)
    if fn is None:
        raise ValueError(f"Unknown tool: {name}")
    if asyncio.iscoroutinefunction(fn):
        return asyncio.run(fn(**arguments))
    return fn(**arguments)


def tool_definitions() -> list[dict]:
    """Public list of built-in tools for the app's own MCP server."""
    return [{"name": t["function"]["name"], "description": t["function"]["description"],
             "parameters": t["function"]["parameters"]} for t in BUILTIN_TOOLS]


# --------------------------------------------------------------------------
# Agent loop
# --------------------------------------------------------------------------

def build_messages(history: list[dict], user_message: str) -> list[dict]:
    system = SYSTEM_PROMPT
    mem = memory_layer.build_memory_context(user_message)
    if mem:
        system = system + "\n\n" + mem
    messages = [{"role": "system", "content": system}]
    for m in history:
        role = m["role"]
        if role == "tool":
            messages.append({"role": "tool", "tool_call_id": m.get("tool_call_id", ""),
                             "content": m["content"]})
        elif role == "assistant" and m.get("tool_calls"):
            messages.append({"role": "assistant", "content": m.get("content") or "",
                             "tool_calls": [
                                 {"id": tc["id"], "type": "function",
                                  "function": {"name": tc["name"],
                                               "arguments": json.dumps(tc.get("arguments", {}))}}
                                 for tc in m["tool_calls"]]})
        else:
            messages.append({"role": role, "content": m["content"]})
    messages.append({"role": "user", "content": user_message})
    return messages


async def run_agent(user_message: str, history: list[dict],
                    max_steps: int | None = None,
                    mode: str = "auto") -> AsyncGenerator[dict, None]:
    cfg = get_runtime_config()
    if not cfg["api_key"]:
        yield {"type": "error", "message": "LLM API key is not configured. Open Settings to add one."}
        yield {"type": "done"}
        return
    try:
        client = make_client(cfg)
    except LLMError as exc:
        yield {"type": "error", "message": str(exc)}
        yield {"type": "done"}
        return

    steps = max_steps or cfg["max_steps"]
    hard_cap = max(steps, 60)
    messages = build_messages(history, user_message)
    tools = BUILTIN_TOOLS + _mcp_tool_schemas()
    step_no = 0

    # ---- Multi-agent phase 1: PLAN ----
    use_plan = mode in ("auto", "plan")
    if use_plan:
        yield {"type": "status", "message": "planning…"}
        plan = await _make_plan(client, user_message, cfg)
        if plan:
            yield {"type": "plan", "steps": plan}
            messages.append({"role": "system", "content":
                             "Planned steps for this request:\n" +
                             "\n".join(f"{i+1}. {s}" for i, s in enumerate(plan)) +
                             "\nWork through them in order using your tools."})

    # ---- Multi-agent phase 2: EXECUTE ----
    for _step in range(hard_cap):
        try:
            raw = await client.chat(messages, tools=tools, temperature=cfg["temperature"])
        except LLMError as exc:
            yield {"type": "error", "message": str(exc)}
            yield {"type": "done"}
            return

        parsed = parse_response(raw)
        if parsed["content"] and parsed["content"].strip():
            yield {"type": "assistant", "content": parsed["content"]}

        if not parsed["tool_calls"]:
            # ---- Multi-agent phase 3: VERIFY (only once the model stops acting) ----
            if use_plan and step_no > 0:
                verdict = await _verify(client, user_message, messages, cfg)
                if not verdict["complete"] and verdict.get("next"):
                    yield {"type": "status", "message": "verifying… continuing: " + verdict["next"][:60]}
                    messages.append({"role": "user", "content":
                                     f"The task is not complete yet. {verdict['missing']}\n"
                                     f"Next: {verdict['next']}\nContinue now using your tools."})
                    continue
            break

        messages.append({
            "role": "assistant", "content": parsed["content"],
            "tool_calls": [{"id": tc["id"], "type": "function",
                            "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
                           for tc in parsed["tool_calls"]],
        })

        for tc in parsed["tool_calls"]:
            step_no += 1
            yield {"type": "step", "n": step_no, "status": "running", "name": tc["name"],
                   "arguments": tc["arguments"]}
            try:
                result = await _dispatch(tc["name"], tc["arguments"])
                result_text = json.dumps(result, default=str)
                ok = not (isinstance(result, dict) and result.get("ok") is False)
                yield {"type": "tool_call", "id": tc["id"], "name": tc["name"], "arguments": tc["arguments"]}
                yield {"type": "tool_result", "id": tc["id"], "name": tc["name"], "ok": ok, "result": result}
                yield {"type": "step", "n": step_no, "status": "done" if ok else "failed",
                       "name": tc["name"], "ok": ok}
            except Exception as exc:  # noqa: BLE001
                result_text = json.dumps({"error": str(exc)})
                yield {"type": "tool_call", "id": tc["id"], "name": tc["name"], "arguments": tc["arguments"]}
                yield {"type": "tool_result", "id": tc["id"], "name": tc["name"], "ok": False, "error": str(exc)}
                yield {"type": "step", "n": step_no, "status": "failed", "name": tc["name"], "ok": False,
                       "error": str(exc)}
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result_text})

    if step_no >= hard_cap:
        yield {"type": "assistant",
               "content": f"⏳ Reached the safety cap of {hard_cap} steps. The task may be unfinished — "
                          f"reply **continue** and I will keep going."}
    yield {"type": "done", "rate_limit": llm_limiter.snapshot()}
