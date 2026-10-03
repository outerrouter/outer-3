"""FastAPI application: routes for auth, settings, credentials, MCP, and chat."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth
from . import database as db
from . import memory as memory_layer
from . import security_scan
from . import storage
from .agent import run_agent
from .app_mcp import get_or_create_token, regenerate_token, sse_transport, server as mcp_server, _token_ok
from .config import STATIC_DIR
from .llm import get_runtime_config, is_configured, llm_limiter, make_client, normalize_base_url, LLMError
from .mcp_manager import manager as mcp_manager
from mcp import types
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

MASK = lambda v: "" if not v else (("*" * len(v)) if len(v) <= 8 else f"{v[:4]}{'*'*(len(v)-8)}{v[-4:]}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.ensure_password_initialized()
    storage.ensure_schema()
    memory_layer.ensure_schema()
    mcp_manager.start()
    yield
    mcp_manager.shutdown()


app = FastAPI(title="Agent Control Assistant", lifespan=lifespan, docs_url=None, redoc_url=None)

protected = Depends(auth.require_session)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'"
    )
    return response


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class LoginBody(BaseModel):
    password: str


class PasswordBody(BaseModel):
    current_password: str
    new_password: str = Field(min_length=4)


class LLMBody(BaseModel):
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None
    rate_limit: int | None = None
    temperature: float | None = None
    max_steps: int | None = None


class CredentialBody(BaseModel):
    name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    kind: str = "api_key"
    description: str = ""


class MCPBody(BaseModel):
    name: str = Field(min_length=1)
    transport: str = "stdio"
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict = Field(default_factory=dict)
    url: str = ""
    headers: dict = Field(default_factory=dict)
    enabled: bool = True


class ScanBody(BaseModel):
    code: str


class ChatBody(BaseModel):
    session_id: str = "default"
    message: str = Field(min_length=1)


class CallBody(BaseModel):
    tool: str
    arguments: dict = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

@app.get("/api/auth/status")
async def auth_status(request: Request):
    token = auth._extract_token(request)
    return {"authenticated": auth.validate_token(token), "password_set": db.get_setting("password_hash") is not None}


@app.post("/api/auth/login")
async def login(body: LoginBody, request: Request):
    token = auth.login(body.password, request)
    resp = JSONResponse({"ok": True, "token": token})
    resp.set_cookie("session", token, httponly=True, samesite="strict", max_age=60 * 60 * 12)
    return resp


@app.post("/api/auth/logout")
async def logout(request: Request):
    auth.logout(auth._extract_token(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


@app.post("/api/auth/password")
async def change_password(body: PasswordBody, request: Request, _=protected):
    stored = db.get_setting("password_hash")
    if not stored or not auth.verify_password(body.current_password, stored):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    auth.set_password(body.new_password)
    return {"ok": True}


# --------------------------------------------------------------------------
# LLM settings
# --------------------------------------------------------------------------

@app.get("/api/llm")
async def get_llm(_=protected):
    cfg = get_runtime_config()
    return {
        "configured": is_configured(),
        "api_key_masked": MASK(cfg["api_key"]),
        "api_key_set": bool(cfg["api_key"]),
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "rate_limit": cfg["rate_limit"],
        "temperature": cfg["temperature"],
        "max_steps": cfg["max_steps"],
        "rate_status": llm_limiter.snapshot(),
    }


@app.put("/api/llm")
async def set_llm(body: LLMBody, _=protected):
    cfg = db.get_secret_setting("llm_config") or {}
    if body.api_key:
        cfg["api_key"] = body.api_key
    if body.base_url is not None:
        cfg["base_url"] = body.base_url
    if body.model is not None:
        cfg["model"] = body.model
    if body.rate_limit is not None:
        llm_limiter.set_limit(body.rate_limit)
        cfg["rate_limit"] = llm_limiter.limit
    if body.temperature is not None:
        cfg["temperature"] = max(0.0, min(float(body.temperature), 2.0))
    if body.max_steps is not None:
        cfg["max_steps"] = max(1, min(int(body.max_steps), 30))
    db.set_secret_setting("llm_config", cfg)
    cfg_out = dict(cfg)
    cfg_out["api_key"] = MASK(cfg.get("api_key", ""))
    return {"ok": True, "config": cfg_out}


@app.post("/api/llm/test")
async def test_llm(body: LLMBody, _=protected):
    cfg = get_runtime_config()
    api_key = body.api_key or cfg["api_key"]
    base_url = body.base_url or cfg["base_url"]
    model = body.model or cfg["model"]
    if not api_key:
        raise HTTPException(status_code=400, detail="No API key provided.")
    try:
        client = make_client({"api_key": api_key, "base_url": base_url, "model": model,
                              "rate_limit": cfg["rate_limit"], "temperature": 0.0, "max_steps": 1})
        await client.chat([{"role": "user", "content": "ping"}], tools=None, temperature=0.0)
        return {"ok": True, "message": "Connection successful."}
    except LLMError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)


@app.get("/api/llm/rate")
async def rate_status(_=protected):
    return llm_limiter.snapshot()


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

@app.get("/api/credentials")
async def list_creds(_=protected):
    return {"credentials": db.list_credentials()}


@app.post("/api/credentials")
async def create_cred(body: CredentialBody, _=protected):
    findings = security_scan.scan_code(body.value)
    cid = db.upsert_credential(body.name, body.value, kind=body.kind, description=body.description)
    return {"ok": True, "id": cid, "scan": {"risk_level": security_scan.risk_level(findings),
                                            "finding_count": len(findings)}}


@app.delete("/api/credentials/{cid}")
async def delete_cred(cid: int, _=protected):
    if not db.delete_credential(cid):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


# --------------------------------------------------------------------------
# MCP
# --------------------------------------------------------------------------

@app.get("/api/mcp")
async def list_mcp(_=protected):
    return {"servers": mcp_manager.states()}


@app.post("/api/mcp")
async def create_mcp(body: MCPBody, _=protected):
    if body.transport not in ("stdio", "sse"):
        raise HTTPException(status_code=400, detail="transport must be 'stdio' or 'sse'")
    if body.transport == "stdio" and not body.command:
        raise HTTPException(status_code=400, detail="stdio transport requires a command")
    if body.transport == "sse" and not body.url:
        raise HTTPException(status_code=400, detail="sse transport requires a url")
    sid = db.upsert_mcp_server(body.name, transport=body.transport, command=body.command,
                               args=body.args, env=body.env, url=body.url, headers=body.headers,
                               enabled=body.enabled)
    return {"ok": True, "id": sid}


@app.delete("/api/mcp/{sid}")
async def delete_mcp(sid: int, _=protected):
    mcp_manager.disconnect(sid)
    if not db.delete_mcp_server(sid):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.post("/api/mcp/{sid}/connect")
async def connect_mcp(sid: int, _=protected):
    try:
        state = mcp_manager.connect(sid)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": state.status == "connected", "status": state.status, "error": state.error,
            "tools": [t["name"] for t in state.tools]}


@app.post("/api/mcp/{sid}/disconnect")
async def disconnect_mcp(sid: int, _=protected):
    mcp_manager.disconnect(sid)
    return {"ok": True}


@app.get("/api/mcp/tools")
async def mcp_tools(_=protected):
    return {"tools": mcp_manager.all_tools()}


@app.post("/api/mcp/{sid}/call")
async def call_mcp(sid: int, body: CallBody, _=protected):
    try:
        return {"ok": True, "result": mcp_manager.call_tool(sid, body.tool, body.arguments)}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)


# --------------------------------------------------------------------------
# Security scan
# --------------------------------------------------------------------------

@app.post("/api/scan")
async def scan(body: ScanBody, _=protected):
    findings = security_scan.scan_code(body.code)
    return {
        "risk_level": security_scan.risk_level(findings),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "secrets_detected": security_scan.detect_secrets(body.code),
    }


# --------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------

@app.get("/api/chat/sessions")
async def chat_sessions(_=protected):
    return {"sessions": db.list_sessions()}


@app.get("/api/chat/{session_id}/messages")
async def chat_messages(session_id: str, _=protected):
    return {"messages": db.get_messages(session_id)}


@app.delete("/api/chat/{session_id}")
async def clear_chat(session_id: str, _=protected):
    db.clear_messages(session_id)
    return {"ok": True}


CONTINUE_WORDS = {"continue", "চালিয়ে যাও", "চালাও", "go on", "keep going", "next", "পরবর্তী"}


@app.post("/api/chat/stream")
async def chat_stream(body: ChatBody, _=protected):
    history = db.get_messages(body.session_id)
    user_msg_id = db.add_message(body.session_id, "user", body.message)

    async def event_stream():
        assistant_text: list[str] = []
        had_error = False
        try:
            async for event in run_agent(body.message, history):
                if event["type"] == "assistant":
                    if event["content"].strip():
                        assistant_text.append(event["content"])
                elif event["type"] == "error":
                    had_error = True
                yield f"data: {json.dumps(event, default=str)}\n\n"
        except Exception as exc:  # noqa: BLE001
            had_error = True
            err = {"type": "error", "message": f"{type(exc).__name__}: {exc}"}
            yield f"data: {json.dumps(err)}\n\n"
        finally:
            final = "\n\n".join(t for t in assistant_text if t).strip()
            if had_error and not final:
                # Nothing useful was produced — drop this turn so history stays clean.
                db.clear_messages(body.session_id, keep_after_id=user_msg_id)
            elif final:
                db.add_message(body.session_id, "assistant", final)
            yield "data: {\"type\": \"end\"}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------
# Number-letter system layers
# --------------------------------------------------------------------------

class ItemBody(BaseModel):
    kind: str = "note"
    name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    description: str = ""
    tags: str = ""
    code: str | None = None


class MemoryBody(BaseModel):
    text: str = Field(min_length=1)
    tags: str = ""
    importance: int = 3
    pinned: bool = False


@app.get("/api/layers")
async def layers(_=protected):
    return {"layers": storage.layers_overview()}


@app.get("/api/items")
async def list_items(layer: str | None = None, _=protected):
    return {"items": storage.list_items(layer, reveal=False)}


@app.get("/api/items/search")
async def search_items(q: str, _=protected):
    return {"items": storage.search_items(q, reveal=False)}


@app.post("/api/items")
async def create_item(body: ItemBody, _=protected):
    result = storage.add_item(kind=body.kind, name=body.name, value=body.value,
                              description=body.description, tags=body.tags,
                              source="ui", code=body.code)
    result["stored_encrypted"] = True
    return {"ok": True, **result}


@app.get("/api/items/{code}")
async def get_item(code: str, reveal: bool = False, _=protected):
    item = storage.get_item(code, reveal=reveal)
    if not item:
        raise HTTPException(status_code=404, detail=f"No item with code {code}")
    return {"item": item}


@app.delete("/api/items/{code}")
async def delete_item(code: str, _=protected):
    if not storage.delete_item(code):
        raise HTTPException(status_code=404, detail=f"No item with code {code}")
    return {"ok": True}


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------

@app.get("/api/memory")
async def list_memory(q: str | None = None, _=protected):
    if q:
        return {"memories": memory_layer.recall(q, limit=50)}
    return {"memories": memory_layer.list_memories()}


@app.post("/api/memory")
async def create_memory(body: MemoryBody, _=protected):
    return {"ok": True, "memory": memory_layer.remember(
        body.text, tags=body.tags, importance=body.importance, pinned=body.pinned, source="ui")}


class MemoryPatch(BaseModel):
    text: str | None = None
    tags: str | None = None
    importance: int | None = None
    pinned: bool | None = None


@app.put("/api/memory/{mid}")
async def update_memory(mid: int, body: MemoryPatch, _=protected):
    if not memory_layer.update_memory(mid, text=body.text, tags=body.tags,
                                      importance=body.importance, pinned=body.pinned):
        raise HTTPException(status_code=404, detail="Not found or nothing to update")
    return {"ok": True}


@app.delete("/api/memory/{mid}")
async def delete_memory(mid: int, _=protected):
    if not memory_layer.forget(mid):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


# --------------------------------------------------------------------------
# This app's own MCP server (external control)
# --------------------------------------------------------------------------

class TokenBody(BaseModel):
    regenerate: bool = False


@app.get("/api/app-mcp/info")
async def app_mcp_info(request: Request, _=protected):
    token = get_or_create_token()
    base = str(request.base_url).rstrip("/")
    return {
        "name": "agent-control-assistant",
        "sse_url": f"{base}/mcp/sse",
        "messages_url": f"{base}/mcp/messages",
        "token": token,
        "auth": "Send 'Authorization: Bearer <token>' or add '?token=<token>' to the SSE URL.",
        "tools": [t["name"] for t in __import__("app.agent", fromlist=["tool_definitions"]).tool_definitions()],
    }


@app.post("/api/app-mcp/token")
async def app_mcp_token(body: TokenBody, _=protected):
    token = regenerate_token() if body.regenerate else get_or_create_token()
    return {"ok": True, "token": token}


@app.get("/mcp/sse")
async def mcp_sse(request: StarletteRequest):
    if not _token_ok(request.headers.get("authorization"), request.query_params.get("token")):
        return StarletteResponse("Unauthorized", status_code=401)
    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())
    return StarletteResponse()


@app.post("/mcp/messages")
async def mcp_messages(request: StarletteRequest):
    # The MCP SSE client links back to this endpoint using an unguessable session_id
    # that was issued only to an authenticated SSE connection, so it is not required to
    # repeat the bearer token here. A token, if sent, must still be valid.
    auth = request.headers.get("authorization")
    token = request.query_params.get("token")
    if (auth or token) and not _token_ok(auth, token):
        return StarletteResponse("Unauthorized", status_code=401)
    await sse_transport.handle_post_message(request.scope, request.receive, request._send)
    return StarletteResponse()


# --------------------------------------------------------------------------
# Static frontend
# --------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
