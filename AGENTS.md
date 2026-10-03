# AGENTS.md

Repository knowledge for AI coding agents working on **Agent Control Assistant**.

## What this is
A local, single-user, password-locked, chat-based AI **control** assistant (not a coding
agent). FastAPI backend + vanilla JS frontend. It checks/tests API keys, MCP servers, links
and code, stores them in a number-letter layered registry (encrypted), keeps a long-term
memory layer, and exposes itself as an MCP server so external clients can control it.
Secrets are encrypted at rest.

## Commands
- Run: `./run.sh` (installs deps, starts uvicorn on `$HOST:$PORT`, default `0.0.0.0:8000`)
- Supervised run: `./run_server.sh 8000` (restarts uvicorn if it exits; log in `data/server-8000.log`)
- Dev run: `.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000`
- Install: `.venv/bin/pip install -r requirements.txt`
- Import check: `.venv/bin/python -c "from app.main import app; print('ok')"`
- There is no formal test suite. Verify changes by hitting the REST API with curl
  (see README "API reference") and by exercising the UI.

## Architecture
- `app/main.py` — FastAPI routes, SSE chat streaming, static file serving, and the app's own
  MCP server (`/mcp/sse`, `/mcp/messages`). All `/api/*` routes except
  `auth/status|login|logout` depend on `auth.require_session`.
- `app/storage.py` — number-letter system layers. Letter = layer (A creds, B mcp, C links,
  D code, E notes, F memory facts); number = slot. `kind` maps to a layer automatically.
  Values are encrypted; reads are masked unless `reveal=True`.
- `app/memory.py` — long-term memory (tags, importance, pinning, recency-decayed recall).
  `build_memory_context()` is injected into the system prompt.
- `app/agent.py` — control-assistant system prompt, `_REGISTRY` of built-in tools,
  `BUILTIN_TOOLS` schemas, and the multi-agent engine `run_agent()`. `run_agent` runs three
  phases: **PLAN** (`_make_plan`, emits `plan`/`status` events), **EXECUTE** (tool loop, emits
  `step`/`tool_call`/`tool_result`/`assistant`), and **VERIFY** (`_verify`, may re-drive the
  executor). It continues internally past the soft step budget up to a hard cap (60) so long
  tasks finish in one turn. `dispatch_sync` is used by the app's MCP server.
- `app/app_mcp.py` — the app's own MCP server (lowlevel `Server` + `SseServerTransport`),
  exposing every built-in tool; bearer token stored in settings.
- `app/llm.py` — OpenAI-compatible client; `normalize_base_url` accepts a base URL or a
  full `/chat/completions` URL. Uses the shared `llm_limiter`.
- `app/mcp_manager.py` — runs a dedicated asyncio loop in a background thread; keeps
  persistent MCP sessions; sync wrappers (`connect`, `call_tool`, `states`, `all_tools`).
  MCP tools are namespaced `mcp__<server>__<tool>`.
- `app/database.py` — SQLite (WAL). Secrets go through `encrypt_json`/`decrypt_json`.
- `app/crypto.py` — Fernet (key at `data/master.key`, 0600) + PBKDF2 password hashing.
- `app/auth.py` — password lock, in-memory session tokens, per-IP brute-force lockout.
- `app/rate_limit.py` — sliding-window per-minute limiter; default 10 (`DEFAULT_RATE_LIMIT`).
- `app/security_scan.py` — regex scanner for secrets and dangerous code.

## Conventions
- Keep the "check before store" flow: check tools first, save only on explicit request.
- Never store plaintext secrets. Use the encrypted stores (`storage`, `db.set_secret_setting`,
  MCP `env`/`headers`) and mask secrets in output (`MASK`, `_mask`).
- Keep `data/` git-ignored. It holds `assistant.db` and `master.key`.
- Add new agent tools in `app/agent.py`: a `_tool_*` function, a `_REGISTRY` entry, and a
  `BUILTIN_TOOLS` schema. `_REGISTRY` is the single source of truth — tools are exposed
  automatically through both the agent and the app's MCP server. Sync functions are
  auto-run via `asyncio.to_thread`.
- Frontend is dependency-free (no build step): `app/static/{index.html,css/styles.css,js/app.js}`.
  Mobile-first: the sidebar is a slide-in drawer under 900px (`#menu-btn`/`#control-btn` open it);
  `.sidebar.open` + `.sidebar-backdrop.show` drive it. Assistant replies are rendered with the
  XSS-safe `renderMarkdown()` (headings, lists, tables, code, blockquotes) — never re-add
  `white-space: pre-wrap` to assistant bubbles or newlines will double.
- Chat layout: the composer is pinned to the bottom of `.main` (which is `overflow:hidden`), and only
  `.messages` scrolls. Auto-follow is smart — `scrollDown()` only jumps to the newest message when the
  user is already at the bottom, otherwise it reveals the `#scroll-down` pill. Never switch it back to
  an unconditional `scrollTop = scrollHeight`, or typing while reading older text yanks the view down.
- Assistant replies render as plain line-by-line text (no bubble/box): `.msg.assistant .bubble` is
  transparent with no border. User messages keep a small bubble. Body copy is 13px.
- Every control panel renders its form inside a `.card` and its actions inside `.card-actions`;
  form rows use `.row` (flex, `flex-wrap`, `flex: 1 1 150px`) so they wrap instead of overflowing
  on a 390px phone. Keep long labels short and never rely on fixed-width rows.
- Security headers and CSP are set in the `security_headers` middleware — update the CSP if
  you add external resources.

## Gotchas
- The MCP manager needs its background loop started (`mcp_manager.start()`, done in the
  FastAPI lifespan). Don't call MCP sync wrappers before startup.
- `run_agent` yields events; `main.py` persists only the final assistant text to history.
- The MCP `/mcp/messages` POST is authenticated by the unguessable `session_id` issued to an
  authenticated SSE connection, not by repeating the bearer token.
- `SseServerTransport` and the lowlevel `Server` in `app_mcp.py` are created once at import.
- Rate limit is clamped to 1..600 per minute (`MAX_REQUESTS_PER_MINUTE`).
