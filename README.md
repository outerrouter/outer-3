# Agent Control Assistant

A personal, password-locked, chat-based **AI control assistant**. It is *not* a coding
agent — it checks, tests and stores your API keys, MCP servers, links, code and notes, and
controls them on command, all through chat. It is also itself an **MCP server**, so an
external MCP client (including another AI assistant) can drive it from outside.

Everything runs locally. Secrets are encrypted at rest.

---

## Features

- **Password lock** — the whole app is behind a password. Default: `shift&&67`
  (override with the `APP_PASSWORD` env var on first run; change it later in
  *AI Model & API → Change app password*).
- **Phone-first UI** — a mobile-first, responsive layout: slide-in menu, sticky composer,
  safe-area aware, tap-friendly buttons and tables that scroll instead of overflowing.
- **Chat with an AI agent** — OpenAI-compatible chat completions with tool calling.
- **Multi-agent engine** — every request runs through three roles:
  1. **Planner** breaks the request into an ordered plan (shown as a 🧭 Plan card).
  2. **Executor** works through the plan step by step with tools, autonomously, in one turn.
  3. **Verifier** checks whether the task is actually complete and drives the executor on if
     anything is missing.
- **Autonomous, step-by-step execution** — the agent keeps working through a task in one
  turn (checks, then saves, then remembers…) instead of stopping after one step. A live
  **Task progress** card shows each step's status (⏳ running / ✅ done / ❌ failed).
  If it ever hits the safety cap, reply **continue** and it resumes.
- **Step-by-step checking** — checks API keys (`check_api_key`), links (`check_link`) and
  code (`scan_code`) before storing anything, and reports concrete results (status codes,
  reachability, findings) — never just "working".
- **Number-letter system layers** — everything saved gets a code like `A1`, `B2`, `C3`:
  - **A** Credentials & API keys · **B** MCP servers · **C** Links & endpoints ·
    **D** Code & snippets · **E** Notes & configs · **F** Memory facts
- **Long-term memory layer** — durable facts with tags, importance, pinning, and
  relevance-ranked recall injected into the assistant's context automatically.
- **Encrypted vault** — keys/tokens/passwords are encrypted (Fernet/AES) with a local
  master key. The database never contains plaintext secrets.
- **MCP control** — add MCP servers (stdio or remote SSE), connect/disconnect, list tools,
  and let the AI call those tools itself. Secrets in `env`/`headers` are encrypted.
- **This app is an MCP server** — external clients connect over SSE and get 22 tools to
  read/write layers, manage memory, drive MCP servers, and change settings.
- **AI model settings** — set the API key, base URL, model, and a **per-minute request
  limit** (default **10/min**) so your key doesn't get rate-limited/blocked. Live usage is
  shown in the sidebar. `detect_best_model` finds a working model on your provider.
- **Security scanner** — detects leaked secrets and dangerous code patterns and redacts
  secrets in output. PBKDF2 password hashing, brute-force lockout, strict headers + CSP.

---

## Quick start

```bash
./run.sh
```

Then open <http://localhost:8000> and unlock with the password. The MCP endpoint is at
`/mcp/sse` on the same host/port.

Manual run:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Environment variables: `HOST`, `PORT`, `APP_PASSWORD`, `APP_DATA_DIR`.

Auto-restart (recommended for long-running use — restarts the server if it ever exits):

```bash
./run_server.sh 8000        # supervised uvicorn, logs to data/server-8000.log
```

---

## First-time setup

1. Unlock the app with the password.
2. Open **AI Model & API** (sidebar) and enter:
   - **API key** — your model provider key (powers the assistant itself).
   - **Base URL** — e.g. `https://router.bynara.id/v1`, `https://api.openai.com/v1`, or any
     OpenAI-compatible endpoint.
   - **Model** — e.g. `agnes-3-flash`.
   - **Requests / minute** — the throttle. Default 10, set below your provider's limit.
3. Click **Test connection**, then **Save**.

You can also do all of this from chat: *"Set my model to agnes-3-flash with a 10/min limit"*
or *"Find the best working model on my provider and set it."*

---

## Using it

Everything happens in chat. Examples:

- **Check a key:** "Here is my key `sk-...` — check it and tell me if it works."
- **Save a key:** "Save that key permanently as `openai-main`."
- **Check a link:** "Is `https://router.bynara.id/v1` reachable?"
- **Scan code:** "Scan this for secrets:" then paste the code.
- **Add an MCP server:** "Add an MCP server named `filesystem`, stdio, command `npx`,
  args `-y @modelcontextprotocol/server-filesystem /tmp`."
- **Use an MCP tool:** "Connect `filesystem` and list the files in /tmp."

### Built-in tools

| Tool | Purpose |
| --- | --- |
| `save_item` / `get_item` / `list_items` / `search_items` / `delete_item` / `layers_overview` | The number-letter system layers |
| `remember` / `recall` / `forget` | The long-term memory layer |
| `scan_code` | Security-scan code/text for secrets and dangerous patterns |
| `check_link` | Check a link/endpoint's reachability and HTTP status |
| `check_api_key` | Validate an API key with a minimal test request |
| `detect_best_model` | Find a working model on your provider and optionally apply it |
| `save_mcp_server` / `list_mcp_servers` / `connect_mcp_server` / `disconnect_mcp_server` / `delete_mcp_server` | Manage MCP servers |
| `list_mcp_tools` / `call_mcp_tool` | Discover and call MCP tools |
| `get_llm_config` / `set_llm_config` | Read/update the AI model settings |

MCP tools appear to the model as `mcp__<server>__<tool>`.

---

## This app as an MCP server (external control)

Open **App MCP (external)** in the sidebar to get the SSE URL and an access token.

```
SSE URL:  http://<host>:<port>/mcp/sse?token=<token>
```

Any MCP client can connect and use the 22 tools listed above. Example with the `mcp`
Python package:

```python
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async with sse_client("http://localhost:8000/mcp/sse?token=YOUR_TOKEN") as (r, w):
    async with ClientSession(r, w) as s:
        await s.initialize()
        print(await s.list_tools())
        print(await s.call_tool("layers_overview", {}))
```

Access is controlled by the token; the SSE connection is authenticated with it, and the
message endpoint only accepts sessions created by an authenticated connection.
Regenerate the token any time from the panel.

---

## Demo MCP server

A tiny stdio MCP server is included for testing:

- **Name:** `demo` · **Transport:** `stdio` · **Command:** `.venv/bin/python` · **Args:** `-m app.example_mcp_server`

It exposes `echo`, `add`, and `server_time`. Register it in **MCP servers** or by asking
the agent, then click **Connect**.

---

## Project layout

```
app/
  main.py             FastAPI app + routes + static serving + MCP mounting
  agent.py            Control-assistant prompt, built-in tools, agent loop
  storage.py          Number-letter system layers (A1, B2, ...) — encrypted
  memory.py           Long-term memory layer (tags, importance, recall)
  app_mcp.py          The app's own MCP server (SSE) for external control
  llm.py              OpenAI-compatible client + rate limiting
  mcp_manager.py      MCP client manager (stdio + SSE)
  database.py         SQLite storage
  crypto.py           Fernet encryption + PBKDF2 password hashing
  auth.py             Password lock, session tokens, brute-force throttling
  security_scan.py    Secret & dangerous-code scanner
  rate_limit.py       Per-minute sliding-window limiter (default 10)
  example_mcp_server.py  Demo MCP server
  static/             Frontend (index.html, css, js)
data/                 Runtime: assistant.db + master.key (git-ignored, 0600)
```

---

## Security notes

- **Secrets are encrypted** with a key in `data/master.key` (mode `0600`). Back that file
  up securely — without it, stored secrets cannot be decrypted.
- The app is **single-user** and meant to be run locally or on a trusted network. It has no
  TLS of its own; put it behind a reverse proxy with HTTPS if you expose it.
- **Rotate** any key you paste into a chat, if that chat is ever shared or logged. Prefer
  entering keys directly in the panels.
- The scanner redacts secrets in its output, but the AI provider still sees whatever you
  send to it in chat.

---

## API reference (all require a session token)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/auth/status` | Auth state |
| `POST` | `/api/auth/login` `/logout` `/password` | Unlock / lock / change password |
| `GET`/`PUT` | `/api/llm` | Read/update model settings |
| `POST` | `/api/llm/test` | Test the LLM connection |
| `GET` | `/api/llm/rate` | Rate-limit status |
| `GET` | `/api/layers` | Layer overview (A-F) |
| `GET`/`POST` | `/api/items` | List / create layer items |
| `GET`/`DELETE` | `/api/items/{code}` | Get / delete by code |
| `GET` | `/api/memory` | List or recall memories (`?q=`) |
| `POST`/`PUT`/`DELETE` | `/api/memory[/{id}]` | Manage memories |
| `GET`/`POST` | `/api/mcp` | List / create MCP servers |
| `POST` | `/api/mcp/{id}/connect` `/disconnect` | Connect / disconnect |
| `GET` | `/api/mcp/tools` | All tools across connected servers |
| `POST` | `/api/mcp/{id}/call` | Call a tool |
| `POST` | `/api/scan` | Security-scan code |
| `GET` | `/api/app-mcp/info` | This app's MCP URL + token + tools |
| `POST` | `/api/app-mcp/token` | Get / regenerate the MCP token |
| `GET` | `/mcp/sse` · `POST /mcp/messages` | The app's MCP server (SSE transport) |
| `GET` | `/api/chat/sessions` | List chat sessions |
| `GET`/`DELETE` | `/api/chat/{session_id}` | History / clear |
| `POST` | `/api/chat/stream` | Send a message (Server-Sent Events) |
