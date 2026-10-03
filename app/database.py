"""SQLite storage layer. Sensitive values are stored encrypted."""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

from .config import DB_PATH
from .crypto import decrypt_json, encrypt_json

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL DEFAULT 'api_key',
    value_enc   TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    transport   TEXT NOT NULL DEFAULT 'stdio',
    command     TEXT DEFAULT '',
    args        TEXT DEFAULT '[]',
    env_enc     TEXT DEFAULT '',
    url         TEXT DEFAULT '',
    headers_enc TEXT DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    tool_calls TEXT DEFAULT '',
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id);
"""


def get_conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("PRAGMA foreign_keys=ON")
            _conn.executescript(SCHEMA)
            _conn.commit()
        return _conn


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

def get_setting(key: str, default: str | None = None) -> str | None:
    row = get_conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _lock:
        conn = get_conn()
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()


def get_secret_setting(key: str, default: Any = None) -> Any:
    """Read a JSON value stored encrypted under settings."""
    raw = get_setting(key)
    if raw is None:
        return default
    try:
        return decrypt_json(raw)
    except Exception:
        return default


def set_secret_setting(key: str, value: Any) -> None:
    set_setting(key, encrypt_json(value))


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

def list_credentials() -> list[dict]:
    rows = get_conn().execute(
        "SELECT id, name, kind, description, created_at, updated_at FROM credentials ORDER BY name"
    ).fetchall()
    return [dict(r) for r in rows]


def get_credential(name: str) -> dict | None:
    row = get_conn().execute("SELECT * FROM credentials WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["value"] = decrypt_json(data.pop("value_enc"))
    except Exception:
        data["value"] = None
    return data


def get_credential_by_id(cid: int) -> dict | None:
    row = get_conn().execute("SELECT * FROM credentials WHERE id=?", (cid,)).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["value"] = decrypt_json(data.pop("value_enc"))
    except Exception:
        data["value"] = None
    return data


def upsert_credential(name: str, value: Any, kind: str = "api_key", description: str = "") -> int:
    now = time.time()
    enc = encrypt_json(value)
    with _lock:
        conn = get_conn()
        existing = conn.execute("SELECT id FROM credentials WHERE name=?", (name,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE credentials SET value_enc=?, kind=?, description=?, updated_at=? WHERE id=?",
                (enc, kind, description, now, existing["id"]),
            )
            cid = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO credentials(name, kind, value_enc, description, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (name, kind, enc, description, now, now),
            )
            cid = cur.lastrowid
        conn.commit()
        return cid


def delete_credential(cid: int) -> bool:
    with _lock:
        conn = get_conn()
        cur = conn.execute("DELETE FROM credentials WHERE id=?", (cid,))
        conn.commit()
        return cur.rowcount > 0


# --------------------------------------------------------------------------
# MCP servers
# --------------------------------------------------------------------------

def _mcp_row_to_dict(row: sqlite3.Row, *, reveal: bool = False) -> dict:
    import json as _json
    data = dict(row)
    data["enabled"] = bool(data["enabled"])
    try:
        data["args"] = _json.loads(data.get("args") or "[]")
    except Exception:
        data["args"] = []
    if reveal:
        for field, key in (("env_enc", "env"), ("headers_enc", "headers")):
            raw = data.pop(field, "")
            try:
                data[key] = decrypt_json(raw) if raw else {}
            except Exception:
                data[key] = {}
    else:
        data.pop("env_enc", None)
        data.pop("headers_enc", None)
    return data


def list_mcp_servers(*, reveal: bool = False) -> list[dict]:
    rows = get_conn().execute("SELECT * FROM mcp_servers ORDER BY name").fetchall()
    return [_mcp_row_to_dict(r, reveal=reveal) for r in rows]


def get_mcp_server(sid: int, *, reveal: bool = True) -> dict | None:
    row = get_conn().execute("SELECT * FROM mcp_servers WHERE id=?", (sid,)).fetchone()
    return _mcp_row_to_dict(row, reveal=reveal) if row else None


def get_mcp_server_by_name(name: str, *, reveal: bool = True) -> dict | None:
    row = get_conn().execute("SELECT * FROM mcp_servers WHERE name=?", (name,)).fetchone()
    return _mcp_row_to_dict(row, reveal=reveal) if row else None


def upsert_mcp_server(
    name: str,
    *,
    transport: str = "stdio",
    command: str = "",
    args: list[str] | None = None,
    env: dict | None = None,
    url: str = "",
    headers: dict | None = None,
    enabled: bool = True,
) -> int:
    import json as _json
    now = time.time()
    args_json = _json.dumps(args or [])
    env_enc = encrypt_json(env or {})
    headers_enc = encrypt_json(headers or {})
    with _lock:
        conn = get_conn()
        existing = conn.execute("SELECT id FROM mcp_servers WHERE name=?", (name,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE mcp_servers SET transport=?, command=?, args=?, env_enc=?, url=?, "
                "headers_enc=?, enabled=?, updated_at=? WHERE id=?",
                (transport, command, args_json, env_enc, url, headers_enc, int(enabled), now, existing["id"]),
            )
            sid = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO mcp_servers(name, transport, command, args, env_enc, url, headers_enc, "
                "enabled, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (name, transport, command, args_json, env_enc, url, headers_enc, int(enabled), now, now),
            )
            sid = cur.lastrowid
        conn.commit()
        return sid


def set_mcp_enabled(sid: int, enabled: bool) -> None:
    with _lock:
        conn = get_conn()
        conn.execute("UPDATE mcp_servers SET enabled=?, updated_at=? WHERE id=?", (int(enabled), time.time(), sid))
        conn.commit()


def delete_mcp_server(sid: int) -> bool:
    with _lock:
        conn = get_conn()
        cur = conn.execute("DELETE FROM mcp_servers WHERE id=?", (sid,))
        conn.commit()
        return cur.rowcount > 0


# --------------------------------------------------------------------------
# Messages / chat history
# --------------------------------------------------------------------------

def add_message(session_id: str, role: str, content: str, tool_calls: Any = None) -> int:
    import json as _json
    with _lock:
        conn = get_conn()
        cur = conn.execute(
            "INSERT INTO messages(session_id, role, content, tool_calls, created_at) VALUES(?,?,?,?,?)",
            (session_id, role, content, _json.dumps(tool_calls or []), time.time()),
        )
        conn.commit()
        return cur.lastrowid


def get_messages(session_id: str, limit: int = 200) -> list[dict]:
    import json as _json
    rows = get_conn().execute(
        "SELECT * FROM messages WHERE session_id=? ORDER BY id ASC LIMIT ?", (session_id, limit)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["tool_calls"] = _json.loads(d.get("tool_calls") or "[]")
        except Exception:
            d["tool_calls"] = []
        out.append(d)
    return out


def clear_messages(session_id: str, keep_after_id: int | None = None) -> None:
    with _lock:
        conn = get_conn()
        if keep_after_id is None:
            conn.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
        else:
            conn.execute("DELETE FROM messages WHERE session_id=? AND id>?", (session_id, keep_after_id))
        conn.commit()


def list_sessions() -> list[dict]:
    rows = get_conn().execute(
        "SELECT session_id, MIN(created_at) AS started, MAX(created_at) AS last, COUNT(*) AS n "
        "FROM messages GROUP BY session_id ORDER BY last DESC"
    ).fetchall()
    return [dict(r) for r in rows]
