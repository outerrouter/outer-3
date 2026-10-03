"""Number-letter system layer storage.

Every saved thing (API key, MCP, link, code, note, ...) lives in a layered registry
identified by a short code such as ``A1``, ``B2``, ``C10``.

- The **letter** is the layer (A = credentials, B = MCP, C = links, D = code, E = notes,
  F = memory).
- The **number** is the slot inside that layer, allocated sequentially.

Sensitive payloads are encrypted with the same vault as the rest of the app.
"""
from __future__ import annotations

import re
import time
from typing import Any

from . import database as db
from .crypto import decrypt_json, encrypt_json

# Layer definitions: letter -> (slug, human label)
LAYERS: dict[str, tuple[str, str]] = {
    "A": ("credentials", "Credentials & API keys"),
    "B": ("mcp", "MCP servers"),
    "C": ("links", "Links & endpoints"),
    "D": ("code", "Code & snippets"),
    "E": ("notes", "Notes & configs"),
    "F": ("memory", "Memory facts"),
}

# Kinds that must never be returned in cleartext.
SECRET_KINDS = {"api_key", "token", "password", "secret", "credential"}

_LAYER_OF_KIND = {
    "api_key": "A", "token": "A", "password": "A", "secret": "A", "credential": "A",
    "mcp": "B",
    "link": "C", "url": "C", "endpoint": "C",
    "code": "D", "snippet": "D",
    "note": "E", "config": "E",
    "fact": "F", "memory": "F",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT NOT NULL UNIQUE,
    layer       TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    value_enc   TEXT NOT NULL,
    description TEXT DEFAULT '',
    tags        TEXT DEFAULT '',
    source      TEXT DEFAULT 'chat',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    UNIQUE(layer, slot)
);
CREATE INDEX IF NOT EXISTS idx_items_layer ON items(layer, slot);
CREATE INDEX IF NOT EXISTS idx_items_name ON items(name);
"""


def ensure_schema() -> None:
    conn = db.get_conn()
    with db._lock:  # reuse the shared connection lock
        conn.executescript(SCHEMA)
        conn.commit()


_CODE_RE = re.compile(r"^([A-Za-z])(\d{1,4})$")


def layer_for_kind(kind: str) -> str:
    return _LAYER_OF_KIND.get((kind or "note").lower(), "E")


def parse_code(code: str) -> tuple[str, int]:
    m = _CODE_RE.match((code or "").strip().upper())
    if not m:
        raise ValueError(f"Invalid code '{code}'. Use a letter + number, e.g. A1.")
    letter = m.group(1)
    if letter not in LAYERS:
        raise ValueError(f"Unknown layer '{letter}'. Valid: {', '.join(LAYERS)}.")
    return letter, int(m.group(2))


def _next_slot(layer: str) -> int:
    row = db.get_conn().execute("SELECT MAX(slot) AS m FROM items WHERE layer=?", (layer,)).fetchone()
    return (row["m"] or 0) + 1


def _row_to_dict(row, *, reveal: bool) -> dict:
    data = dict(row)
    try:
        raw = decrypt_json(data.pop("value_enc"))
    except Exception:
        raw = None
    if reveal:
        data["value"] = raw
    else:
        data["value"] = _mask_value(raw)
        data["redacted"] = True
    return data


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
    return "<hidden>"


def add_item(kind: str, name: str, value: Any, description: str = "",
             tags: str = "", source: str = "chat", code: str | None = None) -> dict:
    """Create (or overwrite) an item and return its number-letter code."""
    ensure_schema()
    now = time.time()
    if code:
        layer, slot = parse_code(code)
    else:
        layer = layer_for_kind(kind)
        slot = _next_slot(layer)
    full_code = f"{layer}{slot}"
    enc = encrypt_json(value)
    with db._lock:
        conn = db.get_conn()
        conn.execute(
            "INSERT INTO items(code, layer, slot, kind, name, value_enc, description, tags, source, "
            "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(code) DO UPDATE SET kind=excluded.kind, name=excluded.name, "
            "value_enc=excluded.value_enc, description=excluded.description, tags=excluded.tags, "
            "updated_at=excluded.updated_at",
            (full_code, layer, slot, kind, name, enc, description, tags, source, now, now),
        )
        conn.commit()
    return {"code": full_code, "layer": layer, "slot": slot, "layer_label": LAYERS[layer][1],
            "kind": kind, "name": name}


def get_item(code: str, *, reveal: bool = False) -> dict | None:
    ensure_schema()
    row = db.get_conn().execute("SELECT * FROM items WHERE code=?", (code.strip().upper(),)).fetchone()
    return _row_to_dict(row, reveal=reveal) if row else None


def find_by_name(name: str, *, reveal: bool = False) -> list[dict]:
    ensure_schema()
    rows = db.get_conn().execute(
        "SELECT * FROM items WHERE name=? ORDER BY layer, slot", (name,)
    ).fetchall()
    return [_row_to_dict(r, reveal=reveal) for r in rows]


def list_items(layer: str | None = None, *, reveal: bool = False, limit: int = 500) -> list[dict]:
    ensure_schema()
    if layer:
        rows = db.get_conn().execute(
            "SELECT * FROM items WHERE layer=? ORDER BY slot LIMIT ?", (layer.upper(), limit)
        ).fetchall()
    else:
        rows = db.get_conn().execute(
            "SELECT * FROM items ORDER BY layer, slot LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r, reveal=reveal) for r in rows]


def search_items(query: str, *, reveal: bool = False, limit: int = 50) -> list[dict]:
    ensure_schema()
    like = f"%{query}%"
    rows = db.get_conn().execute(
        "SELECT * FROM items WHERE name LIKE ? OR description LIKE ? OR tags LIKE ? OR code LIKE ? "
        "ORDER BY layer, slot LIMIT ?",
        (like, like, like, like, limit),
    ).fetchall()
    return [_row_to_dict(r, reveal=reveal) for r in rows]


def delete_item(code: str) -> bool:
    ensure_schema()
    with db._lock:
        conn = db.get_conn()
        cur = conn.execute("DELETE FROM items WHERE code=?", (code.strip().upper(),))
        conn.commit()
        return cur.rowcount > 0


def update_item(code: str, *, name: str | None = None, value: Any = None,
                description: str | None = None, tags: str | None = None) -> bool:
    ensure_schema()
    item = get_item(code, reveal=True)
    if not item:
        return False
    sets, params = [], []
    if name is not None:
        sets.append("name=?"); params.append(name)
    if value is not None:
        sets.append("value_enc=?"); params.append(encrypt_json(value))
    if description is not None:
        sets.append("description=?"); params.append(description)
    if tags is not None:
        sets.append("tags=?"); params.append(tags)
    sets.append("updated_at=?"); params.append(time.time())
    params.append(code.strip().upper())
    with db._lock:
        conn = db.get_conn()
        conn.execute(f"UPDATE items SET {', '.join(sets)} WHERE code=?", params)
        conn.commit()
    return True


def layers_overview() -> list[dict]:
    ensure_schema()
    rows = db.get_conn().execute(
        "SELECT layer, COUNT(*) AS n FROM items GROUP BY layer"
    ).fetchall()
    counts = {r["layer"]: r["n"] for r in rows}
    return [
        {"letter": letter, "slug": slug, "label": label, "count": counts.get(letter, 0)}
        for letter, (slug, label) in LAYERS.items()
    ]
