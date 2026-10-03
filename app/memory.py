"""Long-term memory layer.

Stores durable facts the assistant should recall across chats. Supports tags,
importance ranking, pinning, and keyword recall with a simple relevance score.
"""
from __future__ import annotations

import re
import time

from . import database as db

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT NOT NULL,
    tags        TEXT DEFAULT '',
    importance  INTEGER NOT NULL DEFAULT 3,
    pinned      INTEGER NOT NULL DEFAULT 0,
    source      TEXT DEFAULT 'chat',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_pinned ON memories(pinned, importance);
"""


def ensure_schema() -> None:
    conn = db.get_conn()
    with db._lock:
        conn.executescript(SCHEMA)
        conn.commit()


def remember(text: str, tags: str = "", importance: int = 3, pinned: bool = False,
             source: str = "chat") -> dict:
    ensure_schema()
    now = time.time()
    importance = max(1, min(int(importance), 5))
    with db._lock:
        conn = db.get_conn()
        # Avoid exact duplicates: bump importance/updated_at instead.
        existing = conn.execute(
            "SELECT id FROM memories WHERE text=?", (text,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE memories SET tags=?, importance=?, pinned=?, updated_at=? WHERE id=?",
                (tags, importance, int(pinned), now, existing["id"]),
            )
            mid = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO memories(text, tags, importance, pinned, source, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (text, tags, importance, int(pinned), source, now, now),
            )
            mid = cur.lastrowid
        conn.commit()
    return {"id": mid, "text": text, "tags": tags, "importance": importance, "pinned": pinned}


_WORD_RE = re.compile(r"[a-z0-9]+")


def _score(mem: dict, terms: list[str], now: float) -> float:
    hay = (mem["text"] + " " + (mem["tags"] or "")).lower()
    hits = sum(hay.count(t) for t in terms)
    if hits == 0:
        return 0.0
    # Recency decay over ~30 days, plus importance and pin boost.
    age_days = max(0.0, (now - mem["updated_at"]) / 86400.0)
    recency = 1.0 / (1.0 + age_days / 30.0)
    return hits * (1.0 + 0.35 * mem["importance"] + (2.0 if mem["pinned"] else 0.0)) * recency


def recall(query: str = "", limit: int = 8) -> list[dict]:
    ensure_schema()
    rows = db.get_conn().execute("SELECT * FROM memories").fetchall()
    mems = [dict(r) for r in rows]
    now = time.time()
    if not query.strip():
        mems.sort(key=lambda m: (m["pinned"], m["importance"], m["updated_at"]), reverse=True)
        return mems[:limit]
    terms = _WORD_RE.findall(query.lower())
    scored = [(m, _score(m, terms, now)) for m in mems]
    scored = [(m, s) for m, s in scored if s > 0]
    scored.sort(key=lambda x: x[1], reverse=True)
    for m, s in scored:
        m["_score"] = round(s, 3)
    return [m for m, _ in scored[:limit]]


def list_memories(limit: int = 100) -> list[dict]:
    ensure_schema()
    rows = db.get_conn().execute(
        "SELECT * FROM memories ORDER BY pinned DESC, importance DESC, updated_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_memory(mid: int, *, text: str | None = None, tags: str | None = None,
                  importance: int | None = None, pinned: bool | None = None) -> bool:
    ensure_schema()
    sets, params = [], []
    if text is not None:
        sets.append("text=?"); params.append(text)
    if tags is not None:
        sets.append("tags=?"); params.append(tags)
    if importance is not None:
        sets.append("importance=?"); params.append(max(1, min(int(importance), 5)))
    if pinned is not None:
        sets.append("pinned=?"); params.append(int(pinned))
    if not sets:
        return False
    sets.append("updated_at=?"); params.append(time.time())
    params.append(mid)
    with db._lock:
        conn = db.get_conn()
        cur = conn.execute(f"UPDATE memories SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()
        return cur.rowcount > 0


def forget(mid: int) -> bool:
    ensure_schema()
    with db._lock:
        conn = db.get_conn()
        cur = conn.execute("DELETE FROM memories WHERE id=?", (mid,))
        conn.commit()
        return cur.rowcount > 0


def build_memory_context(query: str, limit: int = 6) -> str:
    """Return a compact memory block to inject into the system prompt."""
    mems = recall(query, limit=limit)
    if not mems:
        return ""
    lines = []
    for m in mems:
        tag = f" [{m['tags']}]" if m.get("tags") else ""
        pin = "📌 " if m.get("pinned") else ""
        lines.append(f"- {pin}{m['text']}{tag}")
    return "Relevant long-term memory about the owner and their setup:\n" + "\n".join(lines)
