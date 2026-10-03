"""Application configuration and filesystem paths."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("APP_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "assistant.db"
KEY_PATH = DATA_DIR / "master.key"

STATIC_DIR = BASE_DIR / "app" / "static"

# Default password for the personal lock screen. Can be overridden with the
# APP_PASSWORD environment variable. Stored as a salted hash after first run.
DEFAULT_PASSWORD = "shift&&67"

# Session token lifetime (seconds).
SESSION_TTL = 60 * 60 * 12

# Hard ceiling for the per-minute request limiter (safety net).
MAX_REQUESTS_PER_MINUTE = 600

# Default per-minute request limit, chosen to stay under the provider's throttle.
DEFAULT_RATE_LIMIT = 10

# MCP tool execution timeout (seconds).
MCP_CALL_TIMEOUT = 60
