"""Session-token auth and the password lock."""
from __future__ import annotations

import secrets
import time
from threading import Lock

from fastapi import HTTPException, Request

from .config import DEFAULT_PASSWORD, SESSION_TTL
from .crypto import hash_password, verify_password
from . import database as db

_PASSWORD_KEY = "password_hash"
_sessions: dict[str, float] = {}
_lock = Lock()

# Brute-force throttling: ip -> (attempts, first_attempt_ts, locked_until)
_attempts: dict[str, list] = {}
MAX_ATTEMPTS = 8
LOCKOUT_SECONDS = 120


def ensure_password_initialized() -> None:
    if db.get_setting(_PASSWORD_KEY) is None:
        import os
        pw = os.environ.get("APP_PASSWORD", DEFAULT_PASSWORD)
        db.set_setting(_PASSWORD_KEY, hash_password(pw))


def set_password(new_password: str) -> None:
    db.set_setting(_PASSWORD_KEY, hash_password(new_password))


def _throttle_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_lockout(request: Request) -> None:
    key = _throttle_key(request)
    with _lock:
        rec = _attempts.get(key)
        if rec and rec[2] > time.time():
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {int(rec[2]-time.time())}s.")


def record_failure(request: Request) -> None:
    key = _throttle_key(request)
    with _lock:
        now = time.time()
        rec = _attempts.get(key)
        if not rec or now - rec[1] > LOCKOUT_SECONDS:
            rec = [0, now, 0.0]
        rec[0] += 1
        if rec[0] >= MAX_ATTEMPTS:
            rec[2] = now + LOCKOUT_SECONDS
            rec[0] = 0
        _attempts[key] = rec


def clear_failures(request: Request) -> None:
    with _lock:
        _attempts.pop(_throttle_key(request), None)


def login(password: str, request: Request) -> str:
    check_lockout(request)
    stored = db.get_setting(_PASSWORD_KEY)
    if not stored or not verify_password(password, stored):
        record_failure(request)
        raise HTTPException(status_code=401, detail="Incorrect password.")
    clear_failures(request)
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = time.time() + SESSION_TTL
    return token


def _prune_sessions() -> None:
    now = time.time()
    for tok in [t for t, exp in _sessions.items() if exp < now]:
        _sessions.pop(tok, None)


def validate_token(token: str | None) -> bool:
    if not token:
        return False
    with _lock:
        _prune_sessions()
        return token in _sessions


def logout(token: str | None) -> None:
    with _lock:
        if token:
            _sessions.pop(token, None)


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get("session")


def require_session(request: Request) -> None:
    if not validate_token(_extract_token(request)):
        raise HTTPException(status_code=401, detail="Not authenticated.")


def session_count() -> int:
    with _lock:
        _prune_sessions()
        return len(_sessions)
