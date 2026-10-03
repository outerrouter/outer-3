"""Cryptographic primitives: master key, secret vault encryption, password hashing."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import KEY_PATH


def _load_or_create_key() -> bytes:
    """Load the master key, creating it with 0600 perms on first run."""
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(data: bytes) -> str:
    return _fernet.encrypt(data).decode("ascii")


def decrypt(token: str) -> bytes:
    return _fernet.decrypt(token.encode("ascii"))


def encrypt_json(value: Any) -> str:
    return encrypt(json.dumps(value).encode("utf-8"))


def decrypt_json(token: str) -> Any:
    return json.loads(decrypt(token).decode("utf-8"))


# --------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, 200k iterations)
# --------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, digest_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
