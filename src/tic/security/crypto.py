# src/tic/security/crypto.py
"""Cryptographic primitives: HMAC-based deterministic pseudonymization."""

from __future__ import annotations

import hmac
from hashlib import sha256


def hmac_pseudonymize(value: str, *, key: bytes, length: int = 16) -> str:
    """Return a stable pseudonym for `value` using HMAC-SHA256.

    Security:
    - Deterministic within a session (same key, same input, same output).
    - Non-reversible without the key.
    - `length` truncates the hex digest; do not use < 16 for low-collision needs.
    """
    if length < 8 or length > 64:
        raise ValueError("length must be between 8 and 64 hex chars")
    mac = hmac.new(key, value.encode("utf-8"), sha256).hexdigest()
    return mac[:length]
