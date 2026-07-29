# src/tic/ports/secret_store.py
"""SecretStore port. Backed by OS keyring, Vault, or in-memory (tests)."""

from __future__ import annotations

from typing import Protocol


class SecretStore(Protocol):
    """Contract: return raw secret bytes for a (service, user) tuple.

    Implementations MUST:
    - Raise AuthError if the credential does not exist.
    - Avoid caching the secret beyond the call boundary.
    - Never log the secret value. Metadata (service/user) may be logged.

    Security note: callers should keep references narrow (function scope) and
    never build longer-lived strings containing the secret.
    """

    def get(self, service: str, user: str) -> bytes: ...
