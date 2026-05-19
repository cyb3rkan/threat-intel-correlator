# src/tic/adapters/secrets/keyring_store.py
"""OS keyring-backed secret store. No plaintext fallback in MVP."""
from __future__ import annotations

import keyring
from keyring.errors import KeyringError

from tic.domain.errors import AuthError, ConfigError
from tic.infra.logging import get_logger
from tic.ports.secret_store import SecretStore

_log = get_logger(__name__)


class KeyringSecretStore(SecretStore):
    """keyring.get_password wrapper. Returns bytes to enable zeroize patterns.

    Security: never caches the secret beyond the call site. Callers should keep
    references as narrow as possible and avoid logging the returned bytes.
    """

    def get(self, service: str, user: str) -> bytes:
        try:
            val = keyring.get_password(service, user)
        except KeyringError as e:
            raise AuthError(
                f"keyring backend error for {service}/{user}",
                user_message="Unable to read credentials from keyring.",
            ) from e
        if val is None or val == "":
            raise ConfigError(
                f"no credential found for {service}/{user}",
                user_message="Missing credential in keyring. Use `tic config set-key`.",
            )
        _log.debug("secret_loaded", service=service, user=user, length=len(val))
        return val.encode("utf-8")