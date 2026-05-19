# tests/fixtures/fake_secret_store.py
"""In-memory SecretStore for tests.

Test-only. Production code uses `KeyringSecretStore` against the OS
keyring. This fake lets tests exercise the wiring without touching the
host keyring and without any real secret material — the byte strings are
synthetic test placeholders.
"""
from __future__ import annotations

from tic.ports.secret_store import SecretStore


# A 32-byte synthetic key. NOT a real secret — only used to satisfy
# `Redactor`'s `len(hmac_key) >= 32` precondition in tests.
PLACEHOLDER_HMAC_32B: bytes = b"phase-d-test-hmac-key-32-bytes-X"


class FakeSecretStore(SecretStore):
    """Returns canned bytes per (service, user). Raises KeyError-shape
    RuntimeError when the key is absent — matches what the real
    `KeyringSecretStore` does when the OS keyring has no entry."""

    def __init__(self, mapping: dict[tuple[str, str], bytes] | None = None) -> None:
        self._m: dict[tuple[str, str], bytes] = dict(mapping or {})

    def get(self, service: str, user: str) -> bytes:
        try:
            return self._m[(service, user)]
        except KeyError as e:
            raise RuntimeError(
                f"fake_secret_store: no key for {service}/{user}"
            ) from e

    def put(self, service: str, user: str, value: bytes) -> None:
        self._m[(service, user)] = value


def default_ai_and_hmac_store(
    *,
    ai_service: str = "tic-ai",
    ai_user: str = "default",
    hmac_service: str = "tic-redaction-hmac",
    hmac_user: str = "default",
) -> FakeSecretStore:
    """A FakeSecretStore pre-populated with the keys an AI-enabled sweep
    needs: the AI bearer (synthetic placeholder) and the redaction HMAC."""
    return FakeSecretStore({
        # The AI bearer value is never inspected by the mock provider;
        # we still pass it through wiring so the keyring lookup succeeds.
        (ai_service, ai_user): b"phase-d-placeholder-ai-key-NOT-REAL",
        (hmac_service, hmac_user): PLACEHOLDER_HMAC_32B,
    })
