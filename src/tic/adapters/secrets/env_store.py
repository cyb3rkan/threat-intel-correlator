# src/tic/adapters/secrets/env_store.py
"""Environment-variable-backed secret store for container/Kubernetes runtime.

The OS keyring (the default local backend) is unavailable inside a hardened
container: a read-only root filesystem plus no D-Bus session mean
``keyring.get_password`` cannot work. This adapter implements the same
read-only ``SecretStore`` port by reading secrets from environment variables,
which is how Kubernetes (and similar runtimes) inject them from a Secret.

Selection is runtime-driven via ``TIC_SECRET_BACKEND=env``; anything else (or
unset) keeps the keyring backend, so the local developer flow is unchanged.

Mapping convention
------------------
A ``(service, user)`` pair maps to exactly one environment variable::

    TIC_SECRET__{SERVICE}__{USER}

where each component is upper-cased and every character outside ``[A-Z0-9]`` is
replaced with ``_``. This covers every secret type uniformly -- provider API
keys, the redaction HMAC, and the Part-2 audit HMAC -- with no per-secret
special-casing. Examples (shipped default service/user names)::

    VirusTotal   (tic-virustotal, default)    -> TIC_SECRET__TIC_VIRUSTOTAL__DEFAULT
    AbuseIPDB    (tic-abuseipdb, default)      -> TIC_SECRET__TIC_ABUSEIPDB__DEFAULT
    redaction    (tic-redaction-hmac, default) -> TIC_SECRET__TIC_REDACTION_HMAC__DEFAULT
    audit (P2)   (tic-audit-hmac, default)     -> TIC_SECRET__TIC_AUDIT_HMAC__DEFAULT

Fail-closed
-----------
A missing or empty variable raises ``AuthError`` (callers disable the affected
provider, or -- for audit signing with ``audit.sign=true`` -- fail the run).
There is no plaintext or other fallback, mirroring the keyring backend.
"""

from __future__ import annotations

import os
import re

from tic.domain.errors import AuthError
from tic.infra.logging import get_logger
from tic.ports.secret_store import SecretStore

_log = get_logger(__name__)

_ENV_PREFIX = "TIC_SECRET__"
_NON_ALNUM = re.compile(r"[^A-Z0-9]")


def env_var_name(service: str, user: str) -> str:
    """Map a ``(service, user)`` pair to its environment variable name.

    Deterministic and stable: this is the documented injection contract for
    container deployments.
    """
    svc = _NON_ALNUM.sub("_", service.upper())
    usr = _NON_ALNUM.sub("_", user.upper())
    return f"{_ENV_PREFIX}{svc}__{usr}"


class EnvSecretStore(SecretStore):
    """Read secrets from environment variables. See the module docstring."""

    def get(self, service: str, user: str) -> bytes:
        var = env_var_name(service, user)
        val = os.environ.get(var)
        if not val:
            raise AuthError(
                f"no secret in environment for {service}/{user} (${var})",
                user_message=(
                    f"Missing secret environment variable {var}. Inject it from your "
                    "deployment's Secret (set TIC_SECRET_BACKEND=env)."
                ),
            )
        _log.debug("secret_loaded", service=service, user=user, length=len(val), backend="env")
        return val.encode("utf-8")
