# src/tic/api/_provider_status.py
"""Build a public-safe ProviderStatus DTO from Settings + SecretStore.

Pure helper. NEVER includes:
- API keys or any keyring value
- keyring service / user names
- full endpoint URLs
- allowed_hosts entries
- model names
- file paths
- tracebacks / internal exception messages

Returned shape contains only:
- name
- configured (bool)
- enabled (bool)
- key_present (bool)
- supported_ioc_types (list[str])
- endpoint_kind ("public" | "internal" | "none")
- ready (bool)
- reason (enum string)
"""
from __future__ import annotations

from typing import Any, Literal

from tic.adapters.enrichment.abuseipdb import AbuseIPDBProvider
from tic.adapters.enrichment.misp_provider import MispProvider
from tic.adapters.enrichment.virustotal import VirusTotalProvider
from tic.infra.config import Settings
from tic.ports.secret_store import SecretStore

# All provider names the wiring layer recognises. Kept in sync with
# tic.cli._wiring._KNOWN — duplication is intentional so we never expose a
# provider here that isn't actually wired in.
_KNOWN_PROVIDERS: tuple[str, ...] = ("abuseipdb", "virustotal", "misp")

# Whitelist of reasons returned to the frontend. Closed set so callers can
# render localized text without fearing free-form leaks.
ProviderReason = Literal[
    "ok",
    "not_configured",
    "disabled",
    "no_keyring_key",
    "endpoint_missing",
]

AIReason = Literal[
    "ok",
    "ai_disabled",
    "endpoint_allowlist_empty",
    "no_keyring_key",
]


def _supported_types_for(name: str) -> list[str]:
    """Static IOC type capability per provider — derived from class metadata.

    Kept in this module (not the providers themselves) because we want a
    cheap synchronous lookup that does not instantiate HTTP clients.
    """
    if name == "abuseipdb":
        return sorted(AbuseIPDBProvider.supported_types)
    if name == "virustotal":
        return sorted(VirusTotalProvider.supported_types)
    if name == "misp":
        return sorted(MispProvider.supported_types)
    return []


def _endpoint_kind(name: str, has_endpoint: bool) -> Literal["public", "internal", "none"]:
    """Kind enum — never the URL itself.

    AbuseIPDB and VirusTotal use fixed public endpoints baked into the
    adapters; MISP is operator-supplied (typically internal). We never
    return the actual URL — only a coarse classification useful for UI
    grouping.
    """
    if name in {"abuseipdb", "virustotal"}:
        return "public"
    if name == "misp":
        return "internal" if has_endpoint else "none"
    return "none"


def _key_present(secret_store: SecretStore | None, service: str, user: str) -> bool:
    """Probe keyring without revealing or caching the value.

    Calls get() and treats any exception (missing entry, backend error) as
    "not present". The bytes object returned by a successful get() goes
    out of scope immediately.
    """
    if secret_store is None:
        return False
    try:
        secret = secret_store.get(service, user)
        return bool(secret)
    except Exception:  # noqa: BLE001 — type only, value never inspected
        return False


def build_provider_status(
    settings: Settings,
    secret_store: SecretStore | None,
) -> dict[str, Any]:
    """Build the public-safe payload for GET /api/providers/status."""
    providers_out: list[dict[str, Any]] = []

    for name in _KNOWN_PROVIDERS:
        cfg = settings.providers.get(name)
        if cfg is None:
            providers_out.append({
                "name": name,
                "configured": False,
                "enabled": False,
                "key_present": False,
                "supported_ioc_types": _supported_types_for(name),
                "endpoint_kind": _endpoint_kind(name, has_endpoint=False),
                "ready": False,
                "reason": "not_configured",
            })
            continue

        key_present = _key_present(secret_store, cfg.keyring_service, cfg.keyring_user)
        has_endpoint = bool(cfg.endpoint)
        endpoint_kind = _endpoint_kind(name, has_endpoint=has_endpoint)

        # Reason is the FIRST blocking condition, in order of severity.
        if not cfg.enabled:
            reason: ProviderReason = "disabled"
        elif name == "misp" and not has_endpoint:
            reason = "endpoint_missing"
        elif not key_present:
            reason = "no_keyring_key"
        else:
            reason = "ok"

        ready = reason == "ok"

        providers_out.append({
            "name": name,
            "configured": True,
            "enabled": cfg.enabled,
            "key_present": key_present,
            "supported_ioc_types": _supported_types_for(name),
            "endpoint_kind": endpoint_kind,
            "ready": ready,
            "reason": reason,
        })

    # AI status — same closed-set approach.
    ai_key_present = _key_present(
        secret_store,
        settings.ai.keyring_service,
        settings.ai.keyring_user,
    )
    if not settings.ai.enabled:
        ai_reason: AIReason = "ai_disabled"
    elif not settings.ai.endpoint_allowlist:
        ai_reason = "endpoint_allowlist_empty"
    elif not ai_key_present:
        ai_reason = "no_keyring_key"
    else:
        ai_reason = "ok"

    ai_out = {
        "enabled": settings.ai.enabled,
        "endpoint_count": len(settings.ai.endpoint_allowlist),
        "key_present": ai_key_present,
        "ready": ai_reason == "ok",
        "reason": ai_reason,
    }

    redaction_out = {
        "key_present": _key_present(
            secret_store,
            settings.redaction_hmac_keyring_service,
            settings.redaction_hmac_keyring_user,
        ),
    }

    return {
        "providers": providers_out,
        "ai": ai_out,
        "redaction_hmac": redaction_out,
    }
