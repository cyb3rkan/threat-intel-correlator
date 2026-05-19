# src/tic/cli/_wiring.py
"""Provider/narrator factories + lifecycle close_all()."""
from __future__ import annotations
from typing import TYPE_CHECKING

from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.adapters.enrichment.abuseipdb import AbuseIPDBProvider
from tic.adapters.enrichment.misp_provider import MispProvider
from tic.adapters.enrichment.virustotal import VirusTotalProvider
from tic.adapters.http.safe_client import SafeHttpClient
from tic.adapters.secrets.keyring_store import KeyringSecretStore
from tic.application.ai.narrator import Narrator
from tic.application.redaction import Redactor
from tic.domain.errors import ConfigError
from tic.infra.config import ProviderConfig, Settings
from tic.infra.logging import get_logger
from tic.ports.audit_logger import AuditLogger
from tic.ports.cache import Cache
from tic.ports.enrichment_provider import EnrichmentProvider
from tic.ports.secret_store import SecretStore

if TYPE_CHECKING:
    from tic.ports.ai_provider import AIProvider

_log = get_logger(__name__)
_KNOWN = frozenset({"abuseipdb", "virustotal", "misp"})


def build_secret_store() -> SecretStore:
    return KeyringSecretStore()


def try_load_redaction_hmac(settings: Settings, secret_store: SecretStore | None) -> bytes | None:
    """Best-effort load of the redaction HMAC key from the keyring.

    Returns None when the key is absent or the backend errors. Callers that
    need hash output mode should treat None as fatal (see hash_mode docs);
    callers that don't need it (analyst/summary) can ignore None.
    """
    if secret_store is None:
        return None
    try:
        return secret_store.get(
            settings.redaction_hmac_keyring_service,
            settings.redaction_hmac_keyring_user,
        )
    except Exception:  # noqa: BLE001 — log type only, never the value
        _log.warning("redaction_hmac_unavailable")
        return None


def build_cache(settings: Settings) -> Cache:
    db = settings.paths.cache_dir / "tic-cache.sqlite"
    return SqliteCache(db, allowed_root=settings.paths.cache_dir)


def _build_one(
    name: str,
    cfg: ProviderConfig,
    *,
    secret_store: SecretStore,
    cache: Cache,
    http_cfg,
    audit: AuditLogger | None = None,
) -> EnrichmentProvider | None:
    try:
        api_key = secret_store.get(cfg.keyring_service, cfg.keyring_user)
    except Exception as e:  # noqa: BLE001
        _log.warning("provider_skipped_no_key", provider=name, error=type(e).__name__)
        return None

    extra = frozenset(cfg.allowed_hosts) if cfg.allowed_hosts else frozenset()
    # Per-provider verify_tls override. Default True (matches HttpClientConfig).
    # Setting False is a deliberate operator opt-in for lab self-signed certs;
    # it is logged so audits can spot every provider that runs with verification
    # disabled. Other providers in the same sweep keep verification on.
    if not cfg.verify_tls:
        _log.warning("provider_tls_verify_disabled", provider=name)
        if audit is not None:
            # Tamper-evident record so an after-the-fact reviewer can prove
            # whether and when TLS verification was disabled. Payload carries
            # only the provider name and the allowed_hosts list — no secrets,
            # no full endpoint URL.
            try:
                audit.append(
                    "provider_tls_verify_disabled",
                    {
                        "provider": name,
                        "allowed_hosts": list(cfg.allowed_hosts),
                    },
                )
            except Exception as e:  # noqa: BLE001 — audit failure must not block sweep
                _log.warning("audit_append_failed", event="provider_tls_verify_disabled", error=type(e).__name__)
    http = SafeHttpClient(
        http_cfg,
        extra_host_allowlist=extra,
        verify_tls=cfg.verify_tls,
    )

    if name == "abuseipdb":
        return AbuseIPDBProvider(http, cache, api_key, ttl_seconds=cfg.cache_ttl_seconds)
    if name == "virustotal":
        return VirusTotalProvider(http, cache, api_key, ttl_seconds=cfg.cache_ttl_seconds)
    if name == "misp":
        if not cfg.endpoint:
            _log.warning("misp_endpoint_missing")
            return None
        return MispProvider(http, cache, api_key, endpoint=cfg.endpoint, ttl_seconds=cfg.cache_ttl_seconds)
    raise ConfigError(f"unknown provider: {name}", user_message=f"Unknown provider: {name}")


def build_providers(
    settings: Settings,
    *,
    secret_store: SecretStore,
    cache: Cache,
    audit: AuditLogger | None = None,
) -> list[EnrichmentProvider]:
    """Construct enabled providers. `audit` is optional for backward compat;
    when supplied, security-relevant decisions (e.g. per-provider TLS verify
    bypass) are appended to the hash-chained audit log."""
    unknown = set(settings.providers.keys()) - _KNOWN
    if unknown:
        raise ConfigError(
            f"unknown providers: {sorted(unknown)}",
            user_message=f"Unknown provider(s): {', '.join(sorted(unknown))}. Known: {', '.join(sorted(_KNOWN))}.",
        )
    out: list[EnrichmentProvider] = []
    for name, cfg in settings.providers.items():
        if not cfg.enabled:
            continue
        p = _build_one(
            name,
            cfg,
            secret_store=secret_store,
            cache=cache,
            http_cfg=settings.http,
            audit=audit,
        )
        if p is not None:
            out.append(p)
    return out


def build_narrator(
    settings: Settings,
    *,
    secret_store: SecretStore,
    audit: AuditLogger | None = None,
) -> Narrator | None:
    """Construct a Narrator if AI is enabled and the keyring has the keys.

    `audit` is optional and backward-compatible. When supplied, the Narrator
    will append metadata-only AI events (`ai_invoke`, `ai_response_rejected`,
    `ai_narrative_attached`) to the tamper-evident audit chain. Existing
    callers that pass no audit logger continue to work unchanged.
    """
    if not settings.ai.enabled or not settings.ai.endpoint_allowlist:
        return None
    try:
        ai_key   = secret_store.get(settings.ai.keyring_service, settings.ai.keyring_user)
        hmac_key = secret_store.get(settings.redaction_hmac_keyring_service, settings.redaction_hmac_keyring_user)
    except Exception as e:  # noqa: BLE001
        _log.warning("narrator_keys_missing", error=type(e).__name__)
        return None
    redactor = Redactor(hmac_key)
    endpoint: str = settings.ai.endpoint_allowlist[0]
    http: SafeHttpClient = SafeHttpClient(settings.http)
    ai: AIProvider
    if settings.ai.provider == "gemini":
        from tic.adapters.ai_providers.gemini import GeminiProvider

        # Audit the (at-most-one) retry as a metadata-only event. We
        # construct the closure here so the adapter never imports
        # AuditLogger. If no audit sink is configured, the callback is
        # None and the adapter simply skips it.
        retry_cb = None
        if audit is not None:
            _audit_ref = audit

            def _on_retry(finding_id: str, reason: str) -> None:
                try:
                    _audit_ref.append(
                        "ai_response_retried",
                        {"finding_id": finding_id, "reason": reason},
                    )
                except Exception as e:  # noqa: BLE001 — audit must not break sweep
                    _log.warning(
                        "ai_audit_append_failed",
                        audit_event="ai_response_retried",
                        error=type(e).__name__,
                    )

            retry_cb = _on_retry

        ai = GeminiProvider(http, settings.ai, ai_key, endpoint, audit_retry=retry_cb)
    else:
        from tic.adapters.ai_providers.openai_compat import OpenAICompatProvider
        ai = OpenAICompatProvider(http, settings.ai, ai_key, endpoint)
    return Narrator(
        ai,
        redactor,
        audit=audit,
        max_input_chars=settings.ai.max_input_chars,
    )


async def close_all(providers: list[EnrichmentProvider], narrator: "Narrator | None") -> None:
    """Close all HTTP clients. Call in finally after sweep."""
    for p in providers:
        h = getattr(p, "_http", None)
        if h is not None:
            try:
                await h.aclose()
            except Exception as e:  # noqa: BLE001
                _log.warning("provider_http_close_failed", error=type(e).__name__)
    if narrator is not None:
        ai = getattr(narrator, "_ai", None)
        if ai is not None:
            h = getattr(ai, "_http", None)
            if h is not None:
                try:
                    await h.aclose()
                except Exception as e:  # noqa: BLE001
                    _log.warning("narrator_http_close_failed", error=type(e).__name__)
