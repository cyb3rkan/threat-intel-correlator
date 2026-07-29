# src/tic/adapters/enrichment/misp_provider.py
"""MISP enrichment provider via /attributes/restSearch."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.finding import EnrichmentResult
from tic.domain.ioc import IOC, IOCType
from tic.infra.logging import get_logger
from tic.ports.cache import Cache
from tic.ports.enrichment_provider import EnrichmentProvider

_log = get_logger(__name__)
_MAX_RAW_PREVIEW = 2048
_MAX_REASON_LEN = 160

# Patterns that may carry secrets or URLs with embedded tokens. Stripped from
# any free-form exception text before we log it. Authorization values, API
# keys, and bearer tokens must never reach the log even when an exception
# string happens to include the request context.
_SECRET_PATTERN = re.compile(
    r"(authorization|bearer|api[_-]?key|x[_-]?apikey|key|cookie)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)


def _sanitize_reason(exc: BaseException) -> str:
    """Return a short, secret-free description of an exception.

    httpx exception messages can include the full request URL, which may carry
    query-string tokens. We keep only the exception class name plus a heavily
    sanitized fragment of the message (any URL or auth-looking key=value pair
    is replaced with a placeholder). Length-capped to keep log lines short.
    """
    raw = str(exc) or type(exc).__name__
    raw = _URL_PATTERN.sub("<url>", raw)
    raw = _SECRET_PATTERN.sub(r"\1=<redacted>", raw)
    return raw[:_MAX_REASON_LEN]


def _debug_cache_raw_enabled() -> bool:
    """Local debug flag. Default OFF — raw provider bytes never persisted to disk."""
    return os.environ.get("TIC_DEBUG_CACHE_RAW", "").strip().lower() in {"1", "true", "yes", "on"}


_MISP_TYPE_MAP: dict[str, str] = {
    IOCType.IP.value: "ip-dst",
    IOCType.DOMAIN.value: "domain",
    IOCType.URL.value: "url",
    IOCType.HASH_MD5.value: "md5",
    IOCType.HASH_SHA1.value: "sha1",
    IOCType.HASH_SHA256.value: "sha256",
    IOCType.HASH_SHA512.value: "sha512",
    IOCType.EMAIL.value: "email",
    IOCType.FILENAME.value: "filename",
}


class _MispAttribute(BaseModel):
    model_config = ConfigDict(extra="ignore")
    to_ids: bool = False
    category: str | None = Field(default=None, max_length=128)
    type: str | None = Field(default=None, max_length=64)
    value: str | None = Field(default=None, max_length=8192)


class _MispResponseAttributes(BaseModel):
    model_config = ConfigDict(extra="ignore")
    Attribute: list[_MispAttribute] = Field(default_factory=list)


class _MispResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    response: _MispResponseAttributes


def _reputation_from_attributes(attrs: list[_MispAttribute]) -> int | None:
    if not attrs:
        return None
    if any(a.to_ids for a in attrs):
        return 85
    return 55


class MispProvider(EnrichmentProvider):
    name = "misp"
    supported_types = frozenset(_MISP_TYPE_MAP.keys())

    def __init__(
        self, http: SafeHttpClient, cache: Cache, api_key: bytes, endpoint: str, ttl_seconds: int
    ) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("MISP endpoint must use https")
        self._http = http
        self._cache = cache
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._ttl = ttl_seconds
        # Cache the host for diagnostics — never log the full endpoint (path
        # could carry an org id) and never log the API key (it lives in
        # self._api_key only and only as bytes).
        self._endpoint_host = (urlparse(self._endpoint).hostname or "unknown").lower()
        # Per-process memoisation of corrupt cache keys — keeps the warning
        # from firing on every enrich() call when the same row remains
        # corrupt. We can't delete via the Cache port (it does not expose a
        # delete primitive), but a successful enrich will overwrite the row.
        self._corrupt_cache_keys: set[str] = set()

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        misp_type = _MISP_TYPE_MAP.get(ioc.ioc_type.value)
        if misp_type is None:
            return None

        cache_key = f"{ioc.ioc_type.value}:{ioc.value}"
        cached = self._cache.get(self.name, cache_key)
        if cached is not None:
            try:
                return EnrichmentResult.model_validate_json(cached)
            except ValidationError:
                if cache_key not in self._corrupt_cache_keys:
                    _log.warning("cache_corrupt_entry", provider=self.name)
                    self._corrupt_cache_keys.add(cache_key)
                # Fall through and refetch — a successful enrich() below
                # overwrites the corrupt row via cache.set().

        url = f"{self._endpoint}/attributes/restSearch"
        body = json.dumps(
            {"returnFormat": "json", "type": misp_type, "value": ioc.value, "limit": 50}
        ).encode()
        headers = {
            "Authorization": self._api_key.decode("utf-8"),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        try:
            resp = await self._http.post(url, headers=headers, content=body)
        except Exception as e:  # noqa: BLE001
            # Diagnostics: enough to debug self-signed TLS / DNS / timeout
            # failures without leaking the API key, full URL, or stack trace.
            # The Authorization header is intentionally never referenced here.
            # SafeHttpClient wraps httpx errors in NetworkError; the underlying
            # cause carries the useful classifier (ConnectError, ReadTimeout,
            # SSL failure, ...) so we surface it as a separate field.
            cause = e.__cause__
            _log.warning(
                "provider_request_failed",
                provider=self.name,
                error="NetworkError",
                exception_type=(type(cause).__name__ if cause is not None else type(e).__name__),
                endpoint_host=self._endpoint_host,
                verify_tls=getattr(self._http, "verify_tls", True),
                total_timeout_seconds=getattr(self._http, "total_timeout_seconds", None),
                sanitized_reason=_sanitize_reason(cause if cause is not None else e),
            )
            return None

        if resp.status_code in (401, 403):
            self._log_status_problem("provider_auth_failed", resp.status_code)
            return None
        if resp.status_code == 429:
            self._log_status_problem("provider_rate_limited", resp.status_code)
            return None
        if resp.status_code >= 400:
            self._log_status_problem("provider_error_status", resp.status_code)
            return None

        try:
            parsed = _MispResponse.model_validate(json.loads(resp.body_bytes))
        except (json.JSONDecodeError, ValidationError) as e:
            _log.warning("provider_schema_violation", provider=self.name, error=str(e)[:200])
            return None

        attrs = parsed.response.Attribute
        reputation = _reputation_from_attributes(attrs)
        if reputation is None:
            return None

        categories: set[str] = set()
        for a in attrs:
            if a.category:
                categories.add(a.category[:64])
            if len(categories) >= 32:
                break

        # Raw provider bytes are NEVER cached by default. Gated behind
        # TIC_DEBUG_CACHE_RAW for local debugging only; never returned to
        # the public API regardless (PublicEnrichment strips this field).
        truncated_raw = (
            resp.body_bytes[:_MAX_RAW_PREVIEW].decode("utf-8", errors="replace")
            if _debug_cache_raw_enabled()
            else ""
        )
        result = EnrichmentResult(
            provider=self.name,
            reputation_score=reputation,
            tags=frozenset(categories),
            fetched_at=datetime.now(UTC),
            ttl_seconds=self._ttl,
            truncated_raw=truncated_raw,
        )

        try:
            self._cache.set(self.name, cache_key, result.model_dump_json().encode(), self._ttl)
            # Successful cache write — clear any corrupt-key memo for this row.
            self._corrupt_cache_keys.discard(cache_key)
        except Exception as e:  # noqa: BLE001
            _log.warning("cache_write_failed", provider=self.name, error=type(e).__name__)

        return result

    def _log_status_problem(self, event: str, status: int) -> None:
        """Emit a uniform diagnostic log for non-2xx provider responses.

        Keeps `provider_auth_failed`, `provider_rate_limited`, and
        `provider_error_status` log shape consistent so dashboards can
        slice on the same fields. Never includes the Authorization
        header, full URL, or response body.
        """
        _log.warning(
            event,
            provider=self.name,
            status=status,
            endpoint_host=self._endpoint_host,
            verify_tls=getattr(self._http, "verify_tls", True),
            total_timeout_seconds=getattr(self._http, "total_timeout_seconds", None),
        )
