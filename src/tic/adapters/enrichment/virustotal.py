# src/tic/adapters/enrichment/virustotal.py
"""VirusTotal v3 enrichment provider."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.finding import EnrichmentResult
from tic.domain.ioc import IOC, IOCType
from tic.infra.logging import get_logger
from tic.ports.cache import Cache
from tic.ports.enrichment_provider import EnrichmentProvider

_log = get_logger(__name__)
_BASE_URL = "https://www.virustotal.com/api/v3"
_MAX_RAW_PREVIEW = 2048


def _debug_cache_raw_enabled() -> bool:
    """Local debug flag. Default OFF — raw provider bytes never persisted to disk."""
    return os.environ.get("TIC_DEBUG_CACHE_RAW", "").strip().lower() in {"1", "true", "yes", "on"}


class _VtAnalysisStats(BaseModel):
    model_config = ConfigDict(extra="ignore")
    harmless: int = Field(default=0, ge=0)
    malicious: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    undetected: int = Field(default=0, ge=0)
    timeout: int = Field(default=0, ge=0)


class _VtAttributes(BaseModel):
    model_config = ConfigDict(extra="ignore")
    last_analysis_stats: _VtAnalysisStats | None = None
    reputation: int | None = None
    tags: list[str] = Field(default_factory=list)


class _VtData(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attributes: _VtAttributes


class _VtResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    data: _VtData


def _reputation_score(stats: _VtAnalysisStats | None) -> int | None:
    if stats is None:
        return None
    total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout
    if total == 0:
        return None
    flagged = stats.malicious + stats.suspicious
    return max(0, min(100, int(round(100.0 * flagged / total))))


def _endpoint_for(ioc: IOC) -> str | None:
    t = ioc.ioc_type
    if t == IOCType.IP:
        return f"{_BASE_URL}/ip_addresses/{ioc.value}"
    if t == IOCType.DOMAIN:
        return f"{_BASE_URL}/domains/{ioc.value}"
    if t in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256, IOCType.HASH_SHA512):
        return f"{_BASE_URL}/files/{ioc.value}"
    if t == IOCType.URL:
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).rstrip(b"=").decode("ascii")
        return f"{_BASE_URL}/urls/{url_id}"
    return None


class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported_types = frozenset(
        {
            IOCType.IP.value,
            IOCType.DOMAIN.value,
            IOCType.URL.value,
            IOCType.HASH_MD5.value,
            IOCType.HASH_SHA1.value,
            IOCType.HASH_SHA256.value,
            IOCType.HASH_SHA512.value,
        }
    )

    def __init__(
        self, http: SafeHttpClient, cache: Cache, api_key: bytes, ttl_seconds: int
    ) -> None:
        self._http = http
        self._cache = cache
        self._api_key = api_key
        self._ttl = ttl_seconds

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if ioc.ioc_type.value not in self.supported_types:
            return None

        cache_key = f"{ioc.ioc_type.value}:{ioc.value}"
        cached = self._cache.get(self.name, cache_key)
        if cached is not None:
            try:
                return EnrichmentResult.model_validate_json(cached)
            except ValidationError:
                _log.warning("cache_corrupt_entry", provider=self.name)

        url = _endpoint_for(ioc)
        if url is None:
            return None

        headers = {"x-apikey": self._api_key.decode("utf-8"), "Accept": "application/json"}
        try:
            resp = await self._http.get(url, headers=headers)
        except Exception as e:  # noqa: BLE001
            _log.warning("provider_request_failed", provider=self.name, error=type(e).__name__)
            return None

        if resp.status_code in (401, 403):
            _log.warning("provider_auth_failed", provider=self.name, status=resp.status_code)
            return None
        if resp.status_code == 404:
            _log.debug("provider_not_found", provider=self.name)
            return None
        if resp.status_code == 429:
            _log.warning("provider_rate_limited", provider=self.name)
            return None
        if resp.status_code >= 400:
            _log.warning("provider_error_status", provider=self.name, status=resp.status_code)
            return None

        try:
            parsed = _VtResponse.model_validate(json.loads(resp.body_bytes))
        except (json.JSONDecodeError, ValidationError) as e:
            _log.warning("provider_schema_violation", provider=self.name, error=str(e)[:200])
            return None

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
            reputation_score=_reputation_score(parsed.data.attributes.last_analysis_stats),
            tags=frozenset(t[:64] for t in parsed.data.attributes.tags[:32]),
            fetched_at=datetime.now(UTC),
            ttl_seconds=self._ttl,
            truncated_raw=truncated_raw,
        )

        try:
            self._cache.set(self.name, cache_key, result.model_dump_json().encode(), self._ttl)
        except Exception as e:  # noqa: BLE001
            _log.warning("cache_write_failed", provider=self.name, error=type(e).__name__)

        return result
