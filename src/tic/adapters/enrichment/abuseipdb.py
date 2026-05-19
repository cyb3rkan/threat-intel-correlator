# src/tic/adapters/enrichment/abuseipdb.py
"""AbuseIPDB provider adapter. Handles only IPv4/IPv6 IOCs."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field, ValidationError

from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.finding import EnrichmentResult
from tic.domain.ioc import IOC, IOCType
from tic.infra.logging import get_logger
from tic.ports.cache import Cache
from tic.ports.enrichment_provider import EnrichmentProvider

_log = get_logger(__name__)

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT_HINT = 15


class _AbuseResponse(BaseModel):
    """Strict schema for AbuseIPDB responses. Unknown fields ignored safely."""

    class Data(BaseModel):
        abuseConfidenceScore: int = Field(ge=0, le=100)
        totalReports: int = Field(ge=0)
        countryCode: str | None = Field(default=None, max_length=4)
        usageType: str | None = Field(default=None, max_length=64)

    data: Data


class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported_types = frozenset({IOCType.IP.value})

    def __init__(
        self,
        http: SafeHttpClient,
        cache: Cache,
        api_key: bytes,
        ttl_seconds: int,
    ) -> None:
        self._http = http
        self._cache = cache
        self._api_key = api_key
        self._ttl = ttl_seconds

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if ioc.ioc_type.value not in self.supported_types:
            return None

        cached = self._cache.get("abuseipdb", ioc.value)
        if cached is not None:
            try:
                return EnrichmentResult.model_validate_json(cached)
            except ValidationError:
                _log.warning("cache_corrupt_entry", provider=self.name)

        url = f"{_ENDPOINT}?ipAddress={ioc.value}&maxAgeInDays=90"
        headers = {
            "Key": self._api_key.decode("utf-8"),
            "Accept": "application/json",
        }
        try:
            resp = await self._http.get(url, headers=headers)
        except Exception as e:  # noqa: BLE001 — intentionally broad; wrap & log
            _log.warning("provider_request_failed", provider=self.name, error=type(e).__name__)
            return None

        if resp.status_code == 401 or resp.status_code == 403:
            _log.warning("provider_auth_failed", provider=self.name, status=resp.status_code)
            return None
        if resp.status_code == 429:
            _log.warning("provider_rate_limited", provider=self.name)
            return None
        if resp.status_code >= 400:
            _log.warning("provider_error_status", provider=self.name, status=resp.status_code)
            return None

        try:
            payload = json.loads(resp.body_bytes)
            parsed = _AbuseResponse.model_validate(payload)
        except (json.JSONDecodeError, ValidationError) as e:
            _log.warning("provider_schema_violation", provider=self.name, error=str(e)[:200])
            return None

        result = EnrichmentResult(
            provider=self.name,
            reputation_score=parsed.data.abuseConfidenceScore,
            tags=frozenset(t for t in (parsed.data.countryCode, parsed.data.usageType) if t),
            fetched_at=datetime.now(UTC),
            ttl_seconds=self._ttl,
            truncated_raw="",  # debug-only: set TIC_DEBUG_CACHE_RAW=true to enable,
        )

        try:
            self._cache.set(
                "abuseipdb",
                ioc.value,
                result.model_dump_json().encode("utf-8"),
                self._ttl,
            )
        except Exception as e:  # noqa: BLE001
            _log.warning("cache_write_failed", provider=self.name, error=type(e).__name__)

        return result
