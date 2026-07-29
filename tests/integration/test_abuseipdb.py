# tests/integration/test_abuseipdb.py
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from tic.adapters.enrichment.abuseipdb import AbuseIPDBProvider
from tic.adapters.http.safe_client import HttpResponse
from tic.application.normalization import make_ioc
from tic.domain.errors import NetworkError


def _make_provider(status=200, body=None, cache_hit=None):
    default_body = json.dumps(
        {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 10,
                "countryCode": "CN",
                "usageType": "Data Center/Web Hosting/Transit",
            }
        }
    ).encode()

    http = MagicMock()
    http.get = AsyncMock(
        return_value=HttpResponse(
            status_code=status,
            headers={},
            body_bytes=body if body is not None else default_body,
        )
    )

    cache = MagicMock()
    cache.get = MagicMock(return_value=cache_hit)
    cache.set = MagicMock()

    return AbuseIPDBProvider(http=http, cache=cache, api_key=b"test-key", ttl_seconds=3600)


@pytest.mark.asyncio()
async def test_enriches_ip_successfully():
    provider = _make_provider()
    ioc = make_ioc("1.2.3.4", source="test")
    result = await provider.enrich(ioc)
    assert result is not None
    assert result.reputation_score == 85
    assert result.provider == "abuseipdb"
    assert "CN" in result.tags


@pytest.mark.asyncio()
async def test_skips_non_ip_ioc():
    http = MagicMock()
    http.get = AsyncMock()
    cache = MagicMock()
    cache.get = MagicMock(return_value=None)
    provider = AbuseIPDBProvider(http=http, cache=cache, api_key=b"key", ttl_seconds=3600)
    ioc = make_ioc("evil.example.com", source="test")
    result = await provider.enrich(ioc)
    assert result is None
    http.get.assert_not_called()


@pytest.mark.asyncio()
async def test_returns_cached_result():
    from tic.domain.finding import EnrichmentResult

    cached = EnrichmentResult(
        provider="abuseipdb",
        reputation_score=50,
        tags=frozenset(),
        fetched_at=datetime.now(UTC),
        ttl_seconds=3600,
    )
    provider = _make_provider(cache_hit=cached.model_dump_json().encode())
    ioc = make_ioc("1.2.3.4", source="test")
    result = await provider.enrich(ioc)
    assert result is not None
    assert result.reputation_score == 50


@pytest.mark.asyncio()
async def test_returns_none_on_401():
    provider = _make_provider(status=401)
    result = await provider.enrich(make_ioc("1.2.3.4", source="test"))
    assert result is None


@pytest.mark.asyncio()
async def test_returns_none_on_429():
    provider = _make_provider(status=429)
    result = await provider.enrich(make_ioc("1.2.3.4", source="test"))
    assert result is None


@pytest.mark.asyncio()
async def test_returns_none_on_500():
    provider = _make_provider(status=500)
    result = await provider.enrich(make_ioc("1.2.3.4", source="test"))
    assert result is None


@pytest.mark.asyncio()
async def test_returns_none_on_invalid_json():
    provider = _make_provider(body=b"not json")
    result = await provider.enrich(make_ioc("1.2.3.4", source="test"))
    assert result is None


@pytest.mark.asyncio()
async def test_returns_none_on_network_error():
    http = MagicMock()
    http.get = AsyncMock(side_effect=NetworkError("timeout"))
    cache = MagicMock()
    cache.get = MagicMock(return_value=None)
    provider = AbuseIPDBProvider(http=http, cache=cache, api_key=b"key", ttl_seconds=3600)
    result = await provider.enrich(make_ioc("1.2.3.4", source="test"))
    assert result is None
