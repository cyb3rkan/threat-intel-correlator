# tests/integration/test_providers_mocked.py
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.adapters.enrichment.misp_provider import MispProvider
from tic.adapters.enrichment.virustotal import VirusTotalProvider
from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.ioc import IOC, IOCType
from tic.infra.config import HttpClientConfig


def _ip_ioc() -> IOC:
    return IOC(value="8.8.8.8", ioc_type=IOCType.IP, source="test")


def _domain_ioc() -> IOC:
    return IOC(value="example.com", ioc_type=IOCType.DOMAIN, source="test")


def _sha256_ioc() -> IOC:
    return IOC(
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type=IOCType.HASH_SHA256,
        source="test",
    )


@pytest.fixture()
def http_client() -> SafeHttpClient:
    return SafeHttpClient(HttpClientConfig())


@pytest.fixture()
def http_internal() -> SafeHttpClient:
    return SafeHttpClient(HttpClientConfig(), extra_host_allowlist=frozenset({"misp.internal"}))


@pytest.fixture()
def cache(tmp_path: Path) -> SqliteCache:
    return SqliteCache(tmp_path / "cache.db", allowed_root=tmp_path)


# --- VirusTotal ---


@pytest.mark.asyncio()
@respx.mock
async def test_vt_ip_enrichment(http_client, cache):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 80,
                            "malicious": 5,
                            "suspicious": 2,
                            "undetected": 10,
                            "timeout": 3,
                        },
                        "tags": ["anonymizer"],
                    }
                }
            },
        )
    )
    provider = VirusTotalProvider(http_client, cache, b"key", 60)
    result = await provider.enrich(_ip_ioc())
    assert result is not None
    assert result.reputation_score == 7
    assert "anonymizer" in result.tags


@pytest.mark.asyncio()
async def test_vt_unsupported_type_returns_none(http_client, cache):
    provider = VirusTotalProvider(http_client, cache, b"k", 60)
    ioc = IOC(value="CVE-2024-0001", ioc_type=IOCType.CVE, source="test")
    assert await provider.enrich(ioc) is None


@pytest.mark.asyncio()
@respx.mock
async def test_vt_rate_limit_returns_none(http_client, cache):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(429)
    )
    provider = VirusTotalProvider(http_client, cache, b"k", 60)
    assert await provider.enrich(_ip_ioc()) is None


@pytest.mark.asyncio()
@respx.mock
async def test_vt_auth_failure_returns_none(http_client, cache):
    respx.get("https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(401)
    )
    provider = VirusTotalProvider(http_client, cache, b"bad", 60)
    assert await provider.enrich(_domain_ioc()) is None


@pytest.mark.asyncio()
@respx.mock
async def test_vt_schema_violation_returns_none(http_client, cache):
    respx.get("https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(200, json={"unexpected": True})
    )
    provider = VirusTotalProvider(http_client, cache, b"k", 60)
    assert await provider.enrich(_domain_ioc()) is None


@pytest.mark.asyncio()
@respx.mock
async def test_vt_cache_hit_skips_http(http_client, cache):
    provider = VirusTotalProvider(http_client, cache, b"k", 60)
    route = respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 10,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 89,
                            "timeout": 0,
                        },
                        "tags": [],
                    }
                }
            },
        )
    )
    await provider.enrich(_ip_ioc())
    first = route.call_count
    await provider.enrich(_ip_ioc())
    assert route.call_count == first


# --- MISP ---


@pytest.mark.asyncio()
@respx.mock
async def test_misp_hit_with_to_ids(http_internal, cache):
    respx.post("https://misp.internal/attributes/restSearch").mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "to_ids": True,
                            "category": "Network activity",
                            "type": "ip-dst",
                            "value": "8.8.8.8",
                        }
                    ]
                }
            },
        )
    )
    provider = MispProvider(http_internal, cache, b"k", "https://misp.internal", 60)
    result = await provider.enrich(_ip_ioc())
    assert result is not None
    assert result.reputation_score == 85
    assert "Network activity" in result.tags


@pytest.mark.asyncio()
@respx.mock
async def test_misp_empty_returns_none(http_internal, cache):
    respx.post("https://misp.internal/attributes/restSearch").mock(
        return_value=httpx.Response(200, json={"response": {"Attribute": []}})
    )
    provider = MispProvider(http_internal, cache, b"k", "https://misp.internal", 60)
    assert await provider.enrich(_ip_ioc()) is None


@pytest.mark.asyncio()
@respx.mock
async def test_misp_auth_failure_returns_none(http_internal, cache):
    respx.post("https://misp.internal/attributes/restSearch").mock(return_value=httpx.Response(403))
    provider = MispProvider(http_internal, cache, b"bad", "https://misp.internal", 60)
    assert await provider.enrich(_ip_ioc()) is None


@pytest.mark.asyncio()
@respx.mock
async def test_misp_invalid_json_returns_none(http_internal, cache):
    respx.post("https://misp.internal/attributes/restSearch").mock(
        return_value=httpx.Response(200, content=b"not-json")
    )
    provider = MispProvider(http_internal, cache, b"k", "https://misp.internal", 60)
    assert await provider.enrich(_ip_ioc()) is None


def test_misp_rejects_http_endpoint(http_client, cache):
    with pytest.raises(ValueError):
        MispProvider(http_client, cache, b"k", "http://misp.internal", 60)


@pytest.mark.asyncio()
async def test_misp_unsupported_type_returns_none(http_internal, cache):
    provider = MispProvider(http_internal, cache, b"k", "https://misp.internal", 60)
    ioc = IOC(value="CVE-2024-0001", ioc_type=IOCType.CVE, source="test")
    assert await provider.enrich(ioc) is None


# --- R1 regression: raw provider bytes must NOT be persisted by default ---


@pytest.mark.asyncio()
@respx.mock
async def test_vt_does_not_cache_truncated_raw_by_default(http_client, cache, monkeypatch):
    monkeypatch.delenv("TIC_DEBUG_CACHE_RAW", raising=False)
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 90,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 9,
                            "timeout": 0,
                        },
                        "tags": ["scanner"],
                        "reputation": 10,
                    }
                }
            },
        )
    )
    provider = VirusTotalProvider(http_client, cache, b"key", 60)
    result = await provider.enrich(_ip_ioc())
    assert result is not None
    assert result.truncated_raw == ""
    cached = cache.get("virustotal", "ip:8.8.8.8")
    assert cached is not None
    assert b"truncated_raw" in cached  # field present
    assert b'"truncated_raw":""' in cached  # but empty


@pytest.mark.asyncio()
@respx.mock
async def test_vt_caches_truncated_raw_when_debug_flag_set(http_client, cache, monkeypatch):
    monkeypatch.setenv("TIC_DEBUG_CACHE_RAW", "true")
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 90,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 9,
                            "timeout": 0,
                        },
                        "tags": ["scanner"],
                    }
                }
            },
        )
    )
    provider = VirusTotalProvider(http_client, cache, b"key", 60)
    result = await provider.enrich(_ip_ioc())
    assert result is not None
    assert result.truncated_raw != ""
    assert "scanner" in result.truncated_raw


@pytest.mark.asyncio()
@respx.mock
async def test_misp_does_not_cache_truncated_raw_by_default(http_internal, cache, monkeypatch):
    monkeypatch.delenv("TIC_DEBUG_CACHE_RAW", raising=False)
    respx.post("https://misp.internal/attributes/restSearch").mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "to_ids": True,
                            "category": "Network activity",
                            "type": "ip-dst",
                            "value": "8.8.8.8",
                        }
                    ]
                }
            },
        )
    )
    provider = MispProvider(http_internal, cache, b"k", "https://misp.internal", 60)
    result = await provider.enrich(_ip_ioc())
    assert result is not None
    assert result.truncated_raw == ""
    cached = cache.get("misp", "ip:8.8.8.8")
    assert cached is not None
    assert b'"truncated_raw":""' in cached
