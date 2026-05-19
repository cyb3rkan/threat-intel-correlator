# tests/integration/test_misp_verify_tls.py
"""MISP provider — TLS verify, NetworkError diagnostics, and parse coverage.

Covers:
- Self-signed TLS failure surfaces as NetworkError and is logged with
  endpoint_host, exception_type, verify_tls, total_timeout_seconds, and a
  sanitized_reason that contains no secrets, no Authorization header, no
  full URL, and no stack trace.
- verify_tls=false applied to ONE provider keeps verification on for any
  other SafeHttpClient instance in the same process.
- MISP {"response":{"Attribute":[...]}} parses correctly and produces an
  EnrichmentResult with provider="misp".
- Empty Attribute response silently returns None.
- All supported IOC types (ip, domain, url, hash_md5/sha1/sha256/sha512,
  email) map to the right MISP type and parse a hit.
- The Authorization header value is never serialised into log records.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from structlog.testing import capture_logs

from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.adapters.enrichment.misp_provider import MispProvider, _sanitize_reason
from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.ioc import IOC, IOCType
from tic.infra.config import HttpClientConfig


def _blob(records: list[dict]) -> str:
    """Flatten a structlog capture list to a single string for substring checks."""
    return json.dumps(records, default=str)


_MISP_HOST = "misp.internal"
_MISP_URL = f"https://{_MISP_HOST}"
_RESTSEARCH = f"{_MISP_URL}/attributes/restSearch"
_SECRET_KEY = b"super-secret-misp-key-DO-NOT-LEAK"


@pytest.fixture()
def cache(tmp_path: Path) -> SqliteCache:
    return SqliteCache(tmp_path / "cache.db", allowed_root=tmp_path)


def _http(verify_tls: bool = True) -> SafeHttpClient:
    return SafeHttpClient(
        HttpClientConfig(),
        extra_host_allowlist=frozenset({_MISP_HOST}),
        verify_tls=verify_tls,
    )


def _ip() -> IOC:
    return IOC(value="8.8.8.8", ioc_type=IOCType.IP, source="test")


# ---------------------------------------------------------------------------
# verify_tls behavior
# ---------------------------------------------------------------------------


def test_safe_client_defaults_verify_tls_true():
    c = SafeHttpClient(HttpClientConfig())
    assert c.verify_tls is True


def test_safe_client_per_instance_verify_tls_false():
    c = SafeHttpClient(HttpClientConfig(), verify_tls=False)
    assert c.verify_tls is False


def test_safe_client_other_instances_unaffected_by_misp_opt_out():
    misp_http = SafeHttpClient(HttpClientConfig(), verify_tls=False)
    other_http = SafeHttpClient(HttpClientConfig())  # default — provider unrelated to MISP
    assert misp_http.verify_tls is False
    assert other_http.verify_tls is True


@pytest.mark.asyncio()
@respx.mock
async def test_misp_request_allowed_when_verify_tls_false(cache):
    """verify_tls=false on the MISP client must not block requests."""
    respx.post(_RESTSEARCH).mock(
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
    provider = MispProvider(_http(verify_tls=False), cache, _SECRET_KEY, _MISP_URL, 60)
    result = await provider.enrich(_ip())
    assert result is not None
    assert result.provider == "misp"
    assert result.reputation_score == 85


# ---------------------------------------------------------------------------
# NetworkError diagnostics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_self_signed_tls_failure_yields_no_enrichment_and_logs_diagnostics(cache):
    """Simulate the symptom: httpx raises ConnectError on TLS verification.

    The provider must:
      * return None (no enrichment)
      * emit a single provider_request_failed log
      * include endpoint_host, exception_type, verify_tls, sanitized_reason
      * NOT include the API key, Authorization header, or full URL
    """
    respx.post(_RESTSEARCH).mock(
        side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")
    )
    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)

    with capture_logs() as logs:
        result = await provider.enrich(_ip())
    assert result is None

    failed = [r for r in logs if r.get("event") == "provider_request_failed"]
    assert failed, f"expected provider_request_failed, got {logs}"
    rec = failed[0]
    assert rec["provider"] == "misp"
    assert rec["endpoint_host"] == _MISP_HOST
    assert rec["exception_type"] == "ConnectError"
    assert rec["verify_tls"] is True
    assert "total_timeout_seconds" in rec
    assert "sanitized_reason" in rec

    blob = _blob(logs)
    assert _SECRET_KEY.decode() not in blob
    assert "Authorization" not in blob
    # Full URL path must not leak via the sanitized_reason
    assert "/attributes/restSearch" not in blob


@pytest.mark.asyncio()
@respx.mock
async def test_network_error_log_redacts_authorization_from_exception_text(cache):
    """Even if an exception message embeds an Authorization header, we strip it."""
    respx.post(_RESTSEARCH).mock(
        side_effect=httpx.ConnectError(
            "TLS handshake failed for request with Authorization: super-secret-misp-key-DO-NOT-LEAK"
        )
    )
    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    blob = _blob(logs)
    assert _SECRET_KEY.decode() not in blob


def test_sanitize_reason_strips_urls_and_auth_pairs():
    # URL with query string carrying a token
    e = RuntimeError("connect failed to https://misp.internal/attributes/restSearch?key=abc123")
    out = _sanitize_reason(e)
    assert "https://" not in out
    assert "abc123" not in out

    # Authorization-style key/value
    e2 = RuntimeError("bad header api_key=THIS_IS_SECRET stuff")
    out2 = _sanitize_reason(e2)
    assert "THIS_IS_SECRET" not in out2


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_parses_canonical_restsearch_response(cache):
    respx.post(_RESTSEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "to_ids": False,
                            "category": "Payload delivery",
                            "type": "ip-dst",
                            "value": "8.8.8.8",
                        },
                        {
                            "to_ids": True,
                            "category": "Network activity",
                            "type": "ip-dst",
                            "value": "8.8.8.8",
                        },
                    ]
                }
            },
        )
    )
    provider = MispProvider(_http(), cache, _SECRET_KEY, _MISP_URL, 60)
    r = await provider.enrich(_ip())
    assert r is not None
    assert r.provider == "misp"
    assert r.reputation_score == 85  # any to_ids -> 85
    assert {"Network activity", "Payload delivery"}.issubset(r.tags)


@pytest.mark.asyncio()
@respx.mock
async def test_empty_attribute_list_silently_returns_none(cache):
    respx.post(_RESTSEARCH).mock(
        return_value=httpx.Response(200, json={"response": {"Attribute": []}})
    )
    provider = MispProvider(_http(), cache, _SECRET_KEY, _MISP_URL, 60)
    assert await provider.enrich(_ip()) is None


@pytest.mark.parametrize(
    "ioc_type,ioc_value,misp_type",
    [
        (IOCType.IP, "8.8.8.8", "ip-dst"),
        (IOCType.DOMAIN, "example.com", "domain"),
        (IOCType.URL, "https://bad.example.com/x", "url"),
        (IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "md5"),
        (IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        (
            IOCType.HASH_SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256",
        ),
        (
            IOCType.HASH_SHA512,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47"
            "d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "sha512",
        ),
        (IOCType.EMAIL, "user@example.com", "email"),
    ],
)
@pytest.mark.asyncio()
async def test_all_supported_ioc_types_round_trip(cache, ioc_type, ioc_value, misp_type):
    with respx.mock() as router:
        route = router.post(_RESTSEARCH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": {
                        "Attribute": [
                            {
                                "to_ids": True,
                                "category": "Network activity",
                                "type": misp_type,
                                "value": ioc_value,
                            }
                        ]
                    }
                },
            )
        )
        provider = MispProvider(_http(), cache, _SECRET_KEY, _MISP_URL, 60)
        ioc = IOC(value=ioc_value, ioc_type=ioc_type, source="test")
        r = await provider.enrich(ioc)
    assert r is not None, f"no enrichment for {ioc_type}"
    assert r.provider == "misp"
    # The request body must carry the right MISP type.
    sent = route.calls[0].request
    body = json.loads(sent.content)
    assert body["type"] == misp_type
    assert body["value"] == ioc_value


# ---------------------------------------------------------------------------
# Authorization header must never reach logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_authorization_header_never_logged_even_on_success(cache):
    respx.post(_RESTSEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"to_ids": True, "category": "x", "type": "ip-dst", "value": "8.8.8.8"}
                    ]
                }
            },
        )
    )
    provider = MispProvider(_http(), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        await provider.enrich(_ip())
    blob = _blob(logs)
    assert "Authorization" not in blob
    assert _SECRET_KEY.decode() not in blob


# ---------------------------------------------------------------------------
# Additional NetworkError shapes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_read_timeout_surfaces_exception_type_in_log(cache):
    respx.post(_RESTSEARCH).mock(side_effect=httpx.ReadTimeout("slow lab"))
    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    failed = [r for r in logs if r.get("event") == "provider_request_failed"]
    assert failed and failed[0]["exception_type"] == "ReadTimeout"


@pytest.mark.asyncio()
async def test_network_error_without_cause_does_not_crash_logger(cache, monkeypatch):
    """If SafeHttpClient raises a NetworkError with no __cause__ set, the
    provider must still log a sensible exception_type (the NetworkError
    class itself) rather than crashing on attribute access."""
    from tic.domain.errors import NetworkError

    async def _raise(*a, **k):
        raise NetworkError("bare NetworkError, no cause")

    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)
    monkeypatch.setattr(provider._http, "post", _raise)

    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    failed = [r for r in logs if r.get("event") == "provider_request_failed"]
    assert failed
    assert failed[0]["exception_type"] == "NetworkError"


# ---------------------------------------------------------------------------
# Status problem logs include diagnostic fields (auth/rate-limit/error)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_auth_403_logs_diagnostics_without_leaking_key(cache):
    respx.post(_RESTSEARCH).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    provider = MispProvider(_http(verify_tls=False), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    auth = [r for r in logs if r.get("event") == "provider_auth_failed"]
    assert auth
    rec = auth[0]
    assert rec["status"] == 403
    assert rec["endpoint_host"] == _MISP_HOST
    assert rec["verify_tls"] is False
    assert "total_timeout_seconds" in rec
    blob = _blob(logs)
    assert _SECRET_KEY.decode() not in blob
    assert "Authorization" not in blob


@pytest.mark.asyncio()
@respx.mock
async def test_rate_limit_429_logs_diagnostics(cache):
    respx.post(_RESTSEARCH).mock(return_value=httpx.Response(429))
    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    rate = [r for r in logs if r.get("event") == "provider_rate_limited"]
    assert rate
    assert rate[0]["status"] == 429
    assert rate[0]["endpoint_host"] == _MISP_HOST
    assert rate[0]["verify_tls"] is True


@pytest.mark.asyncio()
@respx.mock
async def test_500_status_logs_diagnostics(cache):
    respx.post(_RESTSEARCH).mock(return_value=httpx.Response(500))
    provider = MispProvider(_http(verify_tls=True), cache, _SECRET_KEY, _MISP_URL, 60)
    with capture_logs() as logs:
        assert await provider.enrich(_ip()) is None
    err = [r for r in logs if r.get("event") == "provider_error_status"]
    assert err
    assert err[0]["status"] == 500
    assert err[0]["endpoint_host"] == _MISP_HOST


# ---------------------------------------------------------------------------
# Corrupt cache entry no longer floods the log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
@respx.mock
async def test_corrupt_cache_entry_warns_only_once(cache):
    # Plant a junk row that will fail EnrichmentResult.model_validate_json
    cache.set("misp", "ip:8.8.8.8", b"{not-valid-enrichment-json}", 300)
    respx.post(_RESTSEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"to_ids": True, "category": "x", "type": "ip-dst", "value": "8.8.8.8"}
                    ]
                }
            },
        )
    )
    provider = MispProvider(_http(), cache, _SECRET_KEY, _MISP_URL, 60)

    # First call: warning fires, cache is overwritten via .set() on success
    with capture_logs() as logs1:
        first = await provider.enrich(_ip())
    assert first is not None
    assert sum(1 for r in logs1 if r.get("event") == "cache_corrupt_entry") == 1

    # Second call: row is now valid, so no warning at all
    with capture_logs() as logs2:
        second = await provider.enrich(_ip())
    assert second is not None
    assert all(r.get("event") != "cache_corrupt_entry" for r in logs2)
