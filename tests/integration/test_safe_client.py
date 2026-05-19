# tests/integration/test_safe_client.py
from __future__ import annotations

import httpx
import pytest
import respx

from tic.adapters.http.safe_client import SafeHttpClient
from tic.domain.errors import SecurityViolationError
from tic.infra.config import HttpClientConfig


def _cfg() -> HttpClientConfig:
    return HttpClientConfig(
        connect_timeout_seconds=5.0,
        read_timeout_seconds=5.0,
        total_timeout_seconds=10.0,
        max_retries=0,
    )


@pytest.mark.asyncio()
@respx.mock
async def test_get_returns_response():
    respx.get("https://example.com/api").mock(return_value=httpx.Response(200, content=b"ok"))
    client = SafeHttpClient(_cfg())
    resp = await client.get("https://example.com/api")
    assert resp.status_code == 200
    assert resp.body_bytes == b"ok"
    await client.aclose()


@pytest.mark.asyncio()
@respx.mock
async def test_post_returns_response():
    respx.post("https://example.com/api").mock(return_value=httpx.Response(201, content=b"created"))
    client = SafeHttpClient(_cfg())
    resp = await client.post("https://example.com/api", content=b"data")
    assert resp.status_code == 201
    await client.aclose()


@pytest.mark.asyncio()
async def test_rejects_http_scheme():
    client = SafeHttpClient(_cfg())
    with pytest.raises(SecurityViolationError):
        await client.get("http://example.com/api")
    await client.aclose()


@pytest.mark.asyncio()
async def test_rejects_private_ip():
    client = SafeHttpClient(_cfg())
    with pytest.raises(SecurityViolationError):
        await client.get("https://192.168.1.1/api")
    await client.aclose()


@pytest.mark.asyncio()
@respx.mock
async def test_headers_lowercased():
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "application/json"}, content=b"{}"
        )
    )
    client = SafeHttpClient(_cfg())
    resp = await client.get("https://example.com/")
    assert "content-type" in resp.headers
    await client.aclose()
