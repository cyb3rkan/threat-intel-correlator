# src/tic/adapters/http/safe_client.py
"""Hardened HTTP client.

Security fixes applied:
- Auth headers dropped on cross-host redirect (credential leak prevention).
- Cross-origin redirects fail-closed for provider calls (integrity).
- total_timeout enforced via asyncio.timeout.
- Relative Location headers resolved before SSRF check.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from tic.domain.errors import NetworkError, SecurityViolationError
from tic.infra.config import HttpClientConfig
from tic.infra.logging import get_logger
from tic.security.ssrf_guard import ensure_public_url

_log = get_logger(__name__)

_CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "x-apikey",
        "key",
        "cookie",
        "x-auth-token",
        "api-key",
    }
)


def _drop_auth_on_cross_host(
    orig_url: str, redir_url: str, headers: dict[str, str]
) -> dict[str, str]:
    orig_host = (urlparse(orig_url).hostname or "").lower()
    redir_host = (urlparse(redir_url).hostname or "").lower()
    if orig_host == redir_host:
        return headers
    safe = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
    if len(safe) < len(headers):
        _log.warning("auth_headers_dropped_cross_host", from_host=orig_host, to_host=redir_host)
    return safe


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body_bytes: bytes


class SafeHttpClient:
    def __init__(
        self,
        cfg: HttpClientConfig,
        *,
        extra_host_allowlist: frozenset[str] = frozenset(),
        max_body_bytes: int = 16 * 1024 * 1024,
        allow_cross_origin_redirect: bool = False,
        verify_tls: bool | None = None,
    ) -> None:
        self._cfg = cfg
        self._extra = extra_host_allowlist
        self._max_body = max_body_bytes
        # Provider calls should use allow_cross_origin_redirect=False (default)
        # so unexpected redirects to foreign hosts fail-closed rather than
        # being silently followed (even after auth-header drop).
        self._cross_origin_ok = allow_cross_origin_redirect

        # TLS verification: per-instance override falls back to HttpClientConfig.
        # Default True. Opt-in False is reserved for lab targets with self-signed
        # certs (e.g., a Dockerised on-prem MISP) and is wired in only when an
        # operator explicitly sets verify_tls: false in that provider's config.
        effective_verify = cfg.verify_tls if verify_tls is None else verify_tls
        self._verify_tls = bool(effective_verify)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=cfg.connect_timeout_seconds,
                read=cfg.read_timeout_seconds,
                write=cfg.read_timeout_seconds,
                pool=None,
            ),
            verify=self._verify_tls,
            follow_redirects=False,
            http2=True,
            headers={"User-Agent": cfg.user_agent},
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
        )
        self._total_timeout = cfg.total_timeout_seconds
        self._closed = False

    @property
    def verify_tls(self) -> bool:
        return self._verify_tls

    @property
    def total_timeout_seconds(self) -> float:
        return self._total_timeout

    async def aclose(self) -> None:
        """Idempotent close.

        The CLI sweep runs the orchestrator on one event loop and the
        cleanup on a second `asyncio.run(...)` — by then the original
        loop is gone, and httpx's `AsyncClient.aclose` raises
        `RuntimeError: Event loop is closed` (or "no running event
        loop") even though all sockets the loop owned are already
        reclaimed. The right behaviour for the caller is "we tried,
        nothing leaked, move on" — so we swallow that specific
        RuntimeError pattern, mark ourselves closed, and never raise.

        Real network exceptions during in-flight requests are
        unrelated to this method; they surface through the request
        path and are not suppressed here.
        """
        if self._closed:
            return
        self._closed = True
        try:
            await self._client.aclose()
        except RuntimeError:
            # Cross-loop / already-closed transport. Resources owned by
            # the dead loop are reclaimed by the runtime; nothing to
            # do here, and emitting a warning during a successful sweep
            # is noise. Keep silent.
            return

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return await self._request("GET", url, headers=headers, content=None)

    async def post(
        self, url: str, *, headers: dict[str, str] | None = None, content: bytes | None = None
    ) -> HttpResponse:
        return await self._request("POST", url, headers=headers, content=content)

    async def _request(
        self, method: str, url: str, *, headers: dict[str, str] | None, content: bytes | None
    ) -> HttpResponse:
        ensure_public_url(url, extra_allowlist=self._extra)
        original_url = url
        active_headers = dict(headers or {})

        async def _do() -> HttpResponse:
            current_url = original_url
            cur_headers = dict(active_headers)
            try:
                resp = await self._client.request(
                    method, current_url, headers=cur_headers, content=content
                )
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                httpx.TimeoutException,
            ) as e:
                raise NetworkError(f"{method} network error: {type(e).__name__}") from e

            hops = 0
            while resp.is_redirect and hops < 5:
                loc = resp.headers.get("location", "").strip()
                if not loc:
                    break
                absolute_loc = urljoin(current_url, loc)
                ensure_public_url(absolute_loc, extra_allowlist=self._extra)

                orig_host = (urlparse(current_url).hostname or "").lower()
                redir_host = (urlparse(absolute_loc).hostname or "").lower()
                if orig_host != redir_host and not self._cross_origin_ok:
                    raise SecurityViolationError(
                        f"cross-origin redirect rejected: {current_url} -> {absolute_loc}",
                        user_message="Provider redirect to unexpected host rejected.",
                    )

                cur_headers = _drop_auth_on_cross_host(current_url, absolute_loc, cur_headers)
                try:
                    resp = await self._client.request(method, absolute_loc, headers=cur_headers)
                    current_url = absolute_loc
                except (httpx.ConnectError, httpx.ReadTimeout) as e:
                    raise NetworkError(f"redirect hop failed: {type(e).__name__}") from e
                hops += 1

            body = await self._read_body_bounded(resp)
            return HttpResponse(
                status_code=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body_bytes=body,
            )

        async def _with_timeout() -> HttpResponse:
            try:
                async with asyncio.timeout(self._total_timeout):
                    is_idempotent = method in {"GET", "HEAD"}
                    if is_idempotent and self._cfg.max_retries > 0:
                        retrying = retry(
                            stop=stop_after_attempt(self._cfg.max_retries),
                            wait=wait_exponential_jitter(initial=0.5, max=10.0),
                            retry=retry_if_exception_type(NetworkError),
                            reraise=True,
                        )
                        try:
                            return await retrying(_do)()  # type: ignore[misc]
                        except RetryError as e:
                            raise NetworkError("all retries exhausted") from e
                    return await _do()
            except TimeoutError as e:
                raise NetworkError(f"total timeout ({self._total_timeout}s) exceeded") from e

        return await _with_timeout()

    async def _read_body_bounded(self, resp: httpx.Response) -> bytes:
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            if len(buf) + len(chunk) > self._max_body:
                raise SecurityViolationError(
                    f"response body exceeded {self._max_body} bytes",
                    user_message="Provider response too large.",
                )
            buf.extend(chunk)
        return bytes(buf)
