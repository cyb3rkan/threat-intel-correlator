# src/tic/api/rate_limit.py
"""Per-client-IP sliding-window rate limiting for the local API.

The window is keyed on the transport peer address (``request.client.host``),
never on ``X-Forwarded-For``: this service is local-first (binds 127.0.0.1)
with no trusted reverse proxy, so an XFF header would be attacker-controlled
and trivially spoofable. Keeping one window per client prevents a single
noisy caller from exhausting the budget for everyone — the previous global
counter did exactly that.

Limits (defaults): ``POST /api/sweep`` -> 10 / 60s; every other route -> 60 /
60s. A throttled request receives ``429`` with a ``Retry-After`` header.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import TYPE_CHECKING, Protocol

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from tic.infra.logging import get_logger

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.responses import Response
    from starlette.types import ASGIApp

    from tic.ports.state_store import StateStore

_log = get_logger(__name__)

# Upper bound on distinct client windows kept in memory, so a flood of spoofed
# source addresses cannot grow the maps without limit. Idle windows are evicted
# first; for the expected local-first single-client use this is never reached.
_MAX_TRACKED_CLIENTS = 4096


class _SlidingWindow:
    """Monotonic-clock sliding-window counter for one client + route class."""

    __slots__ = ("_hits", "_limit", "_window")

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: deque[float] = deque()

    def allow(self, now: float) -> bool:
        cutoff = now - self._window
        hits = self._hits
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self._limit:
            return False
        hits.append(now)
        return True

    def idle(self, now: float) -> bool:
        """True when no recorded hit falls inside the window (safe to evict)."""
        return not self._hits or self._hits[-1] < now - self._window


class _PerClientLimiter:
    """Holds one :class:`_SlidingWindow` per client key for a route class."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._windows: dict[str, _SlidingWindow] = {}

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def window(self) -> float:
        return self._window

    def allow(self, client_key: str, now: float) -> bool:
        window = self._windows.get(client_key)
        if window is None:
            if len(self._windows) >= _MAX_TRACKED_CLIENTS:
                self._evict_idle(now)
            window = _SlidingWindow(self._limit, self._window)
            self._windows[client_key] = window
        return window.allow(now)

    def _evict_idle(self, now: float) -> None:
        idle = [key for key, win in self._windows.items() if win.idle(now)]
        for key in idle:
            del self._windows[key]
        if not idle and self._windows:
            # Nothing idle (active flood): drop one entry to stay bounded.
            self._windows.pop(next(iter(self._windows)))


class _ClientLimiter(Protocol):
    """Structural type shared by the in-memory and store-backed limiters."""

    @property
    def limit(self) -> int: ...

    @property
    def window(self) -> float: ...

    def allow(self, client_key: str, now: float) -> bool: ...


class _StoreClientLimiter:
    """Per-client fixed-window limiter backed by a shared StateStore.

    Used when a StateStore is injected (e.g. Redis) so the budget is enforced
    across replicas. Fixed-window (counter + TTL) rather than the in-process
    sliding window; the two agree for the common single-window case.
    """

    def __init__(
        self, limit: int, window_seconds: float, store: StateStore, prefix: str
    ) -> None:
        self._limit = limit
        self._window = window_seconds
        self._store = store
        self._prefix = prefix

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def window(self) -> float:
        return self._window

    def allow(self, client_key: str, now: float) -> bool:
        bucket = int(now // self._window) if self._window > 0 else 0
        key = f"ratelimit:{self._prefix}:{client_key}:{bucket}"
        return self._store.incr(key, ttl_seconds=self._window) <= self._limit


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject callers that exceed their per-client budget.

    Defaults to the in-process per-client sliding window (unchanged behavior).
    Inject a ``StateStore`` to share the budget across replicas; pass distinct
    ``sweep_window`` / ``read_window`` to size each route class independently.
    """

    def __init__(  # noqa: PLR0913
        self,
        app: ASGIApp,
        *,
        sweep_limit: int = 10,
        read_limit: int = 60,
        window_seconds: float = 60.0,
        sweep_window: float | None = None,
        read_window: float | None = None,
        store: StateStore | None = None,
    ) -> None:
        super().__init__(app)
        sweep_w = sweep_window if sweep_window is not None else window_seconds
        read_w = read_window if read_window is not None else window_seconds
        self._sweep: _ClientLimiter
        self._read: _ClientLimiter
        if store is None:
            self._sweep = _PerClientLimiter(sweep_limit, sweep_w)
            self._read = _PerClientLimiter(read_limit, read_w)
        else:
            self._sweep = _StoreClientLimiter(sweep_limit, sweep_w, store, "sweep")
            self._read = _StoreClientLimiter(read_limit, read_w, store, "read")
        self._lock = asyncio.Lock()

    def _limiter_for(self, request: Request) -> _ClientLimiter:
        if request.method == "POST" and request.url.path == "/api/sweep":
            return self._sweep
        return self._read

    @staticmethod
    def _client_key(request: Request) -> str:
        # Local-first: trust the transport peer, never X-Forwarded-For
        # (spoofable, and there is no trusted proxy in this deployment).
        client = request.client
        return client.host if client is not None else "unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        limiter = self._limiter_for(request)
        key = self._client_key(request)
        now = time.monotonic()
        async with self._lock:
            allowed = limiter.allow(key, now)
        if not allowed:
            retry_after = int(limiter.window)
            _log.warning(
                "rate_limit_exceeded", method=request.method, path=request.url.path
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limiter.limit),
                },
            )
        return await call_next(request)
