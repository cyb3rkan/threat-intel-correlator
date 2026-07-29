# src/tic/api/security_headers.py
"""Attach hardened security headers to every API response.

The local API serves a same-origin SPA and returns only JSON, so the policy is
deliberately strict (``default-src 'none'``) — there is no first-party
script/style/image to allow. Headers are written with ``setdefault`` so a
handler that already set its own value is never clobbered, which means the
policy still lands on error responses produced by the framework.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import Response

_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
}
_SERVER_HEADER = "tic-api"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers["Server"] = _SERVER_HEADER
        with contextlib.suppress(KeyError):
            del response.headers["X-Powered-By"]
        return response
