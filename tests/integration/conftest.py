# tests/integration/conftest.py
"""Integration-test fixtures for the FastAPI app.

The API wires a stateful, per-client rate limiter. Because ``app`` is a
module-level singleton shared across the whole test session, sweep POSTs from
one test would otherwise consume the shared 10/min budget and make *other*
tests observe spurious 429s depending on collection order. Rebuilding the
middleware stack around every test hands each one a clean set of rate-limit
windows without weakening the production limits (Starlette re-instantiates the
middleware when ``middleware_stack`` is ``None``).

Opt-in rather than ``autouse``: it imports ``tic.api.main``, which pulls in the
whole FastAPI app, the HTTP providers and their dependencies. As an autouse
fixture it forced that import on every test in this directory, including ones
that only read a YAML file. Tests that exercise the API request it explicitly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


# PT004 wants a leading underscore on a fixture that returns nothing, but this
# one is referenced by name from `pytest.mark.usefixtures` in the API test
# modules, so the public name is the point.
@pytest.fixture()
def fresh_app_middleware() -> Iterator[None]:  # noqa: PT004
    """Give one test a clean rate-limit window.

    Request this from every test that drives the API through ``TestClient``;
    without it, tests share the 10/min sweep budget and fail as 429s depending
    on collection order.
    """
    from tic.api.main import app

    app.middleware_stack = None
    yield
    app.middleware_stack = None
