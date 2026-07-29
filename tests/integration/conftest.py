# tests/integration/conftest.py
"""Integration-test fixtures for the FastAPI app.

The API now wires a stateful, per-client rate limiter. Because ``app`` is a
module-level singleton shared across the whole test session, sweep POSTs from
one test would otherwise consume the shared 10/min budget and make *other*
tests observe spurious 429s depending on collection order. Rebuilding the
middleware stack around every test hands each one a clean set of rate-limit
windows without weakening the production limits (Starlette re-instantiates the
middleware when ``middleware_stack`` is ``None``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _fresh_app_middleware() -> Iterator[None]:
    from tic.api.main import app

    app.middleware_stack = None
    yield
    app.middleware_stack = None
