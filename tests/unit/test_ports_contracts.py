# tests/unit/test_ports_contracts.py
"""Structural subtyping sanity checks for port Protocols."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import TextIO

from tic.application.correlation import LogLine
from tic.domain.finding import Finding
from tic.ports.log_source import LogSource
from tic.ports.renderer import Renderer
from tic.ports.secret_store import SecretStore


class _FakeRenderer:
    name = "fake"

    def render(self, findings: Iterable[Finding], out: TextIO) -> int:
        return sum(1 for _ in findings)


class _FakeLogSource:
    name = "fake"

    def stream(self) -> Iterator[LogLine]:
        return iter(())


class _FakeSecretStore:
    def get(self, service: str, user: str) -> bytes:
        return b"x"


def test_fake_renderer_is_structural_subtype() -> None:
    r: Renderer = _FakeRenderer()
    assert r.name == "fake"


def test_fake_log_source_is_structural_subtype() -> None:
    s: LogSource = _FakeLogSource()
    assert s.name == "fake"


def test_fake_secret_store_is_structural_subtype() -> None:
    s: SecretStore = _FakeSecretStore()
    assert s.get("svc", "usr") == b"x"
