# src/tic/ports/renderer.py
"""Renderer port. All output formatters implement this protocol."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, TextIO

from tic.domain.finding import Finding


class Renderer(Protocol):
    """Contract: write `findings` to `out`, return count of rendered findings.

    Implementations MUST NOT write raw untrusted strings directly; they must
    pass all user-controlled fields through appropriate sanitizers
    (ANSI strip for terminal, CSV escape for tabular, HTML/Markdown escape
    where relevant). See `tic.security.*` primitives.
    """

    name: str

    def render(self, findings: Iterable[Finding], out: TextIO) -> int: ...