# src/tic/ports/log_source.py
"""Log source port. Streams normalized LogLine objects for correlation."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from tic.application.correlation import LogLine


class LogSource(Protocol):
    """Contract: yield LogLine objects in a memory-bounded, streaming fashion.

    Implementations MUST:
    - Enforce per-line size limits (DoS defense).
    - Never persist raw log text beyond the yielded LogLine; caller may only
      hash the text for audit.
    - Skip malformed records with a log message rather than raising, unless
      the underlying source itself is unusable.
    """

    name: str

    def stream(self) -> Iterator[LogLine]: ...