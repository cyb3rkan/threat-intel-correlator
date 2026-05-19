# src/tic/adapters/parsers/base.py
"""Parser protocol. All feed parsers implement this contract.

Security contract (MANDATORY for all implementations):
- Resolve the input path via `tic.security.path_guard.safe_resolve_within`
  before opening it.
- Enforce `limits.max_file_size_bytes` by inspecting `stat().st_size` before
  streaming begins, and count bytes/rows during iteration.
- Apply `limits.max_string_length` per raw IOC candidate.
- Apply `limits.max_iocs_per_feed` as a hard ceiling; raise ParseError if
  exceeded.
- Yield only fully-normalized `IOC` value objects (via
  `tic.application.normalization.make_ioc`).
- On malformed rows, log at DEBUG/WARNING and skip; do not raise unless the
  underlying file is unusable.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from tic.domain.ioc import IOC
from tic.infra.config import ParserLimits


class FeedParser(Protocol):
    """Contract for streaming IOC feed parsers."""

    format_name: str

    def parse(
        self,
        path: Path,
        *,
        allowed_root: Path,
        limits: ParserLimits,
        source_hint: str,
    ) -> Iterator[IOC]: ...