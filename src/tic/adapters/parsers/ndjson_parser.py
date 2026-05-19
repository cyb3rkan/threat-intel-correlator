# src/tic/adapters/parsers/ndjson_parser.py
"""NDJSON IOC feed parser.

One JSON object per line. Each object must contain an IOC value in one of
the known value keys. Lines that fail to parse are skipped with a DEBUG log
entry; the feed is not aborted unless the underlying file is unusable or a
hard limit is exceeded.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from tic.adapters.parsers.base import FeedParser
from tic.application.normalization import make_ioc
from tic.domain.errors import InputValidationError, ParseError
from tic.domain.ioc import IOC
from tic.infra.config import ParserLimits
from tic.infra.logging import get_logger
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

_VALUE_KEYS: tuple[str, ...] = ("value", "indicator", "ioc", "observable")
_CONFIDENCE_KEYS: tuple[str, ...] = ("confidence", "score")
_TAG_KEYS: tuple[str, ...] = ("tags", "labels")


def _extract_value(obj: dict[str, Any]) -> str | None:
    for k in _VALUE_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _extract_confidence(obj: dict[str, Any]) -> int:
    for k in _CONFIDENCE_KEYS:
        v = obj.get(k)
        if isinstance(v, int):
            return max(0, min(100, v))
        if isinstance(v, float):
            return max(0, min(100, int(v)))
    return 50


def _extract_tags(obj: dict[str, Any]) -> frozenset[str]:
    for k in _TAG_KEYS:
        v = obj.get(k)
        if isinstance(v, list):
            return frozenset(str(x)[:64] for x in v[:32] if isinstance(x, (str, int)))
    return frozenset()


class NdjsonFeedParser(FeedParser):
    """Streaming NDJSON parser. Implements FeedParser protocol."""

    format_name = "ndjson"

    def parse(
        self,
        path: Path,
        *,
        allowed_root: Path,
        limits: ParserLimits,
        source_hint: str = "ndjson",
    ) -> Iterator[IOC]:
        return parse_ndjson_feed(
            path,
            allowed_root=allowed_root,
            limits=limits,
            source_hint=source_hint,
        )


def parse_ndjson_feed(
    path: Path,
    *,
    allowed_root: Path,
    limits: ParserLimits,
    source_hint: str = "ndjson",
) -> Iterator[IOC]:
    """Stream IOCs from an NDJSON feed.

    Security:
    - Path confined to allowed_root via safe_resolve_within.
    - File size capped pre-read.
    - Per-line length bounded (limits.max_string_length); oversized lines skipped.
    - IOC count capped at limits.max_iocs_per_feed.
    """
    resolved = safe_resolve_within(path, allowed_root=allowed_root)
    size = resolved.stat().st_size
    if size > limits.max_file_size_bytes:
        raise ParseError(
            f"ndjson too large: {size} > {limits.max_file_size_bytes}",
            user_message="Feed file exceeds configured size limit.",
        )

    count = 0
    with resolved.open("r", encoding="utf-8", errors="strict") as f:
        for line_num, raw_line in enumerate(f, start=1):
            # Bound per-line size to prevent single-line memory blowup.
            if len(raw_line) > limits.max_string_length:
                _log.warning("ndjson_line_too_long", line=line_num, length=len(raw_line))
                continue
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                _log.debug("ndjson_line_not_json", line=line_num, error=str(e)[:120])
                continue
            if not isinstance(obj, dict):
                _log.debug("ndjson_line_not_object", line=line_num)
                continue

            raw_value = _extract_value(obj)
            if raw_value is None:
                _log.debug("ndjson_line_missing_value", line=line_num)
                continue

            try:
                yield make_ioc(
                    raw_value,
                    source=source_hint,
                    confidence=_extract_confidence(obj),
                    tags=_extract_tags(obj),
                )
            except InputValidationError as e:
                _log.debug("ndjson_row_invalid_ioc", line=line_num, error=str(e)[:120])
                continue

            count += 1
            if count > limits.max_iocs_per_feed:
                raise ParseError(
                    f"feed exceeds max IOC count: {limits.max_iocs_per_feed}",
                    user_message="Feed exceeds configured IOC count limit.",
                )