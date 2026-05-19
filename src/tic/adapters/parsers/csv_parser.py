# src/tic/adapters/parsers/csv_parser.py
"""CSV IOC feed parser. Streams rows; enforces file size cap."""
from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from tic.application.normalization import make_ioc
from tic.domain.errors import InputValidationError, ParseError
from tic.domain.ioc import IOC
from tic.infra.config import ParserLimits
from tic.infra.logging import get_logger
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)


def parse_csv_feed(
    path: Path,
    *,
    allowed_root: Path,
    limits: ParserLimits,
    value_column: str = "value",
    source_hint: str = "csv",
) -> Iterator[IOC]:
    """Stream IOCs from a CSV file.

    Security:
    - Path confined to allowed_root.
    - File size capped pre-read.
    - Per-row bounded; malformed rows logged and skipped, not raised.
    - Values trimmed; non-printable chars rejected via normalizer.
    """
    resolved = safe_resolve_within(path, allowed_root=allowed_root)
    size = resolved.stat().st_size
    if size > limits.max_file_size_bytes:
        raise ParseError(
            f"csv too large: {size} > {limits.max_file_size_bytes}",
            user_message="Feed file exceeds configured size limit.",
        )

    count = 0
    with resolved.open("r", encoding="utf-8", newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or value_column not in reader.fieldnames:
            # Surface the missing column name in user_message so the UI
            # banner can tell the analyst exactly what is wrong with the
            # uploaded file. `value_column` is operator-configured (it
            # comes from our own Settings, never from user-uploaded
            # data), so embedding it directly into the message carries
            # no injection risk.
            raise ParseError(
                f"csv missing column '{value_column}'",
                user_message=f"CSV file is missing required column: {value_column}",
            )
        for row_num, row in enumerate(reader, start=2):
            raw = (row.get(value_column) or "").strip()
            if not raw:
                continue
            if len(raw) > limits.max_string_length:
                _log.warning("csv_row_too_long", row=row_num, length=len(raw))
                continue
            try:
                confidence = int(row.get("confidence") or 50)
            except (TypeError, ValueError):
                confidence = 50
            try:
                yield make_ioc(raw, source=source_hint, confidence=confidence)
            except InputValidationError as e:
                _log.debug("csv_row_invalid_ioc", row=row_num, error=str(e)[:120])
                continue
            count += 1
            if count > limits.max_iocs_per_feed:
                raise ParseError(
                    f"feed exceeds max IOC count: {limits.max_iocs_per_feed}",
                    user_message="Feed exceeds configured IOC count limit.",
                )