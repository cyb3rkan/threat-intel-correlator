# src/tic/adapters/log_sources/file_source.py
"""File-backed log sources: NDJSON and CSV.

Fail-closed on size limit. Hard-stop (not warning-and-continue) on line limit.
Partial scan flag emitted to caller via StopIteration value (not implemented
in generator protocol; instead raised as InputValidationError for file too
large, and warning+return for line count).
"""
from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from tic.application.correlation import LogLine
from tic.domain.errors import InputValidationError
from tic.infra.logging import get_logger
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

DEFAULT_MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_FILE_BYTES = 2 * 1024 ** 3   # 2 GB
DEFAULT_MAX_LINES      = 50_000_000


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


class NdjsonFileLogSource:
    name = "file-ndjson"

    def __init__(self, path: Path, *, allowed_root: Path,
                 max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_lines: int = DEFAULT_MAX_LINES) -> None:
        self._path      = safe_resolve_within(path, allowed_root=allowed_root)
        self._max_line  = max_line_bytes
        self._max_file  = max_file_bytes
        self._max_lines = max_lines
        self.partial_scan = False  # set to True when truncated

    def stream(self) -> Iterator[LogLine]:
        size = self._path.stat().st_size
        if size > self._max_file:
            raise InputValidationError(
                f"log file too large: {size} > {self._max_file}",
                user_message=f"Log file exceeds {self._max_file // (1024**3)} GB limit.",
            )
        with self._path.open("r", encoding="utf-8", errors="strict") as f:
            for line_num, raw in enumerate(f, start=1):
                if line_num > self._max_lines:
                    self.partial_scan = True
                    _log.warning("ndjson_line_limit_reached", max_lines=self._max_lines)
                    return
                if len(raw.encode("utf-8", errors="replace")) > self._max_line:
                    _log.warning("ndjson_line_too_large", line=line_num)
                    continue
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                ts_raw = obj.get("@timestamp") or obj.get("timestamp") or ""
                yield LogLine(source=self._path.name,
                              timestamp=_parse_ts(str(ts_raw)),
                              text=stripped)


class CsvFileLogSource:
    name = "file-csv"

    def __init__(self, path: Path, *, allowed_root: Path,
                 timestamp_column: str = "timestamp",
                 max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_lines: int = DEFAULT_MAX_LINES) -> None:
        self._path      = safe_resolve_within(path, allowed_root=allowed_root)
        self._ts_col    = timestamp_column
        self._max_line  = max_line_bytes
        self._max_file  = max_file_bytes
        self._max_lines = max_lines
        self.partial_scan = False

    def stream(self) -> Iterator[LogLine]:
        size = self._path.stat().st_size
        if size > self._max_file:
            raise InputValidationError(
                f"csv log too large: {size} > {self._max_file}",
                user_message=f"Log file exceeds {self._max_file // (1024**3)} GB limit.",
            )
        with self._path.open("r", encoding="utf-8", errors="strict", newline="") as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, start=2):
                if row_num > self._max_lines:
                    self.partial_scan = True
                    _log.warning("csv_line_limit_reached", max_lines=self._max_lines)
                    return
                text = " ".join(f"{k}={row[k]}" for k in sorted(row.keys()) if row[k])
                if len(text.encode("utf-8", errors="replace")) > self._max_line:
                    _log.warning("csv_row_too_large", row=row_num)
                    continue
                ts_raw = row.get(self._ts_col) or ""
                yield LogLine(source=self._path.name, timestamp=_parse_ts(ts_raw), text=text)
