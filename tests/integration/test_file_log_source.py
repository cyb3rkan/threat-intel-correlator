# tests/integration/test_file_log_source.py
from __future__ import annotations

from pathlib import Path

from tic.adapters.log_sources.file_source import (
    CsvFileLogSource,
    NdjsonFileLogSource,
)


def test_ndjson_source_streams_valid_lines(tmp_path: Path) -> None:
    logs = tmp_path / "x.ndjson"
    logs.write_text(
        '{"@timestamp":"2025-01-01T00:00:00Z","msg":"hello 1.2.3.4"}\n'
        "\n"  # blank
        "not-json\n"
        '{"timestamp":"2025-01-02T00:00:00+00:00","msg":"world"}\n',
        encoding="utf-8",
    )
    src = NdjsonFileLogSource(logs, allowed_root=tmp_path)
    lines = list(src.stream())
    assert len(lines) == 2
    assert "1.2.3.4" in lines[0].text
    assert lines[0].timestamp.year == 2025


def test_ndjson_source_skips_oversized_lines(tmp_path: Path) -> None:
    logs = tmp_path / "x.ndjson"
    logs.write_text(
        '{"@timestamp":"2025-01-01T00:00:00Z","msg":"ok"}\n' '{"msg":"' + "A" * 200 + '"}\n',
        encoding="utf-8",
    )
    src = NdjsonFileLogSource(logs, allowed_root=tmp_path, max_line_bytes=50)
    lines = list(src.stream())
    assert len(lines) == 1
    assert lines[0].text.count("ok") == 1


def test_csv_source_canonicalizes_rows(tmp_path: Path) -> None:
    logs = tmp_path / "y.csv"
    logs.write_text(
        "timestamp,host,ioc\n"
        "2025-01-01T00:00:00Z,web-01,1.2.3.4\n"
        "2025-01-02T00:00:00Z,web-02,evil.example.com\n",
        encoding="utf-8",
    )
    src = CsvFileLogSource(logs, allowed_root=tmp_path)
    lines = list(src.stream())
    assert len(lines) == 2
    # Canonical form has keys in sorted order.
    assert "host=web-01" in lines[0].text
    assert "ioc=1.2.3.4" in lines[0].text


def test_log_source_name_attribute(tmp_path: Path) -> None:
    logs = tmp_path / "x.ndjson"
    logs.write_text("", encoding="utf-8")
    src = NdjsonFileLogSource(logs, allowed_root=tmp_path)
    assert src.name == "file-ndjson"
