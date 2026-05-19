# tests/integration/test_parsers.py
from __future__ import annotations

from pathlib import Path

import pytest

from tic.adapters.parsers.csv_parser import parse_csv_feed
from tic.domain.errors import ParseError
from tic.infra.config import ParserLimits


def test_parses_valid_csv(tmp_path: Path) -> None:
    feed = tmp_path / "f.csv"
    feed.write_text("value,confidence\n1.2.3.4,80\nevil.example.com,60\n", encoding="utf-8")
    iocs = list(parse_csv_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 2
    assert iocs[0].value == "1.2.3.4"


def test_rejects_oversized(tmp_path: Path) -> None:
    feed = tmp_path / "big.csv"
    feed.write_bytes(b"value\n" + b"a" * 2000)
    limits = ParserLimits(max_file_size_bytes=1024)  # min geçerli değer
    with pytest.raises(ParseError):
        list(parse_csv_feed(feed, allowed_root=tmp_path, limits=limits))


def test_missing_value_column_user_message_names_the_column(tmp_path: Path) -> None:
    """The UI banner shows `e.user_message` verbatim — it must name the
    column that is missing so analysts know what to fix."""
    feed = tmp_path / "no_value.csv"
    feed.write_text("name,confidence\n1.2.3.4,80\n", encoding="utf-8")
    with pytest.raises(ParseError) as ei:
        list(parse_csv_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    msg = ei.value.user_message
    assert "missing required column" in msg
    assert "value" in msg  # the default value_column
    # The banner-style contract: the column name appears after a colon.
    assert "column: value" in msg


def test_missing_custom_column_user_message_names_it(tmp_path: Path) -> None:
    """Operator-configured column name flows through user_message."""
    feed = tmp_path / "no_ioc.csv"
    feed.write_text("foo,bar\nx,y\n", encoding="utf-8")
    with pytest.raises(ParseError) as ei:
        list(
            parse_csv_feed(
                feed,
                allowed_root=tmp_path,
                limits=ParserLimits(),
                value_column="ioc",
            )
        )
    assert "column: ioc" in ei.value.user_message


def test_skips_malformed_rows(tmp_path: Path) -> None:
    feed = tmp_path / "mixed.csv"
    feed.write_text(
        "value,confidence\n"
        "1.2.3.4,50\n"
        ",40\n"  # empty
        "not a valid ioc,30\n"
        "8.8.8.8,60\n",
        encoding="utf-8",
    )
    iocs = list(parse_csv_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 2