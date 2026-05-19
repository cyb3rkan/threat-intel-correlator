# tests/integration/test_ndjson_parser.py
from __future__ import annotations

from pathlib import Path

import pytest

from tic.adapters.parsers.ndjson_parser import (
    NdjsonFeedParser,
    parse_ndjson_feed,
)
from tic.domain.errors import ParseError
from tic.domain.ioc import IOCType
from tic.infra.config import ParserLimits


def test_parses_standard_ndjson(tmp_path: Path) -> None:
    feed = tmp_path / "f.ndjson"
    feed.write_text(
        '{"value":"1.2.3.4","confidence":80}\n'
        '{"indicator":"evil.example.com","tags":["apt","c2"]}\n'
        '{"ioc":"d41d8cd98f00b204e9800998ecf8427e"}\n',
        encoding="utf-8",
    )
    iocs = list(parse_ndjson_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 3
    types = {ioc.ioc_type for ioc in iocs}
    assert IOCType.IP in types
    assert IOCType.DOMAIN in types
    assert IOCType.HASH_MD5 in types


def test_skips_malformed_lines(tmp_path: Path) -> None:
    feed = tmp_path / "mixed.ndjson"
    feed.write_text(
        '{"value":"1.2.3.4"}\n'
        "not-json-at-all\n"
        "[1,2,3]\n"  # array, not object
        '{"nope":"x"}\n'  # no value key
        '{"value":"8.8.8.8"}\n',
        encoding="utf-8",
    )
    iocs = list(parse_ndjson_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert [ioc.value for ioc in iocs] == ["1.2.3.4", "8.8.8.8"]


def test_rejects_oversized_file(tmp_path: Path) -> None:
    # ParserLimits enforces max_file_size_bytes >= 1024 as a safety minimum
    # (so that a misconfigured tiny limit can't silently reject everything).
    # We therefore generate a feed larger than that cap and verify rejection.
    feed = tmp_path / "big.ndjson"
    line = b'{"value":"1.1.1.1"}\n'
    # Write ~5 KB (250 lines x 20 bytes), then cap at 1024.
    feed.write_bytes(line * 250)
    limits = ParserLimits(max_file_size_bytes=1024)
    with pytest.raises(ParseError):
        list(parse_ndjson_feed(feed, allowed_root=tmp_path, limits=limits))


def test_enforces_ioc_count_cap(tmp_path: Path) -> None:
    feed = tmp_path / "many.ndjson"
    feed.write_text(
        "\n".join(f'{{"value":"10.0.0.{i % 250}"}}' for i in range(50)) + "\n",
        encoding="utf-8",
    )
    limits = ParserLimits(max_iocs_per_feed=10)
    with pytest.raises(ParseError):
        list(parse_ndjson_feed(feed, allowed_root=tmp_path, limits=limits))


def test_parser_protocol_implementation(tmp_path: Path) -> None:
    feed = tmp_path / "f.ndjson"
    feed.write_text('{"value":"1.2.3.4"}\n', encoding="utf-8")
    parser = NdjsonFeedParser()
    assert parser.format_name == "ndjson"
    iocs = list(parser.parse(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 1