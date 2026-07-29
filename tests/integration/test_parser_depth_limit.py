# tests/integration/test_parser_depth_limit.py
"""Finding #2: parsers enforce max_json_depth instead of crashing on a bomb."""
from __future__ import annotations

from pathlib import Path

import pytest

from tic.adapters.parsers.misp_json import parse_misp_feed
from tic.adapters.parsers.ndjson_parser import parse_ndjson_feed
from tic.adapters.parsers.stix import parse_stix_feed
from tic.domain.errors import ParseError
from tic.infra.config import ParserLimits

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "feeds"
    / "malformed_depth_bomb.json"
)


def _deep(n: int) -> str:
    return "[" * n + "]" * n


def test_committed_depth_bomb_fixture_is_actually_deep() -> None:
    # Guard: the shipped fixture must exceed the default depth limit, else the
    # regressions below could silently pass on a benign file.
    text = _FIXTURE.read_text(encoding="utf-8")
    assert text.count("[") > ParserLimits().max_json_depth


def test_stix_rejects_depth_bomb_fixture() -> None:
    root = _FIXTURE.parent
    with pytest.raises(ParseError):
        list(parse_stix_feed(_FIXTURE, allowed_root=root, limits=ParserLimits()))


def test_misp_rejects_depth_bomb_fixture() -> None:
    root = _FIXTURE.parent
    with pytest.raises(ParseError):
        list(parse_misp_feed(_FIXTURE, allowed_root=root, limits=ParserLimits()))


def test_stix_rejects_deep_json(tmp_path: Path) -> None:
    feed = tmp_path / "deep.json"
    feed.write_text(_deep(300), encoding="utf-8")
    with pytest.raises(ParseError):
        list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))


def test_depth_limit_is_configurable(tmp_path: Path) -> None:
    feed = tmp_path / "d.json"
    feed.write_text(_deep(40), encoding="utf-8")  # valid nested arrays, depth 40
    # depth 40 <= 64 default -> no indicators, no raise
    assert list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits())) == []
    # lower the limit below 40 -> rejected
    low = ParserLimits(max_json_depth=8)
    with pytest.raises(ParseError):
        list(parse_stix_feed(feed, allowed_root=tmp_path, limits=low))


def test_ndjson_skips_deep_line_without_crashing(tmp_path: Path) -> None:
    feed = tmp_path / "f.ndjson"
    feed.write_text(
        '{"value":"1.2.3.4"}\n' + _deep(300) + "\n" + '{"value":"5.6.7.8"}\n',
        encoding="utf-8",
    )
    iocs = list(parse_ndjson_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    # Deep line skipped (lenient per-line contract); the two valid lines parse.
    assert len(iocs) == 2
