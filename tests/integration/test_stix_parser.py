# tests/integration/test_stix_parser.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tic.adapters.parsers.stix import StixFeedParser, parse_stix_feed
from tic.domain.errors import ParseError
from tic.domain.ioc import IOCType
from tic.infra.config import ParserLimits


def _indicator(pattern: str, *, confidence: int = 75) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--11111111-1111-4111-8111-111111111111",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
        "confidence": confidence,
        "labels": ["malicious-activity"],
    }


def _bundle(*indicators) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--22222222-2222-4222-8222-222222222222",
        "objects": list(indicators),
    }


def test_extracts_simple_equalities(tmp_path: Path) -> None:
    feed = tmp_path / "s.json"
    feed.write_text(
        json.dumps(
            _bundle(
                _indicator("[ipv4-addr:value = '1.2.3.4']"),
                _indicator("[domain-name:value = 'evil.example.com']"),
                _indicator(
                    "[file:hashes.'SHA-256' = "
                    "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
                ),
            )
        ),
        encoding="utf-8",
    )
    iocs = list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    values = {ioc.value for ioc in iocs}
    assert "1.2.3.4" in values
    assert "evil.example.com" in values
    assert any(ioc.ioc_type == IOCType.HASH_SHA256 for ioc in iocs)


def test_skips_non_stix_pattern_type(tmp_path: Path) -> None:
    ind = _indicator("some-pcre-pattern")
    ind["pattern_type"] = "pcre"
    feed = tmp_path / "s.json"
    feed.write_text(json.dumps(_bundle(ind)), encoding="utf-8")
    iocs = list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert iocs == []


def test_skips_malformed_pattern(tmp_path: Path) -> None:
    feed = tmp_path / "s.json"
    feed.write_text(
        json.dumps(_bundle(_indicator("[this is not valid stix"))),
        encoding="utf-8",
    )
    iocs = list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert iocs == []


def test_accepts_bare_indicator_list(tmp_path: Path) -> None:
    feed = tmp_path / "s.json"
    feed.write_text(
        json.dumps([_indicator("[ipv4-addr:value = '8.8.8.8']")]),
        encoding="utf-8",
    )
    iocs = list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 1
    assert iocs[0].value == "8.8.8.8"


def test_confidence_propagated(tmp_path: Path) -> None:
    feed = tmp_path / "s.json"
    feed.write_text(
        json.dumps(
            _bundle(_indicator("[ipv4-addr:value = '1.1.1.1']", confidence=92))
        ),
        encoding="utf-8",
    )
    iocs = list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 1
    assert iocs[0].confidence == 92


def test_rejects_malformed_json(tmp_path: Path) -> None:
    feed = tmp_path / "bad.json"
    feed.write_text("{broken", encoding="utf-8")
    with pytest.raises(ParseError):
        list(parse_stix_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))


def test_parser_protocol(tmp_path: Path) -> None:
    feed = tmp_path / "s.json"
    feed.write_text(
        json.dumps(_bundle(_indicator("[ipv4-addr:value = '1.2.3.4']"))),
        encoding="utf-8",
    )
    parser = StixFeedParser()
    assert parser.format_name == "stix"
    iocs = list(parser.parse(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) == 1