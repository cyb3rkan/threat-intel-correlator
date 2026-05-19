# tests/integration/test_misp_parser.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tic.adapters.parsers.misp_json import (
    MispJsonFeedParser,
    parse_misp_feed,
)
from tic.domain.errors import ParseError
from tic.infra.config import ParserLimits


def _sample_event() -> dict:
    return {
        "Event": {
            "uuid": "abc-123",
            "Attribute": [
                {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True},
                {"type": "domain", "value": "evil.example.com"},
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "comment", "value": "not an IOC"},  # ignored type
            ],
            "Object": [
                {
                    "Attribute": [
                        {"type": "url", "value": "https://bad.example/x"},
                        {
                            "type": "filename|sha256",
                            "value": "bad.exe|" + "a" * 64,
                        },
                    ]
                }
            ],
        }
    }


def test_parses_single_event(tmp_path: Path) -> None:
    feed = tmp_path / "misp.json"
    feed.write_text(json.dumps(_sample_event()), encoding="utf-8")
    iocs = list(parse_misp_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    values = {ioc.value for ioc in iocs}
    assert "1.2.3.4" in values
    assert "evil.example.com" in values
    assert "d41d8cd98f00b204e9800998ecf8427e" in values
    assert "https://bad.example/x" in values
    # Compound filename|sha256 produces two candidate halves.
    assert "a" * 64 in values


def test_parses_response_wrapper(tmp_path: Path) -> None:
    feed = tmp_path / "misp_resp.json"
    feed.write_text(
        json.dumps({"response": [_sample_event(), _sample_event()]}),
        encoding="utf-8",
    )
    iocs = list(parse_misp_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))
    # Two identical events → duplicate IOCs are NOT deduped by parser
    # (dedup is orchestrator responsibility). Expect >5 IOCs.
    assert len(iocs) > 5


def test_rejects_malformed_json(tmp_path: Path) -> None:
    feed = tmp_path / "bad.json"
    feed.write_text("{not json", encoding="utf-8")
    with pytest.raises(ParseError):
        list(parse_misp_feed(feed, allowed_root=tmp_path, limits=ParserLimits()))


def test_to_ids_true_bumps_confidence(tmp_path: Path) -> None:
    feed = tmp_path / "misp.json"
    feed.write_text(
        json.dumps(
            {
                "Event": {
                    "uuid": "x",
                    "Attribute": [
                        {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True},
                        {"type": "ip-dst", "value": "5.6.7.8", "to_ids": False},
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    iocs = {ioc.value: ioc for ioc in parse_misp_feed(
        feed, allowed_root=tmp_path, limits=ParserLimits()
    )}
    assert iocs["1.2.3.4"].confidence > iocs["5.6.7.8"].confidence


def test_parser_protocol(tmp_path: Path) -> None:
    feed = tmp_path / "m.json"
    feed.write_text(json.dumps(_sample_event()), encoding="utf-8")
    parser = MispJsonFeedParser()
    assert parser.format_name == "misp-json"
    iocs = list(parser.parse(feed, allowed_root=tmp_path, limits=ParserLimits()))
    assert len(iocs) > 0