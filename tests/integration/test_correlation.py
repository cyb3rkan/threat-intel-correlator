# tests/integration/test_correlation.py
from __future__ import annotations

import hashlib
from datetime import datetime

from tic.application.correlation import Correlator, LogLine
from tic.application.normalization import make_ioc


def _ts() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0)


def _ioc(value: str):
    return make_ioc(value, source="test")


def test_single_match() -> None:
    ioc = _ioc("1.2.3.4")
    c = Correlator([ioc])
    lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4 on port 80")]
    matches = list(c.iter_matches(lines))
    assert len(matches) == 1
    found_ioc, match = matches[0]
    assert found_ioc.value == "1.2.3.4"
    assert match.log_source == "fw"
    assert match.field == "text"


def test_no_match() -> None:
    ioc = _ioc("1.2.3.4")
    c = Correlator([ioc])
    lines = [LogLine(source="fw", timestamp=_ts(), text="nothing suspicious here")]
    assert list(c.iter_matches(lines)) == []


def test_deduplicates_same_ioc_in_same_line() -> None:
    ioc = _ioc("1.2.3.4")
    c = Correlator([ioc])
    lines = [LogLine(source="fw", timestamp=_ts(), text="1.2.3.4 then again 1.2.3.4")]
    matches = list(c.iter_matches(lines))
    assert len(matches) == 1


def test_multiple_iocs_in_one_line() -> None:
    iocs = [_ioc("1.2.3.4"), _ioc("evil.example.com")]
    c = Correlator(iocs)
    lines = [LogLine(source="fw", timestamp=_ts(), text="src=1.2.3.4 dst=evil.example.com")]
    matches = list(c.iter_matches(lines))
    assert len(matches) == 2


def test_raw_line_hash_is_sha256() -> None:
    ioc = _ioc("1.2.3.4")
    c = Correlator([ioc])
    text = "connection from 1.2.3.4"
    lines = [LogLine(source="fw", timestamp=_ts(), text=text)]
    _, match = list(c.iter_matches(lines))[0]
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert match.raw_line_hash == expected


def test_empty_ioc_list_no_matches() -> None:
    c = Correlator([])
    lines = [LogLine(source="fw", timestamp=_ts(), text="1.2.3.4")]
    assert list(c.iter_matches(lines)) == []


def test_duplicate_iocs_deduplicated() -> None:
    ioc1 = _ioc("1.2.3.4")
    ioc2 = _ioc("1.2.3.4")
    c = Correlator([ioc1, ioc2])
    lines = [LogLine(source="fw", timestamp=_ts(), text="saw 1.2.3.4")]
    assert len(list(c.iter_matches(lines))) == 1


def test_multiple_lines() -> None:
    ioc = _ioc("8.8.8.8")
    c = Correlator([ioc])
    lines = [
        LogLine(source="fw", timestamp=_ts(), text="query to 8.8.8.8"),
        LogLine(source="fw", timestamp=_ts(), text="clean line"),
        LogLine(source="fw", timestamp=_ts(), text="again 8.8.8.8 seen"),
    ]
    matches = list(c.iter_matches(lines))
    assert len(matches) == 2
