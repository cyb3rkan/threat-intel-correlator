# tests/unit/test_json_depth_guard.py
"""Finding #2: string-aware JSON nesting-depth guard."""
from __future__ import annotations

import json

import pytest

from tic.adapters.parsers.json_depth import check_json_depth, json_max_depth
from tic.domain.errors import ParseError

_BSLASH = chr(92)  # single backslash without a source-level escape


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("null", 0),
        ("[]", 1),
        ("{}", 1),
        ('{"a":{"b":{"c":1}}}', 3),  # nested objects counted
        ("[[[[]]]]", 4),  # nested arrays counted
        ('{"a":[{"b":[1]}]}', 4),  # both [ and { counted, mixed
        ('{"note":"]]]]]]]]"}', 1),  # closers inside a string: ignored
        ('{"note":"[[[[[["}', 1),  # openers inside a string: ignored
    ],
)
def test_json_max_depth(text: str, expected: int) -> None:
    assert json_max_depth(text) == expected


def test_escaped_quote_keeps_scanner_in_string() -> None:
    # Value is  a"][  : the escaped quote must NOT terminate the string early,
    # so the following ] and [ stay inside the string and are not counted.
    text = '{"s": "a' + _BSLASH + '"][' + '"}'
    assert json.loads(text) == {"s": 'a"]['}
    assert json_max_depth(text) == 1


def test_check_under_limit_passes() -> None:
    check_json_depth('{"a":{"b":1}}', 64)  # depth 2 <= 64 -> no raise


def test_check_at_limit_passes() -> None:
    check_json_depth("{" * 64 + "}" * 64, 64)  # depth 64 == limit -> ok


def test_check_over_limit_raises() -> None:
    with pytest.raises(ParseError):
        check_json_depth("[" * 65 + "]" * 65, 64)


def test_bracket_heavy_string_is_not_a_false_positive() -> None:
    # A shallow object whose string value is full of brackets must pass even a
    # tight limit -- this is the false-positive case the guard must avoid.
    text = '{"payload":"' + "][" * 1000 + '"}'
    assert json_max_depth(text) == 1
    check_json_depth(text, 4)  # must not raise
