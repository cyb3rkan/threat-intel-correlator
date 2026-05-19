# tests/unit/test_csv_injection.py
from __future__ import annotations

import pytest

from tic.security.csv_injection import escape_csv_cell


@pytest.mark.parametrize(
    "inp,expected",
    [
        ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
        ("+SUM(1)", "'+SUM(1)"),
        ("-2+3", "'-2+3"),
        ("@import", "'@import"),
        ("\tTAB", "'\tTAB"),
        ("normal", "normal"),
        ("", ""),
    ],
)
def test_escape(inp: str, expected: str) -> None:
    assert escape_csv_cell(inp) == expected