# tests/unit/test_ansi_strip.py
from __future__ import annotations

from tic.security.ansi_strip import strip_terminal_controls


def test_strips_color_codes() -> None:
    assert strip_terminal_controls("\x1b[31mRED\x1b[0m") == "RED"


def test_strips_osc_hyperlink() -> None:
    inp = "\x1b]8;;http://evil\x07click\x1b]8;;\x07"
    assert "evil" not in strip_terminal_controls(inp)
    # Result keeps "click"
    assert "click" in strip_terminal_controls(inp)


def test_preserves_newlines_and_tabs() -> None:
    assert strip_terminal_controls("a\nb\tc") == "a\nb\tc"