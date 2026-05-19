# src/tic/security/ansi_strip.py
"""Strip ANSI/control chars from untrusted strings before display.

Security: untrusted feed/log content must never write raw escape sequences
to the user's terminal (hijack, clear screen, hyperlink injection).
"""
from __future__ import annotations

import re

# Matches CSI, OSC, DCS, SOS, PM, APC and standalone ESC sequences.
_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_terminal_controls(text: str) -> str:
    """Remove ANSI escapes and most C0 controls. Preserves \\t, \\n, \\r."""
    text = _ANSI_RE.sub("", text)
    return _CONTROL_RE.sub("", text)