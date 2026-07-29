# src/tic/adapters/renderers/terminal_renderer.py
"""Terminal renderer — ANSI strip on all untrusted fields, uses PublicFinding."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TextIO

from tic.domain.finding import Finding, OutputMode, Severity
from tic.security.ansi_strip import strip_terminal_controls

_SEVERITY_BADGE = {
    Severity.INFO: "[.]",
    Severity.LOW: "[+]",
    Severity.MEDIUM: "[*]",
    Severity.HIGH: "[!]",
    Severity.CRITICAL: "[!!]",
}


def render_terminal(
    findings: Iterable[Finding],
    out: TextIO,
    *,
    use_color: bool = False,
    mode: OutputMode = OutputMode.ANALYST,
    hmac_key: bytes | None = None,
) -> int:
    count = 0
    for f in findings:
        pub = f.to_public(mode=mode, hmac_key=hmac_key)
        badge = _SEVERITY_BADGE[f.severity]
        val = strip_terminal_controls(pub.ioc_value)[:120]
        line = (
            f"{badge} {pub.severity.upper():<8} "
            f"score={pub.score:>3}  type={pub.ioc_type:<12} value={val}  matches={pub.match_count}"
        )
        out.write(line + "\n")
        if pub.ai_narrative is not None:
            summary = strip_terminal_controls(pub.ai_narrative.summary)[:300]
            out.write(f"    [AI-generated advisory] {summary}\n")
        count += 1
    return count
