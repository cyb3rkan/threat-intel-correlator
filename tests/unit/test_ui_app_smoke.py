# tests/unit/test_ui_app_smoke.py
"""Phase B: minimal smoke check for the Streamlit dashboard module.

Streamlit pages execute most of their UI at import time (calls like
`st.set_page_config`, `st.markdown` run as soon as the module is imported).
A full functional test would require the Streamlit script runner, which is
non-trivial to host inside pytest and is out of scope for Phase B.

What this smoke does:
- Parse `src/tic/ui/app.py` with the standard library's `ast` module to
  prove the file is syntactically valid Python. This is a zero-runtime
  check: no Streamlit calls, no widget side effects, no network.
- Confirm the module imports `from tic.ui import adapter` and uses
  `streamlit as st`. If either disappears we want to know — the security
  contract for the Streamlit UI relies on `tic.ui.adapter` for all
  privacy-sensitive paths.

This deliberately does NOT exercise rendering. A future Phase may add a
real Streamlit test via `streamlit.testing` once the harness cost is
justified; documented in docs/OPERATIONS.md.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_APP_PATH = pathlib.Path(__file__).resolve().parents[2] / "src" / "tic" / "ui" / "app.py"


def _read_app_source() -> str:
    if not _APP_PATH.exists():
        pytest.skip("Streamlit app source not present in this checkout")
    return _APP_PATH.read_text(encoding="utf-8")


def test_streamlit_app_is_syntactically_valid_python() -> None:
    """If a future edit to the Streamlit page introduces a syntax error,
    catch it without booting Streamlit."""
    source = _read_app_source()
    ast.parse(source, filename=str(_APP_PATH))


def test_streamlit_app_uses_the_secure_adapter() -> None:
    """All privacy-sensitive paths in the Streamlit UI must go through
    `tic.ui.adapter`. Confirm the import is still present."""
    source = _read_app_source()
    assert "from tic.ui import adapter" in source


def test_streamlit_app_does_not_use_dangerous_html_helpers() -> None:
    """Streamlit's `unsafe_allow_html=True` is the closest analogue to
    React's `dangerouslySetInnerHTML`. It is sometimes needed for CSS
    styling, which is acceptable for theme strings; but ANY usage near
    the AI narrative rendering path must be reviewable. We do not ban
    `unsafe_allow_html` outright here — that would force a style
    regression — but we DO ban it in conjunction with `ai_narrative`
    interpolation on the same line / nearby lines.

    Concretely: search for `ai_narrative` references; for each, walk a
    small window of surrounding source and assert `unsafe_allow_html=True`
    is not in that window.
    """
    source = _read_app_source()
    lines = source.splitlines()
    indices = [i for i, line in enumerate(lines) if "ai_narrative" in line]
    if not indices:
        pytest.skip("Streamlit app does not currently reference ai_narrative")
    window = 5  # lines before/after
    for idx in indices:
        chunk = "\n".join(lines[max(0, idx - window) : idx + window + 1])
        assert (
            "unsafe_allow_html=True" not in chunk
        ), f"unsafe_allow_html near ai_narrative at line {idx + 1}"
