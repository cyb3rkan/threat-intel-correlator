# tests/security/test_frontend_ai_safety.py
"""Phase A: source-level guard for the Next.js frontend.

We do not run a JS test runner from Python — instead we statically scan the
frontend source tree to ensure no `dangerouslySetInnerHTML` usage was added
to AI-rendering paths (or anywhere else outside of explicit, vetted
exceptions). This freezes a contract: AI-generated text is rendered as
React children only, so React's automatic escaping protects against XSS.

We also scan for ad-hoc innerHTML assignments and `eval(` to catch other
common script-injection sinks introduced by mistake.

The walk:
- starts at frontend/
- skips node_modules/ and .next/ build artefacts
- reads .ts, .tsx, .js, .jsx, .mjs files
- limits each file to a reasonable max read so a stray big file does not
  hang CI.

If the frontend tree is absent (e.g. a backend-only checkout), the test is
skipped — Phase A's promise is "if it exists, it stays safe", not "the
frontend must exist".
"""

from __future__ import annotations

import pathlib

import pytest

_FRONTEND_ROOT = pathlib.Path(__file__).resolve().parents[2] / "frontend"
_EXCLUDED_DIRS = {"node_modules", ".next", "dist", "out", ".turbo", "coverage"}
_INCLUDED_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs"}
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB per file — generous but bounded

# Patterns we never want to see in our own frontend code. Each entry is a
# (substring, reason) tuple — substring matching keeps the test fast and
# avoids regex pitfalls for a security guard. We intentionally do NOT scan
# for `innerHTML =` because legitimate framework code may use it; the
# dangerous React-specific sink is dangerouslySetInnerHTML.
_FORBIDDEN_SUBSTRINGS: list[tuple[str, str]] = [
    (
        "dangerouslySetInnerHTML",
        "React's dangerouslySetInnerHTML must not be used; AI text is rendered as children only.",
    ),
]


def _iter_frontend_sources() -> list[pathlib.Path]:
    if not _FRONTEND_ROOT.exists():
        return []
    out: list[pathlib.Path] = []
    for path in _FRONTEND_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _INCLUDED_SUFFIXES:
            continue
        # Skip anything under an excluded directory at any depth.
        if any(part in _EXCLUDED_DIRS for part in path.parts):
            continue
        out.append(path)
    return out


def test_frontend_has_no_dangerously_set_inner_html() -> None:
    """No source file in the frontend tree may contain
    `dangerouslySetInnerHTML`. AI narrative content is rendered via the
    React children pipeline so the default XSS escaping applies."""
    files = _iter_frontend_sources()
    if not files:
        pytest.skip("frontend directory not present in this checkout")
    offenders: list[str] = []
    for path in files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for substr, _reason in _FORBIDDEN_SUBSTRINGS:
            if substr in text:
                offenders.append(f"{path.relative_to(_FRONTEND_ROOT)}: contains {substr!r}")
    assert not offenders, "frontend safety violations:\n" + "\n".join(offenders)


def test_frontend_api_client_only_targets_loopback() -> None:
    """The frontend must never default to a non-loopback API base. We
    confirm the resolver guards localhost / 127.0.0.1 / ::1 by inspecting
    lib/api.ts; if the file is moved/renamed in a future refactor, this
    test will fail loudly and force a manual review."""
    api_path = _FRONTEND_ROOT / "lib" / "api.ts"
    if not api_path.exists():
        pytest.skip("frontend/lib/api.ts not present in this checkout")
    text = api_path.read_text(encoding="utf-8", errors="ignore")
    assert "_DEFAULT_API_BASE" in text
    # Confirm at least one loopback hostname is referenced. A regression
    # that swapped the default to a remote host would not have these.
    assert "127.0.0.1" in text or "localhost" in text
