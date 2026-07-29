# tests/security/test_frontend_ai_rendering.py
"""Phase D: source-level guard for frontend AI rendering safety.

We do not run a JS test runner from Python. Instead, we read the
frontend source for the AI rendering site and verify:

  1. The `ai_narrative.summary` flows through React children only —
     never through `dangerouslySetInnerHTML`. (Phase A guard scans the
     whole tree; here we re-check the specific component for
     defence-in-depth.)
  2. The component renders the `summary` field inside an element whose
     content channel is React children — the standard `{value}` JSX
     interpolation that React auto-escapes.
  3. CSV export in `frontend/lib/api.ts` emits the `ai_present` column
     (yes / no) and does NOT emit the summary / suggested_actions /
     model strings.
  4. The advisory label "AI üretimi · inceleme gerekli" (or its English
     equivalent) is present near the AI rendering site so a downstream
     reader cannot mistake AI output for deterministic detection.

If the frontend tree is absent (backend-only checkout), the test skips.
"""

from __future__ import annotations

import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2] / "frontend"


def _read(path: pathlib.Path) -> str | None:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8", errors="ignore")


# The AI narrative is rendered in the findings detail drawer, which delegates
# the summary to an inner AISection. The advisory label lives both there and in
# the dedicated ai-advisory-banner component.
_AI_DRAWER = "findings-detail-drawer.tsx"
_AI_BANNER = "ai-advisory-banner.tsx"


def test_finding_detail_renders_ai_summary_via_react_children() -> None:
    src = _read(_ROOT / "components" / _AI_DRAWER)
    if src is None:
        pytest.skip(f"frontend/components/{_AI_DRAWER} not present")
    # No raw-HTML escape hatch.
    assert "dangerouslySetInnerHTML" not in src
    # The summary must be interpolated via JSX children, not via attribute
    # injection.
    assert "ai_narrative" in src
    assert "summary" in src
    # The standard children-channel interpolation pattern. The drawer binds the
    # narrative to an inner component and renders `{narrative.summary}`.
    assert "{narrative.summary}" in src or "ai_narrative?.summary" in src


def test_finding_detail_labels_ai_output_as_advisory() -> None:
    drawer = _read(_ROOT / "components" / _AI_DRAWER)
    banner = _read(_ROOT / "components" / _AI_BANNER)
    if drawer is None and banner is None:
        pytest.skip(f"neither {_AI_DRAWER} nor {_AI_BANNER} present")
    # Advisory marker for analysts — present so AI output is not mistaken for a
    # deterministic detection result. Accept the Turkish or English wording.
    advisory_markers = (
        "AI üretimi",
        "inceleme gerekli",
        "review required",
        "AI-generated",
    )
    combined = (drawer or "") + (banner or "")
    assert any(m in combined for m in advisory_markers), (
        "AI rendering site must carry an advisory label"
    )


def test_frontend_csv_export_includes_ai_present_only() -> None:
    src = _read(_ROOT / "lib" / "api.ts")
    if src is None:
        pytest.skip("frontend/lib/api.ts not present")
    # Phase C added the column.
    assert '"ai_present"' in src
    # And NEVER the long-form fields.
    for forbidden in (
        "ai_summary",
        "ai_suggested_actions",
        "ai_narrative_summary",
    ):
        assert forbidden not in src, f"frontend CSV must not carry {forbidden!r}"


def test_frontend_sweep_form_sends_with_ai_flag() -> None:
    """The toggle in `sweep-form.tsx` must serialise into a `with_ai`
    form field that the backend understands."""
    src = _read(_ROOT / "components" / "sweep-form.tsx")
    if src is None:
        pytest.skip("frontend/components/sweep-form.tsx not present")
    assert "with_ai" in src
    # The flag is bound to a React state variable and forwarded via
    # `onSubmit`, never to a raw HTML form action.
    assert "setWithAi" in src or "with_ai:" in src


def test_frontend_ai_status_hint_uses_closed_set_reason() -> None:
    """The UI displays AI readiness via `aiStatus.reason`, mapped through
    a closed-set label dictionary. No raw error text from the backend
    can render into the hint."""
    src = _read(_ROOT / "lib" / "api.ts")
    if src is None:
        pytest.skip("frontend/lib/api.ts not present")
    # The closed-set reasons match what build_provider_status emits.
    for reason in ("ai_disabled", "endpoint_allowlist_empty", "no_keyring_key"):
        assert reason in src, f"closed-set reason {reason!r} missing from frontend types"


def test_frontend_api_base_remains_loopback_only() -> None:
    """Defence-in-depth re-check: the API base resolver still pins to
    loopback. A regression that points the frontend at a remote host
    would be a critical privacy leak — AI prompt data would cross the
    machine boundary."""
    src = _read(_ROOT / "lib" / "api.ts")
    if src is None:
        pytest.skip("frontend/lib/api.ts not present")
    assert "_resolveApiBase" in src
    assert "127.0.0.1" in src or "localhost" in src
    assert "isLoopback" in src
