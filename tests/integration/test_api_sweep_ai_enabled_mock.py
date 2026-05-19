# tests/integration/test_api_sweep_ai_enabled_mock.py
"""Phase D: /api/sweep with AI enabled, backed by a deterministic mock.

We do NOT hit a real AI provider. We do NOT need a real AI key. The
mock is injected at the Narrator boundary via `monkeypatch.setattr` on
`tic.ui.adapter.build_narrator`, so the wiring layer never tries to
load keys from the OS keyring and never opens an HTTP client.

Contracts frozen:
  * `ai_attempted=true` and `ai_active=true` when AI is enabled, the
    operator passed `with_ai=true`, and the wiring produced a Narrator.
  * At least one finding in the JSON response has `ai_narrative` set.
  * Failure paths (timeout, schema rejection) keep the sweep successful
    with `ai_narrative=null` on each finding.
  * The response body NEVER contains:
      - the raw IOC value from the uploaded feed (analyst mode displays
        it in the `ioc_value` field, but the AI prompt fragments and
        completion text must not leak as separate strings)
      - `Authorization`, `Bearer`, or any keyring service / user name
      - prompt envelope markers (`<untrusted>`)
      - the test-only placeholder key string
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from tests.fixtures.fake_secret_store import PLACEHOLDER_HMAC_32B
from tests.fixtures.mock_ai_provider import (
    MockAIProvider,
    MockAIProviderInvalidJson,
    MockAIProviderTimeout,
)


_FEED = b"value,confidence,source,tags\n198.51.100.23,80,sample,doc;ipv4\n"
_LOG = (
    json.dumps({"@timestamp": "2026-05-14T08:14:02Z", "source": "fw", "dst_ip": "198.51.100.23"})
    + "\n"
).encode()


def _env() -> dict[str, str]:
    work = tempfile.mkdtemp(prefix="tic-test-work-")
    cache = tempfile.mkdtemp(prefix="tic-test-cache-")
    audit = Path(tempfile.mkdtemp(prefix="tic-test-audit-")) / "audit.log"
    return {
        "TIC_PATHS__WORKING_DIR": work,
        "TIC_PATHS__CACHE_DIR": cache,
        "TIC_PATHS__AUDIT_LOG_PATH": str(audit),
    }


def _patch_ai_supported_true(monkeypatch) -> None:
    """ai_supported is a pure helper over settings.ai. We override it to
    return True so the adapter believes the operator opted in, without
    needing to mutate the (frozen) Settings model from a YAML file."""
    monkeypatch.setattr("tic.ui.adapter.ai_supported", lambda _settings: True)


def _inject_mock_narrator(monkeypatch, mock_ai) -> None:
    """Replace `build_narrator` so the wiring layer never touches the
    keyring and never opens an HTTP client. We construct the Narrator
    in-process around our mock AI provider."""
    from tic.application.ai.narrator import Narrator
    from tic.application.redaction import Redactor

    def _fake_build_narrator(_settings, *, secret_store=None, audit=None):
        return Narrator(
            mock_ai,
            Redactor(PLACEHOLDER_HMAC_32B),
            audit=audit,
            max_input_chars=8000,
        )

    monkeypatch.setattr("tic.ui.adapter.build_narrator", _fake_build_narrator)


def _post(client: TestClient, *, with_ai: str = "true") -> dict:
    r = client.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _FEED, "text/csv"),
            "log_file": ("events.ndjson", _LOG, "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": with_ai,
        },
    )
    return {"status": r.status_code, "text": r.text, "json": r.json(), "headers": dict(r.headers)}


# ---------------------------------------------------------------------------
# Happy path: AI enabled + mock works → narrative attaches.
# ---------------------------------------------------------------------------


def test_api_sweep_ai_enabled_mock_attaches_narrative(monkeypatch):
    for k, v in _env().items():
        monkeypatch.setenv(k, v)
    _patch_ai_supported_true(monkeypatch)
    _inject_mock_narrator(monkeypatch, MockAIProvider())

    from tic.api.main import app
    c = TestClient(app)

    res = _post(c, with_ai="true")
    assert res["status"] == 200, res["text"]

    body = res["json"]
    assert body["ai_attempted"] is True
    assert body["ai_active"] is True
    assert body["finding_count"] >= 1
    annotated = [f for f in body["findings"] if f.get("ai_narrative") is not None]
    assert annotated, "expected at least one finding with AI narrative"

    # Advisory hint visible in the structured narrative — the model name
    # comes from the mock (mock-ai-test); the summary is the canned text.
    n = annotated[0]["ai_narrative"]
    assert n["ai_origin"] is True
    assert n["model"] == "mock-ai-test"
    assert n["summary"]

    # The mock's placeholder key marker must NEVER appear in the response.
    blob = res["text"]
    for s in (
        "phase-d-placeholder-ai-key-NOT-REAL",
        "Authorization",
        "Bearer ",
        "<untrusted>",
        "Traceback",
    ):
        assert s not in blob, f"response leaked {s!r}"


def test_api_sweep_ai_enabled_correlation_id_header_present(monkeypatch):
    for k, v in _env().items():
        monkeypatch.setenv(k, v)
    _patch_ai_supported_true(monkeypatch)
    _inject_mock_narrator(monkeypatch, MockAIProvider())

    from tic.api.main import app
    c = TestClient(app)

    res = _post(c, with_ai="true")
    assert res["status"] == 200
    cid = res["headers"].get("x-tic-correlation-id")
    assert cid and len(cid) >= 32  # UUID-like; same contract Phase A froze


# ---------------------------------------------------------------------------
# Failure paths: AI off, AI timeout, AI invalid output → no crash, no leak.
# ---------------------------------------------------------------------------


def test_api_sweep_ai_disabled_remains_silent(monkeypatch):
    """Sanity: even with `with_ai=true`, when AI is not supported the
    wiring returns no narrator and the API surfaces ai_attempted=false."""
    for k, v in _env().items():
        monkeypatch.setenv(k, v)
    # No ai_supported patch — default returns False because YAML disables AI.

    from tic.api.main import app
    c = TestClient(app)

    res = _post(c, with_ai="true")
    assert res["status"] == 200
    body = res["json"]
    assert body["ai_attempted"] is False
    assert body["ai_active"] is False
    assert all(f["ai_narrative"] is None for f in body["findings"])


def test_api_sweep_ai_timeout_falls_back_safely(monkeypatch):
    for k, v in _env().items():
        monkeypatch.setenv(k, v)
    _patch_ai_supported_true(monkeypatch)
    _inject_mock_narrator(monkeypatch, MockAIProviderTimeout())

    from tic.api.main import app
    c = TestClient(app)

    res = _post(c, with_ai="true")
    assert res["status"] == 200, res["text"]
    body = res["json"]
    assert body["ai_attempted"] is True
    assert body["ai_active"] is True  # the narrator was built; AI just timed out
    # No narrative on findings.
    assert all(f["ai_narrative"] is None for f in body["findings"])
    # Sweep still succeeded — exit_code comes from severity gating, not AI.
    assert "exit_code" in body
    assert "Traceback" not in res["text"]


def test_api_sweep_ai_invalid_response_falls_back_safely(monkeypatch):
    for k, v in _env().items():
        monkeypatch.setenv(k, v)
    _patch_ai_supported_true(monkeypatch)
    _inject_mock_narrator(monkeypatch, MockAIProviderInvalidJson())

    from tic.api.main import app
    c = TestClient(app)

    res = _post(c, with_ai="true")
    assert res["status"] == 200
    body = res["json"]
    assert body["ai_attempted"] is True
    assert all(f["ai_narrative"] is None for f in body["findings"])


# ---------------------------------------------------------------------------
# Deterministic invariance: AI on/off → identical security-relevant fields.
# ---------------------------------------------------------------------------


def test_api_sweep_ai_on_off_identical_severity_score_exit_code(monkeypatch):
    for k, v in _env().items():
        monkeypatch.setenv(k, v)

    from tic.api.main import app

    # Off run.
    c1 = TestClient(app)
    off = _post(c1, with_ai="false")["json"]

    # On run with mock AI.
    _patch_ai_supported_true(monkeypatch)
    _inject_mock_narrator(monkeypatch, MockAIProvider())
    c2 = TestClient(app)
    on = _post(c2, with_ai="true")["json"]

    # Deterministic fields identical (modulo finding_id / correlation_id
    # which are generated per-run).
    def core(body):
        return sorted(
            (f["ioc_value"], f["score"], f["severity"], f["match_count"])
            for f in body["findings"]
        )

    assert core(off) == core(on)
    assert off["above_threshold"] == on["above_threshold"]
    assert off["exit_code"] == on["exit_code"]
