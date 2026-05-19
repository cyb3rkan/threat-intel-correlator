# tests/integration/test_cli_ai_enabled_mock.py
"""Phase D: `tic sweep --with-ai` with a deterministic mock narrator.

We patch `tic.cli.commands.sweep.build_narrator` to return a Narrator
backed by `MockAIProvider`. The CLI exit code must continue to come from
the severity gate; AI output must surface in the JSON / Markdown
renderers without changing the deterministic security results.

Test isolation note: the real sweep command calls `configure_logging`
near the top of its `try` block. structlog uses
`cache_logger_on_first_use=True`, which means the first such call in a
pytest session locks the processor chain into the cached logger and
breaks `structlog.testing.capture_logs()` used elsewhere in the test
suite (e.g. `test_misp_verify_tls.py`). We patch `configure_logging`
out for these CLI tests so this file stays hermetic.
"""
from __future__ import annotations

import contextlib
import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from tests.fixtures.fake_secret_store import PLACEHOLDER_HMAC_32B
from tests.fixtures.mock_ai_provider import (
    MockAIProvider,
    MockAIProviderTimeout,
)
from tic.application.ai.narrator import Narrator
from tic.application.redaction import Redactor
from tic.cli.commands import sweep as sweep_cmd
from tic.infra.config import AIConfig, PathsConfig, Settings


runner = CliRunner(mix_stderr=False)


def _settings_ai_enabled(tmp_path) -> Settings:
    """Settings with ai.enabled=True and a placeholder endpoint allowlist.
    The wiring layer's narrator construction is patched out, so the
    allowlist value never reaches an HTTP client."""
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        ),
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://placeholder.test/v1/chat/completions"],
            model="mock-ai-test",
            language="tr",
            narration_level="concise",
            max_findings_per_sweep=25,
        ),
    )  # type: ignore[call-arg]


def _settings_ai_disabled(tmp_path) -> Settings:
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        ),
        ai=AIConfig(enabled=False),
    )  # type: ignore[call-arg]


class _DummyCache:
    def get(self, *_): return None
    def set(self, *_): pass
    def purge_expired(self): return 0
    def close(self): pass


def _feed_and_logs(tmp_path: Path) -> tuple[Path, Path]:
    feed = tmp_path / "feed.csv"
    feed.write_text("value,confidence\n1.2.3.4,90\n", encoding="utf-8")
    logs = tmp_path / "logs.ndjson"
    logs.write_text(
        json.dumps({"@timestamp": "2026-05-14T00:00:00Z", "src_ip": "1.2.3.4"}) + "\n",
        encoding="utf-8",
    )
    return feed, logs


def _mock_narrator_factory(mock_ai):
    def _build(_settings, *, secret_store=None, audit=None):
        return Narrator(
            mock_ai, Redactor(PLACEHOLDER_HMAC_32B), audit=audit, max_input_chars=8000
        )
    return _build


@contextlib.contextmanager
def _patched(tmp_path, *, ai_enabled: bool, mock_ai_factory_or_none):
    """Apply all sweep-command patches as a single context manager so the
    test bodies do not depend on patch list indexing.

    Note on logging: the real sweep CLI calls
    `configure_logging(level=settings.log_level, fmt=settings.log_format)`
    early. We patch this to a no-op so we (a) do not re-configure structlog
    globally (which would break `structlog.testing.capture_logs()` in
    other tests via `cache_logger_on_first_use=True`), and (b) keep the
    existing per-session logger configuration — which writes to stderr —
    intact. Without this patch the very first sweep test would lock the
    structlog cache and break MISP capture_logs assertions.
    """
    settings = _settings_ai_enabled(tmp_path) if ai_enabled else _settings_ai_disabled(tmp_path)
    narrator_builder = (
        mock_ai_factory_or_none if mock_ai_factory_or_none else (lambda *a, **kw: None)
    )
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("tic.cli.commands.sweep.load_settings", return_value=settings))
        stack.enter_context(patch("tic.cli.commands.sweep.configure_logging", lambda *a, **kw: None))
        stack.enter_context(patch("tic.cli.commands.sweep.build_secret_store", return_value=None))
        stack.enter_context(patch("tic.cli.commands.sweep.build_cache", return_value=_DummyCache()))
        stack.enter_context(patch("tic.cli.commands.sweep.build_providers", return_value=[]))
        stack.enter_context(patch(
            "tic.cli.commands.sweep.build_narrator",
            side_effect=narrator_builder,
        ))
        stack.enter_context(patch("tic.cli.commands.sweep.close_all"))
        stack.enter_context(patch(
            "tic.cli.commands.sweep.try_load_redaction_hmac",
            return_value=PLACEHOLDER_HMAC_32B,
        ))
        yield


def _parse_json_after_logs(stdout: str) -> dict:
    """Extract the JSON renderer payload from the captured stdout.

    Background: when the CLI's `configure_logging` is patched out for
    test isolation (see module docstring), a previously configured
    structlog logger may still emit human-format `info` lines to
    stdout/stderr. The renderer writes the JSON payload as the last
    line of stdout. We scan upward for the first line that parses as
    a JSON object, so the parser stays robust against pre-existing
    log noise from earlier tests in the same session.
    """
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    for ln in reversed(lines):
        try:
            obj = json.loads(ln)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and "findings" in obj:
            return obj
    raise AssertionError(f"no JSON findings payload in stdout: {stdout!r}")


# ---------------------------------------------------------------------------
# AI on (mock): narrative surfaces in renderer output, exit code unaffected.
# ---------------------------------------------------------------------------


def test_cli_with_ai_mock_renders_narrative_in_json(tmp_path):
    feed, logs = _feed_and_logs(tmp_path)
    with _patched(
        tmp_path, ai_enabled=True,
        mock_ai_factory_or_none=_mock_narrator_factory(MockAIProvider()),
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed", str(feed),
                "--logs", str(logs),
                "--format", "json",
                "--fail-on", "critical",
                "--with-ai",
            ],
        )
    assert result.exit_code == 0, result.output
    parsed = _parse_json_after_logs(result.stdout)
    assert "findings" in parsed and parsed["findings"]
    f0 = parsed["findings"][0]
    assert f0["ai_narrative"] is not None
    assert f0["ai_narrative"]["ai_origin"] is True
    assert f0["ai_narrative"]["model"] == "mock-ai-test"
    assert "Authorization" not in result.stdout
    assert "Bearer " not in result.stdout
    assert "<untrusted>" not in result.stdout


def test_cli_with_ai_mock_renders_advisory_in_markdown(tmp_path):
    feed, logs = _feed_and_logs(tmp_path)
    with _patched(
        tmp_path, ai_enabled=True,
        mock_ai_factory_or_none=_mock_narrator_factory(MockAIProvider()),
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed", str(feed),
                "--logs", str(logs),
                "--format", "markdown",
                "--fail-on", "critical",
                "--with-ai",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "AI-generated advisory" in result.stdout
    assert "review required" in result.stdout
    assert "Authorization" not in result.stdout


# ---------------------------------------------------------------------------
# AI off: --with-ai prints a stderr warning and produces a successful sweep.
# ---------------------------------------------------------------------------


def test_cli_with_ai_when_disabled_warns_and_succeeds(tmp_path):
    feed, logs = _feed_and_logs(tmp_path)
    with _patched(tmp_path, ai_enabled=False, mock_ai_factory_or_none=None):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed", str(feed),
                "--logs", str(logs),
                "--format", "json",
                "--fail-on", "critical",
                "--with-ai",
            ],
        )
    assert result.exit_code == 0, result.output
    # Warning surfaced on stderr.
    assert "--with-ai" in (result.stderr or "")
    assert "ai.enabled=false" in (result.stderr or "")
    parsed = _parse_json_after_logs(result.stdout)
    for f in parsed["findings"]:
        assert f["ai_narrative"] is None


# ---------------------------------------------------------------------------
# Exit code is severity-driven, not AI-driven.
# ---------------------------------------------------------------------------


def test_cli_ai_on_and_off_share_exit_code_for_same_severity_gate(tmp_path):
    feed, logs = _feed_and_logs(tmp_path)

    with _patched(
        tmp_path, ai_enabled=True,
        mock_ai_factory_or_none=_mock_narrator_factory(MockAIProvider()),
    ):
        on = runner.invoke(
            sweep_cmd.app,
            ["--feed", str(feed), "--logs", str(logs), "--format", "json", "--fail-on", "info", "--with-ai"],
        )

    with _patched(tmp_path, ai_enabled=False, mock_ai_factory_or_none=None):
        off = runner.invoke(
            sweep_cmd.app,
            ["--feed", str(feed), "--logs", str(logs), "--format", "json", "--fail-on", "info"],
        )

    assert on.exit_code == off.exit_code


# ---------------------------------------------------------------------------
# AI timeout — sweep still succeeds with ai_narrative=null on each finding.
# ---------------------------------------------------------------------------


def test_cli_with_ai_timeout_does_not_break_sweep(tmp_path):
    feed, logs = _feed_and_logs(tmp_path)
    with _patched(
        tmp_path, ai_enabled=True,
        mock_ai_factory_or_none=_mock_narrator_factory(MockAIProviderTimeout()),
    ):
        result = runner.invoke(
            sweep_cmd.app,
            ["--feed", str(feed), "--logs", str(logs), "--format", "json", "--fail-on", "critical", "--with-ai"],
        )
    assert result.exit_code == 0, result.output
    parsed = _parse_json_after_logs(result.stdout)
    for f in parsed["findings"]:
        assert f["ai_narrative"] is None
    assert "Traceback" not in result.stdout
