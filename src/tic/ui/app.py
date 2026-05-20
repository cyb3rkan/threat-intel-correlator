"""`tic sweep` command.

Fix #6 (renderer mode via parameter, no monkey-patch).
Fix #5 (HTTP lifecycle: close_all in finally).
Fix #10 (partial_scan surfaced to audit + output).
Fix #5 (output-mode: analyst|summary|hash).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, TextIO

import typer
import yaml  # type: ignore[import-untyped]

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.adapters.log_sources.file_source import NdjsonFileLogSource
from tic.adapters.parsers.csv_parser import parse_csv_feed
from tic.adapters.parsers.misp_json import parse_misp_feed
from tic.adapters.parsers.ndjson_parser import parse_ndjson_feed
from tic.adapters.parsers.stix import parse_stix_feed
from tic.adapters.renderers.json_renderer import render_json
from tic.adapters.renderers.markdown_renderer import render_markdown
from tic.adapters.renderers.terminal_renderer import render_terminal
from tic.application.orchestrator import SweepOrchestrator
from tic.application.scoring import ScoringProfile
from tic.cli._wiring import (
    build_cache,
    build_narrator,
    build_providers,
    build_secret_store,
    close_all,
    try_load_redaction_hmac,
)
from tic.domain.errors import ConfigError, TICError
from tic.domain.finding import Finding, OutputMode, Severity
from tic.infra.config import Settings, load_settings
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import configure_logging, get_logger

app = typer.Typer(add_completion=False, help="Run a correlation sweep.", no_args_is_help=False)
_log = get_logger(__name__)

_FEED_PARSERS = {
    "csv": parse_csv_feed,
    "ndjson": parse_ndjson_feed,
    "misp-json": parse_misp_feed,
    "stix": parse_stix_feed,
}
_RENDERERS = {"terminal": render_terminal, "json": render_json, "markdown": render_markdown}
_MODES = {"analyst": OutputMode.ANALYST, "summary": OutputMode.SUMMARY, "hash": OutputMode.HASH}


def _resolve_profile(settings: Settings) -> ScoringProfile:
    if settings.scoring_profile_path is None:
        return ScoringProfile(version="1.0.0")
    with open(settings.scoring_profile_path, encoding="utf-8") as f:
        return ScoringProfile.model_validate(yaml.safe_load(f))


@app.callback(invoke_without_command=True)
def sweep(
    ctx: typer.Context,
    feed: Path = typer.Option(..., "--feed", exists=True, dir_okay=False, readable=True),
    feed_format: str = typer.Option("csv", "--feed-format"),
    logs: Path = typer.Option(..., "--logs", exists=True, dir_okay=False, readable=True),
    output_format: str = typer.Option("terminal", "--format"),
    with_ai: bool = typer.Option(False, "--with-ai"),
    fail_on: str = typer.Option("high", "--fail-on"),
    output_mode: str = typer.Option(
        "analyst",
        "--output-mode",
        help="IOC detail: analyst (full) | summary (truncated) | hash (HMAC)",
    ),
) -> None:
    """Run a sweep: ingest a feed, correlate against logs, score, render."""
    if ctx.invoked_subcommand is not None:
        return

    if feed_format not in _FEED_PARSERS:
        typer.echo(f"Unknown --feed-format '{feed_format}'.", err=True)
        raise typer.Exit(code=int(ExitCode.CONFIG_ERROR))
    if output_format not in _RENDERERS:
        typer.echo(f"Unknown --format '{output_format}'.", err=True)
        raise typer.Exit(code=int(ExitCode.CONFIG_ERROR))
    if output_mode not in _MODES:
        typer.echo(f"Unknown --output-mode '{output_mode}'. Valid: analyst|summary|hash.", err=True)
        raise typer.Exit(code=int(ExitCode.CONFIG_ERROR))
    try:
        severity_floor = Severity(fail_on)
    except ValueError:
        typer.echo(f"Unknown --fail-on '{fail_on}'.", err=True)
        raise typer.Exit(code=int(ExitCode.CONFIG_ERROR))

    mode = _MODES[output_mode]
    cache = None
    providers: list[Any] = []
    narrator = None

    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        working_root = settings.paths.working_dir

        audit = HashChainAuditLogger(settings.paths.audit_log_path)
        audit.append(
            "cli_invoke", {"command": "sweep", "with_ai": with_ai, "output_mode": output_mode}
        )

        if with_ai and not settings.ai.enabled:
            typer.echo("Warning: --with-ai requested but ai.enabled=false in config.", err=True)

        secret_store = build_secret_store()
        # Hash output_mode requires the redaction HMAC key in the keyring;
        # never fall back silently to a deterministic zero-key.
        hmac_key = try_load_redaction_hmac(settings, secret_store)
        if mode == OutputMode.HASH and not hmac_key:
            raise ConfigError(
                "hash output_mode selected but redaction HMAC key is missing",
                user_message=(
                    "Hash output mode requires a redaction HMAC key in the OS keyring. "
                    "Run `tic config set-key redaction-hmac` to store one, "
                    "or pick --output-mode analyst|summary."
                ),
            )
        cache = build_cache(settings)
        providers = build_providers(settings, secret_store=secret_store, cache=cache, audit=audit)
        narrator = (
            build_narrator(settings, secret_store=secret_store, audit=audit)
            if (with_ai and settings.ai.enabled)
            else None
        )

        # Parser returns a generator; orchestrator materialises once.
        iocs = _FEED_PARSERS[feed_format](
            feed, allowed_root=working_root, limits=settings.parser_limits
        )

        log_source = NdjsonFileLogSource(logs, allowed_root=working_root)
        log_lines = log_source.stream()

        profile = _resolve_profile(settings)

        # Renderer closure captures mode cleanly — no monkey-patching.
        # `hmac_key` is forwarded so hash mode pseudonymises with the keyring
        # value (never the zero-key fallback).
        base_render = _RENDERERS[output_format]

        def render_fn(findings: list[Finding], out: TextIO) -> int:
            return base_render(findings, out, mode=mode, hmac_key=hmac_key)

        orchestrator = SweepOrchestrator(
            providers=providers,
            narrator=narrator,
            profile=profile,
            audit=audit,
            min_severity_exit=severity_floor,
            ai_max_findings_per_sweep=settings.ai.max_findings_per_sweep,
        )

        exit_code = asyncio.run(
            orchestrator.run(iocs=iocs, log_lines=log_lines, out=sys.stdout, render_fn=render_fn)
        )

        # Surface partial scan to audit log (#10).
        if log_source.partial_scan:
            audit.append(
                "partial_scan_warning", {"path": str(logs), "reason": "line_limit_reached"}
            )
            typer.echo(
                "Warning: log file was partially scanned (line limit reached). Results may be incomplete.",
                err=True,
            )

        raise typer.Exit(code=int(exit_code))

    except typer.Exit:
        raise
    except TICError as e:
        _log.error("tic_error", type=type(e).__name__, detail=e.internal_details[:300])
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        _log.error("unhandled_error", type=type(e).__name__)
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e
    finally:
        if cache is not None:
            try:
                cache.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
        try:
            asyncio.run(close_all(providers, narrator))
        except Exception:  # noqa: BLE001
            pass
