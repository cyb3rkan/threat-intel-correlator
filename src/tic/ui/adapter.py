# src/tic/ui/adapter.py
"""Streamlit-independent adapter for `tic sweep`.

Reuses the existing wiring + orchestrator + parsers + log source + renderers.
This module MUST NOT import streamlit. The Streamlit page (app.py) is the
only consumer.

Security contract:
- All uploaded blobs are staged under settings.paths.working_dir in a
  per-session UUID directory and validated via safe_resolve_within.
- Only PublicFinding (and AINarrative) data is exposed back to the UI.
  Raw log lines, EnrichmentResult.truncated_raw and provider raw payloads
  are never returned.
- CSV export passes every cell through escape_csv_cell and uses
  csv.QUOTE_ALL.
"""

from __future__ import annotations

import asyncio
import csv
import io
import shutil
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TextIO

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.adapters.log_sources.file_source import NdjsonFileLogSource
from tic.adapters.parsers.csv_parser import parse_csv_feed
from tic.adapters.parsers.misp_json import parse_misp_feed
from tic.adapters.parsers.ndjson_parser import parse_ndjson_feed
from tic.adapters.parsers.stix import parse_stix_feed
from tic.adapters.renderers.json_renderer import render_json
from tic.adapters.renderers.markdown_renderer import render_markdown
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
from tic.domain.errors import ConfigError, SecurityViolationError, TICError
from tic.domain.finding import Finding, OutputMode, PublicFinding, Severity
from tic.domain.ioc import IOC
from tic.infra.config import Settings, load_settings
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import get_logger
from tic.security.csv_injection import escape_csv_cell
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

UI_UPLOAD_DIRNAME = ".tic-ui-uploads"
SAFE_EXTENSIONS = frozenset({".csv", ".ndjson", ".json", ".log", ".txt"})

FeedFormat = Literal["csv", "ndjson", "misp-json", "stix"]
OutputModeName = Literal["analyst", "summary", "hash"]
SeverityName = Literal["info", "low", "medium", "high", "critical"]

_FEED_PARSERS: dict[str, Callable[..., Iterator[IOC]]] = {
    "csv": parse_csv_feed,
    "ndjson": parse_ndjson_feed,
    "misp-json": parse_misp_feed,
    "stix": parse_stix_feed,
}

_OUTPUT_MODES: dict[str, OutputMode] = {
    "analyst": OutputMode.ANALYST,
    "summary": OutputMode.SUMMARY,
    "hash": OutputMode.HASH,
}


@dataclass(frozen=True)
class SweepRequest:
    feed_path: Path
    feed_format: FeedFormat
    log_path: Path
    output_mode: OutputModeName = "analyst"
    fail_on: SeverityName = "high"
    with_ai: bool = False


@dataclass
class SweepResult:
    findings: list[Finding] = field(default_factory=list)
    public_findings: list[PublicFinding] = field(default_factory=list)
    exit_code: int = int(ExitCode.SUCCESS)
    partial_scan: bool = False
    ai_attempted: bool = False
    ai_active: bool = False
    above_threshold: bool = False
    # In-memory HMAC key for hash output_mode. Never serialised, never
    # exposed to the API; lives only as long as this SweepResult instance.
    hmac_key: bytes | None = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Settings + AI feasibility
# ---------------------------------------------------------------------------


def get_settings() -> Settings:
    """Thin wrapper around load_settings for the UI layer."""
    return load_settings()


def ai_supported(settings: Settings) -> bool:
    """Return True only if existing config safely supports AI narration.

    We require both `ai.enabled=true` and a non-empty `endpoint_allowlist`.
    Whether the keyring actually has keys is checked later by build_narrator;
    if it returns None the sweep silently runs without AI.
    """
    return bool(settings.ai.enabled and settings.ai.endpoint_allowlist)


# ---------------------------------------------------------------------------
# Upload staging (path-guarded, working_dir confined)
# ---------------------------------------------------------------------------


def _safe_extension(filename: str | None) -> str:
    if not filename:
        return ""
    suffix = Path(filename).suffix.lower()
    if suffix in SAFE_EXTENSIONS:
        return suffix
    return ""


def make_upload_dir(working_dir: Path) -> Path:
    """Create a per-session upload directory under working_dir.

    Returns a resolved, root-confined Path. Caller is responsible for
    eventual cleanup via cleanup_upload_dir.
    """
    base = working_dir / UI_UPLOAD_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    session_dir = base / uuid.uuid4().hex
    session_dir.mkdir(parents=True, exist_ok=False)
    # Belt and suspenders: confirm containment.
    return safe_resolve_within(session_dir, allowed_root=working_dir)


def stage_upload(
    data: bytes,
    *,
    upload_dir: Path,
    working_dir: Path,
    original_filename: str | None,
) -> Path:
    """Write `data` to a UUID-named file inside upload_dir.

    The original filename is discarded except for its extension, which is only
    preserved if it is on the SAFE_EXTENSIONS allowlist. The returned path is
    re-validated with safe_resolve_within against working_dir.
    """
    # Resolve the upload_dir against working_dir to defend against tampered state.
    safe_dir = safe_resolve_within(upload_dir, allowed_root=working_dir)
    suffix = _safe_extension(original_filename)
    target = safe_dir / (uuid.uuid4().hex + suffix)
    target.write_bytes(data)
    return safe_resolve_within(target, allowed_root=working_dir)


def cleanup_upload_dir(upload_dir: Path) -> None:
    try:
        shutil.rmtree(upload_dir, ignore_errors=True)
    except Exception:  # noqa: BLE001 — best-effort cleanup, never raise from UI
        _log.warning("ui_cleanup_failed")


# ---------------------------------------------------------------------------
# Sweep execution
# ---------------------------------------------------------------------------


def _resolve_profile(settings: Settings) -> ScoringProfile:
    if settings.scoring_profile_path is None:
        return ScoringProfile(version="1.0.0")
    import yaml  # local import keeps cold-import footprint small

    with open(settings.scoring_profile_path, encoding="utf-8") as f:
        return ScoringProfile.model_validate(yaml.safe_load(f))


class _CollectingSink:
    """In-memory render sink. Captures Finding objects without writing output.

    The orchestrator hands us a list of Finding via the render_fn callback;
    we keep them so the UI can later derive PublicFinding views in any mode.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def render(self, findings: list[Finding], _out: TextIO) -> int:
        self.findings = list(findings)
        return len(self.findings)


async def _run_async(req: SweepRequest, settings: Settings) -> SweepResult:
    working_root = settings.paths.working_dir
    severity_floor = Severity(req.fail_on)
    mode = _OUTPUT_MODES[req.output_mode]

    audit = HashChainAuditLogger(settings.paths.audit_log_path)
    audit.append(
        "ui_invoke",
        {"command": "sweep", "with_ai": req.with_ai, "output_mode": req.output_mode},
    )

    cache: Any = None
    providers: list = []
    narrator = None
    try:
        secret_store = build_secret_store()
        # Load redaction HMAC up-front for hash output mode. Fail closed if
        # the user picked hash without configuring a key — never silently
        # fall back to a deterministic zero-key (see _mask_ioc_value).
        hmac_key: bytes | None = try_load_redaction_hmac(settings, secret_store)
        if mode == OutputMode.HASH and not hmac_key:
            raise ConfigError(
                "hash output_mode selected but redaction HMAC key is missing",
                user_message=(
                    "Hash output mode requires a redaction HMAC key in the OS keyring. "
                    "Run `tic config set-key redaction-hmac` to store one, "
                    "or pick output_mode=analyst / summary."
                ),
            )
        cache = build_cache(settings)
        providers = build_providers(settings, secret_store=secret_store, cache=cache, audit=audit)
        ai_attempted = bool(req.with_ai and ai_supported(settings))
        narrator = (
            build_narrator(settings, secret_store=secret_store, audit=audit)
            if ai_attempted
            else None
        )

        parser = _FEED_PARSERS[req.feed_format]
        iocs = parser(
            req.feed_path,
            allowed_root=working_root,
            limits=settings.parser_limits,
        )

        log_source = NdjsonFileLogSource(req.log_path, allowed_root=working_root)
        log_lines = log_source.stream()

        profile = _resolve_profile(settings)
        sink = _CollectingSink()

        orchestrator = SweepOrchestrator(
            providers=providers,
            narrator=narrator,
            profile=profile,
            audit=audit,
            min_severity_exit=severity_floor,
            ai_max_findings_per_sweep=settings.ai.max_findings_per_sweep,
        )

        # Use a discarded buffer so the renderer signature stays satisfied.
        # The sink ignores `out`.
        buf = io.StringIO()
        exit_code = await orchestrator.run(
            iocs=iocs, log_lines=log_lines, out=buf, render_fn=sink.render
        )

        partial = bool(getattr(log_source, "partial_scan", False))
        if partial:
            audit.append(
                "partial_scan_warning",
                {"path": str(req.log_path), "reason": "line_limit_reached"},
            )

        public = [f.to_public(mode=mode, hmac_key=hmac_key) for f in sink.findings]
        return SweepResult(
            findings=sink.findings,
            public_findings=public,
            exit_code=int(exit_code),
            partial_scan=partial,
            ai_attempted=ai_attempted,
            ai_active=narrator is not None,
            above_threshold=(int(exit_code) == int(ExitCode.FINDINGS_ABOVE_THRESHOLD)),
            hmac_key=hmac_key,
        )
    finally:
        if cache is not None:
            try:
                cache.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            await close_all(providers, narrator)
        except Exception:  # noqa: BLE001
            pass


def run_sweep(req: SweepRequest, settings: Settings | None = None) -> SweepResult:
    """Synchronous entry point used by Streamlit.

    Translates TICError into the same friendly message contract the CLI uses,
    re-raised as a plain RuntimeError so the UI can show e.user_message
    without leaking internal details.
    """
    if settings is None:
        settings = get_settings()
    try:
        return asyncio.run(_run_async(req, settings))
    except TICError as e:
        _log.warning("ui_tic_error", type=type(e).__name__)
        raise RuntimeError(e.user_message) from None
    except Exception as e:  # noqa: BLE001
        _log.warning("ui_unhandled_error", type=type(e).__name__)
        raise RuntimeError("An unexpected error occurred during the sweep.") from None


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


def to_json_bytes(
    findings: list[Finding],
    mode: OutputModeName,
    *,
    hmac_key: bytes | None = None,
) -> bytes:
    buf = io.StringIO()
    render_json(findings, buf, mode=_OUTPUT_MODES[mode], hmac_key=hmac_key)
    return buf.getvalue().encode("utf-8")


def to_markdown_bytes(
    findings: list[Finding],
    mode: OutputModeName,
    *,
    hmac_key: bytes | None = None,
) -> bytes:
    buf = io.StringIO()
    render_markdown(findings, buf, mode=_OUTPUT_MODES[mode], hmac_key=hmac_key)
    return buf.getvalue().encode("utf-8")


_CSV_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "severity",
    "score",
    "ioc_type",
    "ioc_value",
    "ioc_source",
    "ioc_confidence",
    "match_count",
    "ioc_tags",
    "enrichment_providers",
    "profile_hash",
    "correlation_id",
    "created_at",
    "output_mode",
    # Phase C — CSV policy option C: AI narrative TEXT is intentionally
    # excluded from CSV exports. We expose only a boolean-style flag so
    # downstream consumers can join AI-annotated rows back to the JSON
    # export without parsing free-text inside a spreadsheet column.
    "ai_present",
)


def to_csv_bytes(
    findings: list[Finding],
    mode: OutputModeName,
    *,
    hmac_key: bytes | None = None,
) -> bytes:
    """Build a CSV report from public-safe fields with formula-injection mitigation."""
    out_mode = _OUTPUT_MODES[mode]
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow([escape_csv_cell(c) for c in _CSV_COLUMNS])
    for f in findings:
        pub = f.to_public(mode=out_mode, hmac_key=hmac_key)
        row = [
            pub.finding_id,
            pub.severity,
            str(pub.score),
            pub.ioc_type,
            pub.ioc_value,
            pub.ioc_source,
            str(pub.ioc_confidence),
            str(pub.match_count),
            ", ".join(pub.ioc_tags),
            ", ".join(e.provider for e in pub.enrichments),
            pub.profile_hash,
            pub.correlation_id,
            pub.created_at.isoformat(),
            pub.output_mode,
            # Boolean-style flag; never the narrative text itself.
            "yes" if pub.ai_narrative is not None else "no",
        ]
        writer.writerow([escape_csv_cell(str(cell)) for cell in row])
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Public-safe row projection for the table
# ---------------------------------------------------------------------------


def public_rows(
    findings: list[Finding],
    mode: OutputModeName,
    *,
    hmac_key: bytes | None = None,
) -> list[dict[str, Any]]:
    """Return a list of dicts safe for st.dataframe (no raw log/enrichment data)."""
    out_mode = _OUTPUT_MODES[mode]
    rows: list[dict[str, Any]] = []
    for f in findings:
        pub = f.to_public(mode=out_mode, hmac_key=hmac_key)
        rows.append(
            {
                "severity": pub.severity,
                "score": pub.score,
                "type": pub.ioc_type,
                "value": pub.ioc_value,
                "matches": pub.match_count,
                "providers": len(pub.enrichments),
                "ai": "yes" if pub.ai_narrative is not None else "",
                "finding_id": pub.finding_id,
            }
        )
    return rows


__all__ = [
    "FeedFormat",
    "OutputModeName",
    "SeverityName",
    "SAFE_EXTENSIONS",
    "SecurityViolationError",
    "SweepRequest",
    "SweepResult",
    "ai_supported",
    "cleanup_upload_dir",
    "get_settings",
    "make_upload_dir",
    "public_rows",
    "run_sweep",
    "stage_upload",
    "to_csv_bytes",
    "to_json_bytes",
    "to_markdown_bytes",
]
