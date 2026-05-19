# src/tic/api/main.py
"""Local-only FastAPI backend for the existing `tic sweep` workflow.

Run:
    uvicorn tic.api.main:app --host 127.0.0.1 --port 8000

Endpoints:
    GET  /api/health  → liveness probe
    POST /api/sweep   → multipart upload of feed + log, returns public findings

This module MUST NOT add new HTTP egress, new providers, or new auth surface.
All correlation/enrichment/scoring goes through tic.ui.adapter, which in turn
reuses the existing CLI wiring (path guard, SSRF guard, keyring, audit, cache,
CSV-injection mitigation, public-DTO masking).
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from tic.api._provider_status import build_provider_status
from tic.cli._wiring import build_secret_store
from tic.infra.logging import get_correlation_id, get_logger, new_correlation_id
from tic.ui import adapter

_log = get_logger(__name__)

_CORRELATION_HEADER = "X-TIC-Correlation-Id"


class _CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Mint a correlation id per request and surface it as a response header.

    The id is also bound to the structlog context so backend log lines for
    a single request can be joined with the frontend's HTTPException
    response. Carries no secret material — it is a UUIDv4. The middleware
    catches its own dispatch errors so a logging failure cannot mask the
    original response.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        cid = new_correlation_id()
        try:
            response = await call_next(request)
        except Exception:
            # Fall through to FastAPI's exception handlers, but stamp the
            # current cid on the structlog context so the upstream log
            # line still carries it. The HTTPException handler below adds
            # the header to the eventual response.
            raise
        response.headers[_CORRELATION_HEADER] = cid
        return response


_ALLOWED_ORIGINS = (
    "http://127.0.0.1:3000",
    "http://localhost:3000",
)

_FEED_FORMATS = {"csv", "ndjson", "misp-json", "stix"}
_OUTPUT_MODES = {"analyst", "summary", "hash"}
_FAIL_ON = {"info", "low", "medium", "high", "critical"}

# Hard upload ceiling at the HTTP layer. The parser layer enforces its own
# `parser_limits.max_file_size_bytes`; this is just a coarse early reject.
_MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MB

app = FastAPI(
    title="Threat Intel Correlator API",
    description="Local-only API for the existing `tic sweep` workflow.",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    expose_headers=[_CORRELATION_HEADER],
    max_age=600,
)
app.add_middleware(_CorrelationIdMiddleware)


@app.exception_handler(HTTPException)
async def _http_exception_with_correlation(request: Request, exc: HTTPException) -> JSONResponse:
    """Default JSONResponse for HTTPException + correlation id header.

    The response body keeps its existing shape ({"detail": ...}) so the
    frontend contract does not change. The header is additive and ignored
    by clients that do not look for it. We never include the correlation
    id in the body to keep the public API contract stable.
    """
    cid = get_correlation_id()
    headers = dict(exc.headers or {})
    if cid:
        headers[_CORRELATION_HEADER] = cid
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_choice(value: str, allowed: set[str], field: str) -> str:
    if value not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field}: must be one of {sorted(allowed)}.",
        )
    return value


def _parse_with_ai(value: str | bool | None) -> bool:
    """Form fields arrive as strings; normalize truthy/falsy spellings."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _public_findings_payload(result: adapter.SweepResult, mode: str) -> list[dict[str, Any]]:
    """Project Finding -> PublicFinding dict (safe for the frontend).

    Passes the in-memory HMAC key from SweepResult so hash output_mode uses
    the keyring-backed pseudonym. The key never leaves this process.
    """
    out_mode = adapter._OUTPUT_MODES[mode]
    return [
        f.to_public(mode=out_mode, hmac_key=result.hmac_key).model_dump(mode="json")
        for f in result.findings
    ]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict[str, Any]:
    """Liveness probe. No settings load, no I/O — safe for any state."""
    return {
        "status": "ok",
        "service": "threat-intel-correlator-api",
        "version": "0.1.0",
    }


@app.get("/api/providers/status")
def providers_status() -> JSONResponse:
    """Read-only provider/AI/HMAC readiness.

    Returns ONLY safe metadata (configured/enabled/key_present/ready/reason).
    Never returns API keys, keyring service/user names, full endpoint URLs,
    allowed_hosts, model names, file paths, or tracebacks.

    Issuing this call does NOT instantiate providers or open HTTP clients
    — it only inspects Settings and probes keyring presence. Safe to poll.
    """
    try:
        settings = adapter.get_settings()
    except Exception:  # noqa: BLE001
        _log.warning("api_settings_load_failed")
        raise HTTPException(
            status_code=500,
            detail=(
                "Settings could not be loaded. Configure paths via TIC_PATHS__* "
                "env vars or a YAML config."
            ),
        ) from None

    try:
        secret_store = build_secret_store()
    except Exception:  # noqa: BLE001 — backend may be missing on minimal envs
        _log.warning("api_secret_store_unavailable")
        secret_store = None

    payload = build_provider_status(settings, secret_store)
    return JSONResponse(content=payload)


@app.post("/api/sweep")
async def sweep(
    feed_file: UploadFile = File(...),
    log_file: UploadFile = File(...),
    feed_format: Literal["csv", "ndjson", "misp-json", "stix"] = Form("csv"),
    output_mode: Literal["analyst", "summary", "hash"] = Form("analyst"),
    fail_on: Literal["info", "low", "medium", "high", "critical"] = Form("high"),
    with_ai: str = Form("false"),
) -> JSONResponse:
    """Run a sweep over an uploaded IOC feed + log file.

    Returns only public-safe fields (PublicFinding). Raw log lines, raw
    provider responses, EnrichmentResult.truncated_raw, and any secret are
    never returned.
    """
    # Defense-in-depth: re-validate even though FastAPI's Literal already does.
    feed_format = _validate_choice(feed_format, _FEED_FORMATS, "feed_format")  # type: ignore[assignment]
    output_mode = _validate_choice(output_mode, _OUTPUT_MODES, "output_mode")  # type: ignore[assignment]
    fail_on = _validate_choice(fail_on, _FAIL_ON, "fail_on")  # type: ignore[assignment]

    feed_bytes = await feed_file.read()
    log_bytes = await log_file.read()
    if len(feed_bytes) > _MAX_UPLOAD_BYTES or len(log_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds size limit.")
    if not feed_bytes or not log_bytes:
        raise HTTPException(
            status_code=400, detail="Both feed_file and log_file are required and non-empty."
        )

    try:
        settings = adapter.get_settings()
    except Exception:  # noqa: BLE001
        _log.warning("api_settings_load_failed")
        raise HTTPException(
            status_code=500,
            detail=(
                "Settings could not be loaded. Configure paths via TIC_PATHS__* "
                "env vars or a YAML config."
            ),
        ) from None

    working_dir = settings.paths.working_dir
    upload_dir = None
    try:
        try:
            upload_dir = adapter.make_upload_dir(working_dir)
            feed_path = adapter.stage_upload(
                feed_bytes,
                upload_dir=upload_dir,
                working_dir=working_dir,
                original_filename=feed_file.filename,
            )
            log_path = adapter.stage_upload(
                log_bytes,
                upload_dir=upload_dir,
                working_dir=working_dir,
                original_filename=log_file.filename,
            )
        except adapter.SecurityViolationError:
            _log.warning("api_upload_path_violation")
            raise HTTPException(
                status_code=400, detail="Upload rejected by path security check."
            ) from None

        req = adapter.SweepRequest(
            feed_path=feed_path,
            feed_format=feed_format,  # type: ignore[arg-type]
            log_path=log_path,
            output_mode=output_mode,  # type: ignore[arg-type]
            fail_on=fail_on,  # type: ignore[arg-type]
            with_ai=_parse_with_ai(with_ai),
        )

        try:
            # adapter.run_sweep is synchronous and internally drives its own
            # event loop via asyncio.run(). Calling it directly from this
            # async endpoint would nest event loops and trigger
            # "coroutine was never awaited". Off-load to a worker thread.
            result = await asyncio.to_thread(adapter.run_sweep, req, settings)
        except RuntimeError as e:
            # adapter.run_sweep already converted TICError → friendly RuntimeError
            # (no traceback, no internal_details).
            raise HTTPException(status_code=400, detail=str(e)) from None

        return JSONResponse(
            content={
                "findings": _public_findings_payload(result, output_mode),
                "finding_count": len(result.findings),
                "above_threshold": result.above_threshold,
                "exit_code": result.exit_code,
                "partial_scan": result.partial_scan,
                "ai_attempted": result.ai_attempted,
                "ai_active": result.ai_active,
                "output_mode": output_mode,
            }
        )
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 — last-resort safety net
        _log.warning("api_unhandled_error", type=type(e).__name__)
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred during the sweep."
        ) from None
    finally:
        if upload_dir is not None:
            adapter.cleanup_upload_dir(upload_dir)
