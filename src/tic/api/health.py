# src/tic/api/health.py
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from tic.infra.telemetry import get_registry

router = APIRouter()
_START_TIME = time.monotonic()

@router.get("/api/health", tags=["ops"])
def liveness() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "threat-intel-correlator-api",
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
    }

@router.get("/api/ready", tags=["ops"])
def readiness(request: Request) -> JSONResponse:
    checks: dict[str, Any] = {}
    all_ok = True
    try:
        from tic.ui import adapter
        settings = adapter.get_settings()
        checks["settings"] = "ok"
    except Exception as exc:
        checks["settings"] = f"error: {type(exc).__name__}"
        all_ok = False
    try:
        cache_dir = settings.paths.cache_dir
        checks["cache_dir"] = "ok" if cache_dir.exists() else "missing"
        if not cache_dir.exists():
            all_ok = False
    except Exception:
        checks["cache_dir"] = "unknown"
    status = "ready" if all_ok else "degraded"
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": status, "checks": checks},
    )

@router.get("/api/metrics", tags=["ops"], response_class=PlainTextResponse)
def metrics() -> str:
    # Expose the in-process RED/USE counters, gauges, and histograms in
    # Prometheus text form (see tic.infra.telemetry.MetricsRegistry).
    return get_registry().to_prometheus_text()
