# tests/integration/test_api_upload_limits.py
"""/api/sweep upload size + streaming contract.

Guards the OOM defect where each upload was buffered whole in RAM (bytearray
-> bytes copy) with a 256 MB HTTP ceiling that also exceeded the parser's own
100 MB limit. The endpoint now:
  * streams each upload straight to disk in bounded chunks (never whole-file
    in RAM), and
  * enforces settings.parser_limits.max_file_size_bytes as the ceiling, so
    the HTTP layer never stages a file the parser would reject.

We drive the ceiling down via TIC_PARSER_LIMITS__MAX_FILE_SIZE_BYTES so the
over-limit case is exercised without allocating hundreds of MB.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

# A small ceiling so "over limit" is a few KB, not hundreds of MB.
_MAX_BYTES = 4096


def _make_env() -> dict[str, str]:
    work = tempfile.mkdtemp(prefix="tic-test-work-")
    cache = tempfile.mkdtemp(prefix="tic-test-cache-")
    audit = Path(tempfile.mkdtemp(prefix="tic-test-audit-")) / "audit.log"
    return {
        "TIC_PATHS__WORKING_DIR": work,
        "TIC_PATHS__CACHE_DIR": cache,
        "TIC_PATHS__AUDIT_LOG_PATH": str(audit),
        "TIC_PARSER_LIMITS__MAX_FILE_SIZE_BYTES": str(_MAX_BYTES),
    }


def _small_csv() -> bytes:
    return b"value,confidence,source,tags\n198.51.100.23,80,sample,doc;ipv4\n"


def _small_ndjson() -> bytes:
    line = json.dumps(
        {"@timestamp": "2025-01-12T08:14:02Z", "source": "fw", "dst_ip": "198.51.100.23"}
    )
    return (line + "\n").encode()


def _client(monkeypatch) -> TestClient:
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    from tic.api.main import app

    return TestClient(app)


def test_within_limit_is_accepted(monkeypatch):
    """A feed + log comfortably under the ceiling sweeps successfully."""
    c = _client(monkeypatch)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _small_csv(), "text/csv"),
            "log_file": ("events.ndjson", _small_ndjson(), "application/x-ndjson"),
        },
        data={"feed_format": "csv", "output_mode": "analyst", "fail_on": "high"},
    )
    assert r.status_code == 200, r.text


def test_oversized_feed_is_rejected_with_413(monkeypatch):
    """A feed larger than the ceiling is rejected before any sweep work."""
    c = _client(monkeypatch)
    oversized = b"x" * (_MAX_BYTES + 1)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", oversized, "text/csv"),
            "log_file": ("events.ndjson", _small_ndjson(), "application/x-ndjson"),
        },
        data={"feed_format": "csv", "output_mode": "analyst", "fail_on": "high"},
    )
    assert r.status_code == 413, r.text
    assert "size limit" in r.json()["detail"].lower()


def test_oversized_log_is_rejected_with_413(monkeypatch):
    """The second (log) upload is bounded by the same ceiling as the feed."""
    c = _client(monkeypatch)
    oversized = b"x" * (_MAX_BYTES + 1)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _small_csv(), "text/csv"),
            "log_file": ("events.ndjson", oversized, "application/x-ndjson"),
        },
        data={"feed_format": "csv", "output_mode": "analyst", "fail_on": "high"},
    )
    assert r.status_code == 413, r.text


def test_empty_feed_is_rejected_with_400(monkeypatch):
    """An empty upload is a client error, not a 413 or a 500."""
    c = _client(monkeypatch)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", b"", "text/csv"),
            "log_file": ("events.ndjson", _small_ndjson(), "application/x-ndjson"),
        },
        data={"feed_format": "csv", "output_mode": "analyst", "fail_on": "high"},
    )
    assert r.status_code == 400, r.text
    assert "non-empty" in r.json()["detail"].lower()


def test_upload_streamed_to_disk_not_buffered_whole(monkeypatch):
    """Behavioural check: the endpoint streams via _stream_upload_to, so no
    code path reads the whole UploadFile into a single bytes object.

    We wrap _stream_upload_to and assert it is what consumes the uploads
    (i.e. the disk-streaming path is live), and that the staged file on disk
    matches the uploaded size.
    """
    import tic.api.main as api_main

    seen_sizes: list[int] = []
    original = api_main._stream_upload_to

    async def _spy(upload, dest, max_bytes):
        written = await original(upload, dest, max_bytes)
        # Bytes really landed on disk (not just in RAM).
        assert dest.exists()
        assert dest.stat().st_size == written
        seen_sizes.append(written)
        return written

    monkeypatch.setattr(api_main, "_stream_upload_to", _spy)

    c = _client(monkeypatch)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _small_csv(), "text/csv"),
            "log_file": ("events.ndjson", _small_ndjson(), "application/x-ndjson"),
        },
        data={"feed_format": "csv", "output_mode": "analyst", "fail_on": "high"},
    )
    assert r.status_code == 200, r.text
    # Both uploads went through the streaming helper.
    assert len(seen_sizes) == 2
    assert all(s > 0 for s in seen_sizes)
