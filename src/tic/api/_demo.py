# src/tic/api/_demo.py
"""Public demo mode for the hosted portfolio deployment.

Enabled with ``TIC_DEMO_MODE=1``. When on:

- ``POST /api/sweep`` (multipart upload) is refused — the public instance
  never accepts caller-supplied files, so there is no upload abuse surface.
- ``POST /api/demo-sweep`` becomes available. It stages the bundled sample
  feed + event set below and runs the *real* pipeline: parsing,
  Aho-Corasick correlation, scoring and public-DTO masking. Nothing is
  faked; only the input is fixed.

Sample data rules (same as frontend/lib/samples.ts):
- IPv4 from RFC 5737 documentation ranges, IPv6 from 2001:db8::/32.
- Domains under the IETF example.com/.org/.net reservations.
- Hashes are zero-padded placeholders, never real malware hashes.
- No secrets, tokens or credentials anywhere.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from tic.ui import adapter

# --------------------------------------------------------------------------
# Flags
# --------------------------------------------------------------------------

_TRUTHY = {"1", "true", "yes", "on"}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


DEMO_MODE: bool = _env_flag("TIC_DEMO_MODE")


def demo_origins() -> list[str]:
    """Extra CORS origins for the hosted demo frontend.

    Read from ``TIC_DEMO_ORIGINS`` (comma-separated). Ignored entirely when
    demo mode is off, so a stray env var cannot widen CORS on a local run.
    Each entry must be a scheme+host origin with no path — anything else is
    dropped rather than trusted.
    """
    if not DEMO_MODE:
        return []
    raw = os.environ.get("TIC_DEMO_ORIGINS", "")
    out: list[str] = []
    for candidate in raw.split(","):
        value = candidate.strip().rstrip("/")
        if not value:
            continue
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        if parts.path or parts.query or parts.fragment:
            continue
        out.append(f"{parts.scheme}://{parts.netloc}")
    return out


# --------------------------------------------------------------------------
# Bundled sample inputs
# --------------------------------------------------------------------------

DEMO_FEED_CSV = """value,confidence,source,tags
198.51.100.23,100,demo-feed,doc;ipv4;c2;beacon
malware.example.com,95,demo-feed,doc;domain;dropper
http://evil.example.net/payload.exe,95,demo-feed,doc;url;payload
203.0.113.45,80,demo-feed,doc;ipv4;scanner
phish.example.org,75,demo-feed,doc;domain;phishing
192.0.2.77,60,demo-feed,doc;ipv4;bruteforce
2001:db8::5,50,demo-feed,doc;ipv6
0123456789abcdef0123456789abcdef,40,demo-feed,doc;md5
0000000000000000000000000000000000000000000000000000000000000000,25,demo-feed,doc;sha256
0000000000000000000000000000000000000000,10,demo-feed,doc;sha1
"""

_DEMO_EVENTS: tuple[dict[str, object], ...] = (
    {
        "@timestamp": "2025-01-12T08:14:02Z",
        "source": "firewall",
        "src_ip": "10.0.0.42",
        "dst_ip": "198.51.100.23",
        "action": "allow",
        "bytes": 8421,
    },
    {
        "@timestamp": "2025-01-12T08:14:30Z",
        "source": "proxy",
        "user": "alice",
        "url": "http://malware.example.com/login",
        "status": 200,
    },
    {
        "@timestamp": "2025-01-12T08:16:11Z",
        "source": "proxy",
        "user": "bob",
        "url": "http://evil.example.net/payload.exe",
        "status": 200,
        "bytes": 942_113,
    },
    {
        "@timestamp": "2025-01-12T08:17:45Z",
        "source": "edr",
        "host": "WS-014",
        "process": "powershell.exe",
        "sha256": (
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "verdict": "quarantined",
    },
    {
        "@timestamp": "2025-01-12T08:19:03Z",
        "source": "mail",
        "recipient": "carol@corp.invalid",
        "sender_domain": "phish.example.org",
        "subject_len": 62,
        "action": "delivered",
    },
    {
        "@timestamp": "2025-01-12T08:22:19Z",
        "source": "firewall",
        "src_ip": "203.0.113.45",
        "dst_ip": "10.0.0.15",
        "dst_port": 22,
        "action": "deny",
        "attempts": 214,
    },
    {
        "@timestamp": "2025-01-12T08:25:40Z",
        "source": "vpn",
        "user": "dave",
        "client_ip": "192.0.2.77",
        "result": "failed",
        "attempts": 37,
    },
    {
        "@timestamp": "2025-01-12T08:31:07Z",
        "source": "dns",
        "host": "WS-031",
        "query": "malware.example.com",
        "answer": "2001:db8::5",
        "rcode": "NOERROR",
    },
    {
        "@timestamp": "2025-01-12T08:33:52Z",
        "source": "edr",
        "host": "WS-031",
        "process": "rundll32.exe",
        "md5": "0123456789abcdef0123456789abcdef",
        "verdict": "allowed",
    },
    {
        "@timestamp": "2025-01-12T08:40:12Z",
        "source": "firewall",
        "src_ip": "10.0.0.31",
        "dst_ip": "192.0.2.10",
        "action": "allow",
        "bytes": 512,
    },
)

def _beacon_events() -> list[dict[str, object]]:
    """Regular outbound callbacks to the C2 IOC, plus the dropper lookups.

    match_count saturates at 10 in the scoring engine, so a realistic
    beaconing pattern is what lets the top IOCs reach their full score
    instead of looking like one-off hits.
    """
    out: list[dict[str, object]] = []
    for i in range(12):
        out.append(
            {
                "@timestamp": f"2025-01-12T09:{i * 5 // 60:02d}:{i * 5 % 60:02d}Z",
                "source": "firewall",
                "src_ip": "10.0.0.42",
                "dst_ip": "198.51.100.23",
                "dst_port": 443,
                "action": "allow",
                "bytes": 1180 + i,
            }
        )
    for i in range(9):
        out.append(
            {
                "@timestamp": f"2025-01-12T09:{(i * 7 + 3) % 60:02d}:0{i % 10}Z",
                "source": "dns",
                "host": f"WS-{10 + i:03d}",
                "query": "malware.example.com",
                "rcode": "NOERROR",
            }
        )
    for i in range(9):
        out.append(
            {
                "@timestamp": f"2025-01-12T10:{(i * 6) % 60:02d}:1{i % 10}Z",
                "source": "proxy",
                "user": f"user{i}",
                "url": "http://evil.example.net/payload.exe",
                "status": 200,
                "bytes": 942_113,
            }
        )
    return out


DEMO_EVENTS_NDJSON = (
    "\n".join(
        json.dumps(event, separators=(",", ":"))
        for event in (*_DEMO_EVENTS, *_beacon_events())
    )
    + "\n"
)


def stage_demo_inputs(*, upload_dir: Path, working_dir: Path) -> tuple[Path, Path]:
    """Write the bundled feed + events into the session upload dir.

    Reuses adapter.stage_upload so the demo inputs go through exactly the
    same path guard as a real upload would.
    """
    feed_path = adapter.stage_upload(
        DEMO_FEED_CSV.encode("utf-8"),
        upload_dir=upload_dir,
        working_dir=working_dir,
        original_filename="demo-feed.csv",
    )
    log_path = adapter.stage_upload(
        DEMO_EVENTS_NDJSON.encode("utf-8"),
        upload_dir=upload_dir,
        working_dir=working_dir,
        original_filename="demo-events.ndjson",
    )
    return feed_path, log_path
