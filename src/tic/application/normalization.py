# src/tic/application/normalization.py
"""IOC type detection and canonicalization.

Precedence order matters: hashes before hex-looking strings, IPs before domains
containing digits, etc. All comparisons are locale-invariant (ASCII fold).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import idna

from tic.domain.errors import InputValidationError
from tic.domain.ioc import IOC, IOCType

# ASCII-only locale-invariant lowercase
def _ascii_lower(s: str) -> str:
    return s.encode("ascii", errors="ignore").decode("ascii").lower() if s.isascii() else s.lower()


_HASH_RE = {
    IOCType.HASH_MD5: re.compile(r"^[0-9a-f]{32}$"),
    IOCType.HASH_SHA1: re.compile(r"^[0-9a-f]{40}$"),
    IOCType.HASH_SHA256: re.compile(r"^[0-9a-f]{64}$"),
    IOCType.HASH_SHA512: re.compile(r"^[0-9a-f]{128}$"),
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,255}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,63}$"
)

_DEFANG_MAP = [
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
]


def refang(value: str) -> str:
    """Reverse common defanging patterns. Conservative: only well-known forms."""
    v = value
    for a, b in _DEFANG_MAP:
        v = v.replace(a, b)
    return v.strip()


def _normalize_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(ip)


def _normalize_domain(value: str) -> str | None:
    lowered = value.strip().rstrip(".")
    if not lowered or len(lowered) > 253:
        return None
    # IDN to ASCII (punycode) to defuse homograph.
    try:
        ascii_form = idna.encode(lowered, uts46=True).decode("ascii").lower()
    except idna.IDNAError:
        return None
    if not _DOMAIN_RE.match(ascii_form):
        return None
    return ascii_form


def _normalize_url(value: str) -> str | None:
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https", "ftp"}:
        return None
    host = _normalize_domain(parts.hostname or "") if parts.hostname else None
    if not host:
        # Could be an IP in the URL
        try:
            ipaddress.ip_address(parts.hostname or "")
            host = parts.hostname
        except (ValueError, TypeError):
            return None
    # Reconstruct with lowercase scheme and normalized host; preserve path/query
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def detect_and_normalize(raw: str) -> tuple[IOCType, str]:
    """Detect IOC type and return canonical value. Raises InputValidationError."""
    if not raw or len(raw) > 8192:
        raise InputValidationError("empty or oversized IOC candidate")

    candidate = refang(raw).strip()
    if not candidate:
        raise InputValidationError("empty after refang")

    # CVE (case-insensitive, normalize to upper)
    upper = candidate.upper()
    if _CVE_RE.match(upper):
        return IOCType.CVE, upper

    lower = _ascii_lower(candidate)

    # Hashes (order: longest first to avoid ambiguity)
    for h_type in (IOCType.HASH_SHA512, IOCType.HASH_SHA256, IOCType.HASH_SHA1, IOCType.HASH_MD5):
        if _HASH_RE[h_type].match(lower):
            return h_type, lower

    # IP
    norm = _normalize_ip(candidate)
    if norm:
        return IOCType.IP, norm

    # URL (has scheme)
    if "://" in candidate:
        url = _normalize_url(candidate)
        if url:
            return IOCType.URL, url
        raise InputValidationError("malformed URL")

    # Email
    if "@" in candidate and _EMAIL_RE.match(candidate):
        local, _, domain = candidate.rpartition("@")
        dom = _normalize_domain(domain)
        if dom:
            return IOCType.EMAIL, f"{local.lower()}@{dom}"
        raise InputValidationError("malformed email domain")

    # Domain
    dom = _normalize_domain(candidate)
    if dom:
        return IOCType.DOMAIN, dom

    # Hiçbir pattern uymadı → hata fırlat (FILENAME fallback kaldırıldı)
    raise InputValidationError(f"unrecognized IOC format: {candidate!r}")


def make_ioc(
    raw_value: str,
    *,
    source: str,
    confidence: int = 50,
    tags: frozenset[str] = frozenset(),
) -> IOC:
    """Build an IOC from raw input. Used only by adapters/parsers."""
    ioc_type, canonical = detect_and_normalize(raw_value)
    return IOC(
        value=canonical,
        ioc_type=ioc_type,
        source=source[:256],
        confidence=max(0, min(100, confidence)),
        tags=frozenset(t[:64] for t in list(tags)[:32]),
    )