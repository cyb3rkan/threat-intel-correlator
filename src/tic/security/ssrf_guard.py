# src/tic/security/ssrf_guard.py
"""SSRF defense: resolve target host and reject private/loopback/link-local/metadata IPs.

Usage: SafeClient calls `ensure_public_url(url)` before every HTTP request
and after every redirect hop.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from tic.domain.errors import SecurityViolationError

_BLOCKED_HOST_SUBSTRINGS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.com",
        "169.254.169.254",
        "fd00:ec2::254",
    }
)

_ALLOWED_SCHEMES = frozenset({"https"})


def ensure_public_url(url: str, *, extra_allowlist: frozenset[str] = frozenset()) -> None:
    """Raise SecurityViolationError if URL resolves to a non-public address.

    `extra_allowlist` may contain host names explicitly permitted (e.g.,
    on-prem MISP instance). Entries are compared case-insensitively against
    the hostname only, not IPs (opt-in, explicit operator decision).
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise SecurityViolationError(
            f"disallowed scheme: {parsed.scheme}",
            user_message="Only https URLs are permitted.",
        )

    host = parsed.hostname
    if not host:
        raise SecurityViolationError("missing host", user_message="Invalid URL.")

    host_lower = host.lower()

    # Unconditional metadata/blocked host check — runs BEFORE allowlist.
    # The allowlist must NEVER be able to bypass metadata endpoint blocks.
    for bad in _BLOCKED_HOST_SUBSTRINGS:
        if bad in host_lower:
            raise SecurityViolationError(
                f"blocked host: {host_lower}",
                user_message="Target host is not permitted.",
            )

    # Allowlist opt-in — only for hosts that passed the unconditional check above.
    if host_lower in extra_allowlist:
        return  # explicit operator opt-in

    # Resolve all A/AAAA records and check each. Guard against DNS rebinding
    # by checking every returned address.
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SecurityViolationError(
            f"dns resolve failed for {host}: {e}",
            user_message="Unable to resolve target host.",
        ) from e

    for info in infos:
        addr_str = info[4][0]
        try:
            ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if _is_disallowed_ip(ip):
            raise SecurityViolationError(
                f"host {host} resolves to disallowed IP {ip}",
                user_message="Target resolves to a non-public address.",
            )


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    # Cloud metadata ranges
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return True
    elif ip.ipv4_mapped is not None and _is_disallowed_ip(ip.ipv4_mapped):
        return True
    return False
