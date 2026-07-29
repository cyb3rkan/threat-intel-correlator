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


def ensure_public_url(
    url: str,
    *,
    extra_allowlist: frozenset[str] = frozenset(),
    allowed_cidrs: frozenset[str] = frozenset(),
) -> None:
    """Raise SecurityViolationError if URL resolves to a non-public address.

    `extra_allowlist` may contain host names explicitly permitted (e.g., an
    on-prem MISP instance), compared case-insensitively against the hostname.

    `allowed_cidrs` optionally pins those allowlisted hosts to declared IP
    ranges: when non-empty, an allowlisted host's resolved IP MUST fall inside
    one of the ranges or the request is rejected. This closes the DNS-rebind
    gap where an allowlisted name resolves to an unexpected internal IP. When
    `allowed_cidrs` is empty, an allowlisted host keeps the documented residual
    (its resolved IP is not range-checked); the unconditional metadata/blocked
    host check above always applies regardless.
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

    is_allowlisted = host_lower in extra_allowlist

    # Allowlisted host WITHOUT a declared CIDR keeps the documented residual:
    # it is a deliberate internal target, the unconditional metadata block
    # already ran, and its resolved IP is not range-checked. A rebind to a
    # *different* internal IP stays possible -- declare allowed_host_cidrs to
    # close that gap.
    if is_allowlisted and not allowed_cidrs:
        return

    # Resolve all A/AAAA records and check each. Guard against DNS rebinding
    # by checking every returned address.
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SecurityViolationError(
            f"dns resolve failed for {host}: {e}",
            user_message="Unable to resolve target host.",
        ) from e

    allowed_networks = _parse_cidrs(allowed_cidrs)
    for info in infos:
        addr_str = info[4][0]
        try:
            ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if is_allowlisted:
            # Allowlisted + CIDR declared: the resolved IP MUST fall inside a
            # declared range, else this is a DNS-rebind to an unexpected
            # address and is rejected.
            if not _ip_in_any(ip, allowed_networks):
                raise SecurityViolationError(
                    f"allowlisted host {host} resolved to {ip} outside declared cidrs",
                    user_message="Target resolves outside its permitted range.",
                )
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


def _parse_cidrs(
    cidrs: frozenset[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _ip_in_any(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    for net in nets:
        if (
            isinstance(ip, ipaddress.IPv4Address)
            and isinstance(net, ipaddress.IPv4Network)
            and ip in net
        ):
            return True
        if (
            isinstance(ip, ipaddress.IPv6Address)
            and isinstance(net, ipaddress.IPv6Network)
            and ip in net
        ):
            return True
    return False
