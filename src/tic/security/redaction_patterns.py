# src/tic/security/redaction_patterns.py
"""Defense-in-depth: regex patterns that MUST NOT appear in outbound AI payloads.

Purpose:
- `tic.application.redaction.Redactor` performs the primary structural
  redaction (field allowlist + HMAC pseudonymization). This module provides
  a secondary pattern-based *check* that can be applied to the serialized
  payload immediately before it leaves the process.
- This is a detection layer, not a replacement layer. If a pattern is found,
  the payload MUST NOT be sent; it indicates a redaction bug.

Rationale:
- A single missed field in `Redactor` could leak PII. A post-serialization
  regex scan catches that class of bugs.
- Patterns are deliberately conservative to minimize false positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


class _SearchableRe(Protocol):
    """Minimal surface we need from both `re.Pattern` and composite matchers."""

    def search(self, text: str) -> re.Match[str] | None: ...


@dataclass(frozen=True)
class _Pattern:
    name: str
    regex: _SearchableRe


_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,24}\b"
)

# RFC1918 IPv4 (full, not partial-match). Excludes 127.0.0.0/8 since loopback
# values may be legitimate constants in generic config examples.
_PRIVATE_IPV4 = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


# -- Phone pattern ------------------------------------------------------------
# International and common local phone number forms. Captured in two stages:
#   1) Shape regex: optional +country code, then 2-5 subsequent digit groups.
#   2) Minimum digit count gate: rejects short numeric runs (order IDs etc).
#
# Defense-in-depth notes:
# - Lookaround anchors (?<!\d) / (?!\d) prevent matching inside longer runs.
# - Bounded quantifier {2,5} avoids catastrophic backtracking.
# - We avoid variable-width negative lookbehinds (not supported by `re`) by
#   post-filtering matches for a minimum digit count.
_PHONE_SHAPE = re.compile(
    r"(?<!\d)"
    r"\+?\d{1,3}"
    r"(?:[\s.\-]?\(?\d{2,4}\)?){2,5}"
    r"(?!\d)"
)
_MIN_PHONE_DIGITS = 8


class _PhonePattern:
    """Shape match + minimum-digit-count gate. Implements the Re search surface."""

    def search(self, text: str) -> re.Match[str] | None:
        for m in _PHONE_SHAPE.finditer(text):
            digits = sum(ch.isdigit() for ch in m.group(0))
            if digits >= _MIN_PHONE_DIGITS:
                return m
        return None


_PHONE: _SearchableRe = _PhonePattern()


# Turkish national ID (TCKN): exactly 11 digits, first digit non-zero.
_TCKN = re.compile(r"\b[1-9]\d{10}\b")

# US SSN (most common redaction target in international tooling).
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Authorization headers / bearer tokens that accidentally got serialized.
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{12,}=*")

# Credential-looking assignments (api_key=..., password=...).
_CRED_ASSIGN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password|token|authorization)\s*[:=]\s*"
    r"['\"]?[A-Za-z0-9\-._~+/]{8,}['\"]?"
)


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("email", _EMAIL),
    _Pattern("private_ipv4", _PRIVATE_IPV4),
    _Pattern("phone", _PHONE),
    _Pattern("tckn", _TCKN),
    _Pattern("ssn", _SSN),
    _Pattern("bearer_token", _BEARER),
    _Pattern("credential_assignment", _CRED_ASSIGN),
)


def detect_pii_patterns(text: str) -> list[str]:
    """Return names of any PII/secret patterns found in `text`.

    An empty list means the text is clean with respect to these patterns.
    Caller responsibility: decide whether to fail-closed (raise) or fail-open
    (log + reject payload) based on context. For AI egress we fail-closed.
    """
    if not text:
        return []
    hits: list[str] = []
    for p in _PATTERNS:
        if p.regex.search(text):
            hits.append(p.name)
    return hits