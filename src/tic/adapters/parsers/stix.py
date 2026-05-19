# src/tic/adapters/parsers/stix.py
"""STIX 2.1 indicator feed parser.

Uses `stix2-patterns` for safe pattern parsing. We extract IOCs only from
simple equality comparisons such as `[ipv4-addr:value = '1.2.3.4']`.
Complex composite patterns (AND/OR/FOLLOWEDBY/observation windows) are
skipped with a DEBUG log entry — extracting IOCs from them is ambiguous
and risks false positives that would degrade correlation quality.

Supported input shapes:
- STIX Bundle (`{"type": "bundle", "objects": [...]}`)
- Bare indicator list (`[{"type": "indicator", ...}, ...]`)
- Single indicator object (`{"type": "indicator", ...}`)
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from stix2patterns.pattern import Pattern  # type: ignore[import-untyped]

from tic.adapters.parsers.base import FeedParser
from tic.application.normalization import make_ioc
from tic.domain.errors import InputValidationError, ParseError
from tic.domain.ioc import IOC
from tic.infra.config import ParserLimits
from tic.infra.logging import get_logger
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

# Path hints keyed by "<object_type>:<joined_path>". The joined_path is the
# path list produced by stix2-patterns, joined with '.'. For hash paths, the
# hash algorithm name is lowercased to make matching case-insensitive
# (stix2-patterns preserves the source casing: 'SHA-256' vs 'sha-256' vs 'md5').
_PATH_HINTS: dict[str, str] = {
    "ipv4-addr:value": "stix:ipv4-addr",
    "ipv6-addr:value": "stix:ipv6-addr",
    "domain-name:value": "stix:domain-name",
    "url:value": "stix:url",
    "email-addr:value": "stix:email-addr",
    "file:name": "stix:file-name",
    "file:hashes.md5": "stix:file-md5",
    "file:hashes.sha-1": "stix:file-sha1",
    "file:hashes.sha-256": "stix:file-sha256",
    "file:hashes.sha-512": "stix:file-sha512",
    "vulnerability:name": "stix:vulnerability",
}


def _iter_indicators(doc: Any) -> Iterator[dict[str, Any]]:
    """Yield indicator objects from any supported STIX input shape."""
    if isinstance(doc, dict):
        if doc.get("type") == "bundle" and isinstance(doc.get("objects"), list):
            for o in doc["objects"]:
                if isinstance(o, dict) and o.get("type") == "indicator":
                    yield o
            return
        if doc.get("type") == "indicator":
            yield doc
            return
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict) and item.get("type") == "indicator":
                yield item


def _strip_quotes(value: str) -> str:
    """Remove surrounding single or double quotes from a STIX literal."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _join_path(path: Any) -> str | None:
    """Normalize a stix2-patterns path list to dotted lowercase form.

    stix2-patterns yields paths as `list[str]` (e.g., ['value'],
    ['hashes', 'SHA-256']). We lowercase each segment so that 'SHA-256',
    'sha-256' and 'Sha-256' collapse to the same lookup key.
    """
    if not isinstance(path, list):
        return None
    parts: list[str] = []
    for seg in path:
        if not isinstance(seg, str):
            return None
        parts.append(seg.lower())
    return ".".join(parts) if parts else None


def _extract_equalities(pattern_text: str) -> list[tuple[str, str]]:
    """Return list of (object_type:joined_path, literal_value) pairs.

    Uses stix2-patterns' `inspect()` which returns a structured view:
        {object_type: [(path_list, comparator, quoted_value), ...], ...}

    Only `=` comparisons with string literals are extracted; everything else
    (IN, MATCHES, LIKE, numeric comparators) is silently skipped.
    """
    try:
        pattern = Pattern(pattern_text)
        inspection = pattern.inspect()
    except Exception:  # noqa: BLE001 — stix2-patterns raises library-local types
        return []

    comparisons = getattr(inspection, "comparisons", None)
    if not isinstance(comparisons, dict):
        return []

    pairs: list[tuple[str, str]] = []
    for obj_type, triples in comparisons.items():
        if not isinstance(obj_type, str) or not isinstance(triples, list):
            continue
        for triple in triples:
            if not (isinstance(triple, (list, tuple)) and len(triple) >= 3):
                continue
            path, comparator, raw_value = triple[0], triple[1], triple[2]
            if comparator != "=":
                continue
            joined = _join_path(path)
            if joined is None or not isinstance(raw_value, str):
                continue
            cleaned = _strip_quotes(raw_value.strip())
            if not cleaned:
                continue
            pairs.append((f"{obj_type}:{joined}", cleaned))
    return pairs


def _indicator_confidence(ind: dict[str, Any]) -> int:
    """STIX 2.1 indicator.confidence is 0..100 (optional)."""
    c = ind.get("confidence")
    if isinstance(c, int):
        return max(0, min(100, c))
    return 50


def _indicator_tags(ind: dict[str, Any]) -> frozenset[str]:
    labels = ind.get("labels")
    if not isinstance(labels, list):
        return frozenset()
    return frozenset(str(x)[:64] for x in labels[:32] if isinstance(x, (str, int)))


class StixFeedParser(FeedParser):
    format_name = "stix"

    def parse(
        self,
        path: Path,
        *,
        allowed_root: Path,
        limits: ParserLimits,
        source_hint: str = "stix",
    ) -> Iterator[IOC]:
        return parse_stix_feed(
            path,
            allowed_root=allowed_root,
            limits=limits,
            source_hint=source_hint,
        )


def parse_stix_feed(
    path: Path,
    *,
    allowed_root: Path,
    limits: ParserLimits,
    source_hint: str = "stix",
) -> Iterator[IOC]:
    """Stream IOCs from a STIX 2.1 bundle or indicator list.

    Security:
    - Path confined to allowed_root.
    - File size capped pre-read; whole-file json.load bounded by that cap.
    - Pattern parsing delegated to `stix2-patterns` (defensive ANTLR grammar),
      not custom regex — this is important because STIX patterns are a formal
      language and misparsing them could lead to IOC injection or omission.
    - Per-value length-checked against limits.max_string_length.
    """
    resolved = safe_resolve_within(path, allowed_root=allowed_root)
    size = resolved.stat().st_size
    if size > limits.max_file_size_bytes:
        raise ParseError(
            f"stix file too large: {size} > {limits.max_file_size_bytes}",
            user_message="Feed file exceeds configured size limit.",
        )

    with resolved.open("r", encoding="utf-8", errors="strict") as f:
        try:
            doc = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"stix json malformed at line {e.lineno} col {e.colno}",
                user_message="STIX JSON file is malformed.",
            ) from e

    count = 0
    for ind in _iter_indicators(doc):
        indicator_id = str(ind.get("id", ""))[:256] or source_hint
        pattern_text = ind.get("pattern")
        pattern_type = ind.get("pattern_type", "stix")
        if not isinstance(pattern_text, str) or pattern_type != "stix":
            _log.debug("stix_indicator_skipped_pattern_type", id=indicator_id)
            continue

        try:
            equalities = _extract_equalities(pattern_text)
        except Exception as e:  # noqa: BLE001
            _log.debug(
                "stix_pattern_parse_failed",
                id=indicator_id,
                error=type(e).__name__,
            )
            continue

        if not equalities:
            _log.debug("stix_indicator_no_equalities", id=indicator_id)
            continue

        confidence = _indicator_confidence(ind)
        tags = _indicator_tags(ind)

        for path_key, raw_value in equalities:
            if len(raw_value) > limits.max_string_length:
                _log.debug(
                    "stix_value_too_long",
                    id=indicator_id,
                    length=len(raw_value),
                )
                continue
            path_hint = _PATH_HINTS.get(path_key, "stix:unknown")
            try:
                yield make_ioc(
                    raw_value,
                    source=f"{source_hint}:{indicator_id}:{path_hint}",
                    confidence=confidence,
                    tags=tags,
                )
            except InputValidationError as e:
                _log.debug(
                    "stix_value_not_valid_ioc",
                    id=indicator_id,
                    path=path_key,
                    error=str(e)[:120],
                )
                continue
            count += 1
            if count > limits.max_iocs_per_feed:
                raise ParseError(
                    f"feed exceeds max IOC count: {limits.max_iocs_per_feed}",
                    user_message="Feed exceeds configured IOC count limit.",
                )
