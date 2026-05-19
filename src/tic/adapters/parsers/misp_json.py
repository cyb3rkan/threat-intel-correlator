# src/tic/adapters/parsers/misp_json.py
"""MISP event JSON parser.

Handles both single-event (`{"Event": {...}}`) and multi-event response
(`{"response": [{...}, ...]}` or `[{"Event": {...}}]`) shapes.

Extracts IOCs from:
- `Event.Attribute[*]` — top-level attributes
- `Event.Object[*].Attribute[*]` — attributes nested inside objects

Unknown attribute `type` values are silently ignored; the normalizer is the
final authority on whether a string is a valid IOC.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from tic.adapters.parsers.base import FeedParser
from tic.application.normalization import make_ioc
from tic.domain.errors import InputValidationError, ParseError
from tic.domain.ioc import IOC
from tic.infra.config import ParserLimits
from tic.infra.logging import get_logger
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

# MISP attribute types that carry IOC-like values. We pass the raw value to
# the normalizer and let it decide the canonical IOC type; this avoids relying
# on MISP's type taxonomy staying stable.
_IOC_BEARING_TYPES: frozenset[str] = frozenset(
    {
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
        "hostname",
        "domain",
        "domain|ip",
        "url",
        "uri",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "filename",
        "filename|md5",
        "filename|sha1",
        "filename|sha256",
        "email",
        "email-src",
        "email-dst",
        "email-subject",
        "vulnerability",
    }
)


def _iter_events(doc: Any) -> Iterator[dict[str, Any]]:
    """Yield event dicts regardless of wrapper shape."""
    if isinstance(doc, dict):
        if "Event" in doc and isinstance(doc["Event"], dict):
            yield doc["Event"]
            return
        if "response" in doc and isinstance(doc["response"], list):
            for item in doc["response"]:
                if isinstance(item, dict) and isinstance(item.get("Event"), dict):
                    yield item["Event"]
            return
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict) and isinstance(item.get("Event"), dict):
                yield item["Event"]


def _iter_attributes(event: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield attribute dicts from an Event, including those inside Objects."""
    top = event.get("Attribute")
    if isinstance(top, list):
        for a in top:
            if isinstance(a, dict):
                yield a
    objects = event.get("Object")
    if isinstance(objects, list):
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            inner = obj.get("Attribute")
            if isinstance(inner, list):
                for a in inner:
                    if isinstance(a, dict):
                        yield a


def _candidate_values(attr: dict[str, Any]) -> list[str]:
    """MISP `|`-joined types produce multiple values (e.g., filename|md5)."""
    att_type = attr.get("type")
    value = attr.get("value")
    if not isinstance(att_type, str) or not isinstance(value, str):
        return []
    if att_type not in _IOC_BEARING_TYPES:
        return []
    # Compound values are split on '|'; each half is an independent candidate.
    if "|" in att_type and "|" in value:
        parts = [p.strip() for p in value.split("|") if p.strip()]
        return parts
    return [value.strip()]


def _attribute_confidence(attr: dict[str, Any]) -> int:
    """MISP attributes have no universal confidence field; fall back to 50.

    Some feeds populate `to_ids` (bool) to indicate high-confidence IOCs; we
    treat that as a +15 bump (still within 0..100 clamp).
    """
    base = 50
    if attr.get("to_ids") is True:
        base += 15
    return max(0, min(100, base))


def _attribute_tags(attr: dict[str, Any]) -> frozenset[str]:
    tags = attr.get("Tag")
    if not isinstance(tags, list):
        return frozenset()
    out: list[str] = []
    for t in tags[:32]:
        if isinstance(t, dict):
            name = t.get("name")
            if isinstance(name, str) and name:
                out.append(name[:64])
    return frozenset(out)


class MispJsonFeedParser(FeedParser):
    format_name = "misp-json"

    def parse(
        self,
        path: Path,
        *,
        allowed_root: Path,
        limits: ParserLimits,
        source_hint: str = "misp-json",
    ) -> Iterator[IOC]:
        return parse_misp_feed(
            path,
            allowed_root=allowed_root,
            limits=limits,
            source_hint=source_hint,
        )


def parse_misp_feed(
    path: Path,
    *,
    allowed_root: Path,
    limits: ParserLimits,
    source_hint: str = "misp-json",
) -> Iterator[IOC]:
    """Stream IOCs from a MISP event JSON export.

    Security:
    - Path confined to allowed_root.
    - File size capped pre-read.
    - Whole-file JSON load is unavoidable for MISP (nested structure); we cap
      file size first to bound memory.
    - Each attribute value length-checked against limits.max_string_length.
    - IOC count capped at limits.max_iocs_per_feed.
    """
    resolved = safe_resolve_within(path, allowed_root=allowed_root)
    size = resolved.stat().st_size
    if size > limits.max_file_size_bytes:
        raise ParseError(
            f"misp json too large: {size} > {limits.max_file_size_bytes}",
            user_message="Feed file exceeds configured size limit.",
        )

    with resolved.open("r", encoding="utf-8", errors="strict") as f:
        try:
            doc = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"misp json malformed at line {e.lineno} col {e.colno}",
                user_message="MISP JSON file is malformed.",
            ) from e

    count = 0
    for event in _iter_events(doc):
        event_uuid = str(event.get("uuid", ""))[:256] or source_hint
        for attr in _iter_attributes(event):
            for candidate in _candidate_values(attr):
                if not candidate or len(candidate) > limits.max_string_length:
                    continue
                try:
                    yield make_ioc(
                        candidate,
                        source=f"{source_hint}:{event_uuid}",
                        confidence=_attribute_confidence(attr),
                        tags=_attribute_tags(attr),
                    )
                except InputValidationError as e:
                    _log.debug(
                        "misp_attr_invalid_ioc",
                        value_len=len(candidate),
                        error=str(e)[:120],
                    )
                    continue
                count += 1
                if count > limits.max_iocs_per_feed:
                    raise ParseError(
                        f"feed exceeds max IOC count: {limits.max_iocs_per_feed}",
                        user_message="Feed exceeds configured IOC count limit.",
                    )