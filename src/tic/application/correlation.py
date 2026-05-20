"""IOC × log correlation. Boundary validators compiled once per IOC (fix #13)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

import ahocorasick  # type: ignore[import-not-found]

from tic.domain.finding import Match
from tic.domain.ioc import IOC, IOCType
from tic.infra.logging import get_logger

_log = get_logger(__name__)

_BOUNDARY_TEMPLATES: dict[IOCType, str] = {
    IOCType.IP: r"(?:^|(?<<=[^0-9.])){{V}}(?=$|[^0-9.])",
    IOCType.DOMAIN: r"(?:^|(?<<=[^a-zA-Z0-9.\-])){{V}}(?=$|[^a-zA-Z0-9.\-])",
    IOCType.HASH_MD5: r"(?:^|(?<<=[^0-9a-f])){{V}}(?=$|[^0-9a-f])",
    IOCType.HASH_SHA1: r"(?:^|(?<<=[^0-9a-f])){{V}}(?=$|[^0-9a-f])",
    IOCType.HASH_SHA256: r"(?:^|(?<<=[^0-9a-f])){{V}}(?=$|[^0-9a-f])",
    IOCType.HASH_SHA512: r"(?:^|(?<<=[^0-9a-f])){{V}}(?=$|[^0-9a-f])",
}


def _compile_boundary(ioc: IOC) -> re.Pattern[str] | None:
    tmpl = _BOUNDARY_TEMPLATES.get(ioc.ioc_type)
    if tmpl is None:
        return None
    return re.compile(tmpl.replace("{{V}}", re.escape(ioc.value)), re.IGNORECASE)


@dataclass(frozen=True)
class _Entry:
    ioc: IOC
    boundary: re.Pattern[str] | None


def _boundary_ok(entry: _Entry, text: str, end_idx: int) -> bool:
    if entry.boundary is None:
        return True
    start = max(0, end_idx - len(entry.ioc.value) + 1)
    snippet = text[max(0, start - 1) : end_idx + 2]
    return entry.boundary.search(snippet) is not None


@dataclass(frozen=True)
class LogLine:
    source: str
    timestamp: datetime
    text: str


class Correlator:
    def __init__(self, iocs: Iterable[IOC]) -> None:
        self._automaton: ahocorasick.Automaton = ahocorasick.Automaton()
        self._entries: dict[str, _Entry] = {}
        count = 0
        for ioc in iocs:
            if ioc.value not in self._entries:
                entry = _Entry(ioc=ioc, boundary=_compile_boundary(ioc))
                self._automaton.add_word(ioc.value, entry)
                self._entries[ioc.value] = entry
                count += 1
        if count > 0:
            self._automaton.make_automaton()
        self._ready = count > 0
        _log.info("correlator_built", ioc_count=count)

    def iter_matches(self, lines: Iterable[LogLine]) -> Iterator[tuple[IOC, Match]]:
        if not self._ready:
            return
        for line in lines:
            line_hash = hashlib.sha256(line.text.encode("utf-8", errors="replace")).hexdigest()
            seen: set[str] = set()
            for end_idx, entry in self._automaton.iter(line.text):
                if entry.ioc.value in seen:
                    continue
                if not _boundary_ok(entry, line.text, end_idx):
                    continue
                seen.add(entry.ioc.value)
                yield (
                    entry.ioc,
                    Match(
                        log_source=line.source,
                        field="text",
                        timestamp=line.timestamp,
                        raw_line_hash=line_hash,
                    ),
                )