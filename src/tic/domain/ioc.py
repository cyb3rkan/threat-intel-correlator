# src/tic/domain/ioc.py
"""Indicator of Compromise value object.

Design:
- Immutable (pydantic frozen=True).
- Canonical string in `value`; parsers must normalize before constructing.
- No I/O, no side effects.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    EMAIL = "email"
    FILENAME = "filename"
    CVE = "cve"


CanonicalStr = Annotated[str, StringConstraints(min_length=1, max_length=2048, strip_whitespace=True)]
ShortStr = Annotated[str, StringConstraints(max_length=256, strip_whitespace=True)]


class IOC(BaseModel):
    """Normalized IOC. Constructed only via adapters/parsers after normalization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: CanonicalStr
    ioc_type: IOCType
    source: ShortStr
    confidence: int = Field(default=50, ge=0, le=100)
    first_seen: datetime | None = None
    tags: frozenset[str] = Field(default_factory=frozenset)
    raw_source_ref: ShortStr | None = None

    def fingerprint(self) -> tuple[IOCType, str]:
        """Dedup key. Callers may use for set/dict membership."""
        return (self.ioc_type, self.value)