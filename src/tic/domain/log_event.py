# src/tic/domain/log_event.py
"""Normalized log event. Used by log_sources to emit structured data.

Security design:
- Raw log text is NEVER stored on this entity; only its SHA-256 hash is kept
  for audit purposes.
- All free-text fields are bounded in length to prevent DoS via oversized
  attribute values.
- Hostname/user fields are candidates for redaction before any AI path.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

_Short = Annotated[str, StringConstraints(max_length=256, strip_whitespace=True)]
_Medium = Annotated[str, StringConstraints(max_length=2048, strip_whitespace=True)]


class LogEvent(BaseModel):
    """A single normalized observation from an internal log source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime
    source: _Short  # e.g. "firewall.ndjson", "elastic:winlogbeat"
    src_ip: _Short | None = None
    dst_ip: _Short | None = None
    url: _Medium | None = None
    hash_fields: dict[str, _Short] = Field(default_factory=dict)
    host: _Short | None = None
    user: _Short | None = None
    raw_line_hash: Annotated[str, StringConstraints(min_length=64, max_length=64)]