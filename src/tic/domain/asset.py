# src/tic/domain/asset.py
"""Asset inventory model.

Security classification:
- hostname, ip: Internal (do not leak to AI)
- owner_email: Confidential (PII; redacted before AI / external output)
- criticality: Internal
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

_Short = Annotated[str, StringConstraints(max_length=256, strip_whitespace=True)]


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}[self.value]


class Asset(BaseModel):
    """An internal asset that may correlate with an IOC observation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: _Short
    ip: _Short | None = None
    owner_email: _Short | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    os: _Short | None = None
    location: _Short | None = None
    tags: frozenset[str] = Field(default_factory=frozenset)
