# src/tic/ports/enrichment_provider.py
"""Enrichment provider port. Adapters implement this protocol."""

from __future__ import annotations

from typing import Protocol

from tic.domain.finding import EnrichmentResult
from tic.domain.ioc import IOC


class EnrichmentProvider(Protocol):
    name: str
    supported_types: frozenset[str]

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        """Return enrichment or None if provider cannot handle this IOC type.

        Must never raise for transient errors; wrap them and return None with
        internal logging. Must raise for programmer errors (wrong types etc).
        """
        ...
