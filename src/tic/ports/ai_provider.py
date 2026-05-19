# src/tic/ports/ai_provider.py
"""AI provider port — abstract interface for narrative generation."""
from __future__ import annotations

from typing import Protocol

from tic.domain.finding import AINarrative, Finding


class AIProvider(Protocol):
    """Port for AI narrative generation. Implementations: openai_compat."""

    async def narrate(self, finding: Finding) -> AINarrative | None:
        """Generate a narrative for a finding. Returns None on failure."""
        ...
