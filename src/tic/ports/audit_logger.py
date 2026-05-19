from __future__ import annotations

from typing import Any, Protocol


class AuditLogger(Protocol):
    def append(self, event_type: str, payload: dict[str, Any]) -> None: ...
    def verify_chain(self) -> bool: ...
