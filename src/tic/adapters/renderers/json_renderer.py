# src/tic/adapters/renderers/json_renderer.py
"""JSON renderer — uses PublicFinding DTO. Never emits truncated_raw or log details."""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import TextIO

from tic.domain.finding import Finding, OutputMode


def render_json(
    findings: Iterable[Finding],
    out: TextIO,
    *,
    mode: OutputMode = OutputMode.ANALYST,
    hmac_key: bytes | None = None,
) -> int:
    finding_list = list(findings)
    payload = {
        "version": 2,
        "findings": [f.to_public(mode=mode, hmac_key=hmac_key).model_dump(mode="json")
                     for f in finding_list],
    }
    out.write(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    out.write("\n")
    return len(finding_list)
