# src/tic/infra/exit_codes.py
"""Standardized CLI exit codes.

Stable contract: downstream CI pipelines depend on these values.
Do not reorder. Additions must get new numbers only.
"""
from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """CLI exit codes. 0=success; non-zero=various failure modes."""

    SUCCESS = 0
    FINDINGS_ABOVE_THRESHOLD = 1
    CONFIG_ERROR = 2
    NETWORK_ERROR = 3
    AUTH_ERROR = 4
    INPUT_ERROR = 5
    SECURITY_VIOLATION = 6  # path traversal, SSRF, etc.
    PARTIAL_FAILURE = 7
    INTERNAL_ERROR = 10