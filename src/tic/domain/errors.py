# src/tic/domain/errors.py
"""Domain exceptions. user_message is safe to show; internal_details is debug-only."""
from __future__ import annotations


class TICError(Exception):
    """Base class. Never raise this directly; use a subclass."""

    user_message: str = "An internal error occurred."
    exit_code: int = 10

    def __init__(self, internal_details: str = "", *, user_message: str | None = None) -> None:
        super().__init__(internal_details)
        self.internal_details = internal_details
        if user_message is not None:
            self.user_message = user_message


class ConfigError(TICError):
    exit_code = 2


class InputValidationError(TICError):
    exit_code = 5
    user_message = "Input validation failed."


class SecurityViolationError(TICError):
    exit_code = 6
    user_message = "Security policy violation detected."


class NetworkError(TICError):
    exit_code = 3
    user_message = "Network error contacting external provider."


class AuthError(TICError):
    exit_code = 4
    user_message = "Authentication failure with external provider."


class ProviderError(TICError):
    exit_code = 7
    user_message = "One or more providers returned invalid data."


class ParseError(InputValidationError):
    user_message = "Failed to parse input file."