"""Structured logging setup with mandatory redaction of sensitive keys."""

from __future__ import annotations

import logging
import re
import sys
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from typing import TextIO

import structlog

_CORRELATION_ID: ContextVar[str] = ContextVar("correlation_id", default="")


class _StderrProxy:
    """Write-through proxy that always targets the *current* ``sys.stderr``.

    structlog's ``PrintLoggerFactory`` binds whatever file object it is handed
    at configure time. Binding ``sys.stderr`` directly would freeze that exact
    stream, which breaks when the stream is later swapped (a second sweep in one
    process, or click's ``CliRunner`` which replaces ``sys.stderr`` per
    invocation). Delegating on every write keeps logs flowing to the live
    stderr. Only the methods structlog's PrintLogger touches are proxied.
    """

    def write(self, s: str) -> int:
        return sys.stderr.write(s)

    def flush(self) -> None:
        sys.stderr.flush()

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)^(.*(api[_-]?key|token|secret|password|authorization|cookie|bearer).*)$"
)

_REDACTED = "***REDACTED***"


def _redact_sensitive(
    logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor: redact any key matching the sensitive pattern.

    Security: central, last-line defense against secret leakage in logs.
    Applies recursively to nested dicts up to depth 4.
    """
    _redact_recursive(event_dict, depth=0, max_depth=4)
    return event_dict


def _redact_recursive(obj: Any, depth: int, max_depth: int) -> None:
    if depth >= max_depth:
        return
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if isinstance(k, str) and _SENSITIVE_KEY_PATTERN.match(k):
                obj[k] = _REDACTED
            else:
                _redact_recursive(obj[k], depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            _redact_recursive(item, depth + 1, max_depth)


def _add_correlation_id(
    logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    cid = _CORRELATION_ID.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def new_correlation_id() -> str:
    cid = str(uuid.uuid4())
    _CORRELATION_ID.set(cid)
    return cid


def get_correlation_id() -> str:
    return _CORRELATION_ID.get()


def configure_logging(*, level: str = "INFO", fmt: str = "json") -> None:
    """Configure structlog. Must be called once at startup."""
    logging.basicConfig(
        level=level,
        stream=sys.stderr,  # stdout reserved for data output
        format="%(message)s",
    )

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_correlation_id,
        _redact_sensitive,
    ]

    if fmt == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        # Route through a proxy that resolves sys.stderr lazily on each write, so
        # logging survives stderr being swapped (a second sweep in one process, or
        # click's per-invocation stream capture in CLI tests).
        logger_factory=structlog.PrintLoggerFactory(
            file=cast("TextIO", _StderrProxy())
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
