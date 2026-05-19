# tests/unit/test_logging.py
from __future__ import annotations

from tic.infra.logging import (
    _redact_recursive,
    configure_logging,
    get_correlation_id,
    new_correlation_id,
)


def test_new_correlation_id_is_uuid() -> None:
    cid = new_correlation_id()
    assert len(cid) == 36
    assert cid.count("-") == 4


def test_get_correlation_id_returns_set_value() -> None:
    cid = new_correlation_id()
    assert get_correlation_id() == cid


def test_redact_api_key() -> None:
    d = {"api_key": "supersecret", "data": "ok"}
    _redact_recursive(d, depth=0, max_depth=4)
    assert d["api_key"] == "***REDACTED***"
    assert d["data"] == "ok"


def test_redact_token() -> None:
    d = {"Authorization": "Bearer abc123"}
    _redact_recursive(d, depth=0, max_depth=4)
    assert d["Authorization"] == "***REDACTED***"


def test_redact_nested() -> None:
    d = {"outer": {"api_key": "secret", "safe": "value"}}
    _redact_recursive(d, depth=0, max_depth=4)
    assert d["outer"]["api_key"] == "***REDACTED***"
    assert d["outer"]["safe"] == "value"


def test_redact_in_list() -> None:
    d = {"items": [{"token": "abc"}, {"normal": "data"}]}
    _redact_recursive(d, depth=0, max_depth=4)
    assert d["items"][0]["token"] == "***REDACTED***"
    assert d["items"][1]["normal"] == "data"


def test_redact_max_depth_not_exceeded() -> None:
    # depth 1 — max_depth=1 olunca nested dict dokunulmamalı
    d = {"outer": {"api_key": "secret"}}
    _redact_recursive(d, depth=0, max_depth=1)
    assert d["outer"]["api_key"] == "secret"  # max_depth'e ulaşıldı, dokunulmadı


def test_configure_logging_console() -> None:
    # Hata fırlatmadan çalışmalı
    configure_logging(level="DEBUG", fmt="console")


def test_configure_logging_json() -> None:
    configure_logging(level="INFO", fmt="json")
