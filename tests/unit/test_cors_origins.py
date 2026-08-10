# tests/unit/test_cors_origins.py
"""``TIC_API_CORS_ORIGINS`` parsing for the hosted-frontend deployment.

The API is served from a different origin than a hosted UI (Vercel, Netlify,
a reverse proxy), and CORSMiddleware reflects only exact matches. These tests
pin the contract that lets an operator add those origins without ever letting
a malformed value widen the policy:

  * the loopback defaults survive every configuration,
  * only well-formed absolute http(s) origins are added,
  * ``*`` is never honoured,
  * malformed entries are dropped, not fatal, and never become a wildcard.
"""

from __future__ import annotations

import pytest

from tic.api.main import _DEFAULT_ALLOWED_ORIGINS, _resolve_allowed_origins


@pytest.fixture(autouse=True)
def _clear_cors_env(monkeypatch):
    monkeypatch.delenv("TIC_API_CORS_ORIGINS", raising=False)


def test_unset_returns_loopback_defaults():
    assert _resolve_allowed_origins() == _DEFAULT_ALLOWED_ORIGINS


def test_blank_value_returns_loopback_defaults(monkeypatch):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", "   ")
    assert _resolve_allowed_origins() == _DEFAULT_ALLOWED_ORIGINS


def test_adds_configured_origin_and_keeps_defaults(monkeypatch):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", "https://tic.example.com")
    resolved = _resolve_allowed_origins()
    assert "https://tic.example.com" in resolved
    for default in _DEFAULT_ALLOWED_ORIGINS:
        assert default in resolved


def test_accepts_comma_separated_list(monkeypatch):
    monkeypatch.setenv(
        "TIC_API_CORS_ORIGINS",
        "https://tic.example.com, https://tic-preview.vercel.app",
    )
    resolved = _resolve_allowed_origins()
    assert "https://tic.example.com" in resolved
    assert "https://tic-preview.vercel.app" in resolved


def test_normalizes_trailing_slash_and_case(monkeypatch):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", "https://TIC.Example.COM/")
    assert "https://tic.example.com" in _resolve_allowed_origins()


def test_preserves_explicit_port(monkeypatch):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", "https://tic.example.com:8443")
    assert "https://tic.example.com:8443" in _resolve_allowed_origins()


def test_does_not_duplicate_a_default(monkeypatch):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", "http://localhost:3000")
    resolved = _resolve_allowed_origins()
    assert resolved.count("http://localhost:3000") == 1


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "https://*.vercel.app",
        "tic.example.com",  # no scheme
        "ftp://tic.example.com",  # unsupported scheme
        "https://tic.example.com/api",  # path component
        "not a url",
        "https://",  # no host
    ],
)
def test_rejects_malformed_or_wildcard_entries(monkeypatch, value):
    monkeypatch.setenv("TIC_API_CORS_ORIGINS", value)
    assert _resolve_allowed_origins() == _DEFAULT_ALLOWED_ORIGINS


def test_keeps_valid_entries_when_one_is_malformed(monkeypatch):
    monkeypatch.setenv(
        "TIC_API_CORS_ORIGINS", "https://good.example.com,*,https://also-good.example.com"
    )
    resolved = _resolve_allowed_origins()
    assert "https://good.example.com" in resolved
    assert "https://also-good.example.com" in resolved
    assert "*" not in resolved
