# tests/unit/test_demo_origins.py
"""``TIC_DEMO_ORIGINS`` parsing for the hosted demo's CORS policy.

`demo_origins` is the only way the public demo backend learns to trust the
hosted frontend, so its failure modes matter:

  * it stays empty unless demo mode is on, so a stray env var on a local run
    cannot widen CORS,
  * it accepts only scheme+host origins, and
  * it drops wildcards instead of registering them verbatim -- CORSMiddleware
    matches literally, so a passed-through "https://*.vercel.app" would match
    nothing while its author believed previews were allowed.

`DEMO_MODE` is read at import time, so these monkeypatch the module attribute
rather than the environment variable.
"""

from __future__ import annotations

import pytest

from tic.api import _demo

# Every test below one exercises demo mode ON with no origins preconfigured;
# test_empty_when_demo_mode_off overrides DEMO_MODE back to False itself.
pytestmark = pytest.mark.usefixtures("_demo_on")


@pytest.fixture()
def _demo_on(monkeypatch):
    monkeypatch.setattr(_demo, "DEMO_MODE", True)
    monkeypatch.delenv("TIC_DEMO_ORIGINS", raising=False)


def test_empty_when_demo_mode_off(monkeypatch):
    monkeypatch.setattr(_demo, "DEMO_MODE", False)
    monkeypatch.setenv("TIC_DEMO_ORIGINS", "https://tic.example.com")
    assert _demo.demo_origins() == []


def test_empty_when_unset():
    assert _demo.demo_origins() == []


def test_accepts_single_origin(monkeypatch):
    monkeypatch.setenv("TIC_DEMO_ORIGINS", "https://tic.example.com")
    assert _demo.demo_origins() == ["https://tic.example.com"]


def test_accepts_comma_separated_list(monkeypatch):
    monkeypatch.setenv(
        "TIC_DEMO_ORIGINS", "https://tic.example.com, https://preview.example.com"
    )
    assert _demo.demo_origins() == [
        "https://tic.example.com",
        "https://preview.example.com",
    ]


def test_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("TIC_DEMO_ORIGINS", "https://tic.example.com/")
    assert _demo.demo_origins() == ["https://tic.example.com"]


def test_preserves_explicit_port(monkeypatch):
    monkeypatch.setenv("TIC_DEMO_ORIGINS", "https://tic.example.com:8443")
    assert _demo.demo_origins() == ["https://tic.example.com:8443"]


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "https://*",
        "https://*.vercel.app",  # regression: urlsplit accepts "*" as a host
        "https://foo.*.example.com",
        "https://tic.example.com/api",  # path
        "https://tic.example.com?x=1",  # query
        "https://tic.example.com#frag",  # fragment
        "tic.example.com",  # no scheme
        "ftp://tic.example.com",  # unsupported scheme
        "https://",  # no host
        "not a url",
    ],
)
def test_rejects_malformed_or_wildcard(monkeypatch, value):
    monkeypatch.setenv("TIC_DEMO_ORIGINS", value)
    assert _demo.demo_origins() == []


def test_keeps_valid_entries_alongside_a_rejected_one(monkeypatch):
    monkeypatch.setenv(
        "TIC_DEMO_ORIGINS",
        "https://good.example.com,https://*.vercel.app,https://also-good.example.com",
    )
    assert _demo.demo_origins() == [
        "https://good.example.com",
        "https://also-good.example.com",
    ]
