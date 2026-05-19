# tests/unit/test_redaction_patterns.py
from __future__ import annotations

import pytest

from tic.security.redaction_patterns import detect_pii_patterns


@pytest.mark.parametrize(
    "text,expected_hit",
    [
        ("reach me at john.doe@example.com please", "email"),
        ("server at 10.0.0.5 is down", "private_ipv4"),
        ("172.16.1.1 in scope", "private_ipv4"),
        ("192.168.1.100 logged", "private_ipv4"),
        ("call +90 212 555 33 44 urgent", "phone"),
        ("tckn 12345678901 confirmed", "tckn"),
        ("SSN 123-45-6789", "ssn"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "bearer_token"),
        ("api_key=sk-live-AbCdEfGh12345", "credential_assignment"),
        ('password: "hunter2hunter2"', "credential_assignment"),
    ],
)
def test_detects_known_patterns(text: str, expected_hit: str) -> None:
    hits = detect_pii_patterns(text)
    assert expected_hit in hits


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no sensitive content here",
        "public ip 8.8.8.8 is fine",
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "plain domain example.com",
    ],
)
def test_clean_text_produces_no_hits(text: str) -> None:
    assert detect_pii_patterns(text) == []


def test_multiple_hits_are_reported() -> None:
    text = "email me at a@b.com from 10.0.0.1"
    hits = detect_pii_patterns(text)
    assert "email" in hits
    assert "private_ipv4" in hits


def test_loopback_is_not_flagged() -> None:
    # Deliberate design: 127.0.0.0/8 is not flagged to keep FP rate low in
    # generic config/docs contexts.
    assert detect_pii_patterns("bind to 127.0.0.1 only") == []
