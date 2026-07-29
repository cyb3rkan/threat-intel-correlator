# tests/unit/test_ioc_normalization.py
from __future__ import annotations

import pytest

from tic.application.normalization import detect_and_normalize, make_ioc
from tic.domain.errors import InputValidationError
from tic.domain.ioc import IOCType


@pytest.mark.parametrize(
    "raw,expected_type,expected_value",
    [
        ("1.2.3.4", IOCType.IP, "1.2.3.4"),
        ("1.1.1[.]1", IOCType.IP, "1.1.1.1"),
        ("hxxps://evil[.]example[.]com/a", IOCType.URL, "https://evil.example.com/a"),
        ("Example.COM", IOCType.DOMAIN, "example.com"),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        ("CVE-2024-0001", IOCType.CVE, "CVE-2024-0001"),
        ("cve-2024-0001", IOCType.CVE, "CVE-2024-0001"),
        ("user@ExAmPlE.com", IOCType.EMAIL, "user@example.com"),
    ],
)
def test_normalization_happy_path(raw: str, expected_type: IOCType, expected_value: str) -> None:
    t, v = detect_and_normalize(raw)
    assert t == expected_type
    assert v == expected_value


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "not-a-valid-anything",
        "http://",  # no host
        "@no-user.com",
        "a" * 9000,  # oversized
    ],
)
def test_normalization_rejects_malformed(raw: str) -> None:
    with pytest.raises(InputValidationError):
        detect_and_normalize(raw)


def test_idn_homograph_to_punycode() -> None:
    # Cyrillic 'а' (U+0430) mixed with latin
    raw = "xn--e1awd7f.com"  # already punycode
    t, v = detect_and_normalize(raw)
    assert t == IOCType.DOMAIN
    assert v == "xn--e1awd7f.com"


def test_make_ioc_clamps_confidence() -> None:
    ioc = make_ioc("1.2.3.4", source="test", confidence=9999)
    assert ioc.confidence == 100
