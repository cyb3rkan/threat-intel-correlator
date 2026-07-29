# tests/unit/test_audit_hmac_signing.py
"""Finding #1: chained-HMAC audit signing (opt-in, fail-closed, tamper-evident)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.cli import _wiring
from tic.cli.commands import config_cmd
from tic.domain.errors import ConfigError
from tic.infra.config import AuditConfig, PathsConfig, Settings

KEY = b"super-secret-audit-key-0123456789"
OTHER = b"a-different-key-aaaaaaaaaaaaaaaaaa"


def _signed_log(path: Path, n: int, key: bytes = KEY) -> HashChainAuditLogger:
    log = HashChainAuditLogger(path, signing_key=key)
    for i in range(n):
        log.append("evt", {"i": i})
    return log


def _verify(path: Path, key: bytes | None) -> bool:
    return HashChainAuditLogger(path, signing_key=key).verify_chain()


def test_signed_chain_verifies_with_key(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 5)
    assert _verify(p, KEY) is True


def test_signed_records_carry_hmac_field(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 2)
    for line in p.read_text().splitlines():
        assert "hmac" in json.loads(line)


def test_wrong_key_fails(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 4)
    assert _verify(p, OTHER) is False


def test_no_key_on_signed_log_fails_closed(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 4)
    # A signed record cannot be authenticated without the key -> fail closed.
    assert _verify(p, None) is False


def test_tamper_signed_payload_fails(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 4)
    lines = p.read_text().splitlines()
    lines[2] = lines[2].replace('"i":2', '"i":222')
    p.write_text("\n".join(lines) + "\n")
    assert _verify(p, KEY) is False


def test_strip_hmac_midchain_is_downgrade_failure(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 4)
    lines = p.read_text().splitlines()
    obj = json.loads(lines[1])
    obj.pop("hmac", None)
    lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    assert _verify(p, KEY) is False


def test_reorder_signed_records_fails(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 4)
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert _verify(p, KEY) is False


def test_legacy_prefix_then_signed_verifies(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    HashChainAuditLogger(p, signing_key=None).append("evt", {"i": 0})  # legacy
    HashChainAuditLogger(p, signing_key=None).append("evt", {"i": 1})  # legacy
    HashChainAuditLogger(p, signing_key=KEY).append("evt", {"i": 2})  # signed
    HashChainAuditLogger(p, signing_key=KEY).append("evt", {"i": 3})  # signed
    assert _verify(p, KEY) is True


def test_unsigned_record_after_signing_fails(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    _signed_log(p, 3)
    HashChainAuditLogger(p, signing_key=None).append("evt", {"i": 99})  # unsigned tail
    assert _verify(p, KEY) is False


def test_truncation_of_trailing_records_is_documented_residual(tmp_path: Path) -> None:
    # Truncating trailing signed records leaves an internally-valid prefix.
    # This is the documented residual (no out-of-band head anchor).
    p = tmp_path / "a.log"
    _signed_log(p, 6)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:3]) + "\n")
    assert _verify(p, KEY) is True


def test_plain_chain_still_works_without_key(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    log = HashChainAuditLogger(p)  # no signing_key
    for i in range(3):
        log.append("evt", {"i": i})
    assert log.verify_chain() is True
    # no hmac field on unsigned records
    assert all("hmac" not in json.loads(line) for line in p.read_text().splitlines())


# ---- wiring helpers --------------------------------------------------------


class _FakeStore:
    def __init__(self, mapping: dict[tuple[str, str], bytes]) -> None:
        self._m = mapping

    def get(self, service: str, user: str) -> bytes:
        try:
            return self._m[(service, user)]
        except KeyError as e:
            raise RuntimeError("missing") from e


def _settings(tmp_path: Path, *, sign: bool) -> Settings:
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        audit=AuditConfig(sign=sign),
    )  # type: ignore[call-arg]


def test_load_signing_key_disabled_returns_none(tmp_path: Path) -> None:
    s = _settings(tmp_path, sign=False)
    assert _wiring.load_audit_signing_key(s, _FakeStore({})) is None


def test_load_signing_key_enabled_missing_fails_closed(tmp_path: Path) -> None:
    s = _settings(tmp_path, sign=True)
    with pytest.raises(ConfigError):
        _wiring.load_audit_signing_key(s, _FakeStore({}))


def test_load_signing_key_enabled_present_returns_key(tmp_path: Path) -> None:
    s = _settings(tmp_path, sign=True)
    store = _FakeStore({("tic-audit-hmac", "default"): KEY})
    assert _wiring.load_audit_signing_key(s, store) == KEY


def test_try_load_audit_hmac_best_effort(tmp_path: Path) -> None:
    s = _settings(tmp_path, sign=False)
    # absent -> None (no raise), even though sign is False
    assert _wiring.try_load_audit_hmac(s, _FakeStore({})) is None
    store = _FakeStore({("tic-audit-hmac", "default"): KEY})
    assert _wiring.try_load_audit_hmac(s, store) == KEY


def test_set_key_resolves_audit_hmac_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = _settings(tmp_path, sign=False)
    monkeypatch.setattr(config_cmd, "load_settings", lambda: s)
    assert config_cmd._resolve_target("audit-hmac") == ("tic-audit-hmac", "default")
