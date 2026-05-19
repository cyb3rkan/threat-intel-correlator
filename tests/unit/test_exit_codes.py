# tests/unit/test_exit_codes.py
from __future__ import annotations

from tic.infra.exit_codes import ExitCode


def test_success_is_zero() -> None:
    assert ExitCode.SUCCESS == 0


def test_all_nonzero_are_nonzero() -> None:
    for code in ExitCode:
        if code is not ExitCode.SUCCESS:
            assert int(code) != 0, f"{code.name} should be non-zero"


def test_values_are_stable() -> None:
    assert ExitCode.SUCCESS == 0
    assert ExitCode.FINDINGS_ABOVE_THRESHOLD == 1
    assert ExitCode.CONFIG_ERROR == 2
    assert ExitCode.NETWORK_ERROR == 3
    assert ExitCode.AUTH_ERROR == 4
    assert ExitCode.INPUT_ERROR == 5
    assert ExitCode.SECURITY_VIOLATION == 6
    assert ExitCode.PARTIAL_FAILURE == 7
    assert ExitCode.INTERNAL_ERROR == 10


def test_is_int_enum() -> None:
    assert isinstance(ExitCode.SUCCESS, int)
    assert ExitCode.CONFIG_ERROR > ExitCode.SUCCESS