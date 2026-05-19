# tests/unit/test_path_guard.py
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tic.domain.errors import SecurityViolationError
from tic.security.path_guard import safe_resolve_within


def test_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(SecurityViolationError):
        safe_resolve_within("../../etc/passwd", allowed_root=tmp_path)


def test_rejects_nul_byte(tmp_path: Path) -> None:
    with pytest.raises(SecurityViolationError):
        safe_resolve_within("file\x00.txt", allowed_root=tmp_path)


def test_allows_within(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child.mkdir()
    result = safe_resolve_within("child/file.txt", allowed_root=tmp_path)
    assert str(result).startswith(str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation requires admin on Windows")
def test_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_target"
    outside.mkdir(exist_ok=True)
    try:
        link = tmp_path / "link"
        link.symlink_to(outside)
        with pytest.raises(SecurityViolationError):
            safe_resolve_within("link/file", allowed_root=tmp_path)
    finally:
        if outside.exists():
            outside.rmdir()