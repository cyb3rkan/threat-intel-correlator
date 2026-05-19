# tests/unit/test_archive_guard.py
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tic.domain.errors import SecurityViolationError
from tic.security.archive_guard import safe_extract_zip


def _make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_extracts_valid_zip(tmp_path: Path) -> None:
    archive = _make_zip(tmp_path / "a.zip", {"file.txt": b"hello world"})
    dest = tmp_path / "out"
    extracted = safe_extract_zip(
        archive,
        dest_dir=dest,
        max_total_uncompressed_bytes=1024 * 1024,
        max_ratio=100,
    )
    assert len(extracted) == 1
    assert extracted[0].read_bytes() == b"hello world"


def test_rejects_zip_slip(tmp_path: Path) -> None:
    archive = tmp_path / "slip.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../evil.txt", b"pwned")
    dest = tmp_path / "out"
    with pytest.raises(SecurityViolationError):
        safe_extract_zip(
            archive,
            dest_dir=dest,
            max_total_uncompressed_bytes=1024 * 1024,
            max_ratio=100,
        )


def test_rejects_too_many_entries(tmp_path: Path) -> None:
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(10):
            zf.writestr(f"file{i}.txt", b"x")
    dest = tmp_path / "out"
    with pytest.raises(SecurityViolationError):
        safe_extract_zip(
            archive,
            dest_dir=dest,
            max_total_uncompressed_bytes=1024 * 1024,
            max_ratio=100,
            max_entries=5,
        )


def test_rejects_total_size_exceeded(tmp_path: Path) -> None:
    archive = _make_zip(tmp_path / "big.zip", {"file.txt": b"a" * 2000})
    dest = tmp_path / "out"
    with pytest.raises(SecurityViolationError):
        safe_extract_zip(
            archive,
            dest_dir=dest,
            max_total_uncompressed_bytes=100,
            max_ratio=100,
        )


def test_skips_directory_entries(tmp_path: Path) -> None:
    archive = tmp_path / "dirs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.mkdir("subdir")
        zf.writestr("subdir/file.txt", b"data")
    dest = tmp_path / "out"
    extracted = safe_extract_zip(
        archive,
        dest_dir=dest,
        max_total_uncompressed_bytes=1024 * 1024,
        max_ratio=100,
    )
    assert all(p.is_file() for p in extracted)