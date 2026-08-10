# tests/unit/test_upload_dir_config.py
"""Upload staging root (paths.upload_dir) behaviour.

Uploads used to stage under working_dir unconditionally, which in Kubernetes is
the PersistentVolume -- a pod killed between staging and cleanup stranded
uploaded feeds and logs (IPs, hostnames, usernames) on durable storage.
paths.upload_dir moves staging to a separate root.

The staging root is also the containment root the path guard enforces, so it
had to move together with the files. These tests pin both halves: uploads land
in the right place, AND the guard is no weaker for having been relocated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tic.domain.errors import SecurityViolationError
from tic.infra.config import PathsConfig
from tic.security.path_guard import safe_resolve_within
from tic.ui import adapter


def _paths(working: Path, upload: Path | None = None) -> PathsConfig:
    return PathsConfig(
        working_dir=working,
        cache_dir=working,
        audit_log_path=working / "audit.log",
        upload_dir=upload,
    )


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_defaults_to_working_dir(tmp_path: Path) -> None:
    """Unset upload_dir must preserve the historical local behaviour."""
    assert _paths(tmp_path).effective_upload_dir == tmp_path


def test_explicit_upload_dir_is_used(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    assert _paths(tmp_path, uploads).effective_upload_dir == uploads


def test_relative_upload_dir_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        _paths(tmp_path, Path("relative/uploads"))


# --------------------------------------------------------------------------
# Staging location
# --------------------------------------------------------------------------


def test_uploads_stage_outside_working_dir(tmp_path: Path) -> None:
    working = tmp_path / "data"
    uploads = tmp_path / "uploads"
    working.mkdir()
    uploads.mkdir()
    root = _paths(working, uploads).effective_upload_dir

    upload_dir = adapter.make_upload_dir(root)
    target = adapter.stage_upload(
        b"value\n1.2.3.4\n",
        upload_dir=upload_dir,
        upload_root=root,
        original_filename="feed.csv",
    )

    assert uploads in target.parents
    assert working not in target.parents


# --------------------------------------------------------------------------
# The guard must not have been weakened by relocating its root
# --------------------------------------------------------------------------


def test_traversal_outside_upload_root_still_rejected(tmp_path: Path) -> None:
    working = tmp_path / "data"
    uploads = tmp_path / "uploads"
    working.mkdir()
    uploads.mkdir()

    # working_dir is now *outside* the upload root and must be refused just
    # like any other foreign directory.
    with pytest.raises(SecurityViolationError):
        adapter.stage_upload(
            b"x", upload_dir=working, upload_root=uploads, original_filename="a.csv"
        )


def test_path_outside_both_roots_is_rejected(tmp_path: Path) -> None:
    """resolve_input_root picks a root; it must never invent a third one."""
    working = tmp_path / "data"
    uploads = tmp_path / "uploads"
    foreign = tmp_path / "elsewhere"
    for d in (working, uploads, foreign):
        d.mkdir()

    stray = foreign / "evil.csv"
    root = adapter.resolve_input_root(stray, working_root=working, upload_root=uploads)
    with pytest.raises(SecurityViolationError):
        safe_resolve_within(stray, allowed_root=root)


# --------------------------------------------------------------------------
# Root selection for sweep inputs
# --------------------------------------------------------------------------


def test_staged_upload_resolves_to_upload_root(tmp_path: Path) -> None:
    working = tmp_path / "data"
    uploads = tmp_path / "uploads"
    working.mkdir()
    uploads.mkdir()

    upload_dir = adapter.make_upload_dir(uploads)
    staged = adapter.stage_upload(
        b"x", upload_dir=upload_dir, upload_root=uploads, original_filename="f.csv"
    )
    assert adapter.resolve_input_root(staged, working_root=working, upload_root=uploads) == uploads


def test_operator_supplied_path_resolves_to_working_root(tmp_path: Path) -> None:
    working = tmp_path / "data"
    uploads = tmp_path / "uploads"
    working.mkdir()
    uploads.mkdir()

    operator_file = working / "feed.csv"
    operator_file.write_bytes(b"x")
    assert (
        adapter.resolve_input_root(operator_file, working_root=working, upload_root=uploads)
        == working
    )


def test_collapsed_roots_behave_as_before(tmp_path: Path) -> None:
    """With upload_dir unset both roots are one, and nothing changes."""
    root = _paths(tmp_path).effective_upload_dir
    operator_file = tmp_path / "feed.csv"
    operator_file.write_bytes(b"x")
    resolved = adapter.resolve_input_root(
        operator_file, working_root=tmp_path, upload_root=root
    )
    assert resolved == tmp_path
