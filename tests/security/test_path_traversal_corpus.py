# tests/security/test_path_traversal_corpus.py
"""Path traversal corpus tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from tic.domain.errors import SecurityViolationError
from tic.security.path_guard import safe_resolve_within


@pytest.fixture()
def root(tmp_path):
    return tmp_path


@pytest.mark.parametrize(
    "candidate",
    [
        "../../etc/passwd",
        "../../../etc/shadow",
        "subdir/../../etc/passwd",
        "./../../etc/hosts",
    ],
)
def test_relative_traversal_rejected(candidate, root):
    with pytest.raises(SecurityViolationError):
        safe_resolve_within(candidate, allowed_root=root)


@pytest.mark.parametrize("candidate", ["/etc/passwd", "/root/.bashrc", "/proc/self/environ"])
def test_absolute_outside_root_rejected(candidate, root):
    with pytest.raises(SecurityViolationError):
        safe_resolve_within(candidate, allowed_root=root)


@pytest.mark.parametrize("candidate", ["file\x00.txt", "\x00etc/passwd"])
def test_nul_byte_rejected(candidate, root):
    with pytest.raises(SecurityViolationError):
        safe_resolve_within(candidate, allowed_root=root)


@pytest.mark.parametrize("candidate", ["feed.csv", "subdir/feed.ndjson", "a/b/c/file.json"])
def test_valid_paths_within_root_succeed(candidate, root):
    result = safe_resolve_within(candidate, allowed_root=root)
    assert str(result).startswith(str(root.resolve()))


def test_relative_root_raises(tmp_path):
    with pytest.raises(SecurityViolationError):
        safe_resolve_within("file.txt", allowed_root=Path("relative/path"))
