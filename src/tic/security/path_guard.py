# src/tic/security/path_guard.py
"""Canonical path resolution with enforced root containment.

Security: all file operations in the project MUST go through safe_resolve_within.
CI lint rule enforces usage.
"""

from __future__ import annotations

import os
from pathlib import Path

from tic.domain.errors import SecurityViolationError


def safe_resolve_within(
    candidate: str | Path,
    *,
    allowed_root: Path,
    follow_symlinks: bool = False,
) -> Path:
    """Resolve `candidate` and ensure it is contained within `allowed_root`.

    Raises SecurityViolationError on traversal or disallowed symlink escape.
    - `allowed_root` must be an absolute, already-resolved path.
    - `follow_symlinks=False` (default) uses lstat semantics; any symlink in
      the path chain whose target escapes the root is rejected.

    This function performs defense-in-depth:
    1. Rejects NUL bytes (defuses C-level path tricks).
    2. Resolves fully (strict=False to allow 'not yet created' files).
    3. Re-checks containment via commonpath.
    4. Optionally walks the chain to detect symlink escapes.
    """
    if not allowed_root.is_absolute():
        raise SecurityViolationError(
            f"allowed_root must be absolute: {allowed_root}",
            user_message="Internal path-guard misconfiguration.",
        )

    cand_str = os.fspath(candidate)
    if "\x00" in cand_str:
        raise SecurityViolationError("NUL byte in path", user_message="Invalid path.")

    # Resolve relative to allowed_root if not absolute
    raw = Path(cand_str)
    if not raw.is_absolute():
        raw = allowed_root / raw

    try:
        resolved = raw.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise SecurityViolationError(
            f"path resolve failed: {e}", user_message="Invalid path."
        ) from e

    try:
        resolved.relative_to(allowed_root.resolve(strict=False))
    except ValueError as e:
        raise SecurityViolationError(
            f"path {resolved} escapes root {allowed_root}",
            user_message="Path outside allowed directory.",
        ) from e

    if not follow_symlinks:
        # Walk existing parts and reject if any is a symlink pointing outside root.
        root_res = allowed_root.resolve(strict=False)
        current = resolved
        while current != root_res and current != current.parent:
            if current.is_symlink():
                target = current.resolve(strict=False)
                try:
                    target.relative_to(root_res)
                except ValueError as e:
                    raise SecurityViolationError(
                        f"symlink {current} -> {target} escapes root",
                        user_message="Disallowed symlink traversal.",
                    ) from e
            if not current.exists():
                break
            current = current.parent

    return resolved
