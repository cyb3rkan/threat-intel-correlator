# src/tic/security/archive_guard.py
"""Safe archive (zip) extraction with decompression ratio + size caps."""

from __future__ import annotations

import zipfile
from pathlib import Path

from tic.domain.errors import SecurityViolationError
from tic.security.path_guard import safe_resolve_within


def safe_extract_zip(
    archive_path: Path,
    *,
    dest_dir: Path,
    max_total_uncompressed_bytes: int,
    max_ratio: int,
    max_entries: int = 100_000,
) -> list[Path]:
    """Extract a zip file safely. Returns list of extracted file paths.

    Raises SecurityViolationError on:
    - entries totaling more than max_total_uncompressed_bytes,
    - compression ratio per-entry exceeding max_ratio,
    - more than max_entries entries,
    - any entry whose resolved path escapes dest_dir (zip-slip).
    """
    extracted: list[Path] = []
    total_uncompressed = 0
    dest_dir = dest_dir.resolve(strict=False)
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise SecurityViolationError(
                f"archive has {len(infos)} entries (>{max_entries})",
                user_message="Archive has too many entries.",
            )
        for info in infos:
            if info.is_dir():
                continue
            if info.file_size <= 0:
                continue
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > max_ratio:
                    raise SecurityViolationError(
                        f"compression ratio {ratio:.0f} exceeds {max_ratio} for {info.filename}",
                        user_message="Archive compression ratio suspicious.",
                    )
            total_uncompressed += info.file_size
            if total_uncompressed > max_total_uncompressed_bytes:
                raise SecurityViolationError(
                    f"total uncompressed size {total_uncompressed} exceeds cap",
                    user_message="Archive uncompressed size exceeds limit.",
                )

            target = safe_resolve_within(
                info.filename, allowed_root=dest_dir, follow_symlinks=False
            )
            target.parent.mkdir(parents=True, exist_ok=True)

            with zf.open(info, "r") as src, open(target, "wb") as dst:
                # Stream copy with per-chunk size check (defense in depth).
                remaining = info.file_size
                chunk_size = 64 * 1024
                while remaining > 0:
                    buf = src.read(min(chunk_size, remaining))
                    if not buf:
                        break
                    dst.write(buf)
                    remaining -= len(buf)
            extracted.append(target)

    return extracted
