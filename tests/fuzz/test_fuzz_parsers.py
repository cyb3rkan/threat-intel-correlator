# tests/fuzz/test_fuzz_parsers.py
"""Fuzz tests for CSV and NDJSON parser surface using Hypothesis.

Goals:
  1. Parser must never raise an unhandled exception on arbitrary input.
  2. CSV parser must handle: empty files, missing header, non-UTF8, huge rows,
     ReDoS-susceptible patterns, embedded newlines, null bytes, BOM markers.
  3. NDJSON parser must handle: invalid JSON, deeply nested objects, very long
     lines, truncated JSON, Unicode edge cases, bare primitives.
  4. Size limits must be respected — no silent over-limit processing.

CWE-20 (Improper Input Validation), CWE-400 (Resource Exhaustion).
"""
from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tic.domain.errors import InputValidationError, ParseError
from tic.infra.config import ParserLimits

_LIMITS = ParserLimits(
    max_file_size_bytes=10 * 1024 * 1024,  # 10 MB for fuzz
    max_iocs_per_feed=10_000,
    max_string_length=512,
)

_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    max_size=512,
)

_csv_row = st.fixed_dictionaries({
    "value": _safe_text,
    "confidence": st.one_of(st.integers(-9999, 9999), _safe_text, st.none()),
})


def _write_temp(content: bytes) -> tuple[Path, Path]:
    """Write content to a temp file; return (path, parent_dir)."""
    tmpdir = Path(tempfile.mkdtemp())
    p = tmpdir / "feed.txt"
    p.write_bytes(content)
    return p, tmpdir


def _csv_bytes_from_rows(rows: list[dict]) -> bytes:
    import csv
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["value", "confidence"])
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if v is None else str(v)) for k, v in row.items()})
    return buf.getvalue().encode("utf-8", errors="replace")


# ── CSV parser fuzz ───────────────────────────────────────────────────────────

@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(rows=st.lists(_csv_row, min_size=0, max_size=200))
def test_csv_parser_never_panics_on_arbitrary_rows(rows: list[dict]) -> None:
    """CSV parser must only raise ParseError/InputValidationError, never crash."""
    from tic.adapters.parsers.csv_parser import parse_csv_feed

    content = _csv_bytes_from_rows(rows)
    path, allowed_root = _write_temp(content)
    try:
        results = list(
            parse_csv_feed(path, allowed_root=allowed_root, limits=_LIMITS)
        )
        # All yielded values must be valid IOCs.
        for ioc in results:
            assert 1 <= len(ioc.value) <= 2048
    except (ParseError, InputValidationError):
        pass  # Expected.
    except Exception as exc:
        pytest.fail(f"Unexpected exception from CSV parser: {type(exc).__name__}: {exc}")
    finally:
        import shutil
        shutil.rmtree(allowed_root, ignore_errors=True)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(raw_bytes=st.binary(max_size=4096))
def test_csv_parser_handles_arbitrary_bytes(raw_bytes: bytes) -> None:
    """CSV parser must not crash on non-UTF8 / binary input."""
    from tic.adapters.parsers.csv_parser import parse_csv_feed

    path, allowed_root = _write_temp(raw_bytes)
    try:
        list(parse_csv_feed(path, allowed_root=allowed_root, limits=_LIMITS))
    except (ParseError, InputValidationError, UnicodeDecodeError):
        pass
    except Exception as exc:
        pytest.fail(f"Unexpected exception: {type(exc).__name__}: {exc}")
    finally:
        import shutil
        shutil.rmtree(allowed_root, ignore_errors=True)


# ── NDJSON parser fuzz ────────────────────────────────────────────────────────

def _make_ndjson(records: list[Any]) -> bytes:
    lines = []
    for r in records:
        try:
            lines.append(json.dumps(r, ensure_ascii=False))
        except (TypeError, ValueError):
            lines.append("{}")  # Fall back to empty object.
    return "\n".join(lines).encode("utf-8", errors="replace")


_json_value = st.recursive(
    st.one_of(
        st.none(), st.booleans(), st.integers(-2**31, 2**31),
        st.floats(allow_nan=False, allow_infinity=False),
        _safe_text,
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(_safe_text, children, max_size=8),
    ),
    max_leaves=20,
)

_ndjson_record = st.one_of(
    st.dictionaries(_safe_text, _json_value, max_size=10),
    _json_value,
    _safe_text,
)


@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(records=st.lists(_ndjson_record, min_size=0, max_size=100))
def test_ndjson_parser_never_panics(records: list[Any]) -> None:
    """NDJSON parser must only raise ParseError/InputValidationError."""
    from tic.adapters.parsers.ndjson_parser import NdjsonFeedParser

    content = _make_ndjson(records)
    path, allowed_root = _write_temp(content)
    try:
        parser = NdjsonFeedParser()
        results = list(
            parser.parse(path, allowed_root=allowed_root, limits=_LIMITS)
        )
        for ioc in results:
            assert 1 <= len(ioc.value) <= 2048
    except (ParseError, InputValidationError):
        pass
    except Exception as exc:
        pytest.fail(f"Unexpected exception from NDJSON parser: {type(exc).__name__}: {exc}")
    finally:
        import shutil
        shutil.rmtree(allowed_root, ignore_errors=True)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(raw_bytes=st.binary(max_size=4096))
def test_ndjson_parser_handles_arbitrary_bytes(raw_bytes: bytes) -> None:
    """NDJSON parser must not crash on binary/non-UTF8 content."""
    from tic.adapters.parsers.ndjson_parser import NdjsonFeedParser

    path, allowed_root = _write_temp(raw_bytes)
    try:
        parser = NdjsonFeedParser()
        list(parser.parse(path, allowed_root=allowed_root, limits=_LIMITS))
    except (ParseError, InputValidationError, UnicodeDecodeError):
        pass
    except Exception as exc:
        pytest.fail(f"Unexpected exception: {type(exc).__name__}: {exc}")
    finally:
        import shutil
        shutil.rmtree(allowed_root, ignore_errors=True)


# ── Edge cases (parametrized) ─────────────────────────────────────────────────

@pytest.mark.parametrize("content", [
    b"",                                          # Empty file
    b"\n\n\n",                                   # Only newlines
    b"\x00\x01\x02",                             # Null bytes
    b"\xef\xbb\xbf" + b"value\n1.2.3.4\n",      # BOM + valid CSV
    b"value\n" + b"A" * 100_000,                 # Single huge row (>max_string_length)
    b"value\n" + b"\n".join(b"1.2.3.4" for _ in range(50_000)),  # Many rows
    b"not,valid,csv\xff\xfe",                    # Mixed encoding
    b'{"unclosed": "json',                       # Truncated JSON
    b"\n".join(b"{}" for _ in range(10_000)),   # 10k empty objects
], ids=[
    "empty", "only_newlines", "null_bytes", "bom_csv", "huge_row",
    "many_rows", "mixed_encoding", "truncated_json", "many_empty_objects",
])
def test_parsers_handle_edge_cases(content: bytes) -> None:
    """Parametrized edge cases both parsers must handle without crashing."""
    from tic.adapters.parsers.csv_parser import parse_csv_feed
    from tic.adapters.parsers.ndjson_parser import NdjsonFeedParser

    for run_csv in (True, False):
        path, allowed_root = _write_temp(content)
        try:
            if run_csv:
                list(parse_csv_feed(path, allowed_root=allowed_root, limits=_LIMITS))
            else:
                list(NdjsonFeedParser().parse(path, allowed_root=allowed_root, limits=_LIMITS))
        except (ParseError, InputValidationError, UnicodeDecodeError):
            pass
        except Exception as exc:
            parser_name = "CSV" if run_csv else "NDJSON"
            pytest.fail(f"{parser_name} raised {type(exc).__name__}: {exc}")
        finally:
            import shutil
            shutil.rmtree(allowed_root, ignore_errors=True)
