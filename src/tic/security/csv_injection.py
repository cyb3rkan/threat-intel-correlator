# src/tic/security/csv_injection.py
"""CSV formula injection mitigation (OWASP-recommended prefix approach)."""

from __future__ import annotations

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def escape_csv_cell(value: str) -> str:
    """Prefix a leading single-quote if the cell starts with a formula trigger.

    This neutralizes Excel/LibreOffice formula execution on import. The leading
    quote is non-destructive text and commonly understood by analysts.
    """
    if value and value[0] in _FORMULA_PREFIXES:
        return "'" + value
    return value
