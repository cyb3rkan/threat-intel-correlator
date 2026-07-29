# src/tic/adapters/parsers/json_depth.py
"""Bounded-depth pre-scan for JSON inputs.

The stdlib ``json`` module recurses while decoding nested arrays and objects,
so a small but deeply-nested payload can exhaust the interpreter recursion
limit and raise an uncaught ``RecursionError`` -- a bounded denial of service.
``parser_limits.max_json_depth`` is the configured ceiling; this module
enforces it *before* ``json.loads`` runs, with a single linear, non-recursive
scan of the raw text.

The scanner is string-aware: brackets inside JSON string literals, and
backslash-escaped quotes within those literals, are ignored. A value such as
``{"note": "]]]]"}`` is therefore measured as depth 1, not flagged as a false
positive. Both array (``[``) and object (``{``) openers increase the depth.
"""

from __future__ import annotations

from tic.domain.errors import ParseError

_OPEN = frozenset("[{")
_CLOSE = frozenset("]}")


def json_max_depth(text: str) -> int:
    """Return the maximum bracket-nesting depth in ``text``.

    Linear, non-recursive scan. Brackets inside string literals are ignored.
    This does not validate JSON syntax; it only measures structural nesting so
    a depth bound can be enforced before the text reaches ``json.loads``.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in _OPEN:
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in _CLOSE:
            depth = max(depth - 1, 0)
    return max_depth


def check_json_depth(text: str, max_depth: int) -> None:
    """Raise ``ParseError`` if ``text`` nests deeper than ``max_depth``.

    ``max_depth`` is ``parser_limits.max_json_depth``. This is a fail-closed
    guard: it runs before ``json.loads`` so a depth bomb never reaches the
    recursive decoder.
    """
    found = json_max_depth(text)
    if found > max_depth:
        raise ParseError(
            f"json nesting depth {found} exceeds limit {max_depth}",
            user_message="Input JSON nesting is too deep.",
        )
