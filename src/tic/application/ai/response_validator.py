"""Strict JSON schema validation for AI narrative output.

Phase B hardening:
- Drop any `suggested_actions` entries that look like direct command
  invocations (curl, wget, powershell, cmd.exe, bash, sh, nc, netcat,
  msfconsole, sqlmap, nmap when used offensively) or contain reverse-shell
  / exploit / payload execution wording.
- Drop entries that contain raw URLs intended as operational fetch
  instructions (http://, https://, ftp://). Defensive references such as
  "review in SIEM", "verify with EDR", "check firewall logs" remain.
- Reject the whole response when the schema validation fails (extra keys,
  invalid enum, oversize strings, non-JSON, non-object, code-fence garbage)
  — the caller (Narrator) treats None as "no narrative attached" and the
  sweep continues. This is the existing fail-safe contract.
- Validation NEVER changes score, severity, exit_code, or any other
  deterministic Finding field — it only filters the AI-attached narrative.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ValidationError

from tic.domain.finding import AINarrative
from tic.infra.logging import get_logger

# Closed set of rejection reasons surfaced by `parse_and_classify`. The
# Gemini adapter uses these to decide whether a retry is safe: only
# `invalid_json` and `schema` are retried (the model produced something
# we couldn't parse). `filtered` means the defensive filter removed
# *something* from suggested_actions but the rest of the narrative is
# still valid — no retry needed.
ParseRejection = Literal[
    "invalid_json",  # raw text was not valid JSON (or not an object)
    "schema",  # JSON was valid but pydantic AINarrative rejected it
]

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Defensive action filter
# ---------------------------------------------------------------------------
#
# Anything matched here is dropped from `suggested_actions` before pydantic
# validation. We drop rather than fail-the-whole-response so a single bad
# action does not cost the analyst the rest of the (still useful) narrative.
#
# Match is case-insensitive and on a whole-word boundary where it matters
# (e.g. "sh" must not match "ssh-keygen"; "nc" must not match "incident").
# Anchored regexes keep false-positive rate low against defensive phrasing.

_COMMAND_TOOL_TOKENS: tuple[str, ...] = (
    "curl",
    "wget",
    "powershell",
    "pwsh",
    "cmd.exe",
    "bash",
    "msfconsole",
    "metasploit",
    "sqlmap",
    "mimikatz",
    "cobalt strike",
    "empire",
    "beacon",
)

# These tokens are dangerous when they appear as a *standalone* word (not as
# a substring of an unrelated word).
#
# Phase C: `nmap` is intentionally NOT here. A bare mention of a network
# inventory tool — e.g. "verify with approved network inventory or scanner
# according to policy" or "compare with the asset DB before scanning" — is
# legitimate defensive advice and should pass. We only block nmap when it
# is paired with an actionable invocation pattern (see `_NMAP_OFFENSIVE_RE`
# below); offensive nmap usage covered by `_OFFENSIVE_PHRASES`
# ("run nmap", "execute nmap") still drops.
_COMMAND_STANDALONE_TOKENS: tuple[str, ...] = (
    r"\bsh\b",  # /bin/sh-style invocation
    r"\bnc\b",  # netcat
    r"\bnetcat\b",
    r"\bncat\b",
)

# Phrases that indicate offensive intent regardless of the tool name. These
# trigger a drop even when no specific tool name is present.
_OFFENSIVE_PHRASES: tuple[str, ...] = (
    "reverse shell",
    "reverse-shell",
    "bind shell",
    "payload execution",
    "execute payload",
    "drop a payload",
    "deliver payload",
    "exploit chain",
    "run the exploit",
    "exploit the",
    "weaponize",
    "weaponise",
    "persistence mechanism",
    "evasion technique",
    "lateral movement steps",
    "privilege escalation steps",
    "credential dump",
    "dump credentials",
    "exfiltrate via",
    "establish c2",
    "c2 channel via",
)

# Compiled patterns. We keep both the token list and the precompiled regex so
# tests can introspect either form.
_COMMAND_TOOL_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(t) for t in _COMMAND_TOOL_TOKENS) + r")\b"
)
_COMMAND_STANDALONE_RE = re.compile("(?i)(" + "|".join(_COMMAND_STANDALONE_TOKENS) + ")")
_OFFENSIVE_PHRASE_RE = re.compile(
    "(?i)(" + "|".join(re.escape(p) for p in _OFFENSIVE_PHRASES) + ")"
)
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s]+")

# Phase C: nmap is allowed in defensive phrasing ("verify with approved
# network inventory or scanner") but blocked when used as an actionable
# invocation. Patterns:
#   - "nmap -X ..."   any CLI flag form
#   - "run nmap ..."  imperative invocation
#   - "execute nmap"  imperative invocation
#   - "nmap <ip/cidr>" host-or-net target
# The regex matches the imperatives anywhere AND the flag form anywhere,
# so a mixed sentence like "Document the IOC; do not run nmap" still
# drops the action.
_NMAP_OFFENSIVE_RE = re.compile(
    r"(?ix)"
    r"\b(?:"
    r"run\s+nmap"
    r"|execute\s+nmap"
    r"|launch\s+nmap"
    r"|nmap\s+-[a-z0-9]"  # any flag, e.g. -A, -sV, -Pn
    r"|nmap\s+\d{1,3}(?:\.\d{1,3}){3}"  # nmap <ipv4>
    r"|nmap\s+[\w.-]+/\d{1,3}\b"  # nmap <cidr>
    r")"
)


def _action_is_unsafe(action: str) -> bool:
    """Return True if the suggested action looks like an attack instruction.

    Heuristic, conservative:
      - tool-name token present → unsafe
      - standalone command token present → unsafe
      - offensive phrase present → unsafe
      - any URL present → unsafe (treated as operational fetch instruction)

    Defensive phrasing like "review in SIEM", "verify with EDR",
    "check firewall logs", "escalate to incident response" does not contain
    any of these markers and passes through unchanged.
    """
    if not isinstance(action, str):
        return True
    if _COMMAND_TOOL_RE.search(action):
        return True
    if _COMMAND_STANDALONE_RE.search(action):
        return True
    if _OFFENSIVE_PHRASE_RE.search(action):
        return True
    if _NMAP_OFFENSIVE_RE.search(action):
        return True
    if _URL_RE.search(action):
        return True
    return False


def _filter_suggested_actions(obj: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Return a copy of `obj` with unsafe `suggested_actions` dropped, plus
    the number of actions removed."""
    actions = obj.get("suggested_actions")
    if not isinstance(actions, list):
        return obj, 0
    safe: list[Any] = []
    dropped = 0
    for entry in actions:
        if not isinstance(entry, str):
            dropped += 1
            continue
        if _action_is_unsafe(entry):
            dropped += 1
            continue
        safe.append(entry)
    if dropped == 0:
        return obj, 0
    new: dict[str, Any] = dict(obj)
    new["suggested_actions"] = safe
    return new, dropped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_and_classify(raw: str, *, model: str) -> tuple[AINarrative | None, ParseRejection | None]:
    """Like `parse_and_validate`, but also returns *why* it rejected.

    Reasons are limited to the closed `ParseRejection` set — never the
    raw exception message and never the raw response body. The caller
    (Gemini adapter) uses the reason to decide if a retry is safe; the
    Narrator's audit chain receives only the closed-set string.

    On success returns `(AINarrative, None)`. On failure returns
    `(None, reason)`.
    """
    raw = raw.strip()
    if raw.startswith("```"):
        # Some models wrap JSON in code fences; strip them defensively.
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        _log.warning("ai_response_not_json", error=str(e)[:120])
        return None, "invalid_json"

    if not isinstance(parsed, dict):
        _log.warning("ai_response_not_object")
        return None, "invalid_json"

    obj: dict[str, Any] = parsed
    obj, dropped = _filter_suggested_actions(obj)
    if dropped:
        # Metadata-only log; we never log the rejected text itself because
        # it may contain attacker-controlled content.
        _log.warning("ai_response_actions_filtered", dropped=dropped)

    obj["model"] = model
    obj["generated_at"] = datetime.now(UTC).isoformat()
    obj["ai_origin"] = True  # hardcoded

    try:
        return AINarrative.model_validate(obj), None
    except ValidationError as e:
        _log.warning("ai_response_schema_violation", error=str(e)[:200])
        return None, "schema"


def parse_and_validate(raw: str, *, model: str) -> AINarrative | None:
    """Backward-compatible wrapper: returns AINarrative or None.

    Existing callers (OpenAI-compat adapter, tests) keep working
    unchanged. The Gemini adapter calls `parse_and_classify` instead so
    it can route on the rejection reason.
    """
    out, _ = parse_and_classify(raw, model=model)
    return out