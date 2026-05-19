# src/tic/adapters/ai_providers/gemini.py
"""Gemini-native generateContent adapter.

The OpenAI compatibility surface at
`generativelanguage.googleapis.com/v1beta/openai/chat/completions` was
observed to return content that was not strict JSON (the parser failed
with `Unterminated string`), even with `response_format=json_object`.
The native `generateContent` endpoint accepts a `generationConfig` that
hard-binds the response MIME type to `application/json` plus a response
schema — this is the reliable way to get a strict JSON narrative from
Gemini.

Security invariants preserved (identical to `openai_compat`):

- Endpoint must be present in `cfg.endpoint_allowlist` (validated at
  construct time; non-https rejected at config load).
- Traffic goes through `SafeHttpClient` → SSRF guard + TLS verification.
- API key is carried in the `x-goog-api-key` header. **Never** in the
  URL/query string (query keys leak into proxy access logs).
- Explicit `asyncio.timeout(cfg.request_timeout_seconds)` wraps the
  whole round-trip; the shorter of this and `SafeHttpClient.total_timeout`
  wins.
- Any failure (timeout / non-2xx / malformed body / schema violation)
  returns `None`. The Narrator translates this into `ai_narrative=null`
  and the sweep keeps running. AI failure is never a sweep failure.

Privacy invariants preserved:

- The redacted payload comes from `build_messages(RedactedFinding, ...)`.
  No raw IOC ever reaches this code.
- We log only metadata: event name, HTTP status code (when relevant),
  exception *type*, request timeout. Never the prompt, completion, raw
  response body, API key, or Authorization-equivalent header.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

from tic.adapters.http.safe_client import SafeHttpClient
from tic.application.ai.prompt_builder import build_messages
from tic.application.ai.response_validator import parse_and_classify
from tic.application.redaction import RedactedFinding
from tic.domain.finding import AINarrative
from tic.infra.config import AIConfig
from tic.infra.logging import get_logger
from tic.ports.ai_provider import AIProvider

_log = get_logger(__name__)


# Audit hook: receives (finding_id, reason) and appends a metadata-only
# `ai_response_retried` event. The reason is a closed-set string from
# `parse_and_classify` (`invalid_json` | `schema`) so no model output
# ever flows into the audit chain through this path.
RetryAuditCallback = Callable[[str, str], None]


# A short, hard-line system suffix appended only on retry. It does not
# replace the immutable base system prompt — it adds a final sentence
# emphasizing strict JSON. This is the same defensive-narration role,
# just stricter about output shape.
_RETRY_SUFFIX = (
    "\nRETRY: your previous response was not valid JSON. "
    "Respond ONLY with one JSON object matching the schema. "
    "No markdown. No code fences. No prose outside the JSON. "
    "All four required keys MUST be present. "
    "`suggested_actions` may be an empty array. "
    "`summary` must be one short sentence."
)


# Strict JSON schema mirroring `AINarrative`'s author-facing fields. The
# additional backend fields (`model`, `generated_at`, `ai_origin`) are
# injected by `parse_and_validate` after we hand it the model's text, so
# they are intentionally absent here.
#
# Gemini's `responseSchema` rejects keys it does not understand and
# enforces the listed required keys at the model level. This is a belt
# AND suspenders alongside `parse_and_validate`'s pydantic check.
_RESPONSE_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "false_positive_likelihood": {
            "type": "STRING",
            "enum": ["low", "medium", "high"],
        },
        "suggested_actions": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
        },
        "confidence": {
            "type": "STRING",
            "enum": ["low", "medium", "high"],
        },
    },
    "required": [
        "summary",
        "false_positive_likelihood",
        "suggested_actions",
        "confidence",
    ],
}


def _messages_to_gemini_contents(
    messages: list[dict[str, str]],
) -> tuple[dict | None, list[dict]]:
    """Translate OpenAI-style chat messages into Gemini's split format.

    Gemini distinguishes a single `systemInstruction` from a list of
    `contents` (one per turn, role-tagged `user` or `model`). We keep the
    immutable system prompt where it belongs and route the
    `<untrusted>`-wrapped user content into the contents list. This
    preserves the prompt-injection boundary built by `prompt_builder`:
    untrusted IOC data only ever appears under `role: user`, never
    inside `systemInstruction`.
    """
    system_instruction: dict | None = None
    contents: list[dict] = []
    for m in messages:
        role = m.get("role")
        text = m.get("content", "")
        if role == "system":
            system_instruction = {"parts": [{"text": text}]}
        elif role == "user":
            contents.append({"role": "user", "parts": [{"text": text}]})
        elif role == "assistant":
            contents.append({"role": "model", "parts": [{"text": text}]})
        # Unknown roles are silently dropped — we never construct any
        # role beyond {system, user, assistant} in prompt_builder, so
        # this branch is unreachable in practice.
    return system_instruction, contents


class GeminiProvider(AIProvider):
    """Gemini-native generateContent adapter with strict JSON responses.

    Retry policy:

    Gemini's `responseMimeType=application/json` is usually honoured but
    occasionally still emits a truncated string ("Unterminated string
    starting at ..."). The adapter retries ONCE — and only — when the
    response_validator classifies the reason as `invalid_json` or
    `schema`. The retry uses a stricter, shorter system prompt and a
    smaller `maxOutputTokens` to lower the odds of mid-token truncation.

    The retry is NEVER triggered by:
      - timeout, non-2xx, transport failure → already fail-safe to None
      - missing-key or allowlist rejection → constructor / wiring caught
      - unsafe / offensive output (defensive filter removed actions but
        the rest validated) → that's success-with-fewer-actions, not a
        retry condition

    Audit: when the retry path is taken, the optional `audit_retry`
    callback is invoked with `(finding_id, reason)` where `reason` is
    the closed-set string from `parse_and_classify`. No model output is
    ever passed through the callback.
    """

    name = "gemini"

    def __init__(
        self,
        http: SafeHttpClient,
        cfg: AIConfig,
        api_key: bytes,
        endpoint: str,
        *,
        audit_retry: RetryAuditCallback | None = None,
    ) -> None:
        if endpoint not in cfg.endpoint_allowlist:
            raise ValueError("AI endpoint not in allowlist")
        self._http = http
        self._cfg = cfg
        self._api_key = api_key
        self._endpoint = endpoint
        self._audit_retry = audit_retry

    # ------------------------------------------------------------------
    # Request body assembly
    # ------------------------------------------------------------------

    def _build_body(self, finding: RedactedFinding, *, retry: bool) -> dict | None:
        """Build the generateContent body. On retry, the system prompt
        gets a stricter suffix and `maxOutputTokens` is halved (floor 64)
        so the model is less likely to truncate mid-string.

        Returns None if the encoded body exceeds the input-size cap; the
        caller treats None as fail-safe.
        """
        system_instruction, contents = _messages_to_gemini_contents(
            build_messages(
                finding,
                language=self._cfg.language,
                narration_level=self._cfg.narration_level,
            )
        )

        if retry and system_instruction is not None:
            sys_text = system_instruction["parts"][0]["text"] + _RETRY_SUFFIX
            system_instruction = {"parts": [{"text": sys_text}]}

        max_tokens = int(self._cfg.max_output_tokens)
        if retry:
            # Halve, with a sane floor. A tighter cap encourages the
            # model to emit a complete JSON object rather than
            # truncate mid-string at the original limit.
            max_tokens = max(64, max_tokens // 2)

        body: dict = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
                "responseSchema": _RESPONSE_SCHEMA,
            },
        }
        if system_instruction is not None:
            body["systemInstruction"] = system_instruction

        data = json.dumps(body).encode("utf-8")
        if len(data) > self._cfg.max_input_chars * 4:
            _log.warning("ai_input_too_large", size=len(data))
            return None
        return body

    # ------------------------------------------------------------------
    # Single round-trip
    # ------------------------------------------------------------------

    async def _post_once(self, body: dict) -> tuple[AINarrative | None, str | None]:
        """POST the request once. Returns `(narrative, retry_reason)`:

        - `(AINarrative, None)`   → success
        - `(None, "invalid_json")` or `(None, "schema")` → safe to retry
        - `(None, None)`          → hard failure (timeout / non-2xx /
                                     transport / oversize body) — DO NOT
                                     retry; caller surfaces None upstream
        """
        data = json.dumps(body).encode("utf-8")

        headers = {
            "x-goog-api-key": self._api_key.decode("utf-8"),
            "Content-Type": "application/json",
        }

        timeout_s = float(self._cfg.request_timeout_seconds)
        try:
            async with asyncio.timeout(timeout_s):
                resp = await self._http.post(self._endpoint, headers=headers, content=data)
        except TimeoutError:
            _log.warning("ai_request_timeout", timeout_seconds=timeout_s)
            return None, None
        except Exception as e:  # noqa: BLE001 — never propagate provider faults
            _log.warning("ai_request_failed", error=type(e).__name__)
            return None, None

        if resp.status_code >= 400:
            _log.warning("ai_request_non_2xx", status=resp.status_code)
            return None, None

        try:
            obj = json.loads(resp.body_bytes)
            # generateContent shape:
            #   { candidates: [ { content: { parts: [ { text: "..." } ] } } ] }
            text = obj["candidates"][0]["content"]["parts"][0]["text"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            # Outer envelope is malformed. We treat this as `invalid_json`
            # so a transient provider hiccup can be retried — but we
            # never log the body.
            _log.warning("ai_response_malformed", error=str(e)[:120])
            return None, "invalid_json"

        narrative, reason = parse_and_classify(text, model=self._cfg.model)
        return narrative, reason

    # ------------------------------------------------------------------
    # Public entry point (with one-shot retry)
    # ------------------------------------------------------------------

    async def narrate(self, finding: RedactedFinding) -> AINarrative | None:
        body = self._build_body(finding, retry=False)
        if body is None:
            return None

        narrative, reason = await self._post_once(body)
        if narrative is not None:
            return narrative

        # Retry only for parse-level reasons. `reason is None` means
        # hard failure (timeout / non-2xx / transport / oversize body)
        # — we do not retry those because the failure mode is not in
        # the model's text.
        if reason not in ("invalid_json", "schema"):
            return None

        # Audit the retry. Metadata only — closed-set reason, redacted
        # finding_id. No prompt, no completion, no API key.
        if self._audit_retry is not None:
            try:
                self._audit_retry(finding.finding_id, reason)
            except Exception as e:  # noqa: BLE001 — audit failure must not block retry
                _log.warning("ai_audit_retry_failed", error=type(e).__name__)

        retry_body = self._build_body(finding, retry=True)
        if retry_body is None:
            return None

        retry_narrative, _ = await self._post_once(retry_body)
        return retry_narrative
