# tests/unit/test_gemini_provider.py
"""Unit tests for the Gemini-native generateContent AI provider adapter.

Scope:
- Constructor safety (endpoint allowlist gate, identical to OpenAI-compat).
- AIConfig.provider default and validation.
- build_narrator selects Gemini when ai.provider="gemini".
- narrate() success path against a fake SafeHttpClient that mimics the
  generateContent response shape.
- narrate() fail-safe paths: malformed body, non-2xx, timeout, transport.
- No prompt / completion / API-key bytes ever appear in stderr/log capture.
- Endpoint allowlist remains the only gate to call out.

No real HTTP, no real keys. The fake HTTP client records request headers
and asserts the API key is never put in the URL.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tic.adapters.ai_providers.gemini import GeminiProvider
from tic.application.redaction import Redactor
from tic.cli import _wiring
from tic.domain.finding import Finding, Severity
from tic.domain.ioc import IOC, IOCType
from tic.infra.config import AIConfig, HttpClientConfig, PathsConfig, Settings

_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/" "gemini-2.5-flash:generateContent"
)
_RAW_IOC = "very-secret-ioc-value.example"
_API_KEY = b"placeholder-not-a-real-key-12345"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ai_cfg(allowlist: list[str], **overrides) -> AIConfig:
    base = dict(
        enabled=True,
        provider="gemini",
        endpoint_allowlist=allowlist,
        model="gemini-2.5-flash",
        max_output_tokens=128,
        max_input_chars=2048,
        request_timeout_seconds=10.0,
    )
    base.update(overrides)
    return AIConfig(**base)  # type: ignore[arg-type]


def _redacted_finding():
    f = Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value=_RAW_IOC, ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=50,
        severity=Severity.MEDIUM,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    return Redactor(b"0" * 32).redact(f)


class _FakeHttpResponse:
    def __init__(self, status_code: int, body: dict | bytes) -> None:
        self.status_code = status_code
        if isinstance(body, bytes):
            self.body_bytes = body
        else:
            self.body_bytes = json.dumps(body).encode("utf-8")
        self.headers: dict[str, str] = {}


class _RecordingHttp:
    """Captures the last request — used to assert headers/url shape."""

    def __init__(self, response: _FakeHttpResponse) -> None:
        self._response = response
        self.last_url: str | None = None
        self.last_headers: dict[str, str] | None = None
        self.last_body: bytes | None = None

    async def post(self, url, *, headers=None, content=None):
        self.last_url = url
        self.last_headers = dict(headers or {})
        self.last_body = content
        return self._response


# ---------------------------------------------------------------------------
# AIConfig.provider
# ---------------------------------------------------------------------------


def test_ai_config_provider_defaults_to_openai_compat() -> None:
    """Backward-compatible default. Existing deployments do not move."""
    cfg = AIConfig()
    assert cfg.provider == "openai_compat"


def test_ai_config_provider_accepts_gemini() -> None:
    cfg = AIConfig(provider="gemini")
    assert cfg.provider == "gemini"


def test_ai_config_provider_rejects_unknown_value() -> None:
    with pytest.raises(ValidationError):
        AIConfig(provider="bedrock")  # not in the closed Literal


# ---------------------------------------------------------------------------
# build_narrator selects the right adapter
# ---------------------------------------------------------------------------


class _Store:
    def __init__(self, mapping):
        self._m = mapping

    def get(self, service, user):
        return self._m[(service, user)]


def _settings_with_ai(tmp_path, ai_cfg: AIConfig) -> Settings:
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        ),
        http=HttpClientConfig(),
        ai=ai_cfg,
    )  # type: ignore[call-arg]


def test_build_narrator_selects_gemini_when_configured(tmp_path) -> None:
    s = _settings_with_ai(
        tmp_path,
        _ai_cfg([_ENDPOINT], provider="gemini"),
    )
    store = _Store(
        {
            ("tic-ai", "default"): _API_KEY,
            ("tic-redaction-hmac", "default"): b"0" * 32,
        }
    )
    narrator = _wiring.build_narrator(s, secret_store=store)
    assert narrator is not None
    # The narrator's wrapped AI provider is the Gemini adapter.
    assert narrator._ai.__class__.__name__ == "GeminiProvider"


def test_build_narrator_defaults_to_openai_compat(tmp_path) -> None:
    """The default `provider` stays "openai_compat" so prior YAML keeps
    working without any change."""
    cfg = AIConfig(
        enabled=True,
        endpoint_allowlist=["https://allowed.test/v1/chat/completions"],
        model="placeholder",
    )
    s = _settings_with_ai(tmp_path, cfg)
    store = _Store(
        {
            ("tic-ai", "default"): _API_KEY,
            ("tic-redaction-hmac", "default"): b"0" * 32,
        }
    )
    narrator = _wiring.build_narrator(s, secret_store=store)
    assert narrator is not None
    assert narrator._ai.__class__.__name__ == "OpenAICompatProvider"


# ---------------------------------------------------------------------------
# Constructor safety — endpoint allowlist gate
# ---------------------------------------------------------------------------


def test_endpoint_not_in_allowlist_raises() -> None:
    cfg = _ai_cfg([_ENDPOINT])
    with pytest.raises(ValueError, match="not in allowlist"):
        GeminiProvider(
            http=_RecordingHttp(_FakeHttpResponse(200, b"")),
            cfg=cfg,
            api_key=_API_KEY,
            endpoint="https://attacker.example/v1beta/models/x:generateContent",
        )


def test_empty_allowlist_rejects_any_endpoint() -> None:
    cfg = _ai_cfg([])
    with pytest.raises(ValueError):
        GeminiProvider(
            http=_RecordingHttp(_FakeHttpResponse(200, b"")),
            cfg=cfg,
            api_key=_API_KEY,
            endpoint=_ENDPOINT,
        )


def test_constructs_when_endpoint_is_in_allowlist() -> None:
    cfg = _ai_cfg([_ENDPOINT])
    p = GeminiProvider(
        http=_RecordingHttp(_FakeHttpResponse(200, b"")),
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
    )
    assert p.name == "gemini"


# ---------------------------------------------------------------------------
# Success path — strict-JSON generateContent response parses cleanly
# ---------------------------------------------------------------------------


_VALID_NARRATIVE_JSON = json.dumps(
    {
        "summary": "Şüpheli alan adı; trafiği SIEM üzerinde gözden geçir.",
        "false_positive_likelihood": "low",
        "suggested_actions": [
            "review in SIEM",
            "verify with EDR",
        ],
        "confidence": "medium",
    }
)


def _gemini_success_body(text: str) -> dict:
    return {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": text}],
                    "role": "model",
                }
            }
        ]
    }


@pytest.mark.asyncio()
async def test_narrate_returns_ai_narrative_on_valid_response() -> None:
    http = _RecordingHttp(_FakeHttpResponse(200, _gemini_success_body(_VALID_NARRATIVE_JSON)))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    out = await provider.narrate(_redacted_finding())
    assert out is not None
    assert out.false_positive_likelihood == "low"
    assert out.confidence == "medium"
    assert out.model == "gemini-2.5-flash"
    assert out.ai_origin is True
    # The defensive action filter let the safe entries pass.
    assert "review in SIEM" in out.suggested_actions
    assert "verify with EDR" in out.suggested_actions


@pytest.mark.asyncio()
async def test_narrate_request_shape_uses_header_key_not_query() -> None:
    """API key must be in `x-goog-api-key` header. Query-string keys leak
    into access logs."""
    http = _RecordingHttp(_FakeHttpResponse(200, _gemini_success_body(_VALID_NARRATIVE_JSON)))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    await provider.narrate(_redacted_finding())

    # URL is the exact allowlisted endpoint; no `?key=` smuggled in.
    assert http.last_url == _ENDPOINT
    assert "?" not in (http.last_url or "")
    assert "key=" not in (http.last_url or "")

    # Key carried in the header.
    assert http.last_headers is not None
    assert "x-goog-api-key" in http.last_headers
    assert http.last_headers["x-goog-api-key"] == _API_KEY.decode("utf-8")
    # No Authorization Bearer (that is the OpenAI-compat path).
    assert "Authorization" not in http.last_headers


@pytest.mark.asyncio()
async def test_narrate_request_body_has_response_schema_and_mime() -> None:
    """The whole point of this adapter — force strict-JSON via the
    generateContent generationConfig."""
    http = _RecordingHttp(_FakeHttpResponse(200, _gemini_success_body(_VALID_NARRATIVE_JSON)))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    await provider.narrate(_redacted_finding())

    assert http.last_body is not None
    payload = json.loads(http.last_body)
    gc = payload["generationConfig"]
    assert gc["responseMimeType"] == "application/json"
    assert gc["responseSchema"]["type"] == "OBJECT"
    assert set(gc["responseSchema"]["required"]) == {
        "summary",
        "false_positive_likelihood",
        "suggested_actions",
        "confidence",
    }
    # The system prompt is split out — untrusted IOC payload lives under
    # contents[role=user], NEVER under systemInstruction. The literal
    # token `<untrusted>` does appear in the system prompt itself
    # because it instructs the model how to treat that wrapper; what
    # must not leak there is the redacted finding's *content* (the
    # finding_id is a good canary — it only appears in the user turn).
    assert "systemInstruction" in payload
    sys_text = payload["systemInstruction"]["parts"][0]["text"]
    finding_id = "00000000-0000-4000-8000-000000000000"
    assert finding_id not in sys_text
    user_text = payload["contents"][0]["parts"][0]["text"]
    assert finding_id in user_text
    assert "<untrusted>" in user_text  # the redacted block IS wrapped
    assert payload["contents"][0]["role"] == "user"


# ---------------------------------------------------------------------------
# Fail-safe paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_narrate_returns_none_on_non_2xx() -> None:
    http = _RecordingHttp(_FakeHttpResponse(503, b"upstream unavailable"))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


@pytest.mark.asyncio()
async def test_narrate_returns_none_on_malformed_outer_envelope() -> None:
    """The generateContent envelope is missing `candidates`; adapter must
    fail-safe to None rather than KeyError up the stack."""
    http = _RecordingHttp(_FakeHttpResponse(200, {"unexpected": "shape"}))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


@pytest.mark.asyncio()
async def test_narrate_returns_none_when_envelope_text_is_not_json() -> None:
    """Envelope shape is right but the model text is broken JSON. The
    existing parse_and_validate rejects it; we return None."""
    body = _gemini_success_body('{"summary": "unterminated string')
    http = _RecordingHttp(_FakeHttpResponse(200, body))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


@pytest.mark.asyncio()
async def test_narrate_returns_none_when_envelope_text_violates_schema() -> None:
    """Valid JSON but missing required AINarrative fields → None."""
    body = _gemini_success_body('{"summary": "ok"}')
    http = _RecordingHttp(_FakeHttpResponse(200, body))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


@pytest.mark.asyncio()
async def test_narrate_returns_none_when_outer_body_not_json() -> None:
    http = _RecordingHttp(_FakeHttpResponse(200, b"not-json-at-all"))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


class _SlowHttp:
    def __init__(self, sleep_seconds: float) -> None:
        self._sleep = sleep_seconds

    async def post(self, *_a, **_kw):
        await asyncio.sleep(self._sleep)
        raise AssertionError("unreachable — adapter must time out first")


@pytest.mark.asyncio()
async def test_narrate_returns_none_on_timeout() -> None:
    cfg = _ai_cfg([_ENDPOINT], request_timeout_seconds=1.0)
    provider = GeminiProvider(
        http=_SlowHttp(sleep_seconds=5.0),
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
    )
    assert await provider.narrate(_redacted_finding()) is None


class _RaisingHttp:
    async def post(self, *_a, **_kw):
        raise RuntimeError("simulated transport failure")


@pytest.mark.asyncio()
async def test_narrate_returns_none_on_transport_failure() -> None:
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=_RaisingHttp(), cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    assert await provider.narrate(_redacted_finding()) is None


# ---------------------------------------------------------------------------
# Privacy — no prompt, no completion, no API key in logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_no_secret_or_prompt_in_logs_on_success(caplog) -> None:
    """Capture all log output across the happy path; assert it carries
    none of: API key bytes, raw IOC, prompt body, completion body, the
    raw response JSON."""
    import logging

    http = _RecordingHttp(_FakeHttpResponse(200, _gemini_success_body(_VALID_NARRATIVE_JSON)))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    with caplog.at_level(logging.DEBUG):
        await provider.narrate(_redacted_finding())

    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _API_KEY.decode("utf-8") not in blob
    assert _RAW_IOC not in blob
    assert "<untrusted>" not in blob
    assert _VALID_NARRATIVE_JSON not in blob
    assert "Bearer " not in blob
    assert "x-goog-api-key" not in blob


@pytest.mark.asyncio()
async def test_no_secret_or_prompt_in_logs_on_failure(caplog) -> None:
    import logging

    http = _RecordingHttp(_FakeHttpResponse(500, b"boom"))
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(http=http, cfg=cfg, api_key=_API_KEY, endpoint=_ENDPOINT)
    with caplog.at_level(logging.DEBUG):
        await provider.narrate(_redacted_finding())

    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _API_KEY.decode("utf-8") not in blob
    assert _RAW_IOC not in blob
    assert "boom" not in blob  # response body must never appear in logs


# ---------------------------------------------------------------------------
# Retry behaviour — one-shot on invalid_json / schema only
# ---------------------------------------------------------------------------


class _ScriptedHttp:
    """A fake SafeHttpClient that returns a queued response per call.

    Each `post()` pops the next response off `responses`. The recorded
    requests stay around so a test can assert how many times the
    adapter actually called out, what URL and body shape it used, and
    whether the retry prompt suffix landed in the second call.
    """

    def __init__(self, responses: list[_FakeHttpResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict, bytes | None]] = []

    async def post(self, url, *, headers=None, content=None):
        self.calls.append((url, dict(headers or {}), content))
        if not self._responses:
            raise AssertionError("adapter called post() more times than scripted")
        return self._responses.pop(0)


@pytest.mark.asyncio()
async def test_retry_succeeds_on_second_attempt_after_invalid_json() -> None:
    """First response: outer envelope ok, inner text is not strict JSON
    (the observed Gemini failure mode). Second response: valid JSON.
    The adapter should retry exactly once and return the AINarrative."""
    bad = _gemini_success_body('{"summary": "unterminated string')
    good = _gemini_success_body(_VALID_NARRATIVE_JSON)
    http = _ScriptedHttp(
        [
            _FakeHttpResponse(200, bad),
            _FakeHttpResponse(200, good),
        ]
    )
    retried: list[tuple[str, str]] = []

    def on_retry(fid: str, reason: str) -> None:
        retried.append((fid, reason))

    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=on_retry,
    )
    out = await provider.narrate(_redacted_finding())

    assert out is not None
    assert out.false_positive_likelihood == "low"
    assert len(http.calls) == 2
    assert retried == [("00000000-0000-4000-8000-000000000000", "invalid_json")]

    # The retry's body must carry the stricter suffix and a halved
    # maxOutputTokens. We assert both signals directly on the second
    # request body.
    second_body = json.loads(http.calls[1][2])
    assert second_body["generationConfig"]["maxOutputTokens"] == max(64, cfg.max_output_tokens // 2)
    sys_text = second_body["systemInstruction"]["parts"][0]["text"]
    assert "RETRY" in sys_text


@pytest.mark.asyncio()
async def test_retry_on_schema_violation_and_then_success() -> None:
    """First response is valid JSON but missing required fields → schema
    reason → retry. Second response is valid → success."""
    bad = _gemini_success_body('{"summary": "ok"}')
    good = _gemini_success_body(_VALID_NARRATIVE_JSON)
    http = _ScriptedHttp(
        [
            _FakeHttpResponse(200, bad),
            _FakeHttpResponse(200, good),
        ]
    )
    retried: list[tuple[str, str]] = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )

    out = await provider.narrate(_redacted_finding())
    assert out is not None
    assert len(http.calls) == 2
    assert retried == [("00000000-0000-4000-8000-000000000000", "schema")]


@pytest.mark.asyncio()
async def test_no_retry_on_non_2xx() -> None:
    """A 503 is a hard failure, not a parse failure — never retry."""
    http = _ScriptedHttp([_FakeHttpResponse(503, b"upstream unavailable")])
    retried: list = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )
    assert await provider.narrate(_redacted_finding()) is None
    assert len(http.calls) == 1
    assert retried == []


@pytest.mark.asyncio()
async def test_no_retry_on_timeout() -> None:
    cfg = _ai_cfg([_ENDPOINT], request_timeout_seconds=1.0)
    retried: list = []
    provider = GeminiProvider(
        http=_SlowHttp(sleep_seconds=5.0),
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )
    assert await provider.narrate(_redacted_finding()) is None
    assert retried == []


@pytest.mark.asyncio()
async def test_no_retry_on_transport_failure() -> None:
    retried: list = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=_RaisingHttp(),
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )
    assert await provider.narrate(_redacted_finding()) is None
    assert retried == []


@pytest.mark.asyncio()
async def test_no_retry_on_unsafe_actions_only() -> None:
    """Defensive-action filter removed entries but the rest of the
    narrative validated. This is success-with-fewer-actions, not a
    parse failure — never retry."""
    payload = {
        "summary": "test",
        "false_positive_likelihood": "low",
        "suggested_actions": [
            "run nmap -A 10.0.0.0/24",  # filtered as unsafe
            "review in SIEM",  # passes through
        ],
        "confidence": "medium",
    }
    body = _gemini_success_body(json.dumps(payload))
    http = _ScriptedHttp([_FakeHttpResponse(200, body)])
    retried: list = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )
    out = await provider.narrate(_redacted_finding())

    assert out is not None
    assert out.suggested_actions == ["review in SIEM"]
    assert len(http.calls) == 1
    assert retried == []


@pytest.mark.asyncio()
async def test_retry_then_second_failure_returns_none() -> None:
    """If retry still produces malformed JSON, fail-safe to None.
    No third attempt — strictly one-shot."""
    bad1 = _gemini_success_body('{"summary": "broken')
    bad2 = _gemini_success_body("still broken")
    http = _ScriptedHttp(
        [
            _FakeHttpResponse(200, bad1),
            _FakeHttpResponse(200, bad2),
        ]
    )
    retried: list = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: retried.append((f, r)),
    )
    assert await provider.narrate(_redacted_finding()) is None
    assert len(http.calls) == 2
    assert len(retried) == 1


@pytest.mark.asyncio()
async def test_retry_audit_callback_is_metadata_only(caplog) -> None:
    """Callback payload is exactly (finding_id, closed-set reason).
    Capture all logs across the retry path and assert no prompt /
    completion / key / IOC leak."""
    import logging

    bad = _gemini_success_body('{"summary": "broken')
    good = _gemini_success_body(_VALID_NARRATIVE_JSON)
    http = _ScriptedHttp(
        [
            _FakeHttpResponse(200, bad),
            _FakeHttpResponse(200, good),
        ]
    )
    captured: list[tuple[str, str]] = []
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=lambda f, r: captured.append((f, r)),
    )
    with caplog.at_level(logging.DEBUG):
        out = await provider.narrate(_redacted_finding())

    assert out is not None
    # Callback contract: tuple shape, closed-set reason.
    assert len(captured) == 1
    fid, reason = captured[0]
    assert fid == "00000000-0000-4000-8000-000000000000"
    assert reason in {"invalid_json", "schema"}

    # No leaks in logs.
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _API_KEY.decode("utf-8") not in blob
    assert _RAW_IOC not in blob
    assert _VALID_NARRATIVE_JSON not in blob
    assert "broken" not in blob


@pytest.mark.asyncio()
async def test_retry_callback_failure_does_not_break_sweep() -> None:
    """Audit-callback exception must be swallowed — the sweep keeps
    going and the retry still fires."""

    def boom(_f: str, _r: str) -> None:
        raise RuntimeError("audit sink offline")

    bad = _gemini_success_body('{"summary": "broken')
    good = _gemini_success_body(_VALID_NARRATIVE_JSON)
    http = _ScriptedHttp(
        [
            _FakeHttpResponse(200, bad),
            _FakeHttpResponse(200, good),
        ]
    )
    cfg = _ai_cfg([_ENDPOINT])
    provider = GeminiProvider(
        http=http,
        cfg=cfg,
        api_key=_API_KEY,
        endpoint=_ENDPOINT,
        audit_retry=boom,
    )
    out = await provider.narrate(_redacted_finding())
    assert out is not None
    assert len(http.calls) == 2  # retry still happened


# ---------------------------------------------------------------------------
# SafeHttpClient idempotent close
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_safe_http_client_double_close_is_silent() -> None:
    """Closing twice must not raise and must not produce a warning the
    second time — the sweep's `close_all` path now relies on this."""
    from tic.adapters.http.safe_client import SafeHttpClient

    client = SafeHttpClient(HttpClientConfig())
    await client.aclose()
    await client.aclose()  # second call is a no-op
    assert client._closed is True  # type: ignore[attr-defined]


@pytest.mark.asyncio()
async def test_safe_http_client_close_swallows_runtime_error(monkeypatch) -> None:
    """If the underlying httpx client raises RuntimeError on close
    (the 'Event loop is closed' pattern when cleanup runs on a fresh
    asyncio.run), the wrapper must swallow it and not propagate."""
    from tic.adapters.http.safe_client import SafeHttpClient

    client = SafeHttpClient(HttpClientConfig())

    async def _raise(*_a, **_kw):
        raise RuntimeError("Event loop is closed")

    monkeypatch.setattr(client._client, "aclose", _raise)
    # Must not raise.
    await client.aclose()
    assert client._closed is True  # type: ignore[attr-defined]
