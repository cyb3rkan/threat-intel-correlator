# src/tic/adapters/ai_providers/openai_compat.py
"""OpenAI-compatible chat completions adapter.

Phase B hardening:
- Explicit per-AI-request timeout via `asyncio.timeout(cfg.request_timeout_seconds)`.
  This is in ADDITION to the SafeHttpClient's `total_timeout_seconds`; the
  shorter of the two wins. A timeout returns None (fail-safe) — the sweep
  continues, the Narrator audits `ai_response_rejected` with reason
  `timeout`, and the caller sees a Finding with `ai_narrative=None`.
- SSRF guard and endpoint allowlist behaviour are unchanged.
"""
from __future__ import annotations

import asyncio
import json

from tic.adapters.http.safe_client import SafeHttpClient
from tic.application.ai.prompt_builder import build_messages
from tic.application.ai.response_validator import parse_and_validate
from tic.application.redaction import RedactedFinding
from tic.domain.finding import AINarrative
from tic.infra.config import AIConfig
from tic.infra.logging import get_logger
from tic.ports.ai_provider import AIProvider

_log = get_logger(__name__)


class OpenAICompatProvider(AIProvider):
    name = "openai-compat"

    def __init__(self, http: SafeHttpClient, cfg: AIConfig, api_key: bytes, endpoint: str) -> None:
        if endpoint not in cfg.endpoint_allowlist:
            raise ValueError("AI endpoint not in allowlist")
        self._http = http
        self._cfg = cfg
        self._api_key = api_key
        self._endpoint = endpoint

    async def narrate(self, finding: RedactedFinding) -> AINarrative | None:
        body = {
            "model": self._cfg.model,
            "messages": build_messages(
                finding,
                language=self._cfg.language,
                narration_level=self._cfg.narration_level,
            ),
            "max_tokens": self._cfg.max_output_tokens,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(body).encode("utf-8")
        if len(data) > self._cfg.max_input_chars * 4:
            _log.warning("ai_input_too_large", size=len(data))
            return None

        headers = {
            "Authorization": f"Bearer {self._api_key.decode('utf-8')}",
            "Content-Type": "application/json",
        }

        # Phase B: explicit per-request timeout wraps the entire round-trip,
        # including read/write and any internal retries the SafeHttpClient
        # may run. SafeHttpClient.total_timeout remains in effect; whichever
        # deadline fires first short-circuits the request.
        timeout_s = float(self._cfg.request_timeout_seconds)
        try:
            async with asyncio.timeout(timeout_s):
                resp = await self._http.post(self._endpoint, headers=headers, content=data)
        except asyncio.TimeoutError:
            _log.warning("ai_request_timeout", timeout_seconds=timeout_s)
            return None
        except Exception as e:  # noqa: BLE001
            _log.warning("ai_request_failed", error=type(e).__name__)
            return None

        if resp.status_code >= 400:
            _log.warning("ai_request_non_2xx", status=resp.status_code)
            return None

        try:
            obj = json.loads(resp.body_bytes)
            text = obj["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            _log.warning("ai_response_malformed", error=str(e)[:120])
            return None

        return parse_and_validate(text, model=self._cfg.model)
