# Secure Coding Guidelines

Conventions every contributor follows. These are not aspirational — the
existing test corpus enforces most of them.

## Never log

- API keys, keyring values, HMAC keys, session cookies.
- `Authorization` / `x-apikey` / `Bearer` headers — by name or value.
- Raw provider response bodies (size cap protects log volume; redaction
  protects content).
- Full request URLs that may carry tokens in query parameters.
- Tracebacks at WARNING / INFO level when they may include secrets;
  log the exception **class name** plus a sanitised message instead.

The structlog redaction processor in `tic.infra.logging` is the last
line of defence, not the first. Sanitise at the call site.

## Never persist

- `EnrichmentResult.truncated_raw` (debug-only, gated behind
  `TIC_DEBUG_CACHE_RAW=true`).
- Raw log lines (`Match.raw_line_hash` is a 64-char SHA-256 only).
- Uploaded feed/log files past the session — `adapter.cleanup_upload_dir`
  must run in `finally`.

## Never trust

- Feed/log file contents — always run through parsers with `ParserLimits`.
- Provider responses — validate against a strict pydantic schema with
  `extra="ignore"`, bound length, bound list size.
- Redirect Location headers — `SafeHttpClient` re-runs the SSRF guard
  on every hop and drops auth headers on host change.
- File paths derived from upload filenames — `tic.security.path_guard`
  rejects anything outside `working_dir`.

## Always

- Use `SafeHttpClient` for outbound HTTP. Never instantiate `httpx`
  directly outside `tic.adapters.http.*`.
- Use `KeyringSecretStore` for credentials. Never read keys from
  environment variables or YAML.
- Use `Redactor` before any text leaves the trusted core (renderers,
  AI prompts).
- Use `PublicFinding` (not the internal `Finding`) for any payload the
  UI or an exporter sees.
- Catch broad `Exception` only at adapter boundaries; log the type,
  re-raise a typed `TICError` subclass.

## Error handling

- Domain errors live in `tic.domain.errors`. Each has `user_message`
  (safe to render) and `internal_details` (debug only).
- API endpoints translate `TICError → HTTPException(detail=user_message)`.
  Never `detail=str(exc)` on an uncaught `Exception`.
- `--no-verify` git hook bypass is forbidden by policy.

## Tests

- New security features ship with a regression test. The
  `tests/security/` corpus and `tests/integration/test_misp_verify_tls.py`
  are good templates.
- Tests that depend on real keyring state must monkeypatch the secret
  store — otherwise CI is non-deterministic.
- Use `respx` for HTTP mocks; never hit a real provider in unit tests.

## AI narration invariants

AI narration is optional, defensive-only, and strictly advisory. The
following invariants are enforced in code and frozen by regression tests
under `tests/security/` and `tests/integration/`. Treat them as
non-negotiable; if a change would violate any of these, raise it as a
threat-model update first, not a code change.

### What may be sent to AI

- **Only `RedactedFinding`** (see `tic.application.redaction`). Its
  `model_config` is `frozen=True, extra="forbid"`. Adding a field
  requires an explicit allowlist change and a regression test.
- The allowlisted fields are: `finding_id`, `ioc_type`, `ioc_pseudo`,
  `confidence`, `tag_count`, `match_count`, `enrichments[*].provider`,
  `enrichments[*].reputation_score`, `enrichments[*].tag_count`,
  `matches[*].log_source_pseudo`, `matches[*].field_generic`,
  `matches[*].timestamp_iso`, `score`, `severity`.
- IOC values are sent as **HMAC pseudonyms** (`ioc_pseudo`). The
  operator-facing `output_mode` (analyst / summary / hash) does **not**
  affect what reaches the AI input layer — analyst mode is for the UI,
  not for the AI.

### What must never be sent to AI

- Raw IOC values, raw log lines, raw provider response bodies,
  `EnrichmentResult.truncated_raw`, `Match.raw_line_hash`,
  `Match.log_source` (hostname), `Match.field` (raw column name).
- Free-text `IOC.source` strings, free-text `IOC.tags` strings, MISP
  free-text tags, provider free-text categories.
- API keys, keyring values, `Authorization` / `Bearer` / `api_key` /
  `Cookie` / `x-apikey` headers, environment variables, keyring service
  / user names, file paths (`working_dir`, `cache_dir`, audit log path),
  endpoint URLs.
- Tracebacks, exception messages, `internal_details` of TICError.

### What AI must never affect

- `Finding.score`, `Finding.severity`, `Finding.enrichments`,
  `Finding.matches`, `Finding.ioc`, `Finding.profile_hash`.
- `above_threshold` and `exit_code` produced by the orchestrator.
- The deterministic correlation/scoring pipeline. AI runs **after**
  scoring, on an immutable Finding, and only attaches an
  `AINarrative` via `model_copy`.

### How AI must fail

- Disabled (`ai.enabled=false`) → `build_narrator()` returns `None`
  without touching the keyring or opening any HTTP client.
- Missing key, endpoint not in allowlist, timeout, rate limit, malformed
  response, schema violation, hallucinated extra keys → narrator returns
  the original Finding with `ai_narrative=None`. The sweep continues.
- No AI failure path may raise to the caller, mutate the Finding's
  deterministic fields, or change `exit_code`.

### How AI output must be presented

- Markdown / terminal / UI panels render AI output with the
  literal label "AI-generated advisory — review required".
- JSON exports keep `ai_origin: true` on every AI-derived field so
  downstream consumers can branch.
- CSV exports do **not** include AI narrative free-text. CSV stays
  structured; if a future change adds an `ai_present` flag column it
  must be a single boolean, never the summary text or actions.
- Frontend renders AI text via React children only. **No**
  `dangerouslySetInnerHTML`. (Enforced by
  `tests/security/test_frontend_ai_safety.py`.)

### How AI must be logged

- Log events for AI invocation record metadata only: model name (short),
  latency, exception **class** name, output validation status,
  correlation_id. **Never** log the prompt, the completion, the API
  key, the endpoint URL in full, or the redacted payload.
- The structlog `_redact_sensitive` processor is a last-line defence,
  not the first. Sanitise at the call site.

### Phase B: AI audit events (metadata-only)

When a `HashChainAuditLogger` is wired into the Narrator (it is when
the CLI and the API drive a sweep), the following tamper-evident events
are appended. Every payload is metadata-only — no prompt, no completion,
no Authorization header, no API key, no raw IOC value, no raw provider
response.

| Event type                | Payload keys                        |
| ------------------------- | ----------------------------------- |
| `ai_invoke`               | `finding_id`                        |
| `ai_response_rejected`    | `finding_id`, `reason`              |
| `ai_narrative_attached`   | `finding_id`                        |
| `sweep_end` (orchestrator) | now also carries `ai_narratives_generated: int` (count only) |

`reason` is from a closed set: `schema`, `timeout`, `non_2xx`,
`filtered`, `invalid_json`, `provider_error`, `redaction_failed`.

An audit-write failure must never break the sweep. The Narrator
isolates the append call in a `try/except` and falls back to a
structlog warning (`ai_audit_append_failed`).

### Phase B: AI output filtering

The response validator drops `suggested_actions` entries that look
like operational attack instructions (curl, wget, powershell, bash,
sh, nc/netcat, msfconsole, metasploit, sqlmap, mimikatz, reverse-shell
wording, payload-execution wording, or any raw URL). Defensive wording
is preserved: "review in SIEM", "verify with EDR", "check firewall
logs", "escalate to incident response", "open a ticket".

The filter drops individual entries rather than rejecting the whole
narrative, so a single bad suggestion does not cost the analyst the
summary and FP/confidence assessment. A coarse `ai_response_actions_filtered`
log event records the drop count — never the dropped text itself.

### Phase B: explicit per-request AI timeout

`OpenAICompatProvider` wraps each AI HTTP call in
`asyncio.timeout(cfg.request_timeout_seconds)` in addition to the
`SafeHttpClient` total timeout. Whichever fires first short-circuits
the request. A timeout returns `None` from the provider, the Narrator
audits `ai_response_rejected` with `reason: "timeout"`, and the sweep
keeps running.

### Phase C: bounded AI execution + truncation + observability

- **Per-sweep cap.** `AIConfig.max_findings_per_sweep` (default 25,
  bounds [1, 100]) limits how many findings are sent to AI per sweep.
  Selection is deterministic (severity desc → score desc → provider
  count desc → match count desc → finding_id asc). Findings beyond the
  cap appear in the sweep result with `ai_narrative=null`. The cap
  never affects score, severity, exit_code, or above_threshold.
- **Input truncation.** If a redacted finding's JSON exceeds
  `ai.max_input_chars`, the Narrator drops trailing `matches` first,
  then trailing `enrichments`, and emits a metadata-only
  `ai_input_truncated` audit event (`finding_id`, `original_chars`,
  `final_chars`, `dropped_matches_count`, `dropped_enrichments_count`).
  Required fields (`finding_id`, `ioc_type`, `ioc_pseudo`, `severity`,
  `score`, `match_count`, remaining provider names) are never dropped.
  If the required core is still oversized, the Narrator audits
  `ai_response_rejected` with `reason: "input_too_large"`.
- **Latency observability.** `ai_invoke` audit payloads may include
  `latency_ms` — wall-clock around the provider call, excluding
  redaction and truncation. Still no prompt, no completion, no header.
- **Language and narration-level hints.** `AIConfig.language`
  (`"en" | "tr"`) and `AIConfig.narration_level`
  (`"concise" | "detailed"`) are appended to the SYSTEM prompt only.
  Both are closed enums built from operator config — they cannot be
  influenced by `<untrusted>` content.
- **CSV policy option C kept.** CSV exports add `ai_present`
  (`yes`/`no`); free-text AI content stays out of CSV.
- **Refined command filter.** `nmap` is no longer dropped as a bare
  token. Operational invocations (`run nmap`, `execute nmap`,
  `nmap -<flag>`, `nmap <ip>`, `nmap <cidr>`) still drop. Defensive
  wording such as "verify with approved network inventory or scanner
  according to policy" now passes through.
