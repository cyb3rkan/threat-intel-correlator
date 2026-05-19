# Threat Model

Scope: Threat Intel Correlator (TIC) run locally on an analyst workstation.

## Assets

| Asset | Sensitivity | Notes |
| --- | --- | --- |
| Provider API keys (AbuseIPDB, VirusTotal, MISP, AI) | High | Stored in OS keyring only. |
| Uploaded feed/log files | Medium–High | May contain customer IOCs, real IPs, file paths. |
| Sweep findings & enrichments | Medium | Distributed as JSON/CSV/Markdown reports. |
| Hash-output HMAC key | High | Loss makes pseudonymised exports re-identifiable. |
| Audit chain (`audit_chain.jsonl`) | Medium | Tamper-evident operational record. |

## Trust Boundaries

1. **Operator ↔ TIC** — operator is trusted; feed/log files they upload
   are **not**.
2. **TIC ↔ Providers** — provider responses are bounded (size cap,
   schema validation, never persisted by default).
3. **TIC ↔ Network** — only HTTPS, only public hostnames unless the
   operator opts a host into `allowed_hosts`, only the configured
   provider endpoint set; metadata IPs always blocked.
4. **Backend ↔ Frontend** — loopback only. The frontend rejects any
   non-loopback `NEXT_PUBLIC_API_BASE`.

## In-Scope Threats

### 1. Malformed / hostile input files
- Mitigations: defusedxml for STIX, archive ratio cap (`max_archive_ratio`),
  per-file size cap, JSON depth cap, IOC count cap, CSV-injection scrub.
- Tests: `tests/security/test_path_traversal_corpus.py`,
  `tests/security/test_prompt_injection_corpus.py`,
  `tests/unit/test_archive_guard.py`.

### 2. SSRF / metadata exfiltration via provider misconfiguration
- Mitigations: `tic.security.ssrf_guard.ensure_public_url` runs on every
  request and every redirect hop; resolves all A/AAAA records; rejects
  private/loopback/link-local/multicast/reserved IPs; blocks
  `169.254.169.254` and equivalents.
- Tests: `tests/security/test_ssrf_corpus.py`,
  `tests/integration/test_safe_client.py`.

### 3. Cross-origin redirect credential leak
- Mitigations: `SafeHttpClient` fails closed on cross-origin redirect
  by default; auth headers (`Authorization`, `Cookie`, `x-apikey`, …)
  are dropped before any redirect hop.

### 4. Self-signed / spoofed TLS on internal MISP
- Mitigations: global `http.verify_tls: true`. Per-provider opt-in
  `providers.<name>.verify_tls: false` for a local lab is logged at
  startup (`provider_tls_verify_disabled`) and is restricted by the
  `allowed_hosts` list. Audit chain records the bypass.

### 5. Secret leak via logs or exports
- Mitigations: structlog `_redact_sensitive` processor drops keys
  matching `api_key|token|secret|password|authorization|cookie|bearer`
  before any sink. Public DTO (`PublicFinding`) strips
  `truncated_raw`, `raw_line_hash`, internal IDs. CSV/Markdown
  renderers use the public DTO only. Provider exception messages are
  sanitised before logging.

### 6. Re-identification of hashed exports
- Mitigations: hash output mode requires an operator-supplied HMAC key
  from the keyring; fails closed if missing. Never falls back to a
  deterministic zero key.

### 7. Prompt injection via feed contents (AI narration)

**Status:** AI narration is OFF by default (`ai.enabled: false`). It is
optional, local-first, and fail-safe — every failure path returns the
original Finding with `ai_narrative=null` and the sweep continues. AI
output **cannot** change `score`, `severity`, `enrichments`,
`above_threshold`, or `exit_code`. Those are produced by the deterministic
scoring/correlation engine before the narrator runs and are not mutated
afterwards.

**Untrusted inputs to AI narration:**
- IOC values, IOC `source`, IOC `tags`
- Provider tags (AbuseIPDB categories, VirusTotal labels, MISP tags)
- Log-derived fields (timestamps, log source identifiers, field names)
- Anything in an uploaded feed file

Every one of these is treated as data, never as instructions. None of
them is interpolated into a prompt template verbatim.

**Mitigations (defence in depth):**

1. **Allowlist DTO before the AI ever sees data.** Only
   `RedactedFinding` (see `tic.application.redaction`) is serialised into
   the prompt. Its `model_config` is `frozen=True, extra="forbid"`, so
   adding a leak channel requires an explicit schema change. Free-text
   fields (`source`, individual tags, log source hostnames) are dropped
   — only counts (`tag_count`, `match_count`) are forwarded.
2. **IOC values are HMAC-pseudonymised** before being sent to AI,
   regardless of the operator-facing `output_mode`. Analyst mode does NOT
   mean raw IOC sent to AI; the AI only ever sees `ioc_pseudo`.
3. **`<untrusted>` envelope.** Untrusted data is wrapped in a delimited
   block. Any embedded `</untrusted>` substring is escaped before the
   prompt is built (see `tic.application.ai.prompt_builder`).
4. **Strict response schema.** `AINarrative` is a frozen pydantic model
   with closed enums, length-capped strings, and `extra="forbid"`. Any
   hallucinated key, oversized field, invalid enum, or non-JSON output
   falls back to `None` and the Finding renders without a narrative.
5. **Endpoint allowlist + HTTPS-only.** `AIConfig.endpoint_allowlist`
   is validated for `https://` at load time. The adapter refuses any
   endpoint not in the allowlist; `SafeHttpClient` enforces the SSRF
   guard on every request.
6. **Renderer-level labelling.** All exports (Markdown, terminal, JSON,
   UI panel) mark AI output as "AI-generated advisory — review required".
   CSV exports deliberately omit AI narrative free-text (policy: CSV
   stays structured; long-form text belongs to JSON/Markdown only).
7. **No raw secrets in logs.** The structlog `_redact_sensitive`
   processor strips `api_key|token|secret|password|authorization|cookie|
   bearer` keys recursively. AI-related log events record only the
   exception *class name*, latency, and validation status — never the
   prompt, never the completion, never the API key.

**Tests (frozen contracts):**
- `tests/security/test_prompt_injection_corpus.py` — 16-payload corpus
  covering role injection, ignore-previous, schema override, command
  injection, base64, HTML/script, Markdown link, RTL/zero-width unicode,
  delimiter break, print-secrets, provider-tag injection, and IOC-value
  injection. Each payload must (a) never appear verbatim in the prompt
  and (b) never change the Finding's score/severity.
- `tests/security/test_ai_logging_redaction.py` — proves the structlog
  redaction processor handles AI-shaped events and that the Narrator
  never forwards `Authorization`, `Bearer`, or raw IOC values to the
  AI provider port.
- `tests/integration/test_orchestrator_ai_invariants.py` — proves AI on
  vs. AI off produces identical score/severity/exit_code/above_threshold,
  and that `sweep_end` audit events carry only the metadata count
  `ai_narratives_generated`, not narrative content.
- `tests/integration/test_api_sweep_no_raw.py` — proves
  `with_ai=true` with `ai.enabled=false` is silent (no exception, no key
  reference, no traceback in the response body).

**Phase B additions:**

8. **AI output filtering (defensive-only `suggested_actions`).** The
   response validator drops AI-suggested actions that look like
   operational attack instructions (shell tools, reverse-shell wording,
   payload-execution wording, raw URLs). Defensive wording such as
   "review in SIEM" / "verify with EDR" / "check firewall logs" passes
   through unchanged. The filter operates per-entry so a single bad
   suggestion does not cost the analyst the rest of the narrative.
9. **Hardened system prompt.** The assistant is explicitly limited to
   defensive narration, must refuse offensive guidance, must not
   attempt to invert HMAC pseudonyms, and must not reinterpret
   `score` / `severity` as its own verdict. Tests freeze the rule set
   as substrings of the system prompt.
10. **Metadata-only audit events.** `ai_invoke`,
    `ai_response_rejected`, `ai_narrative_attached`, and the
    `sweep_end` AI count are tamper-evident in the hash-chained audit
    log. None of these events ever carries the prompt, the completion,
    the Authorization header, the API key, or the raw IOC value.
    Audit-write failures are isolated from the sweep.
11. **Explicit per-request AI timeout.** The adapter wraps each AI
    call in `asyncio.timeout(cfg.request_timeout_seconds)` in
    addition to the `SafeHttpClient` total timeout. A deadline-fail
    returns `None` and the sweep keeps running.

**Phase C additions:**

12. **Bounded AI execution.** `AIConfig.max_findings_per_sweep`
    (default 25, range 1..100) limits AI invocations per sweep.
    Selection is deterministic (severity / score / provider count /
    match count / finding_id). Findings beyond the cap appear in the
    result with `ai_narrative=null`. The cap never affects score,
    severity, exit_code, or above_threshold.
13. **Input truncation with metadata-only audit.** When a redacted
    payload exceeds `ai.max_input_chars`, trailing `matches` then
    trailing `enrichments` are dropped. Required identifiers and
    score/severity are never touched. An `ai_input_truncated` event
    records counts only — no content. Oversize-after-truncation
    surfaces as `ai_response_rejected` with `reason: "input_too_large"`.
14. **Language and narration hints on SYSTEM prompt only.**
    `ai.language` and `ai.narration_level` are closed enums appended
    to the SYSTEM message. They cannot be overridden from the
    `<untrusted>` user block. Turkish hint preserves JSON-only output
    rule, defensive-only refusals, and the `REMAIN English` clause for
    JSON keys / enum values / provider names.
15. **CSV policy option C (final).** Exports add `ai_present`
    (`yes`/`no`). The full AI summary, suggested_actions, and model
    name remain CSV-excluded.
16. **Refined nmap filter (false-positive reduction).** Bare mention
    of network scanners in defensive wording passes; operational
    invocations (flags, `run nmap`, `execute nmap`, `nmap <ip|cidr>`)
    still drop.

## Out of Scope

- Multi-tenant deployments / shared backend.
- Hardening of the analyst's host OS or keyring backend.
- Network egress controls (assumed to be enforced at the host firewall).
