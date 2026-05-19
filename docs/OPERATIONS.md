# Operations Guide

Day-to-day playbook for running TIC on an analyst workstation.

## Install

```bash
poetry install --with dev --extras "ui api"
```

Required paths (set via env or `configs/default.yaml`):

```bash
export TIC_PATHS__WORKING_DIR=$HOME/.local/share/tic/work
export TIC_PATHS__CACHE_DIR=$HOME/.cache/tic
export TIC_PATHS__AUDIT_LOG_PATH=$HOME/.local/state/tic/audit.log
```

## Store keys (keyring only — never in YAML/env)

```bash
poetry run tic config set-key abuseipdb
poetry run tic config set-key virustotal
poetry run tic config set-key misp
poetry run tic config set-key redaction-hmac
```

## Run a sweep (CLI)

```bash
poetry run tic sweep \
  --feed-format csv \
  --feed-file ./iocs.csv \
  --log-file ./events.ndjson \
  --output-mode analyst \
  --fail-on high
```

Exit codes:

- `0` — no findings at or above `--fail-on`.
- `1` — at least one finding crossed the threshold (intended for CI gates).
- non-zero TIC error codes — see `tic.infra.exit_codes`.

## Run the backend + frontend

```bash
poetry run uvicorn tic.api.main:app --host 127.0.0.1 --port 8000
# In another shell:
cd frontend && npm run dev
```

Backend MUST bind to loopback. The frontend rejects any
`NEXT_PUBLIC_API_BASE` that does not resolve to `127.0.0.1`, `::1`,
or `localhost`.

## MISP — local lab

A lab MISP container typically exposes HTTPS on `https://localhost:8443`
with a self-signed certificate. Configure as:

```yaml
providers:
  misp:
    enabled: true
    keyring_service: "tic-misp"
    keyring_user: "default"
    endpoint: "https://localhost:8443"
    allowed_hosts:
      - "localhost"
    verify_tls: false   # LAB ONLY — see Production section
```

At startup the wiring layer emits `provider_tls_verify_disabled` and
appends an audit-chain event so the bypass is tamper-evident.

## MISP — production

```yaml
providers:
  misp:
    enabled: true
    keyring_service: "tic-misp"
    keyring_user: "default"
    endpoint: "https://misp.internal.example"
    allowed_hosts:
      - "misp.internal.example"
    # verify_tls intentionally omitted — defaults to true.
```

Trust your internal CA via the host OS truststore (Linux:
`/usr/local/share/ca-certificates/`, macOS keychain, Windows cert store).

## Diagnostics

When a sweep does not show provider enrichment:

1. `curl http://127.0.0.1:8000/api/providers/status` — confirm
   `ready: true`. The most common blocker is `no_keyring_key`.
2. Tail the backend stderr. A failed provider call now logs:
   ```
   provider_request_failed provider=misp error=NetworkError
     exception_type=ConnectError endpoint_host=localhost
     verify_tls=true total_timeout_seconds=30.0
     sanitized_reason="[SSL: CERTIFICATE_VERIFY_FAILED] ..."
   ```
3. For TLS errors against an on-prem MISP, see "MISP — local lab"
   above. Never disable TLS globally.

## Audit chain

Each sweep appends a hash-chained event sequence to
`TIC_PATHS__AUDIT_LOG_PATH`. Provider TLS-verify bypass, sweep start,
sweep completion, and exit code are all recorded. Use
`tic audit verify` to confirm integrity.

## Backups & restores

A controlled cleanup pass stages the previous state under
`backup/pre-ai-cleanup-YYYYMMDD-HHMMSS/`. Restore with a plain
`cp -a` from that directory; the path is gitignored.

## AI narration setup

AI narration is **optional** and **off by default**. It produces an
advisory summary alongside each Finding; it never changes
score/severity/exit_code. If AI is unavailable for any reason, the
sweep runs without it.

### Enable AI narration

In `configs/default.yaml` (or your local override), set:

```yaml
ai:
  enabled: true
  endpoint_allowlist:
    - "https://YOUR-AI-ENDPOINT.example/v1/chat/completions"
  model: "your-model-id"
  max_output_tokens: 512
  max_input_chars: 8000
  request_timeout_seconds: 20.0
  keyring_service: "tic-ai"
  keyring_user: "default"
```

Then store the AI API key in the OS keyring (never in YAML or env
vars):

```bash
poetry run tic config set-key ai
```

The command verifies as: `tic config set-key ai` — present and wired
since the initial CLI release (see `src/tic/cli/commands/config_cmd.py`).
It prompts for the secret on a TTY and accepts stdin on a pipe; the
value is written to the OS keyring under `service='tic-ai',
user='default'` (or whatever `keyring_service` / `keyring_user` you
configured).

Confirm readiness with the status API:

```bash
curl http://127.0.0.1:8000/api/providers/status
```

The `ai` block should return `ready: true` and `reason: "ok"`. The
response never contains the API key, the endpoint URL, or the keyring
service / user names.

### Endpoint allowlist policy

- `endpoint_allowlist` is the exhaustive set of URLs the adapter may
  POST to. It is validated for `https://` at load time.
- Use placeholder examples like
  `https://YOUR-AI-ENDPOINT.example/v1/chat/completions` in committed
  config; never check in real vendor URLs or real API keys.
- For local lab work you may use an on-prem inference endpoint. Add
  its host to the entry the same way; the SSRF guard combined with
  the per-instance allowlist keeps the call constrained.

### Provider selection (`ai.provider`)

`ai.provider` selects the wire protocol used to talk to the model.
Default is `openai_compat` so existing deployments do not move.

- `openai_compat` (default) — POSTs to `.../v1/chat/completions`
  with `response_format: json_object`. Use for any OpenAI-compatible
  chat-completions endpoint.
- `gemini` — POSTs to `.../v1beta/models/{model}:generateContent`
  with `responseMimeType=application/json` plus a `responseSchema`.
  Use this when the OpenAI-compat shim returns malformed JSON (the
  observed Gemini failure mode).

#### Why a Gemini-native adapter

Gemini exposes an OpenAI-compatibility endpoint at
`/v1beta/openai/chat/completions`. In practice it sometimes returns
content that is not strict JSON (e.g. unterminated strings), which the
`AINarrative` parser rejects — the sweep then attaches `ai_narrative:
null`. The native `generateContent` endpoint accepts a
`generationConfig` block that hard-binds the response MIME type to
`application/json` *and* a response schema. With both set, the model
consistently returns parseable JSON.

#### Gemini configuration

```yaml
ai:
  enabled: true
  provider: "gemini"
  endpoint_allowlist:
    - "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
  model: "gemini-2.5-flash"
  max_output_tokens: 1024
  max_input_chars: 8000
  request_timeout_seconds: 20.0
  keyring_service: "tic-ai"
  keyring_user: "default"
  language: "tr"
  narration_level: "concise"
  max_findings_per_sweep: 25
```

Notes:

- `endpoint_allowlist` must contain the **exact** model-bound URL,
  including the `:generateContent` suffix and the `{model}` segment.
  The adapter does **not** substitute the model name into the URL —
  the allowlist entry is the truth, exactly as on every other AI path.
- The API key is read from the OS keyring as usual:
  `poetry run tic config set-key ai`. The Gemini adapter sends it in
  the `x-goog-api-key` request header — never as a `?key=…` query
  parameter (query keys leak into proxy/access logs).
- Everything else (SSRF guard, TLS verification, per-request timeout,
  response filtering, `AINarrative` schema validation, fail-safe
  `ai_narrative=null` on any failure) is identical to the OpenAI-compat
  path.
- Do **not** paste a real API key into committed YAML, the chat UI,
  the audit log, or any log line. Use the keyring.

### Language policy

- Natural explanations (the `summary` and `suggested_actions` fields)
  may be Turkish.
- Technical terms (IOC types, provider names, severity values,
  schema keys, security terms) remain English.
- A future `ai.language` config field is planned (Phase C). Phase A
  keeps the current schema and rendering.

### Volume / cost ceiling

- A future `ai.max_findings_per_sweep` config field is planned
  (Phase C) with default **25**. Phase A documents the intent; the
  default is not yet enforced in code.
- Until then, operators can keep sweeps small by gating the
  `--with-ai` flag at run time.

### Local / mock testing approach

- Unit / integration tests **never** hit a real AI endpoint. They use
  fake provider classes that record the redacted payload they
  received, or simulate a timeout / malformed response.
- See `tests/unit/test_narrator.py`,
  `tests/unit/test_response_validator.py`, and
  `tests/integration/test_orchestrator_ai_invariants.py` for the
  patterns.
- Prompt-injection coverage lives in
  `tests/security/test_prompt_injection_corpus.py` (16-payload corpus).
- If you want to manually exercise an on-prem model, point
  `endpoint_allowlist` at it, set `verify_tls` defaults (do **not**
  disable TLS verification for AI), and run a single Finding sweep.

### When AI is unavailable

The UI shows an amber hint with the closed-set reason
(`ai_disabled` / `endpoint_allowlist_empty` / `no_keyring_key`).
This is **not** an error — it means the operator's request was
honoured, the AI was not. Findings are still produced and rendered;
the `ai_narrative` field is `null` on each.

### What never leaves the host

- Raw log lines.
- Raw provider response bodies (AbuseIPDB / VirusTotal / MISP).
- Raw IOC values — the AI only ever sees HMAC pseudonyms.
- API keys, keyring values, `Authorization` headers.
- Tracebacks, exception messages, file paths.

If you see any of these on the wire, treat it as a security incident:
disable AI (`ai.enabled: false`), capture the audit chain, and open
an issue.

### Phase B operational notes

- **AI output is filtered.** The response validator drops
  `suggested_actions` entries that contain shell commands, reverse-shell
  wording, payload-execution wording, or raw URLs. Defensive wording
  ("review in SIEM" / "verify with EDR" / etc.) passes through. The
  filter runs before pydantic schema validation; a single bad entry
  does not cost the analyst the rest of the narrative.
- **AI is validated.** The strict `AINarrative` schema still rejects
  hallucinated keys, oversized strings, and invalid enum values. The
  fail-safe behaviour is unchanged: a rejection returns `None` and the
  sweep continues without an `ai_narrative` field.
- **Prompts and completions are NOT logged or audited.** Audit events
  are metadata-only (`finding_id`, `reason`, count). If you need to
  debug an AI invocation, capture timing and reason codes from the
  audit chain — never the prompt or response body.
- **Streamlit dashboard test coverage.** `src/tic/ui/app.py` runs most
  of its UI at import time (Streamlit's pattern), so a meaningful test
  needs the `streamlit.testing` script runner — out of scope for Phase
  B. Phase B includes a minimal AST / source-pattern smoke test
  (`tests/unit/test_ui_app_smoke.py`) that catches syntax breakage and
  guards against `unsafe_allow_html=True` near `ai_narrative`
  rendering. Full functional UI testing is deferred to a later phase.

### When AI was unavailable for a sweep (audit recipe)

To answer "did AI actually narrate this sweep, and if not why?" without
reading prompts or completions:

```bash
poetry run tic audit verify  # confirm chain integrity first
```

Then `grep` the audit log file for the sweep's `correlation_id` and
inspect:

- `ai_invoke` events                 → number of attempts (with optional `latency_ms`)
- `ai_input_truncated` events        → number of findings whose payload exceeded `max_input_chars` (counts only, no content)
- `ai_response_rejected` events      → with closed-set `reason`
- `ai_narrative_attached` events     → number of successful narratives
- `sweep_end.ai_narratives_generated` → final count for that sweep
- `sweep_end.ai_narration_skipped_due_to_cap` → findings beyond `ai.max_findings_per_sweep`

### Phase C: config-driven AI controls

Three new `AIConfig` fields, all backward-compatible. AI is still
disabled by default.

```yaml
ai:
  enabled: false                       # opt-in master switch
  endpoint_allowlist: []               # https-only, validated at load
  language: "tr"                       # natural-language portion: "en" | "tr"
  narration_level: "concise"           # tone hint: "concise" | "detailed"
  max_findings_per_sweep: 25           # 1..100; bounds cost + latency
```

#### Language policy

- `language: "tr"` makes the AI write `summary` and each
  `suggested_actions` entry in Turkish. Technical terms — IOC types,
  provider names, severity values, schema keys, security terminology —
  REMAIN English. JSON keys and enum values are NEVER translated.
- `language: "en"` keeps everything English.
- The hint is appended to the SYSTEM prompt (typed-enum value, built by
  us). It cannot be overridden from inside the `<untrusted>` user block.

#### Narration level

- `concise`: short summary, focused defensive actions (default).
- `detailed`: slightly more explanatory summary, still bounded by the
  strict `AINarrative` length caps (`summary <= 800 chars`,
  `suggested_actions[i] <= 180`, `<= 5 items`).

#### Per-sweep AI cap

- `max_findings_per_sweep: 25` (default) caps how many findings get an
  AI invocation per sweep. Findings beyond the cap still appear in the
  result with `ai_narrative: null`.
- Selection is **deterministic** (same inputs → same selection):
  severity rank desc, score desc, provider count desc, match count desc,
  finding_id asc.
- The cap does **not** affect score, severity, enrichments, exit_code,
  or above_threshold — it only governs which findings get narrated.

### Phase C: input truncation

If a redacted finding's JSON payload would exceed `ai.max_input_chars`,
the Narrator truncates before invoking the AI:

1. Drop trailing `matches` entries until the payload fits.
2. If still oversized, drop trailing `enrichments` entries.
3. Required fields — `finding_id`, `ioc_type`, `ioc_pseudo`, `severity`,
   `score`, `match_count`, and the remaining `enrichments[*].provider`
   names — are **never** dropped.
4. If the required-fields core is itself too large, the Narrator
   skips invocation and audits `ai_response_rejected` with
   `reason: "input_too_large"`.

Every truncation produces a metadata-only audit event:

```jsonc
{
  "type": "ai_input_truncated",
  "payload": {
    "finding_id": "<uuid>",
    "original_chars": 9420,
    "final_chars":    7910,
    "dropped_matches_count":      8,
    "dropped_enrichments_count":  0
  }
}
```

No payload content, no IOC values, no log-source strings ever enter
this event.

### Phase C: CSV exports

Per policy option C, CSV exports add one new column:

| Column        | Value                                    |
| ------------- | ---------------------------------------- |
| `ai_present`  | `yes` if `ai_narrative` is set, else `no` |

Free-text AI content (summary, suggested_actions, model name) remains
**excluded** from CSV. Use the JSON or Markdown export for analyst-
facing narrative content.

## Phase D: safe AI narration setup flow

Use this flow to bring AI narration online. Stop at any step where you
are not sure the next one is safe in your environment. Each step is
reversible — `ai.enabled: false` returns to a known-good baseline.

> **Never paste an API key into chat windows, screenshots, source
> control, YAML configs, or log scrapes.** The CLI key prompt is the
> only intended surface for the key value, and it is hidden when the
> standard input is a TTY. If you must paste a key on a non-TTY pipe,
> rotate it immediately afterwards.

### Step 1 — keep `ai.enabled: false` and prove the no-AI baseline

```bash
poetry run tic config show
# Confirm: AI: enabled: False
poetry run tic sweep --feed-format csv --feed ./iocs.csv --logs ./events.ndjson
# Sweep succeeds without AI. Capture exit code and finding counts.
```

The no-AI baseline must succeed before you change anything. If it does
not, fix the underlying provider / config / keyring issue first — AI
adds work; it does not solve a broken sweep.

### Step 2 — configure `endpoint_allowlist` (no keys yet)

Edit `configs/default.yaml` (or your override) and add the AI provider
endpoint. **Use a placeholder for committed config**; the real URL
belongs in your environment-specific override only.

```yaml
ai:
  enabled: false                # still false at this step
  endpoint_allowlist:
    - "https://YOUR-AI-ENDPOINT.example/v1/chat/completions"
  model: "your-model-id"
  language: "tr"                # or "en"
  narration_level: "concise"    # or "detailed"
  max_findings_per_sweep: 25    # 1..100
```

`endpoint_allowlist` is validated at load time: every entry must be
`https://...`. The list is the exhaustive set of URLs the AI adapter
may POST to; the SSRF guard runs on top of it.

### Step 3 — store the AI API key in the OS keyring

```bash
poetry run tic config set-key ai
# The command prompts hidden when stdin is a TTY.
# It writes to service='tic-ai' user='default' (or whatever you configured).
# The value is NEVER printed, NEVER logged.
```

Verify the keyring entry exists (without revealing the value):

```bash
curl http://127.0.0.1:8000/api/providers/status | jq '.ai'
# Look for: { "key_present": true, ... }
```

### Step 4 — run the provider / status check

```bash
poetry run uvicorn tic.api.main:app --host 127.0.0.1 --port 8000 &
curl http://127.0.0.1:8000/api/providers/status | jq '.ai'
```

The expected payload before enabling AI:

```json
{
  "enabled": false,
  "endpoint_count": 1,
  "key_present": true,
  "ready": false,
  "reason": "ai_disabled"
}
```

If `key_present: true`, you are ready to enable AI for testing. If
`key_present: false`, go back to Step 3.

### Step 5 — run the mock / local smoke test

Before connecting to the real provider, run the Phase D integration
tests against the deterministic mock to confirm the wiring is intact
on this host:

```bash
poetry run pytest tests/integration/test_ai_mock_e2e.py \
                  tests/integration/test_api_sweep_ai_enabled_mock.py \
                  tests/integration/test_cli_ai_enabled_mock.py
```

All three suites must pass without touching the network. If they
fail, do not proceed to Step 6 — investigate the failure first.

If you want a manual sanity check against your own local model
(e.g. a self-hosted inference endpoint), the safest pattern is:

```bash
# 1) Flip ai.enabled to true in your override config.
# 2) Confirm endpoint_allowlist matches your local model exactly.
# 3) Run a one-IOC sweep with --with-ai.
poetry run tic sweep \
  --feed ./tiny-iocs.csv \
  --feed-format csv \
  --logs ./tiny-events.ndjson \
  --format json \
  --fail-on info \
  --with-ai
# 4) Inspect the JSON: every finding has ai_narrative populated
#    or null (timeout / schema rejection). exit_code reflects the
#    severity gate, not AI.
# 5) Tail the audit log: ai_invoke, ai_response_rejected, and
#    ai_narrative_attached events appear with metadata-only payloads.
```

If anything looks wrong (latency too high, unexpected `reason:`
values, narrative content that crosses your safety policy), set
`ai.enabled: false` and rotate the key. AI is opt-in by design;
flipping it back off is always safe.

### Step 6 — only then connect to the real provider, if approved

Real-provider connection requires:

1. A formal sign-off from your team's security review process.
2. Confirmation that the endpoint host is on the approved network
   egress allowlist of your environment.
3. A rotation plan for the API key (90 days max).
4. A monitoring plan for `ai_response_rejected` events with
   `reason: non_2xx` or `reason: timeout`.

Update the endpoint URL in `endpoint_allowlist` to the real value in
your environment-specific override (never the committed default), flip
`ai.enabled: true`, and re-run Step 4 + Step 5 against a small,
non-sensitive feed first.

### What never leaves the host or the audit chain

- API keys (any provider, including the AI key).
- Authorization / Bearer headers.
- Raw IOC values — the AI only ever sees HMAC pseudonyms.
- Raw log lines.
- Raw provider response bodies (AbuseIPDB / VirusTotal / MISP).
- AI prompt bodies.
- AI completion bodies.
- Tracebacks, exception messages, full file paths.

The audit chain (`tic audit verify`) records only metadata: `finding_id`,
counts, closed-set reason strings, latency_ms. If you ever see prompt
text or a Bearer token in the audit log, treat it as an incident:
disable AI, rotate the key, and open a security review.
