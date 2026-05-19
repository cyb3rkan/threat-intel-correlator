# ADR 0003 — AI is a Narrator, Not a Decision-Maker

Status: Accepted

## Context

LLM-backed enrichment is attractive for analyst-readable summaries but
introduces three risks that a defensive tool cannot accept by default:

1. **Data exfiltration** — uploading IOC values, raw log lines, or
   internal hostnames to a remote inference endpoint.
2. **Prompt injection** — feed/log files can carry hostile instructions
   that hijack the model's response.
3. **Hallucinated verdicts** — a confident but wrong severity could
   cause an analyst to dismiss a real incident.

## Decision

AI capability is **scoped to narration**, not scoring or routing:

- The deterministic core (parser → correlator → scorer → renderer)
  always runs first and is authoritative for severity, exit code, and
  the threshold gate.
- The AI layer only attaches a structured `AINarrative` (summary,
  false-positive likelihood, suggested actions, confidence). It can
  never change `Finding.severity` or `Finding.score`.
- AI is **disabled by default**. Enabling requires:
  - `ai.enabled: true`
  - `ai.endpoint_allowlist: ["https://…"]` (https only)
  - a keyring entry under `ai.keyring_service / keyring_user`.
- Prompts are built from a fixed template (`prompt_builder`); IOC
  values are HMAC-hashed before being sent; raw log lines are never
  interpolated.
- Responses pass `response_validator` (strict JSON schema, bounded
  string lengths, closed-set enums) before reaching the UI.

## Consequences

- An offline TIC produces the same severity gates as an online one;
  AI is purely additive.
- A misbehaving model cannot poison the deterministic pipeline.
- A malicious feed cannot trick the model into exfiltrating data;
  prompts are built from already-redacted material.
- AI features remain easy to disable per-environment without code
  changes (`ai.enabled: false`).
