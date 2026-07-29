# ADR 0001 — Hexagonal Architecture

Status: Accepted

## Context

TIC mixes three concerns that change at very different rates:

- **Security-critical core** (SSRF guard, redaction, HMAC, parsers).
- **Adapters** to external systems (HTTP providers, keyring, cache,
  audit log, renderers).
- **UI surfaces** (CLI, FastAPI, Streamlit fallback).

We need to evolve adapters and UIs without re-auditing the core every
time, and we need the core to be testable with no I/O.

## Decision

Use the ports & adapters (hexagonal) layout:

- `tic.domain` — pure value objects, zero I/O.
- `tic.ports` — protocol interfaces.
- `tic.adapters` — concrete implementations of ports.
- `tic.application` — orchestration of ports (sweep, scoring,
  correlation, redaction, narrator).
- `tic.cli`, `tic.api`, `tic.ui` — thin transports that wire adapters
  and call the application layer.

Wiring lives in **one** place (`tic.cli._wiring`) and is reused by
every UI surface. There is no per-UI construction of providers.

## Consequences

- Adding a feed format = one new parser adapter; no other module changes.
- Adding a provider = one new enrichment adapter plus a wiring branch.
- The security tests target adapters and the application layer; the
  domain stays stable across refactors.
- Cost: more files, more boilerplate. Accepted.
