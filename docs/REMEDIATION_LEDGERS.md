# TIC Security Remediation — Ledgers

Maintained across the 5-part remediation. Two ledgers:
- **A. Baseline Debt** — reds that pre-date remediation, outside the touched
  surface of Parts 1–3. The bar for incremental work is *zero new violations on
  the touched surface*; each pre-existing item is mapped to the part that will
  resolve it.
- **B. Residuals** — accepted limitations of the fixes we *shipped*.

CI is currently run with `--ignore=tests/chaos/test_chaos_resilience.py` (a
pre-existing collection error). The final DoD ("≥85% coverage + green") depends
on clearing Ledger A — almost entirely in **Part 5**.

---

## A. Baseline Debt Ledger (pre-existing; NOT introduced by Parts 1–3)

### A.1 Failing tests (9)

| Test(s) | Root cause | Owner |
|---|---|---|
| `test_telemetry_extended.py` (×8) | `MetricsRegistry` real API ≠ test expectations (`observe_duration`, `record_*`, prometheus output, `reset`) | **Part 5** (telemetry / metrics abstraction) |
| `test_ui_app_smoke.py::test_streamlit_app_uses_the_secure_adapter` | `src/tic/ui/app.py` is a CLI-sweep module; the test expects the Streamlit app importing `tic.ui.adapter`. Code/test drift. | **Part 5** (UI smoke alignment) |

### A.2 mypy `--strict` errors

25 at Part-2 close. Part 3 fixes `orchestrator.py:54` on its own surface (the
`_ai_selection_key` return type), so 24 remain afterward.

| Location | Error | Owner |
|---|---|---|
| `infra/otel/setup.py` (×4) | `import-not-found` for `opentelemetry.sdk.*` (stubs/extra missing) | **Part 5** (otel) |
| `infra/otel/decorators.py` (×6) | `Callable` missing type args | **Part 5** (otel) |
| `application/orchestrator.py:54` | return type `tuple[int,…]` vs actual `(…, str)` | **Part 3** — *fixed on touched surface* |
| `application/ai/response_validator.py:164` | unreachable statement | Part 5 / AI cleanup |
| `adapters/http/bulkhead.py:137` | `Callable` missing type args | **Part 5** (bulkhead abstraction) |
| `infra/config.py` load_settings (×4: 3× unused-ignore + `settings_customise_sources` override) | pydantic-settings typing quirks | General typing cleanup (candidate Part 5) |
| `cli/commands/config_cmd.py:81` (`_read_secret` → Any) | loose return | General typing cleanup |
| `cli/_wiring.py:138` (`event=` kwarg collision in `audit_append_failed` log) | structlog positional+kw `event` | General typing cleanup (trivial fix) |
| `ui/app.py:17`, `cli/commands/sweep.py:17`, `cli/commands/cache_cmd.py:17` | unused `type: ignore` | General typing cleanup |

### A.3 ruff CI-gate (`--select F,E9`) F401 — unused imports (13)

All in files **outside** the Parts 1–3 touched surface (git-untracked
`otel/`, `chaos/`, `fuzz/`, `load/`, `test_otel_setup.py`).

| File | Count | Owner |
|---|---|---|
| `infra/otel/decorators.py`, `infra/otel/setup.py` | 2 | **Part 5** (otel) |
| `tests/chaos/test_chaos_resilience.py` | 6 | **Part 5** (chaos / `circuit_breaker` module) |
| `tests/fuzz/test_fuzz_normalization.py` | 2 | fuzz suite cleanup (Part 5) |
| `tests/load/locustfile.py` | 2 | load suite cleanup (Part 5) |
| `tests/unit/test_otel_setup.py` | 1 | **Part 5** (otel) |

---

## B. Residual Ledger (accepted limitations of shipped fixes)

| Finding (part) | Residual | Why accepted | Mitigation path |
|---|---|---|---|
| **#1 audit HMAC chain** (Part 2) | A writer with file access can **truncate trailing signed records** — or delete *all* signed records so the chain reads as a valid "legacy/unsigned" prefix. `verify_chain` passes on the shortened chain. Splice / reorder / strip-in-middle / unsigned-after-signed are all closed. | `SecretStore` port is read-only (adding `set` widens the contract = scope creep, or binds the adapter to keyring = hexagonal breach); audit appends fire on **every** event (each provider build, TLS bypass, narration), so per-append keyring writes are heavy/fragile and conflict with "append must not block sweep"; the head HMAC is not a secret. | External trust-domain anchor: an append-only remote sink, or a "signing-active-since" marker in a separate domain. Acceptable as **Medium** under the trusted-operator threat model. |
| **#4 SSRF allowlist** (Part 2) | An allowlisted host with **no declared `allowed_host_cidrs`** is not IP-range-checked → DNS-rebind of that host to a *different* internal IP is possible. | Opt-in design; the unconditional metadata/blocked-host substring block always runs first. | Declare `allowed_host_cidrs` (the shipped default lab config already pins `localhost` to loopback). |
| **#2 depth guard** (Part 2) | NDJSON: a too-deep **line** is skipped (lenient), not raised. | Matches NDJSON's base-parser contract (skip malformed rows without aborting the feed); the whole-file STIX/MISP parsers *do* raise `ParseError`. | None needed — documented behavior. |

---

*Last updated: end of Part 2 / start of Part 3.*
