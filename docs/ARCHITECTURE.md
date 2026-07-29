# Architecture

Threat Intel Correlator follows a **hexagonal (ports & adapters)** layout
so that the security-critical core can be reasoned about without dragging
along framework or transport concerns.

## Layers

```
+---------------------------------------------------------------+
|                         UI layer                              |
|  CLI (tic.cli) | FastAPI (tic.api) | Streamlit fallback (ui)  |
+---------------------------------------------------------------+
|                       Application                             |
|  Orchestrator | Scoring | Correlation | Redaction | Narrator  |
+---------------------------------------------------------------+
|                          Ports                                |
|  EnrichmentProvider | LogSource | Cache | SecretStore | …     |
+---------------------------------------------------------------+
|                         Adapters                              |
|  AbuseIPDB | VirusTotal | MISP | NDJSON | STIX | CSV |        |
|  SqliteCache | KeyringSecretStore | HashChainAuditLogger | …  |
+---------------------------------------------------------------+
|                  Infrastructure & Security                    |
|  Config (pydantic-settings) | SafeHttpClient | SSRF guard |   |
|  PathGuard | ArchiveGuard | Redactor (HMAC) | structlog       |
+---------------------------------------------------------------+
```

Key rules:

- The **domain** (`tic.domain`) has zero I/O and zero framework imports.
- **Ports** (`tic.ports`) are protocol-only interfaces.
- **Adapters** depend on ports, never on each other.
- Wiring lives in `tic.cli._wiring` and is reused by every UI surface
  (CLI, FastAPI, Streamlit) — there is exactly one place that constructs
  providers.

## Data Flow (sweep)

1. CLI/API receives a feed file + log file, validates choices.
2. `tic.ui.adapter` stages uploads under a session-scoped temp dir
   (`PathGuard` enforces working_dir containment).
3. Parsers (`tic.adapters.parsers.*`) emit normalised `IOC` objects.
4. `LogSource` yields `LogEvent`s; the `Correlation` application
   matches IOCs against log events.
5. The orchestrator enriches each finding through enabled providers
   (`AbuseIPDB`, `VirusTotal`, `MISP`) over `SafeHttpClient`.
6. `Scoring` computes severity per profile; `Redactor` applies the
   selected output mode (analyst / summary / hash).
7. Renderers emit terminal / JSON / Markdown; the FastAPI layer
   returns the `PublicFinding` DTO only.

## Why these boundaries

- Replacing a provider does not touch scoring or the API.
- A new feed format (STIX, MISP-JSON, NDJSON, CSV) plugs in as a parser
  without changes elsewhere.
- The hardened HTTP client is the single point that talks to the
  network — every SSRF / TLS / redirect decision lives there.

For longer-term decisions see `docs/adr/`.
