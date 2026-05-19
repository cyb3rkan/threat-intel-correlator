# ADR 0002 — Python 3.11+ as Implementation Language

Status: Accepted

## Context

The tool must run locally on analyst workstations across Linux, macOS,
and Windows; integrate with several mature parser libraries (STIX,
defusedxml, pyahocorasick); offer strong type checking; and have first-class
async HTTP for fan-out enrichment.

## Decision

Adopt Python 3.11+ with:

- **pydantic v2** for typed config and DTOs (`Settings`,
  `ProviderConfig`, `Finding`, `PublicFinding`).
- **httpx[http2]** behind a hardened `SafeHttpClient` wrapper.
- **structlog** for redaction-aware structured logs.
- **typer** for the CLI surface; **FastAPI** for the local backend;
  **Streamlit** as an optional single-process UI fallback.
- **Poetry** for dependency and virtualenv management.
- **mypy --strict** and **ruff** for static analysis.

Python 3.11 is the minimum because we rely on `asyncio.timeout`,
`tomllib` (indirectly via tooling), and the improved exception
groups for error handling.

## Consequences

- Cross-platform install is one `poetry install` away.
- Security-critical libraries (`defusedxml`, `idna`, `tenacity`)
  are battle-tested and audit-friendly.
- Async-first HTTP gives free fan-out across providers without
  threading complexity.
- Cost: Python's import system surface is larger than, say, a single
  Rust binary. Accepted for analyst-workstation distribution model.
