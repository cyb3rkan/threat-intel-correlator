# Threat Intel Correlator

A defensive, **local-only** tool for correlating IOC feeds (CSV / NDJSON / MISP / STIX) against
NDJSON log files, enriching with provider data, scoring, and producing public-safe findings.

It ships in three forms — pick the one that fits your workflow:

| Form               | Entry point                                      | Use when                                    |
|--------------------|--------------------------------------------------|---------------------------------------------|
| CLI                | `tic sweep …`                                    | Pipelines, scripting, headless runs         |
| FastAPI + Next.js  | `uvicorn tic.api.main:app` + `frontend/`         | Rich local dashboard with charts / filters  |
| Streamlit fallback | `streamlit run src/tic/ui/app.py`                | Single-process UI, no Node.js needed        |

All three reuse the **same** core logic (`src/tic/`). The web UIs only render `PublicFinding`
fields — raw log lines, raw provider responses, API keys and tracebacks are never returned.

---

## Requirements

- Python **3.11+**
- [Poetry](https://python-poetry.org/) (used by the repo)
- Node.js **20+** and npm — only needed for the Next.js frontend

## Install (Python)

```powershell
poetry install --extras "api ui"
```

Extras:
- `api` → installs `fastapi`, `uvicorn`, `python-multipart` (FastAPI backend)
- `ui`  → installs `streamlit` (Streamlit fallback)

## Configuration

Settings come from `configs/default.yaml` plus environment variables (TIC_… prefix).
At minimum, point the runtime at writable paths:

```powershell
$env:TIC_PATHS__WORKING_DIR  = "D:\tic-work"
$env:TIC_PATHS__CACHE_DIR    = "$HOME\.cache\tic"
$env:TIC_PATHS__AUDIT_LOG_PATH = "$HOME\.local\state\tic\audit.log"
```

Provider API keys (if any) are read from the OS keyring inside the backend; **never** put
secrets in YAML or env files committed to the repo.

---

## Run the CLI

```powershell
poetry run tic --help
poetry run tic sweep `
  --feed-format csv `
  --feed-path D:\tic-work\known_good_iocs.csv `
  --log-path D:\tic-work\known_good_events.ndjson `
  --output-mode analyst `
  --fail-on high
```

## Run the FastAPI backend + Next.js frontend

Terminal 1 — backend (binds to **127.0.0.1**, no public surface):

```powershell
poetry run uvicorn tic.api.main:app --host 127.0.0.1 --port 8000
```

Smoke test:

```powershell
curl http://127.0.0.1:8000/api/health
# {"status":"ok","service":"threat-intel-correlator-api","version":"0.1.0"}
```

Terminal 2 — frontend:

```powershell
cd frontend
copy .env.local.example .env.local    # only the first time
npm install
npm run dev
```

Open `http://localhost:3000`. The dashboard checks the backend health every 30s
(only while the tab is visible) and lets you run a sweep, browse findings, and export
JSON / CSV / Markdown reports.

`frontend/.env.local` only contains `NEXT_PUBLIC_API_BASE` (default
`http://127.0.0.1:8000`). No secrets, no telemetry, no external calls.

## Run the Streamlit fallback

```powershell
poetry run streamlit run src\tic\ui\app.py --server.address 127.0.0.1 --server.headless true
```

The Streamlit app is feature-equivalent to the CLI for a quick local UI.

---

## Provider & key setup (safe, local-only)

All provider/AI keys are read from the **OS keyring** by the backend. They
**never** travel to the frontend, never appear in `/api/sweep` responses, and
never appear in `/api/providers/status` (which returns only safe metadata).

### 1. Pick which providers you want

Edit your config YAML (or set `TIC_*` env vars). Example **without secrets**:

```yaml
# configs/local.yaml — no real values, just structure.
providers:
  abuseipdb:
    enabled: true
    keyring_service: "tic-abuseipdb"
    keyring_user:    "default"
    cache_ttl_seconds: 3600

  virustotal:
    enabled: true
    keyring_service: "tic-virustotal"
    keyring_user:    "default"
    cache_ttl_seconds: 3600

  misp:
    enabled: true
    keyring_service: "tic-misp"
    keyring_user:    "default"
    endpoint: "https://misp.YOUR-INTERNAL-DOMAIN.example"   # https only
    allowed_hosts: ["misp.YOUR-INTERNAL-DOMAIN.example"]
    cache_ttl_seconds: 3600

ai:
  enabled: false                   # keep off until you've set a key
  endpoint_allowlist: []           # https-only when populated
  model: ""
```

Point the runtime at it: `set TIC_CONFIG_FILE=configs/local.yaml`.

### 2. Store keys in the OS keyring

Use the CLI — keys are read from stdin (or interactive prompt) and never echoed:

```powershell
poetry run tic config set-key abuseipdb       # then paste the API key
poetry run tic config set-key virustotal
poetry run tic config set-key misp
poetry run tic config set-key ai               # only if you set ai.enabled=true
poetry run tic config set-key redaction-hmac   # required for output-mode=hash
```

To remove:

```powershell
poetry run tic config delete-key abuseipdb --yes
```

Inspect resolved config (secrets are **never** printed):

```powershell
poetry run tic config show              # masked
poetry run tic config show --verbose    # full endpoint values, still no secrets
```

### 3. Verify readiness

```powershell
curl http://127.0.0.1:8000/api/providers/status
```

Returns only safe metadata:

```json
{
  "providers": [
    {
      "name": "abuseipdb",
      "configured": true,
      "enabled": true,
      "key_present": true,
      "supported_ioc_types": ["ip"],
      "endpoint_kind": "public",
      "ready": true,
      "reason": "ok"
    },
    {
      "name": "virustotal",
      "configured": true,
      "enabled": true,
      "key_present": false,
      "supported_ioc_types": ["domain","hash:md5","hash:sha1","hash:sha256","hash:sha512","ip","url"],
      "endpoint_kind": "public",
      "ready": false,
      "reason": "no_keyring_key"
    }
  ],
  "ai": {
    "enabled": false,
    "endpoint_count": 0,
    "key_present": false,
    "ready": false,
    "reason": "ai_disabled"
  },
  "redaction_hmac": { "key_present": true }
}
```

The frontend "Providers" tab renders this as readiness cards; the "Diagnostics"
tab shows a one-line summary; the AI toggle in the Sweep runner shows the
reason inline if AI is not ready.

### Hash output mode requires a redaction HMAC key

Hash mode pseudonymises IOC values to `hmac:<hex>`. If the redaction HMAC
key is not in the keyring, the backend now **fails closed** with a friendly
error instead of silently using a deterministic zero-key fallback. To enable:

```powershell
# Generate a 32+ byte random secret on your machine and store it:
poetry run tic config set-key redaction-hmac
```

Then `--output-mode hash` (CLI) or `output_mode=hash` (API) will produce
keyring-keyed pseudonyms. The HMAC key never leaves the backend process.

### Debug flag: TIC_DEBUG_CACHE_RAW

By default, **raw provider response bytes are never persisted to disk**. The
provider cache stores parsed `EnrichmentResult` objects with `truncated_raw=""`.
Set `TIC_DEBUG_CACHE_RAW=true` only for local troubleshooting — this stores
the first 2 KB of provider responses inside the cache (still never returned
by the API). Unset it for any production-style use.

## Tests

```powershell
poetry run pytest                                  # full suite (asyncio mode auto)
poetry run pytest tests/unit -q                    # unit tests only
poetry run pytest tests/security -q                # security corpus
poetry run pytest tests/unit/test_ui_adapter.py -v # adapter tests
```

Frontend type-check / build:

```powershell
cd frontend
npm run typecheck
npm run build
```

## Test fixtures

Put local sample files under `D:\tic-work\` (or any writable directory):

- `known_good_iocs.csv` — a CSV feed with at least the columns expected by
  `parse_csv_feed` (e.g. `value, type, source, confidence, tags`).
- `known_good_events.ndjson` — one JSON object per line. Each line is treated as a
  log event and matched against the feed.

These files are **never** committed to the repo.

---

## Security & privacy at a glance

- **Local-only.** The backend binds to 127.0.0.1; CORS is restricted to
  `127.0.0.1:3000` / `localhost:3000`.
- **No telemetry.** No Vercel Analytics, no Google Fonts request from the layout, no
  external SDKs in the frontend.
- **Public-safe DTOs.** Only `PublicFinding` data crosses the API boundary —
  `EnrichmentResult.truncated_raw`, raw log lines, and provider raw payloads stay in the
  backend.
- **Path-guarded uploads.** Files are staged under `settings.paths.working_dir/.tic-ui-uploads/<uuid>/`,
  resolved through `safe_resolve_within`, and removed after each sweep.
- **CSV formula-injection mitigation.** Both backend and frontend exports prefix cells
  starting with `= + - @ \t \r` with `'`.
- **No secrets in source.** API keys come from the OS keyring on the backend side and are
  never echoed back through the API.

For deeper context see `docs/THREAT_MODEL.md`, `docs/SECURE_CODING.md`, and
`SECURITY.md`.
