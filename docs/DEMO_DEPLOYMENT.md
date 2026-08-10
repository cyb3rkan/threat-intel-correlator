# Public demo deployment

How the hosted portfolio demo is wired: a **backend on Render** and a
**frontend on Vercel**, joined by three environment variables.

The demo runs the real pipeline — parsing, Aho-Corasick correlation, scoring,
public-DTO masking — over a fixed sample set. Nothing is mocked; only the
input is fixed.

## The safety model

The API ships **no authentication** — no bearer token, no API key, no OAuth2
check anywhere in `src/tic/api/main.py`. A public URL would therefore let
anyone reach `POST /api/sweep`, upload files, and spend whatever provider
quota the instance is configured with. Rate limiting bounds that; it does not
prevent it.

`TIC_DEMO_MODE=1` is what makes public exposure safe. With it on:

| | |
|---|---|
| `POST /api/sweep` | **Refused (403)** — no caller-supplied files, so no upload abuse surface |
| `POST /api/demo-sweep` | Registered; runs the real pipeline over the bundled sample set |
| Provider API keys | None configured → no outbound calls → **no quota to burn, no key to leak** |

The last row is the important one for a portfolio deployment. Verify it any
time with:

```bash
curl -s https://<your-backend>/api/providers/status
```

Every provider should read `"key_present": false`. If one ever reads `true`,
a key has been added to a service that anyone on the internet can reach.

**Rule: never set a real provider API key on the public demo instance.**
Adding one re-opens exactly the risk demo mode exists to close.

---

## 1. Backend — Render

Use `deploy/demo/Dockerfile` (**not** the root `Dockerfile`, which binds
127.0.0.1 and cannot expand Render's runtime `$PORT`).

**Service settings**

| Field | Value |
|---|---|
| Environment | Docker |
| Dockerfile path | `deploy/demo/Dockerfile` |
| Docker context | `.` (repository root) |
| Health check path | `/api/ready` |

**Environment variables**

| Variable | Value | Notes |
|---|---|---|
| `TIC_DEMO_MODE` | `1` | Already baked into the image; set it explicitly so it is visible in the dashboard and survives a base-image change |
| `TIC_DEMO_ORIGINS` | `https://<your-app>.vercel.app` | Your Vercel URL. Comma-separated for several. **Fill this in after step 2** |

Everything else (`TIC_PATHS__*`, `TIC_SECRET_BACKEND`) is already set in the
Dockerfile. Do not add provider keys.

> **`TIC_DEMO_ORIGINS` takes scheme + host only.** `https://foo.vercel.app` is
> valid. A path (`https://foo.vercel.app/api`) or a wildcard
> (`https://*.vercel.app`) is discarded — and **discarded without any log
> line**, so a wrong value looks exactly like a working one until the browser
> blocks a request. Verify with the CORS check in step 3 rather than assuming.
>
> There is no wildcard support, so Vercel *preview* deployments (each gets its
> own URL) are not covered. List the production URL, and add specific preview
> URLs only if you need them.
>
> Entries are ignored entirely when demo mode is off, so a stray value cannot
> widen CORS on a local run.

### Free-tier sleep

Render's free tier sleeps a service after 15 minutes idle; waking takes about
a minute. `.github/workflows/demo-keepalive.yml` pings `/api/ready` every 10
minutes on weekdays 06:00–20:00 UTC (09:00–23:00 TR) to keep it warm during
likely visiting hours while staying inside the 750 h/month quota. Outside that
window the first visitor waits for the wake-up.

---

## 2. Frontend — Vercel

Import the repository, then:

| Field | Value |
|---|---|
| Root directory | `frontend` |
| Framework preset | Next.js (auto-detected) |

**Environment variables** — both are compiled into the client bundle at
**build time**, so changing one requires a redeploy, not just a restart.

| Variable | Value |
|---|---|
| `NEXT_PUBLIC_API_BASE` | `https://<your-backend>.onrender.com` |
| `NEXT_PUBLIC_TIC_DEMO` | `1` |

`NEXT_PUBLIC_TIC_DEMO=1` does two things: it routes sweeps to
`/api/demo-sweep`, and it relaxes the client's loopback guard so a remote
`NEXT_PUBLIC_API_BASE` is honoured. Without it the client silently falls back
to `http://127.0.0.1:8000` and the deployed page cannot reach anything.

The remote base must be **https**. Uploads and results carry IPs, hostnames
and usernames; a plain-http remote is rejected by the client.

---

## 3. Close the loop

Vercel assigns the URL, and the backend has to trust it — so this step comes
last:

1. Copy the deployed Vercel URL.
2. Set `TIC_DEMO_ORIGINS` on Render to that exact origin.
3. Let Render redeploy.

Skipping this leaves the page loading while every API call fails: the browser
blocks the response because the backend never named that origin in its CORS
policy.

### Verify

```bash
# 1. Backend is up and in demo mode
curl -s https://<your-backend>/api/ready
#    → {"status":"ready", ...}

# 2. No provider keys — the check that matters
curl -s https://<your-backend>/api/providers/status
#    → every provider "key_present": false

# 3. Uploads are refused. Send actual files: FastAPI validates the multipart
#    form before the demo-mode check runs, so a bodyless POST returns 422
#    (missing fields) and proves nothing.
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<your-backend>/api/sweep \
     -F 'feed_file=@/dev/null;filename=a.csv' \
     -F 'log_file=@/dev/null;filename=b.ndjson'
#    → 403

# 4. CORS names the frontend
curl -si https://<your-backend>/api/ready \
     -H "Origin: https://<your-app>.vercel.app" | grep -i access-control-allow-origin
#    → access-control-allow-origin: https://<your-app>.vercel.app
```

Then open the Vercel URL and run a sweep. Findings should appear within a few
seconds — longer on the first request if Render was asleep.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Page loads, every request fails; console shows a CORS error | `TIC_DEMO_ORIGINS` missing or misspelled | Set it to the exact Vercel origin (scheme + host, no trailing slash), redeploy |
| Requests go to `127.0.0.1:8000` instead of the backend | `NEXT_PUBLIC_TIC_DEMO` not set at build time | Set it on Vercel and **redeploy** — it is a build-time constant |
| `404` at the root URL | Only the backend is deployed | The backend serves `/api/*` only; the root is the Vercel app |
| First request takes ~1 minute | Render free tier woke from sleep | Expected; the keepalive workflow limits when it happens |
| Sweep returns `403` | Frontend calling `/api/sweep` instead of `/api/demo-sweep` | `NEXT_PUBLIC_TIC_DEMO=1` missing on the frontend build |
| `providers/status` shows `key_present: true` | A provider key was set on the public instance | Remove it and rotate that key — it was reachable by anyone |
