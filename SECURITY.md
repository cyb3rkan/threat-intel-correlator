# Security Policy

Threat Intel Correlator (TIC) is a **local-first defensive** tool. It runs
on the analyst's workstation and never sends uploaded feeds, log files,
provider responses, or IOC values to any remote service unless the operator
explicitly enables AI narration (default OFF) with a self-managed endpoint.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest minor release on the `main` branch is supported. Older
0.1.x point releases receive security patches on a best-effort basis.

## Reporting a Vulnerability

If you believe you have found a vulnerability in TIC, please report it
privately. **Do not open a public issue.**

- Please use GitHub's private vulnerability reporting: https://github.com/cyb3rkan/threat-intel-correlator/security/advisories/new
- Include a clear reproduction, the affected version, and any relevant
  configuration (with secrets redacted).
- Allow a reasonable disclosure window (typically 90 days) before
  publishing details.

We will acknowledge receipt within 5 business days and, where possible,
provide a remediation timeline within 15 business days.

## What NOT to Include in a Report

To protect you and the project, never include in a bug report:

- Real API keys, OS keyring values, or any secret bytes.
- `Authorization` headers, bearer tokens, session cookies.
- Raw provider response bodies (they may carry the API key in error fields).
- Raw log lines from your environment.
- Full file paths that may reveal home-directory user names.
- Stack traces from production systems that include process state.

Redact the above before sending. The maintainers will reject reports that
expose secrets and ask you to resend a redacted version.

## Local-First Privacy Statement

TIC is designed so that, by default, **no IOC value, log line, or provider
response leaves the analyst workstation**:

- IOC values can be HMAC-pseudonymised for export via `--output-mode hash`.
- All provider HTTP traffic uses the hardened `SafeHttpClient` with SSRF
  guards, explicit host allow-lists, and TLS verification on by default.
- API keys live only in the OS keyring and are never written to disk,
  YAML, environment files committed to source control, or logs.
- The FastAPI backend binds to loopback only (`127.0.0.1`) and the
  frontend validates that `NEXT_PUBLIC_API_BASE` resolves to a loopback
  host before issuing requests.
- AI narration is OFF by default. When enabled, it strips raw log lines
  and IOC values from prompts before sending to the operator-supplied
  endpoint.

## Security-Sensitive Configuration

- `http.verify_tls`: **must remain `true`** in production. The only
  supported exception is a per-provider `providers.<name>.verify_tls: false`
  for a local MISP lab with a self-signed certificate.
- `providers.<name>.allowed_hosts`: opt-in SSRF guard exception list.
  Use only for trusted internal hosts.
- `redaction_hmac_keyring_service` / `redaction_hmac_keyring_user`:
  must point at a keyring entry containing a strong key when hash
  output mode is used. Hash mode fails closed (never falls back to a
  zero key) if the key is missing.

## Threat Model Summary

The full threat model lives in `docs/THREAT_MODEL.md`. The short version:

- TIC trusts the operator who runs the CLI/API on their workstation.
- TIC does **not** trust feed/log files (malformed, oversized, archive
  bombs, prompt-injection content) — see `tic.security.*` modules and
  the `tests/security/` corpus.
- TIC does **not** trust provider responses (size-capped, schema-validated,
  never persisted by default).
- TIC does **not** trust the network: SSRF guard rejects private IPs,
  metadata endpoints, link-local addresses, and unexpected redirect
  hosts (cross-origin redirects fail closed; auth headers dropped on
  any host change).
