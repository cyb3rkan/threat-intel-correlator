# TIC Compliance Control Matrix

**Version:** 1.0 | **Last reviewed:** 2025-01  
**Tool classification:** Local-first defensive security CLI/API, single-user

> Controls marked ✅ are implemented. ⚠️ are partial/documented. ❌ are not applicable or explicitly out of scope.

---

## SOC 2 Type II Mapping

| SOC2 Trust Category | Criteria | Control | Status | Evidence Location |
|---------------------|----------|---------|--------|-------------------|
| **Availability** | CC7.2 | Rate limiting prevents API abuse | ✅ | `src/tic/api/rate_limit.py` |
| **Availability** | CC7.2 | Circuit breaker prevents provider cascade | ✅ | `src/tic/adapters/http/circuit_breaker.py` |
| **Availability** | CC7.2 | Bulkhead isolates provider failure domains | ✅ | `src/tic/adapters/http/bulkhead.py` |
| **Availability** | CC9.1 | Liveness + readiness health probes | ✅ | `src/tic/api/health.py` |
| **Availability** | CC9.1 | SLO burn-rate alerting | ✅ | `deploy/monitoring/alerts.yaml` |
| **Confidentiality** | CC6.1 | API keys stored in OS keyring, not config files | ✅ | `src/tic/adapters/secrets/keyring_store.py` |
| **Confidentiality** | CC6.1 | Mandatory redaction of secrets in all logs | ✅ | `src/tic/infra/logging.py` |
| **Confidentiality** | CC6.1 | IOC values excluded from telemetry/trace spans | ✅ | `src/tic/infra/otel/decorators.py` |
| **Confidentiality** | CC6.1 | Public DTO masking — raw provider data never returned via API | ✅ | `src/tic/domain/finding.py` |
| **Confidentiality** | CC6.7 | `Cache-Control: no-store` on all API responses | ✅ | `src/tic/api/security_headers.py` |
| **Integrity** | CC7.1 | HMAC-chained tamper-evident audit log | ✅ | `src/tic/adapters/audit/hash_chain.py` |
| **Integrity** | CC7.1 | Input validation (Pydantic, `extra="forbid"`) | ✅ | `src/tic/infra/config.py` |
| **Integrity** | CC7.1 | SSRF guard with DNS resolution check | ✅ | `src/tic/security/ssrf_guard.py` |
| **Integrity** | CC8.1 | Dependency audit in CI (pip-audit, npm audit) | ✅ | `.github/workflows/ci.yml` |
| **Integrity** | CC8.1 | SBOM generation (CycloneDX) on release | ✅ | `.github/workflows/release.yml` |
| **Integrity** | CC9.2 | SLSA L3 provenance on released artifacts | ✅ | `.github/workflows/release.yml` |
| **Processing Integrity** | PI1.1 | Correlation IDs on all API requests | ✅ | `src/tic/api/main.py` |
| **Processing Integrity** | PI1.2 | Structured logging with structlog | ✅ | `src/tic/infra/logging.py` |
| **Privacy** | P3.1 | IOC pseudonymisation (HMAC hash mode) | ✅ | `src/tic/domain/finding.py` |
| **Privacy** | P8.1 | No external telemetry without opt-in | ✅ | `src/tic/infra/otel/setup.py` |

---

## NIST CSF 2.0 Mapping

### Govern (GV)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| GV.OC-01 | Organizational context established | THREAT_MODEL.md | ✅ |
| GV.OC-05 | Legal/regulatory requirements identified | This document | ✅ |
| GV.RM-01 | Risk appetite documented | THREAT_MODEL.md §4 Residual Risks | ✅ |

### Identify (ID)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| ID.AM-01 | Software inventory | SBOM (CycloneDX) | ✅ |
| ID.AM-07 | IT assets inventoried | Dockerfile labels + SBOM | ✅ |
| ID.RA-01 | Vulnerabilities identified | pip-audit + bandit in CI | ✅ |
| ID.RA-04 | Threat scenarios identified | THREAT_MODEL.md | ✅ |
| ID.RA-05 | Threat intelligence gathered | Core function of TIC itself | ✅ |

### Protect (PR)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| PR.AA-01 | Identities managed | Keyring-backed API key storage | ✅ |
| PR.AA-05 | Access permissions minimal | Non-root container (uid 1001), cap drop ALL | ✅ |
| PR.DS-01 | Data-at-rest protected | SQLite cache local only; audit log HMAC-chained | ✅ |
| PR.DS-02 | Data-in-transit protected | HTTPS enforcement on all provider calls | ✅ |
| PR.DS-10 | Data leakage prevented | Mandatory log redaction; public DTO masking | ✅ |
| PR.IR-01 | Response plans exist | RUNBOOK.md §8 Incident Response | ✅ |
| PR.PS-01 | Config managed | Pydantic Settings, `extra="forbid"`, immutable | ✅ |
| PR.PS-02 | Software managed | Poetry lock, SHA-pinned CI actions | ✅ |

### Detect (DE)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| DE.AE-02 | Anomalies analyzed | Structured logs + Prometheus metrics | ✅ |
| DE.AE-06 | Information shared | Audit chain (`tic audit verify`) | ✅ |
| DE.CM-01 | Networks monitored | Kubernetes NetworkPolicy; rate limit metrics | ✅ |
| DE.CM-09 | Computing hardware monitored | Readiness probe + container resource limits | ✅ |

### Respond (RS)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| RS.MA-01 | Incident managed | RUNBOOK.md §8 Incident Response | ✅ |
| RS.AN-03 | Root cause identified | Correlation ID log joining; OTel traces | ✅ |

### Recover (RC)

| Subcategory | Description | Control | Status |
|-------------|-------------|---------|--------|
| RC.RP-01 | Recovery plans exist | RUNBOOK.md; circuit breaker auto-recovery | ✅ |
| RC.RP-05 | Restoration verified | `/api/ready` readiness probe | ✅ |

---

## ISO 27001:2022 Mapping

| Annex A Control | Description | TIC Control | Status |
|-----------------|-------------|-------------|--------|
| A.5.7 | Threat intelligence | Core product function | ✅ |
| A.5.23 | Information security for cloud services | SSRF guard, HTTPS enforcement | ✅ |
| A.6.8 | Information security event reporting | Structured audit log | ✅ |
| A.8.2 | Privileged access rights | Non-root container; keyring isolation | ✅ |
| A.8.7 | Protection against malware | Provider API enrichment for detection | ✅ |
| A.8.8 | Management of technical vulnerabilities | pip-audit, npm audit, bandit in CI | ✅ |
| A.8.9 | Configuration management | Pydantic Settings with validation | ✅ |
| A.8.16 | Monitoring activities | Prometheus metrics + Grafana dashboard | ✅ |
| A.8.20 | Networks security | NetworkPolicy; CORS restriction | ✅ |
| A.8.22 | Segregation of networks | Bulkhead isolation per provider | ✅ |
| A.8.24 | Use of cryptography | HMAC audit chain; HTTPS TLS | ✅ |
| A.8.25 | Secure development lifecycle | SAST, secret scan, SBOM in CI | ✅ |
| A.8.26 | Application security requirements | OWASP headers; input validation; fuzz tests | ✅ |
| A.8.29 | Security testing in development | 80%+ test coverage enforced; chaos tests | ✅ |
| A.8.30 | Outsourced development | SHA-pinned actions; SLSA provenance | ✅ |

---

## GDPR / KVKK Considerations

TIC is a local-first security tool. The following principles apply:

| Principle | TIC Implementation | Status |
|-----------|--------------------|--------|
| Data minimisation | IOC values not exported to telemetry spans | ✅ |
| Storage limitation | Cache TTL enforced (default 1h); `tic cache purge` available | ✅ |
| Integrity & confidentiality | Audit log HMAC-chained; keyring-backed secrets | ✅ |
| Pseudonymisation | HMAC hash output mode for IOC pseudonymisation | ✅ |
| Purpose limitation | Tool purpose is threat correlation; no secondary use | ✅ |

**KVKK (Turkish PDPL) note:** TIC does not process "personal data" as defined by KVKK (Law No. 6698) in its primary function — IOC threat indicators (IP addresses, domains, hashes) are security artifacts, not personal data in the Turkish legal context. If TIC were used to enrich IP addresses associated with named individuals (e.g., employee machines), a KVKK DPIA would be required. This is out of scope for the current deployment model.

---

## OWASP API Security Top 10 (2023) Coverage

| Risk | Control | Status |
|------|---------|--------|
| API1:2023 Broken Object Level Authorization | Local-only; no multi-user model; CORS locked | ✅ |
| API2:2023 Broken Authentication | Keyring-backed secrets; no session tokens | ✅ |
| API3:2023 Broken Object Property Level Auth | Public DTO masking; raw data never returned | ✅ |
| API4:2023 Unrestricted Resource Consumption | Rate limiting (10 sweep/60s); bulkhead | ✅ |
| API5:2023 Broken Function Level Authorization | Two endpoints only; no admin surface | ✅ |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Rate limiting; audit log | ✅ |
| API7:2023 Server-Side Request Forgery | SSRF guard + metadata blocklist + HTTPS-only | ✅ |
| API8:2023 Security Misconfiguration | OWASP security headers; `extra="forbid"` | ✅ |
| API9:2023 Improper Inventory Management | OpenAPI docs at `/api/docs`; SBOM | ✅ |
| API10:2023 Unsafe Consumption of APIs | Schema validation on all provider responses | ✅ |
