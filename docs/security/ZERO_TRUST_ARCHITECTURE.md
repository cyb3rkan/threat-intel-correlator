# TIC Zero Trust Architecture

**Version:** 1.0  
**Standard:** NIST SP 800-207 (Zero Trust Architecture)  
**Scope:** Local-first deployment + Kubernetes deployment model

---

## 1. Zero Trust Principles Applied to TIC

NIST SP 800-207 defines Zero Trust as: *"never trust, always verify"* — no implicit trust based on network location.

TIC applies this at each trust boundary:

| Boundary | ZT Principle Applied |
|----------|----------------------|
| Analyst browser → Next.js frontend | CORS locked to `localhost:3000`; CSP blocks cross-origin scripts |
| Next.js frontend → FastAPI API | CORS allowlist; correlation IDs; rate limiting |
| FastAPI API → Provider adapters | SSRF guard; HTTPS enforcement; credential header stripping on redirect |
| Provider adapters → External providers (VT, AbuseIPDB) | TLS verification; allowlist opt-in for internal hosts |
| Kubernetes pod → External network | NetworkPolicy denies all except HTTPS/443 |
| Kubernetes pod → K8s API | `automountServiceAccountToken: false`; no RBAC roles |

---

## 2. Current Trust Model (Local Deployment)

```
┌─────────────────────────────────────────────────────────────┐
│  Analyst workstation (trusted boundary)                      │
│                                                              │
│  ┌─────────────────┐    localhost:3000    ┌───────────────┐  │
│  │ Next.js Frontend│ ──────────────────→  │  FastAPI API  │  │
│  │  (browser)      │   HTTP (loopback)    │  :8000        │  │
│  └─────────────────┘                      └───────────────┘  │
│                                                   │           │
│                                           HTTPS/TLS           │
│                                                   │           │
└───────────────────────────────────────────────────┼───────────┘
                                                    │
                           ┌────────────────────────┼──────────┐
                           │  Public Internet        │          │
                           │                         ▼          │
                           │  ┌──────────┐  ┌──────────────┐   │
                           │  │VirusTotal│  │  AbuseIPDB   │   │
                           │  └──────────┘  └──────────────┘   │
                           └───────────────────────────────────┘
```

**Trust boundary violations prevented:**
- Frontend cannot call any external URL (CSP `connect-src` locked)
- API cannot call non-HTTPS URLs (SSRF guard `_ALLOWED_SCHEMES`)
- API cannot call metadata endpoints (SSRF guard `_BLOCKED_HOST_SUBSTRINGS`)
- API cannot call private RFC1918 IPs (SSRF guard `_is_disallowed_ip`)

---

## 3. Kubernetes Zero Trust Model

```
┌─────── Namespace: tic ──────────────────────────────────────────┐
│                                                                  │
│  ┌─────────────┐   NetworkPolicy:Ingress    ┌─────────────────┐ │
│  │  Frontend   │ ──────────────────────────→ │    TIC API Pod  │ │
│  │  Pod        │   (only from frontend pod)  │    :8000        │ │
│  └─────────────┘                             └─────────────────┘ │
│                                                       │           │
│                                       NetworkPolicy:  │           │
│                                       Egress only     │           │
│                                       HTTPS/443       │           │
│                                                       ▼           │
│                           ┌──────────────────────────────────┐   │
│                           │  ServiceAccount: tic-api          │   │
│                           │  automountServiceAccountToken:    │   │
│                           │  false (no K8s API access)        │   │
│                           └──────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘

┌─────── Namespace: monitoring ───────────────────────────────────┐
│  Prometheus → TIC API :8000/api/metrics  (explicit allow rule)  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. SPIFFE/SPIRE Readiness Assessment

**Current state:** TIC does not implement SPIFFE/SPIRE workload identity.

**Rationale:** SPIFFE/SPIRE provides cryptographic workload identity for service meshes with multiple communicating services. TIC has one service (the API) with no peer services that need mutual identity verification. The investment is not justified for the current architecture.

**Future readiness path** (if TIC evolves to multi-service):

| Step | Action |
|------|--------|
| 1 | Add SPIRE agent as sidecar in K8s deployment |
| 2 | Issue X.509-SVID to TIC API pod |
| 3 | Configure `SafeHttpClient` to present SVID for mTLS to internal MISP |
| 4 | Replace API key auth for internal MISP with mTLS (no static secrets) |

**Trigger:** When TIC adds a second internal service (e.g., a dedicated cache service, a streaming ingestion worker), SPIFFE/SPIRE becomes the recommended identity solution.

---

## 5. mTLS Readiness Assessment

**Current state:** API uses plain HTTP on loopback (local deployment). HTTPS in container.

**Local deployment:** mTLS between frontend and API is disproportionate for a loopback connection on a single machine. OS-level process isolation is the appropriate control.

**Kubernetes deployment:** mTLS can be enabled transparently via a service mesh (Istio, Linkerd) at the pod level without code changes. The TIC API's HTTP server will terminate mTLS at the sidecar proxy.

**mTLS enablement steps (Istio):**
```yaml
# Add to namespace:
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: tic-mtls
  namespace: tic
spec:
  mtls:
    mode: STRICT
```

No application code changes required. TIC's `SafeHttpClient` handles outbound TLS; the sidecar handles inbound mTLS.

---

## 6. Short-Lived Credential Strategy

| Credential | Current Lifetime | ZT Target | Path |
|------------|-----------------|-----------|------|
| VT API key | Long-lived (static) | 90-day rotation | `tic config rotate virustotal-api-key` + keyring update |
| AbuseIPDB key | Long-lived (static) | 90-day rotation | Same pattern |
| HMAC signing key | Per-process (in-memory) | ✅ Already short-lived | Generated at sweep start |
| Kubernetes secrets | Long-lived | 30-day rotation | External Secrets Operator + Vault |

**Recommended:** Integrate with HashiCorp Vault or AWS Secrets Manager for automated key rotation in Kubernetes deployments. TIC's keyring abstraction (`SecretStore` port) makes this a one-adapter change.

---

## 7. Verification Checklist (Zero Trust Audit)

Run these checks periodically:

```bash
# 1. Verify no hardcoded secrets in source
git secrets --scan  # or: trufflehog filesystem .

# 2. Verify TLS on all provider calls
grep -r "verify_tls.*False" src/  # Should only appear in test fixtures

# 3. Verify SSRF guard coverage
poetry run pytest tests/security/test_ssrf_corpus.py -v

# 4. Verify NetworkPolicy is applied (K8s)
kubectl get networkpolicy -n tic

# 5. Verify image signature (K8s)
cosign verify ghcr.io/your-org/tic:latest \
  --certificate-identity-regexp="https://github.com/your-org/tic/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# 6. Verify non-root in running container (K8s)
kubectl exec -n tic deployment/tic-api -- id
# Expected: uid=1001(tic) gid=1001(tic) groups=1001(tic)

# 7. Verify read-only filesystem (K8s)
kubectl exec -n tic deployment/tic-api -- touch /test-write 2>&1
# Expected: touch: cannot touch '/test-write': Read-only file system
```
