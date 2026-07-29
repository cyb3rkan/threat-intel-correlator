# Threat Intel Correlator — Bağımsız Kurumsal Denetim Raporu

> **Denetim tipi:** Salt-okunur (read-only), satın-alma/üretime-geçiş öncesi seviye.
> **Tarih:** 2026-06-29 · **Branch:** `remediation` · **Son commit:** `3f07107`
> **Yöntem:** Kaynak kodun özyinelemeli incelenmesi + gerçek araç çalıştırması (pytest, mypy, ruff, bandit, pip-audit) + statik konfig analizi + çalışma-zamanı doğrulaması.
> **Bağımsızlık notu:** Repo'da kapsamlı bir remediation uygulanmış (commit geçmişi). Bu denetim "düzeltilmiş olmalı" varsaymadan koda sıfırdan bakar; her bulgu kanıta dayalıdır.

---

## 0. Önemli Metodoloji Notu (dürüstlük beyanı)

- Bu denetim **hiçbir kaynak/kod dosyasını değiştirmedi.** Tek yazılan dosya bu rapordur (`docs/AUDIT_REPORT.md`).
- Denetim başında verilen `git status: (clean)` snapshot'ı **eskidir.** Gerçekte working tree'de 9 dosya `deleted` (unstaged) durumdaydı (aşağıda Bulgu A-1). Bu silmeler denetimden **önce** mevcuttu; denetçi tarafından yapılmadı.
- Çalıştırılan komutların hepsi salt-okunur/analiz amaçlıdır. `docker build` denendi ancak **Docker daemon kapalı** olduğu için doğrulanamadı → ilgili yerde "Yetersiz Kanıt" işaretlendi.

---

## 1. YÖNETİCİ ÖZETİ

`threat-intel-correlator`, savunma amaçlı, **yerel-öncelikli (local-first)** bir IOC korelasyon aracıdır: CSV/NDJSON/MISP/STIX feed'lerini NDJSON loglarına karşı eşleştirir, sağlayıcılarla (AbuseIPDB/VirusTotal/MISP) zenginleştirir, deterministik skorlar ve **public-safe** bulgular üretir. Üç yüzeyi vardır: CLI, FastAPI backend, Next.js frontend — hepsi aynı çekirdek (`src/tic/`) mantığını kullanır.

**Mühendislik olgunluğu, küçük/orta ölçekli bir savunma aracı için sınıfının çok üstünde.** Hexagonal mimari temiz uygulanmış (ports/adapters/application/domain ayrımı), mypy `--strict` sıfır hatayla geçiyor (95 dosya), bandit temiz (0 medium/high), test paketi 743 testle geçiyor ve %86.74 coverage tutturuyor. Güvenlik kontrolleri (SSRF guard, path guard, CSV-injection, prompt-injection savunması, HMAC-chained audit log, redaction) gerçekten kodlanmış ve test edilmiştir — "güvenlik tiyatrosu" değil.

**Ancak üretime-hazırlık (özellikle konteyner/Kubernetes dağıtımı) için bir Critical engelleyici vardır:** Dockerfile ve k8s deployment, var olmayan bir env değişkeni (`TIC_PATHS__AUDIT_CHAIN`) ayarlar; doğru ad `TIC_PATHS__AUDIT_LOG_PATH`'tir. Bu, temiz bir konteyner ortamında **settings yüklemesini fail-closed yapar** → `/api/ready`, `/api/sweep`, `/api/providers/status` çalışmaz → pod asla Ready olmaz. Yerel kullanım (CLI / lokal uvicorn) bu hatadan etkilenmez çünkü XDG/env defaultları devreye girer.

### Go-Live Önerisi

| Senaryo | Karar | Gerekçe |
|---|---|---|
| **Yerel kullanım (CLI + lokal API)** | ✅ **Ready** | Çekirdek mantık sağlam, testli, güvenli. Bulgu C-1'in (CVE'ler) etkisi yerel kapalı yüzeyde düşük. |
| **İnternete açık tek-kullanıcı** | ⚠️ **Conditionally Ready** | Rate-limit + security headers + SSRF var; ancak auth yok (tasarım gereği localhost), bağımlılık CVE'leri (C-1) ve ruff/CI tutarsızlıkları (D grubu) önce kapatılmalı. |
| **Konteyner / Kubernetes** | ❌ **Not Ready** | Bulgu B-1 (audit env adı) deployment'ı kıran Critical hatadır. Düzeltilene kadar k8s'te çalışmaz. |
| **Çok-kiracılı / kurumsal SaaS** | ❌ **Not Ready** | Auth/tenant izolasyonu yok (kapsam dışı tasarım), tek-replica stateful (HA yok). Mimari yeniden tasarım gerekir. |

---

## 2. GENEL DENETİM SKORU: **82 / 100**

> Yerel-kullanım bağlamında. İnternete-açık bağlamda etkin skor ~70; konteyner dağıtımı bağlamında B-1 nedeniyle bloklu.

### 15 Kategori Skor Kartı

| # | Kategori | Skor | Gerekçe (kanıt) |
|---|---|---:|---|
| 1 | Security (AppSec) | **88** | SSRF/path/CSV/prompt-injection guard'ları gerçek + testli; bandit temiz. Auth yok (tasarım). |
| 2 | Architecture | **90** | Temiz hexagonal; ports/adapters/domain ayrımı net; döngüsel bağımlılık yok. |
| 3 | Code Quality | **88** | mypy --strict 0 hata; ama tests/ 275 ruff ihlali (D-2). |
| 4 | Privacy (GDPR/KVKK) | **86** | Allowlist-redaction + HMAC pseudonym + public-DTO sınırı; TCKN/SSN/email pattern'leri. |
| 5 | DevOps | **78** | 4 workflow, SLSA L3 release; ama CI lint zayıf (D-1), env tutarsızlığı (B-1). |
| 6 | DevSecOps | **84** | bandit+gitleaks+pip-audit+trivy+SBOM+cosign zinciri var; CI/security tutarsız (D-3). |
| 7 | Supply Chain | **70** | 18 bilinen CVE (C-1); release SHA-pinned ama ci/security tag-pinned (D-4). |
| 8 | Cloud/Infra | **74** | k8s restricted profile + NetworkPolicy mükemmel; ama B-1 kırıcı + Dockerfile env hatası. |
| 9 | Performance | **85** | Bounded global semaphore, sweep deadline, streaming upload, bounded body. |
| 10 | Memory/Resource | **85** | Bounded buffer/cache/match; httpx loop-aware aclose; rate-limit client eviction. |
| 11 | Reliability | **80** | Circuit breaker + bulkhead + retry + fail-closed; ama B-1 + tek replica (HA yok). |
| 12 | Testing/QA | **85** | 743 geçti, %86.74 cov; otel/decorators %0 (E-1); 1 güvenlik testi sessizce skip (E-2). |
| 13 | Compliance | **80** | COMPLIANCE_MATRIX + THREAT_MODEL + ADR'ler; resmi sertifika yok (beklenen). |
| 14 | Observability | **84** | Gerçek Prometheus metrics + OTel + structlog + audit chain; otel test boşluğu. |
| 15 | Production Readiness | **68** | Yerel için yüksek; konteyner/k8s için B-1 nedeniyle düşük. |

---

## 3. EN ÖNEMLİ RİSKLER

1. **(Critical) Konteyner/k8s dağıtımı tamamen kırık** — yanlış audit env değişkeni adı (B-1).
2. **(High) 18 bilinen bağımlılık CVE'si** — starlette (6), python-multipart (3), tornado (4), pydantic-settings, msgpack, pip (C-1). İnternete açık yüzeyde anlamlı.
3. **(Medium) CI lint kalkanı zayıf** — `ci.yml` sadece `F,E9` çalıştırıyor; pyproject'teki S/B/PL kuralları CI'da uygulanmıyor → 275 ruff ihlali sızıyor (D-1, D-2).
4. **(Medium) Repo hijyeni** — 9285 satırlık `_setup_part*.py` bootstrap scriptleri + kök dosya kopyaları git'te (A-1).
5. **(Low) Sessiz test boşlukları** — otel/decorators %0 coverage (E-1); frontend AI-render güvenlik testi yanlış dosya adı yüzünden skip (E-2).

---

## 4. EN ÖNEMLİ GÜÇLÜ YÖNLER (kanıtla)

- **Hexagonal mimari gerçekten uygulanmış:** `src/tic/{domain,ports,application,adapters,infra,api,ui,security}` — domain hiçbir adapter'a bağımlı değil; bağımlılık yönü içe doğru.
- **mypy `--strict` SIFIR hata** (95 dosya) — `pyproject.toml:69-75` strict + disallow_untyped_defs + no_implicit_optional.
- **bandit temiz** (0 medium/high; 7 low, -ll altında filtrelenir) — `src` 6884 satır tarandı.
- **743 test geçti, %86.74 coverage** (eşik %85), gerçek çalıştırmayla doğrulandı (221s).
- **Güvenlik derinliği:** SSRF guard metadata-endpoint'i allowlist'ten ÖNCE bloklar (`ssrf_guard.py:61-68`); cross-origin redirect'te auth header düşürme (`safe_client.py:44-54`); fail-closed cross-origin redirect (`safe_client.py:189-193`); HMAC-chained tamper-evident audit (`hash_chain.py`); allowlist-tabanlı AI redaction (`redaction.py`).
- **Tehlikeli sink YOK:** `git grep pickle|yaml.load|eval|exec|os.system|marshal|subprocess` → src'de yalnızca `re.compile` ve `yaml.safe_load` (asla `yaml.load`). `eval/exec/pickle/subprocess` hiç yok.
- **Olgun supply-chain release:** `release.yml` SHA-pinned actions + SLSA L3 provenance + Cosign keyless + CycloneDX SBOM (fail-closed `test -s sbom.json`).
- **Frontend güvenlik bilinci:** `dangerouslySetInnerHTML` hiç yok; `api.ts` loopback-only guard; CSV + Markdown çıktısında escape.

---

## 5. BULGULAR (severity sıralı)

### 🔴 CRITICAL

---

#### B-1 — Konteyner/k8s'te yanlış audit env değişkeni settings'i fail-closed yapıyor

- **Severity:** Critical
- **Kanıt:**
  - `Dockerfile:55` → `TIC_PATHS__AUDIT_CHAIN=/app/data/audit_chain.jsonl`
  - `deploy/k8s/deployment.yaml:146-147` → `name: TIC_PATHS__AUDIT_CHAIN`
  - Oysa `src/tic/infra/config.py:196` `PathsConfig` alanı `audit_log_path`'tir; geçerli env adı `TIC_PATHS__AUDIT_LOG_PATH` (bkz. `config.py:278`, `README.md:42`).
- **Çalışma-zamanı doğrulaması:** Docker'ın tam env seti ile (`WORKING_DIR + CACHE_DIR + AUDIT_CHAIN`, `AUDIT_LOG_PATH` yok) `load_settings()` çağrıldı:
  ```
  tic.domain.errors.ConfigError: settings validation failed:
  paths.audit_log_path  Field required [type=missing]
  ```
- **Risk:** Temiz konteyner ortamında (XDG home yok, `AUDIT_LOG_PATH` yok) settings yüklemesi `ConfigError` fırlatır. `get_settings()` çağıran her endpoint (`/api/ready`, `/api/sweep`, `/api/providers/status`) 500/503 döner. `/api/ready` 503 → readinessProbe başarısız → **pod asla Ready olmaz.**
- **Business Impact:** Ürün konteyner/Kubernetes'te hiç çalışmaz. Helm/k8s manifestleri "production-ready" iddia ediyor ama deployment baştan bozuk.
- **Technical Impact:** Tam servis kullanılamazlığı (konteyner bağlamında).
- **Likelihood:** Çok yüksek (kaçınılmaz — her temiz konteyner başlatmasında).
- **Remediation:** `Dockerfile:55`, `deploy/k8s/deployment.yaml:146-147` (ve CI'da varsa) `TIC_PATHS__AUDIT_CHAIN` → `TIC_PATHS__AUDIT_LOG_PATH` olarak düzeltilmeli. Bir entegrasyon testi `env -i` ile temiz-konteyner-env senaryosunu pin'lemeli.
- **Confidence:** High (çalışma-zamanı reprodüksiyonu ile kanıtlı).

> **Not — ikincil etki:** Düzeltilse bile mevcut Dockerfile audit log'unu kalıcı `/app/data`'ya (PVC) değil, env yok sayıldığında XDG default'una (`$HOME=/tmp` → tmpfs) yazardı; restart'ta tamper-evident audit chain kaybolurdu. Doğru env adıyla bu da düzelir.

---

### 🟠 HIGH

---

#### C-1 — 18 bilinen CVE içeren 6 bağımlılık (pip-audit)

- **Severity:** High (internete-açık) / Medium (yerel)
- **Kanıt:** `poetry run pip-audit` (gerçek çıktı):
  | Paket | Kurulu | CVE/ID sayısı | Fix |
  |---|---|---|---|
  | starlette | 1.0.0 | 6 (PYSEC-2026-161/248/249, CVE-2026-48817/48818) | 1.3.1 |
  | python-multipart | 0.0.29 | 3 (CVE-2026-53538/53539/53540) | 0.0.31 |
  | tornado | 6.5.5 | 4 (CVE-2026-49853/54/55, GHSA-pw6j) | 6.5.7 |
  | pydantic-settings | 2.14.0 | 1 (GHSA-4xgf) | 2.14.2 |
  | msgpack | 1.1.2 | 1 (GHSA-6v7p) | 1.2.1 |
  | pip | 26.0.1 | 3 (PYSEC-2026-196, CVE-2026-3219/6357) | 26.1.2 |
- **Risk:** starlette + python-multipart doğrudan HTTP/multipart yüzeyindedir (FastAPI). Bir saldırgan multipart/starlette CVE'lerini API açıksa kullanabilir. tornado, ui ekstrasının (streamlit) geçişli bağımlılığıdır.
- **Business Impact:** İnternete açıksa DoS/parsing zafiyetleri. Yerel-loopback'te saldırı yüzeyi düşük.
- **Technical Impact:** Multipart parsing DoS, olası bilgi sızıntısı (CVE detaylarına bağlı).
- **Likelihood:** Orta (yerel), Yüksek (açık).
- **Remediation:** `poetry update starlette python-multipart pydantic-settings msgpack` ve tornado'yu (streamlit zinciri) yükselt; pip'i CI'da zaten `>=26.1.1`'e çekiyorlar (`security.yml:74`) — lockfile'a yansıtılmalı.
- **Confidence:** High.

> **Tutarsızlık notu:** `pyproject.toml:33` `starlette>=0.49.1` der ama kurulu sürüm `1.0.0`'dır (lockfile sürüklenmesi). pip-audit 2026 tarihli CVE DB'siyle çalışıyor.

---

### 🟡 MEDIUM

---

#### A-1 — Repo köküne sızmış 9285 satırlık bootstrap scriptleri + kopya dosyalar

- **Severity:** Medium
- **Kanıt:** `git ls-files` kökte izlenen dosyalar:
  - `_setup_part1.py`..`_setup_part5.py` (77+2596+1413+1155+3572 = **8813 satır**), base64-gömülü kaynak yazan "bootstrap" scriptleri (`_setup_part1.py:1-12` docstring).
  - `rate_limit.py`, `security_headers.py`, `test_api_app_wiring.py`, `conftest.py` — `src/tic/api/` ve `tests/integration/` altındakilerin **kopyaları** (`security_headers.py` ve `test_api_app_wiring.py` bire bir aynı; `rate_limit.py` farklı/eski).
  - Bu 9 dosya **commit edilmiş** ama working tree'de `deleted` (`git status --porcelain` → ` D`). Yani index ile disk tutarsız.
- **Risk:** (a) Kafa karışıklığı — hangi `rate_limit.py` canonical? (b) Bir geliştirici yanlışlıkla `python _setup_part1.py` çalıştırırsa mevcut kaynak dosyaları base64 bloklarıyla yeniden yazar (scriptin amacı bu). (c) Kök kopyalar pytest tarafından yanlışlıkla toplanabilir.
- **Business Impact:** Bakım borcu, due-diligence'ta kötü izlenim ("üretim repo'sunda kişisel build scriptleri").
- **Technical Impact:** Düşük doğrudan risk; orta uzun-vadeli karışıklık.
- **Remediation:** `git rm` ile bu 9 dosyayı kaldır; gerçek kaynak `src/tic/api/`'de. `.gitignore`'a `_setup_part*.py` ekle.
- **Confidence:** High.

---

#### D-1 — CI lint, pyproject ruff konfigürasyonunu uygulamıyor

- **Severity:** Medium
- **Kanıt:** `ci.yml:46` → `ruff check src tests --select F,E9`. Oysa `pyproject.toml:63` tam kural seti `["E","F","W","I","B","UP","S","A","C4","PT","RET","SIM","TCH","PL"]` tanımlıyor. CI yalnızca pyflakes + sözdizimi hatalarını kontrol ediyor.
- **Risk:** Güvenlik-ilgili `S` (bandit-benzeri), `B` (bugbear), kalite kuralları CI gate'inden geçmiyor.
- **Remediation:** `ci.yml`'de `--select F,E9` kaldırılıp tam config kullanılmalı (`ruff check src tests`), `tests/` için per-file-ignore ile (bkz. D-2).
- **Confidence:** High.

---

#### D-2 — `tests/` altında 275 ruff ihlali

- **Severity:** Medium (Code Quality)
- **Kanıt:** `poetry run ruff check src tests` → **Found 275 errors**; tamamı `tests/` altında (`src` temiz). Örnekler: `test_bulkhead.py:12 PT023`, `test_ioc_normalization.py:12 PT006`, çok sayıda `TCH001/003`, `PT018`. `pyproject.toml:66-67` zaten `tests/**` için `S101/S105/S106/PLR2004` ignore'luyor ama PT/TCH/SIM/C4 değil.
- **Risk:** Test kodu kalite sürüklenmesi; tam ruff CI'a (D-1) geçilirse pipeline kırılır.
- **Remediation:** `ruff check --fix` (38 otomatik düzeltilebilir) + `tests/**` per-file-ignore genişletme. D-1 ile birlikte ele alınmalı.
- **Confidence:** High.

---

#### D-3 — pip-audit `--strict` tutarsızlığı (ci.yml vs security.yml)

- **Severity:** Medium
- **Kanıt:** `ci.yml:79` → `pip-audit --ignore threat-intel-correlator` (strict değil, uyarı verir ama geçer). `security.yml:75` → `pip-audit --strict ...` (CVE varsa kırar). Şu an C-1'deki 18 CVE nedeniyle **security.yml fail eder, ci.yml geçer.**
- **Risk:** Hangi pipeline'ın "doğru" gate olduğu belirsiz; PR'lar ci.yml'den temiz geçip nightly security.yml'de kırılır.
- **Remediation:** C-1 kapatıldıktan sonra her iki workflow `--strict` olmalı; tutarlılaştırılmalı.
- **Confidence:** High.

---

#### D-4 — GitHub Actions pin tutarsızlığı (tag vs SHA)

- **Severity:** Medium (Supply Chain)
- **Kanıt:**
  - `release.yml` → **tüm** action'lar SHA-pinned (`actions/checkout@11bd71...`, `trivy-action@915b19...`). ✅
  - `ci.yml` → tag-pinned (`actions/checkout@v4`, `setup-python@v5`, `snok/install-poetry@v1`, `actions/cache@v4`). ⚠️
  - `security.yml` → tag-pinned (`gitleaks/gitleaks-action@v2`, `actions/checkout@v4`). ⚠️
- **Risk:** Tag'ler değiştirilebilir (mutable); bir third-party action'ın tag'i ele geçirilirse CI'a kötü amaçlı kod girer (supply-chain). SLSA L3 release'in titizliği CI/security'de korunmamış.
- **Remediation:** `ci.yml` ve `security.yml`'deki tüm action'ları immutable SHA'ya pinle (release.yml'i örnek al).
- **Confidence:** High.

---

#### D-5 — Lockfile sürüklenmesi (pyproject kısıtları vs kurulu sürümler)

- **Severity:** Medium
- **Kanıt:** `pyproject.toml:33` `starlette>=0.49.1` ⇒ kurulu `1.0.0`; `python-multipart>=0.0.27` ⇒ `0.0.29`. Major sürüm sıçramaları (`starlette 0.x → 1.0`) lockfile'da var; pyproject lower-bound'ları güncellenmemiş.
- **Risk:** Geçişli major yükseltmeler test edilmemiş davranış değişikliği taşıyabilir; reprodüksiyon zorlaşır.
- **Remediation:** Bağımlılık güncellemesi (C-1) sonrası pyproject lower-bound'ları ve lock yeniden senkronlanmalı.
- **Confidence:** Medium.

---

### 🟢 LOW / INFORMATIONAL

---

#### E-1 — `otel/decorators.py` %0 coverage

- **Severity:** Low
- **Kanıt:** pytest --cov → `infra/otel/decorators.py 55 55 0%` (21-97 satırları hiç çalıştırılmamış); `otel/setup.py 58%`.
- **Risk:** OTel decorator yolu hiç test edilmemiş; bir regresyon sessizce kaçar. Genel %86.74 cov bunu maskeliyor.
- **Remediation:** Decorator'lar için en az smoke/wiring testi ekle.
- **Confidence:** High.

---

#### E-2 — Frontend AI-render güvenlik testi sessizce skip ediliyor

- **Severity:** Low
- **Kanıt:** `tests/security/test_frontend_ai_rendering.py:42,57` → `SKIPPED: frontend/components/finding-detail.tsx not present`. Gerçek dosya adı `frontend/components/findings-detail-drawer.tsx` (yeniden adlandırılmış). Test eski adı arıyor → her zaman skip.
- **Risk:** Frontend'de AI summary'nin güvenli render edildiğini doğrulayan test fiilen koşmuyor. (Manuel doğrulama: `dangerouslySetInnerHTML` repo'da yok → fiili XSS riski düşük, ama test kalkanı pasif.)
- **Remediation:** Testteki dosya yolunu güncel bileşene güncelle.
- **Confidence:** High.

---

#### E-3 — Audit `_last_record` 8KB tail okuması

- **Severity:** Informational
- **Kanıt:** `hash_chain.py:85-103` son kaydı dosya sonundan 8192 byte okuyup parse ediyor.
- **Risk:** Tek bir audit kaydı 8KB'ı aşarsa `prev_hash` yanlış hesaplanabilir. Pratikte payload'lar küçük (metadata-only) → gerçekleşmesi düşük.
- **Remediation:** Yorumda varsayımı belgele veya kayıt başına boyut sınırı ekle.
- **Confidence:** Medium.

---

#### E-4 — `app.py` / Streamlit referansları kaynakta kalıntı

- **Severity:** Informational
- **Kanıt:** `src/tic/ui/adapter.py:5` docstring "The Streamlit page (app.py) is the only consumer" der; ama `app.py` repo'da yok (commit `adb94a4`/`6e2ade7`/`3f07107` ile temizlenmiş). `pyproject.toml:27,36` hâlâ opsiyonel `streamlit` ekstrası tanımlıyor (tornado CVE'sinin kaynağı — C-1).
- **Risk:** Kafa karışıklığı; ölü opsiyonel bağımlılık CVE yüzeyi getiriyor.
- **Remediation:** Streamlit ekstrası gerçekten kullanılmıyorsa kaldır (tornado CVE zincirini de keser); docstring güncelle.
- **Confidence:** High.

---

## 6. OWASP Top 10 (2021) Eşleme Tablosu

| OWASP | Durum | Kanıt |
|---|---|---|
| A01 Broken Access Control | N/A (tasarım) | Localhost-only, auth yok; CORS allowlist `main.py:68-71`. Açık dağıtımda auth eklenmeli. |
| A02 Cryptographic Failures | ✅ İyi | HMAC-SHA256 pseudonym (`crypto.py`), audit HMAC chain, min 32-byte key (`redaction.py:68`). |
| A03 Injection | ✅ İyi | SQL parametreli (`sqlite_cache.py:48-51`); CSV-injection (`csv_injection.py`); `eval/exec/pickle` yok. |
| A04 Insecure Design | ✅ İyi | THREAT_MODEL.md + STRIDE; AI "narrator-only" invariantı (ADR-0003). |
| A05 Security Misconfiguration | ⚠️ B-1, D-3, D-4 | Audit env adı kırık; CI gate tutarsız. |
| A06 Vulnerable Components | ⚠️ C-1 | 18 CVE. |
| A07 Auth Failures | N/A (tasarım) | Localhost-only. |
| A08 Data Integrity Failures | ✅ Güçlü | SLSA L3 release, Cosign, SBOM, hash-chained audit. |
| A09 Logging/Monitoring | ✅ İyi | structlog + redaction (`logging.py:16`), audit chain, Prometheus metrics. |
| A10 SSRF | ✅ Güçlü | `ssrf_guard.py` — metadata bloku allowlist'ten önce, DNS-rebind CIDR check, redirect re-check. |

## 7. STRIDE Özeti

| Tehdit | Güven sınırı | Kontrol | Artık risk |
|---|---|---|---|
| **S**poofing | İstemci→API | Localhost bind + CORS | Açık dağıtımda auth yok |
| **T**ampering | Audit log | SHA-link + HMAC chain | Trailing truncation (belgeli, `hash_chain.py:23-26`) |
| **R**epudiation | Sweep eylemleri | Correlation-id + audit | — |
| **I**nfo Disclosure | API→Frontend | PublicFinding DTO, redaction, no-raw | Düşük |
| **D**oS | Upload/enrich | Size cap (256MB), rate-limit, deadline, bounded body | C-1 multipart CVE |
| **E**levation | Provider HTTP | SSRF guard, no shell-out | — |

---

## 8. GERÇEK ÇALIŞTIRMA SONUÇLARI (özet)

| Araç | Komut | Sonuç |
|---|---|---|
| pytest | `pytest -q` (cov'lu) | ✅ **743 passed, 5 skipped**, 221.77s, exit 0 |
| coverage | `--cov=tic --cov-fail-under=85` | ✅ **%86.74** (eşik 85) |
| mypy | `mypy src` | ✅ **0 hata** (95 dosya), strict |
| ruff | `ruff check src tests` | ⚠️ **275 hata** (tamamı tests/; src temiz) |
| bandit | `bandit -r src -ll` | ✅ **0 medium/high** (7 low) |
| pip-audit | `pip-audit` | ⚠️ **18 CVE / 6 paket** |
| git grep sink | `pickle\|yaml.load\|eval\|exec\|os.system\|subprocess\|marshal` | ✅ src'de **tehlikeli sink yok** (sadece `re.compile`, `yaml.safe_load`) |
| docker build | `docker build .` | ⛔ **Yetersiz Kanıt** (daemon kapalı) |
| helm template | — | ⛔ **Yetersiz Kanıt** (helm kurulu değil; manifest statik incelendi, sağlam) |
| settings (B-1) | `env -i` + Docker env | 🔴 **ConfigError reprodüksiyonu** |

Skip nedenleri (meşru): Windows symlink (admin gerekli), Streamlit kaynağı yok, frontend `finding-detail.tsx` yok (E-2).

---

## 9. Performans / Bellek / Reliability (kanıt)

- **Concurrency:** Tek global `asyncio.Semaphore` tüm IOC'ler arası enrichment'ı sınırlar (`orchestrator.py:90`); deterministik sıralama korunur (`orchestrator.py:116,146`).
- **Deadline:** Opsiyonel sweep bütçesi; aşılırsa partial-but-valid + audit flag (`orchestrator.py:138-151`).
- **Bounded kaynaklar:** match cap (`max_matches`), enrichment cap (`[:16]`), upload size cap (256MB, `main.py:79`), streaming read (`main.py:139-153`), bounded response body (16MB, `safe_client.py:231-239`), rate-limit client eviction (`_MAX_TRACKED_CLIENTS=4096`).
- **httpx loop-aware aclose** (`safe_client.py:115-141`) — cross-loop leak'i loglar.
- **Reliability:** circuit breaker + bulkhead adapter'ları mevcut (`adapters/http/`); fail-closed config (`config.py:326-340`), fail-closed hash-mode (`adapter.py:234-242`).
- **HA sınırı:** `deployment.yaml:33-37` `replicas: 1` + `Recreate` — in-memory CB/metrics nedeniyle yatay ölçeklenmiyor (belgeli; Redis backend gerekir).

## 10. Veritabanı & Gizlilik

- SQLite cache: parametreli sorgu (`sqlite_cache.py:48-51,65-70`), WAL, 0600 perms, TTL + index. ✅
- Redaction: allowlist (`redaction.py` — sadece pseudonym + generic field tipi + sayımlar AI'ya gider); TCKN/SSN/email/bearer pattern'leri (`redaction_patterns.py`). ✅
- Public DTO sınırı: raw log/provider payload asla API'den dönmüyor (`main.py:174-184`, adapter docstring). ✅

---

## 11. EN YÜKSEK ROI İYİLEŞTİRMELER

| Öncelik | İyileştirme | Etki | Zorluk |
|---|---|---|---|
| **P0** | B-1: `AUDIT_CHAIN`→`AUDIT_LOG_PATH` (Dockerfile + k8s) | Konteyner dağıtımını kurtarır | Çok düşük (2 satır) |
| **P0** | C-1: bağımlılıkları yükselt (starlette/multipart/tornado…) | 18 CVE kapatır | Düşük |
| **P1** | D-1+D-2: tam ruff CI + tests/ ignore + `--fix` | Kalite gate'i gerçekleştirir | Orta |
| **P1** | D-4: ci/security action'ları SHA-pin | Supply-chain CI'ı sertleştirir | Düşük |
| **P2** | A-1: `_setup_part*.py` + kök kopyaları `git rm` | Repo hijyeni | Çok düşük |
| **P2** | E-2: frontend güvenlik test yolunu düzelt | XSS test kalkanını aktive eder | Çok düşük |
| **P3** | E-1: otel/decorators testi; E-4: streamlit ekstrasını kaldır | Cov + CVE yüzeyi | Düşük |

---

## 12. Teknik Borç

**Seviye: Düşük-Orta.** Çekirdek kaynak (`src/`) borç açısından çok temiz (mypy strict, bandit temiz, %90+ cov çoğu modülde). Borç ağırlıklı **çevre katmanında** birikmiş: (1) repo hijyeni (A-1), (2) CI/CD tutarsızlıkları (D grubu), (3) konteyner konfig hatası (B-1), (4) bağımlılık güncellemesi (C-1). Hiçbiri mimari refactor gerektirmiyor; hepsi konfig/operasyon düzeyinde.

---

## 13. RED TEAM — En Sömürülebilir Yollar (sıralı)

1. **(Açık dağıtımda) python-multipart/starlette CVE'leri** (C-1) — `/api/sweep` multipart endpoint'i doğrudan hedef; DoS/parsing. Yerel-loopback'te ulaşılamaz.
2. **SSRF allowlist residual** — allowlisted host + `allowed_host_cidrs` boşsa, o host DNS-rebind ile farklı internal IP'ye çözülebilir (`ssrf_guard.py:72-78`'de **belgeli** artık risk; metadata bloku yine de geçerli). Operatör CIDR tanımlayarak kapatabilir.
3. **Audit truncation** — write erişimi olan bir saldırgan trailing signed kayıtları kesebilir (`hash_chain.py:23-26` belgeli; out-of-band anchor kapsam dışı).
4. **Privilege escalation / lateral movement:** k8s'te **etkin yol yok** — non-root (1001), drop ALL caps, readOnlyRootFS, no SA token, restrictive NetworkPolicy egress (DNS+provider CIDR only). Güçlü zero-trust hizalaması.
5. **Exfiltration:** PublicFinding DTO + redaction nedeniyle raw veri/secret API'den çıkmıyor; AI'ya giden veri pseudonymize.

---

## 14. NİHAİ KARAR

**Güvenlik olgunluğu:** Yüksek (AppSec kontrolleri gerçek + testli; bandit/sink temiz).
**Mimari olgunluk:** Yüksek (temiz hexagonal, strict tipli).
**Mühendislik olgunluğu:** Yüksek (743 test, %86.74 cov, SLSA L3 release).
**Kurumsal/operasyonel olgunluk:** Orta (konteyner konfig hatası + CVE'ler + CI tutarsızlıkları).

### "Google/Microsoft/Amazon/Cloudflare/Palantir ciddi incelemesinden geçer mi?"

**Kod kalitesi & güvenlik tasarımı katmanında: EVET, geçer.** Hexagonal mimari, strict tipler, derinlemesine güvenlik kontrolleri (SSRF/path/CSV/prompt-injection), tamper-evident audit, SLSA L3 release zinciri ve %86.74 test coverage'ı — bunlar üst-düzey bir firma code review'ında olumlu karşılanır. `src/` çekirdeği "principal-level" işçilik gösteriyor.

**Operasyonel/dağıtım katmanında: HAYIR, mevcut hâliyle geçmez** — ve nedeni tek kelimeyle kanıtlı: **B-1.** Bir "production-ready" iddiasındaki Dockerfile + k8s manifesti, var olmayan bir env değişkeni yüzünden konteynerde **hiç çalışmıyor.** Bu tür bir review'da bu, "manifestler hiç gerçek bir kümede test edilmemiş" sonucunu doğurur ve güveni zedeler. Ayrıca 18 açık CVE ve CI lint gate'inin fiilen devre dışı olması (D-1) "shift-left iddiası ile gerçek arasında boşluk" olarak işaretlenir.

**Sonuç:** Bu, **mükemmel çekirdeğe sahip ama dağıtım/operasyon katmanı henüz doğrulanmamış** bir projedir. P0 bulguları (B-1, C-1) — toplam birkaç saatlik iş — kapatıldığında, yerel ve tek-kullanıcı internete-açık senaryolar için **Ready/Enterprise-Ready'e çok yakın** hâle gelir. Çok-kiracılı kurumsal SaaS, tasarım gereği kapsam dışıdır (auth/tenant izolasyonu yok) ve ayrı bir mimari çalışma gerektirir.

---

*Rapor sonu. Hiçbir kaynak dosya değiştirilmedi; tek yazılan dosya budur.*
