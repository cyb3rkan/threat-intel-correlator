# Threat Intel Correlator -- container image.
#
# Multi-stage:
#   * builder  -- poetry builds a wheel; it is installed (with the `api` extra:
#                 fastapi / uvicorn / python-multipart) into an isolated venv.
#   * runtime  -- python:3.11-slim, NON-ROOT (UID/GID 1001), no build toolchain,
#                 only the venv plus the app's writable data dir.
#
# Local-first: the default CMD binds 127.0.0.1 (loopback only). Cluster
# deployments override the bind address to 0.0.0.0 via `args`
# (see deploy/k8s/deployment.yaml); there the NetworkPolicy + non-root + the
# read-only root filesystem are the network/privilege boundary.
#
# Read-only root filesystem: the app writes ONLY under /app/data (SQLite cache +
# the Part-2 audit_chain.jsonl) and /tmp (upload staging). Mount writable volumes
# at both when running with readOnlyRootFilesystem=true.

# ---- builder ---------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.8.3

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /build
COPY pyproject.toml poetry.lock README.md ./
COPY src ./src

# Build a wheel and install it + the `api` extra into a self-contained venv.
# No dev/test dependencies, no build toolchain leaks into the runtime stage.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && poetry build --format wheel \
 && WHEEL="$(ls dist/*.whl)" \
 && /opt/venv/bin/pip install --no-cache-dir "${WHEEL}[api]"

# ---- runtime ---------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Non-root user/group (UID/GID 1001); no login shell, no home directory.
RUN groupadd --gid 1001 tic \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin tic

# Copy ONLY the built venv -- no poetry, no compilers in the final image.
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    TIC_PATHS__WORKING_DIR=/app/data \
    TIC_PATHS__CACHE_DIR=/app/data/cache \
    TIC_PATHS__AUDIT_LOG_PATH=/app/data/audit_chain.jsonl

# Writable data dir owned by the non-root user. Under readOnlyRootFilesystem
# this path MUST be backed by a writable volume (emptyDir/PVC), else the cache
# and the Part-2 audit chain cannot be written. The cache subdir is created
# up-front so /api/ready (which checks cache_dir.exists()) reports ready on a
# fresh container; TIC_PATHS__CACHE_DIR points here.
RUN mkdir -p /app/data/cache && chown -R 1001:1001 /app

WORKDIR /app
USER 1001

EXPOSE 8000

# Readiness (Part-1 /api/ready): a 2xx is healthy; 5xx/refused raises and the
# probe reports unhealthy. Uses the stdlib so no extra packages are needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=3)"]

# Loopback-only by default; clusters override these args with --host 0.0.0.0.
ENTRYPOINT ["uvicorn", "tic.api.main:app"]
CMD ["--host", "127.0.0.1", "--port", "8000"]
