# deploy/demo/Dockerfile -- image for the PUBLIC DEMO deployment only.
#
# Why this exists separately from the root Dockerfile:
#   * The root image is local-first: it binds 127.0.0.1 via ENTRYPOINT +
#     CMD in exec form, and deploy/k8s/deployment.yaml overrides only the
#     args. That contract must not change.
#   * A managed PaaS (Render/Fly/etc.) injects the listen port as $PORT at
#     RUNTIME and requires a 0.0.0.0 bind. Exec form cannot expand $PORT,
#     and the platform's "custom command" field only replaces CMD, so the
#     bind address has to be baked into the image instead.
#
# Build stages are intentionally identical to the root Dockerfile; only the
# final ENTRYPOINT/CMD differ. Keep them in sync when the root one changes.
#
# This image is ONLY safe to expose publicly with TIC_DEMO_MODE=1, which
# disables the file-upload endpoint (see src/tic/api/_demo.py).

# ---- builder ---------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.8.3

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /build
COPY pyproject.toml poetry.lock README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && poetry build --format wheel \
 && WHEEL="$(ls dist/*.whl)" \
 && /opt/venv/bin/pip install --no-cache-dir "${WHEEL}[api]"

# ---- runtime ---------------------------------------------------------------
FROM python:3.11-slim AS runtime

RUN groupadd --gid 1001 tic \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin tic

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    TIC_PATHS__WORKING_DIR=/app/data \
    TIC_PATHS__CACHE_DIR=/app/data/cache \
    TIC_PATHS__AUDIT_LOG_PATH=/app/data/audit_chain.jsonl \
    TIC_SECRET_BACKEND=env \
    TIC_DEMO_MODE=1

RUN mkdir -p /app/data/cache && chown -R 1001:1001 /app

WORKDIR /app
USER 1001

# Documentation only; the platform routes to whatever $PORT it injects.
EXPOSE 8000

# Shell form so $PORT expands at runtime. 8000 is the fallback for a plain
# `docker run` with no platform variables. The platform provides its own
# health checking, so no HEALTHCHECK here.
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec uvicorn tic.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
