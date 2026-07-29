# Threat Intel Correlator -- frontend (Next.js) container image.
#
# Multi-stage:
#   * deps    -- install node_modules from the lockfile only (cache-friendly).
#   * builder -- `next build` with output:"standalone" produces a self-contained
#                server under .next/standalone.
#   * runtime -- node:22-slim, NON-ROOT (UID/GID 1001), only the standalone
#                bundle + static assets. No dev toolchain, no full node_modules.
#
# NEXT_PUBLIC_API_BASE is baked at BUILD time (it is a client bundle constant)
# and the browser -- not this container -- calls it, so it must point at a host
# address reachable from the browser (http://localhost:8000), not a compose
# service name. The frontend's api.ts guard also rejects non-loopback hosts.

# ---- deps ------------------------------------------------------------------
FROM node:22-slim AS deps
WORKDIR /app
# On Windows/WSL2 the engine can OOM-crash mid-install when npm parallelises
# native builds (lightningcss/oxide). Cap heap + serialise fetches to keep the
# build daemon alive.
ENV NODE_OPTIONS=--max-old-space-size=2048 \
    npm_config_jobs=1 \
    npm_config_fund=false \
    npm_config_audit=false
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---- builder ---------------------------------------------------------------
FROM node:22-slim AS builder
WORKDIR /app
ARG NEXT_PUBLIC_API_BASE=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE} \
    NEXT_TELEMETRY_DISABLED=1 \
    NODE_OPTIONS=--max-old-space-size=2048
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ---- runtime ---------------------------------------------------------------
FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Non-root user (UID/GID 1001).
RUN groupadd --gid 1001 tic \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin tic

# The standalone bundle carries only the node_modules it actually needs.
# Static assets + public/ are copied alongside it as Next expects at runtime.
COPY --from=builder --chown=1001:1001 /app/.next/standalone ./
COPY --from=builder --chown=1001:1001 /app/.next/static ./.next/static
COPY --from=builder --chown=1001:1001 /app/public ./public

USER 1001
EXPOSE 3000

# Readiness: Next serves 200 on "/" once up. Uses node's stdlib http, no extra deps.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"]

CMD ["node", "server.js"]
