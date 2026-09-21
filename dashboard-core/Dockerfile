# ---------- Stage 1: build arkeod and helper tools ----------
FROM golang:1.24 AS builder

RUN apt-get update && apt-get install -y git make build-essential curl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Reproducible candidate source; coordinate changes with the sentinel review.
ARG ARKEO_REPOSITORY=https://github.com/rbechtold69/arkeo.git
ARG ARKEO_REF=e4830e6e4f0d4792aceff571c26392de942be784
RUN git init arkeo && cd arkeo \
    && git remote add origin "${ARKEO_REPOSITORY}" \
    && git fetch --depth 1 origin "${ARKEO_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /src/arkeo

# Build: arkeod, api, indexer, sentinel
RUN make install

# Build: extra tools (signing utilities, helpers, etc.)
RUN make tools

# ---------- Stage 2: build dashboard assets ----------
FROM node:20-alpine AS frontend

WORKDIR /frontend

COPY package*.json /frontend/
COPY tailwind.config.cjs /frontend/tailwind.config.cjs
COPY admin/index.html /frontend/admin/index.html
COPY admin/src/ /frontend/admin/src/

RUN npm ci --ignore-scripts
RUN npm run build

# ---------- Stage 3: runtime container ----------
FROM debian:12-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    supervisor \
    python3 \
    python3-venv \
    python3-flask \
    nginx \
    openssl \
    jq \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all binaries produced by make install + make tools
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy configs and admin assets
COPY config/ /app/config/
COPY admin/ /app/admin/
COPY --from=frontend /frontend/admin/build/ /app/admin/build/
COPY admin_api.py /app/admin_api.py
COPY cache_fetcher.py /app/cache_fetcher.py
COPY dashboard_info.py /app/dashboard_info.py

# Supervisor + entrypoint
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose HTTP/HTTPS for the dashboard, plus the API port.
EXPOSE 80 443 9996

ENTRYPOINT ["/app/entrypoint.sh"]
