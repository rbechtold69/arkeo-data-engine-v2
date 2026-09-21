# ---------- Stage 1: build arkeod, api, indexer, sentinel, tools ----------
FROM golang:1.24 AS builder

RUN apt-get update && apt-get install -y git make build-essential curl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Reproducible candidate source; coordinate changes with the sentinel review.
ARG ARKEO_REPOSITORY=https://github.com/rbechtold69/arkeo.git
ARG ARKEO_REF=e16dbf84f8874e06d52677e4036bbec983baa226
RUN git init arkeo && cd arkeo \
    && git remote add origin "${ARKEO_REPOSITORY}" \
    && git fetch --depth 1 origin "${ARKEO_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /src/arkeo

# Build: arkeod, api, indexer, sentinel
RUN make install

# Build: extra tools (signing utilities, helpers, etc.)
RUN make tools

# Fetch osmosisd release binary (v25.0.0) for key mgmt/signing
RUN curl -L https://github.com/osmosis-labs/osmosis/releases/download/v25.0.0/osmosisd-25.0.0-linux-amd64 -o /go/bin/osmosisd \
    && chmod +x /go/bin/osmosisd

# Show all compiled binaries
RUN ls -al $(go env GOPATH)/bin/


# ---------- Stage 2: build admin UI bundle ----------
FROM node:20-bullseye AS ui-builder
WORKDIR /app/admin

COPY admin/package*.json ./
RUN npm ci --ignore-scripts
COPY admin/src ./src
RUN mkdir -p vendor && npm run build


# ---------- Stage 3: Runtime container ----------
FROM debian:12-slim
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    supervisor \
    python3 \
    python3-venv \
    python3-flask \
    python3-requests \
    jq \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all binaries produced by make install + make tools
COPY --from=builder /go/bin/* /usr/local/bin/
COPY --from=builder /go/bin/osmosisd /usr/local/bin/

# Copy configs (genesis.json, config.toml, sentinel-config.yaml)
COPY config/ /app/config/

# Copy simple admin UI
COPY admin/ /app/admin/
COPY --from=ui-builder /app/admin/vendor/cosmos.bundle.js /app/admin/vendor/cosmos.bundle.js
COPY admin_api.py /app/admin_api.py
COPY run_sentinel.sh /app/run_sentinel.sh
COPY claim_cron.sh /app/claim_cron.sh
RUN chmod +x /app/run_sentinel.sh
RUN chmod +x /app/claim_cron.sh

# Supervisor + entrypoint
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose the admin UI (8080), admin API (9999), and sentinel metadata (3636).
# arkeod RPC/REST remain unexposed.
EXPOSE 8080 9999 3636

ENTRYPOINT ["/app/entrypoint.sh"]
