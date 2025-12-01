# ---------- Stage 1: build arkeod, api, indexer, sentinel, tools ----------
FROM golang:1.22 AS builder

RUN apt-get update && apt-get install -y git make build-essential curl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Clone latest Arkeo source (public repo)
RUN git clone --branch Upgrade-for-v1.0.16 --single-branch https://github.com/arkeonetwork/arkeo.git

WORKDIR /src/arkeo

# Build: arkeod, api, indexer, sentinel
RUN make install

# Build: extra tools (signing utilities, helpers, etc.)
RUN make tools

# Show all compiled binaries
RUN ls -al $(go env GOPATH)/bin/


# ---------- Stage 2: Runtime container ----------
FROM debian:12-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    supervisor \
    python3 \
    python3-venv \
    python3-flask \
    jq \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all binaries produced by make install + make tools
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy configs (genesis.json, config.toml, sentinel-config.yaml)
COPY config/ /app/config/

# Copy simple admin UI
COPY admin/ /app/admin/
COPY admin_api.py /app/admin_api.py
COPY cache_fetcher.py /app/cache_fetcher.py

# Supervisor + entrypoint
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose the admin UI (8080) and admin API (9999).
EXPOSE 8080 9999

ENTRYPOINT ["/app/entrypoint.sh"]
