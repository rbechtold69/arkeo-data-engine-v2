# ---------- Stage 1: build arkeod and helper tools ----------
FROM golang:1.22 AS builder

RUN apt-get update && apt-get install -y git make build-essential curl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Clone Arkeo source (same branch used by subscriber-core)
RUN git clone --branch Upgrade-for-v1.0.16 --single-branch https://github.com/arkeonetwork/arkeo.git

WORKDIR /src/arkeo

# Build: arkeod, api, indexer, sentinel
RUN make install

# Build: extra tools (signing utilities, helpers, etc.)
RUN make tools

# ---------- Stage 2: runtime container ----------
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

# Copy configs and admin assets
COPY config/ /app/config/
COPY admin/ /app/admin/
COPY admin_api.py /app/admin_api.py
COPY cache_fetcher.py /app/cache_fetcher.py
COPY dashboard_info.py /app/dashboard_info.py

# Supervisor + entrypoint
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose the admin UI (8077) and admin API (9996).
EXPOSE 8077 9996

ENTRYPOINT ["/app/entrypoint.sh"]
