# Arkeo Dashboard Core (Docker Image)

Cache-only admin UI + API that reuses the subscriber-core sync pipeline (arkeod + tools) without wallets, listeners, or sentinel control. It keeps a synced marketplace cache that other components can read.

## Quick dev run
```bash
# build
docker build -t arkeonetwork/dashbord-core:dev .

# run (UI defaults to 8077 in the container, API to 9996)
mkdir -p ~/dashbord-core/config ~/dashbord-core/cache ~/dashbord-core/arkeo
docker run --rm --name dashbord-core-dev \
    --env-file dashbord.env \
    -e ENV_ADMIN_PORT=8079 \
    -p 8079:8077 -p 9996:9996 \
    -v ~/dashbord-core/config:/app/config \
    -v ~/dashbord-core/cache:/app/cache \
    -v ~/dashbord-core/arkeo:/root/.arkeo \
    arkeonetwork/dashbord-core:dev
```

Environment hints for `dashbord.env`:
```
# Which node and REST API to use for cache fetches
ARKEOD_NODE=tcp://provider1.innovationtheory.com:26657
EXTERNAL_ARKEO_REST_API=http://provider1.innovationtheory.com:1317

# Optional port overrides inside the container
ENV_ADMIN_PORT=8077
ADMIN_API_PORT=9996

# Cache loop interval (seconds). Set 0 to disable background fetches.
CACHE_FETCH_INTERVAL=300

# Block height poll interval (seconds) for dashboard_info.json
BLOCK_HEIGHT_INTERVAL=60

# Average block time (seconds) used for duration calculations
BLOCK_TIME_SECONDS=5.79954919
```

Volumes:
- `/app/cache` holds the synced marketplace JSON.
- `/app/config` is available for future config files.
- `/root/.arkeo` is the arkeod home (for status queries/tools).

Env knobs:
- `CACHE_INIT_ON_START` (default `1`) to enable/disable the initial cache sync during startup.
- `CACHE_INIT_TIMEOUT` (default `120`) seconds to cap the one-time sync so container startup doesn’t block indefinitely.
- `CACHE_FETCH_INTERVAL` (default `300`) seconds for the background sync loop; set to `0` to disable.
- `BLOCK_HEIGHT_INTERVAL` (default `60`) seconds for updating `dashboard_info.json` with latest block height.
- `BLOCK_TIME_SECONDS` (default `5.79954919`) average block time baked into `dashboard_info.json`.
- `ALLOW_LOCAL_METADATA` (default `0`) set to `1` to allow `metadata_uri` hosts on localhost/127.0.0.1 during testing.

UI is currently header/footer only; API endpoints mirror the subscriber sync surface (`/api/cache-refresh`, `/api/cache-status`, `/api/cache-counts`, `/api/providers-with-contracts`, `/api/block-height`, etc.).
