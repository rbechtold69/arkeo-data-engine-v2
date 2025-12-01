# Arkeo Subscriber Core (Docker)

Containerized hot-wallet admin UI + API for Arkeo subscribers. Run locally or on a server to manage a subscriber hot wallet and related settings through a web UI.

## Prerequisites
- Docker 20+ (buildkit preferred)
- An environment file with your keys and defaults (see `subscriber.env`)

## Quick Start (build locally)
```bash
cd subscriber-core
docker build -t arkeonetwork/subscriber-core:dev .
docker run --rm --env-file subscriber.env \
  -p 8080:8080 -p 9999:9999 -p 3636:3636 \
  arkeonetwork/subscriber-core:dev
```
- Admin UI: http://localhost:8080/index.html
- Admin API: http://localhost:9999
- Sentinel metadata: http://localhost:3636/metadata.json (if enabled)

## Environment
Copy `subscriber.env` and set at least:
```
`PROVIDER_NAME=(Use your subscriber name)`
`MONIKER=(Use a moniker for your subscriber)`
`WEBSITE=(Use your website)`
`DESCRIPTION=(Add a description)`
`LOCATION=(Add a location)`
`FREE_RATE_LIMIT=10`
`FREE_RATE_LIMIT_DURATION=1`

`KEY_NAME=subscriber`
`KEY_KEYRING_BACKEND=test`
`KEY_MNEMONIC=(Use your own Arkeo hot wallet mnemonic)`
`CHAIN_ID=arkeo-main-v1`

`ARKEOD_HOME=~/.arkeod`
`EXTERNAL_ARKEOD_NODE=tcp://provider1.innovationtheory.com:26657`
`ARKEO_REST_API_PORT=http://provider1.innovationtheory.com:1317`

`SENTINEL_NODE=`
`SENTINEL_PORT=`

ADMIN_PORT=8080
ADMIN_API_PORT=9999
```

The UI also persists sentinel values in `config/sentinel.env` and `config/sentinel.yaml`.

## Pull from GHCR (once published)
```bash
docker pull ghcr.io/arkeonetwork/subscriber-core:latest
docker run --rm --env-file subscriber.env \
  -p 8080:8080 -p 9999:9999 -p 3636:3636 \
  ghcr.io/arkeonetwork/subscriber-core:latest
```

## Workflow
1) Start container (above).
2) Open the Admin UI.
3) Configure subscriber settings as needed in the UI forms (defaults come from `subscriber.env`).

## Notes
- Exposed ports: 8080 (web), 9999 (admin API), 3636 (sentinel). Adjust `-p` as needed.
- Sentinel YAML lives at `/app/config/sentinel.yaml`; services are added/removed by the Provider Services form (inactive services are removed; a placeholder is only kept when no services remain).
- Claims helper jobs (if present) can be triggered via the API; see scripts in this folder for examples.
- A cache fetcher runs every 5 minutes (default) to download providers, contracts, and services from `arkeod` and stores them in `/app/cache/{provider-services,provider-contracts,service-types}.json`. Configure via `CACHE_DIR` or `CACHE_FETCH_INTERVAL` env vars. It also derives `/app/cache/active_providers.json` by fetching each provider’s external `metadata_uri` (short timeout; skipped for localhost/127.*), attaching metadata, and setting `status` (1 = fetched, 0 = missing/failed/timeout). After that it builds `/app/cache/active_services.json` for ONLINE services whose provider is active.
- Services are fetched via the REST API (`${EXTERNAL_ARKEO_REST_API}/arkeo/services`) without pagination; set `EXTERNAL_ARKEO_REST_API` to change the source. Providers/contracts use `arkeod` CLI.
- Manual refresh: call `POST /api/cache-refresh` (or use the "Refresh Cache Now" button in the UI) to immediately rebuild the cache files.
- Startup warm: set `CACHE_WARM_ON_START=1` if you want a one-time cache refresh on container start (defaults to off to avoid startup stalls).
