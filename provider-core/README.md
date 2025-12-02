# Arkeo Provider Admin (Docker)

Containerized admin UI, API, and sentinel reverse-proxy for Arkeo providers.

Before you start, install Docker on your host and be comfortable with basic Docker commands (start/stop, logs, pull). Use your OS vendor’s Docker docs.

## Create the `provider.env` for the docker
Create `~/provider.env` (or similar) with:
```
KEY_NAME=provider
KEY_KEYRING_BACKEND=test
KEY_MNEMONIC=
CHAIN_ID="arkeo-main-v1"

ARKEOD_HOME=~/.arkeo
EXTERNAL_ARKEOD_NODE=tcp://provider1.innovationtheory.com:26657
ARKEO_REST_API_PORT=http://provider1.innovationtheory.com:1317

SENTINEL_NODE=http://provider-core-1.innovationtheory.com
SENTINEL_PORT=3636

ADMIN_PORT=8080
ADMIN_API_PORT=9999
```
- If you don’t have a mnemonic, leave `KEY_MNEMONIC` empty. On first launch the container will create a hotwallet and print the mnemonic; copy it and paste it back into `provider.env`.

## Run the latest Provider Core docker image
```bash
# create host dirs
mkdir -p ~/provider-core/config ~/provider-core/arkeo

# stop/remove any existing container with this name
docker stop provider-core || true
docker rm provider-core || true

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/provider-core:latest

# run
docker run -d --name provider-core --restart=unless-stopped \
  --env-file ~/provider.env \
  -e ENV_ADMIN_PORT=8080 \
  -p 8080:8080 -p 3636:3636 -p 9999:9999 \
  -v ~/provider-core/config:/app/config \
  -v ~/provider-core/arkeo:/root/.arkeo \
  ghcr.io/arkeonetwork/provider-core:latest
```

- Open firewall for ports 8080 (admin UI), 9999 (admin API), 3636 (sentinel).
- Admin UI: `http://<host>:8080`
- Copy the Arkeo address shown at the top; fund the address with a small amount of ARKEO (hotwallet).
- In Admin: configure sentinel (so your provider is discoverable).
- Add provider services: pick the service type, set RPC URI and optional user/pass. If your node is firewalled, allow the Docker host IP. The host must reach your node.
- Each provider service requires a minimum bond of 1 ARKEO to prevent spam.
- Do a Provider Export when done. Keep `provider.env` and exports safe—they contain your mnemonic.

You’re now on the Arkeo Data Marketplace.

## Getting ARKEO Tokens (using the Keplr wallet)
In Keplr, add the Osmosis chain, swap for `ARKEO` on Osmosis, then IBC-transfer it to your Arkeo address via the `ARKEO (Arkeo/channel-103074)` route. After it lands, it appears as native `ARKEO` on Arkeo. Start with a small test send and keep a little OSMO for fees.
