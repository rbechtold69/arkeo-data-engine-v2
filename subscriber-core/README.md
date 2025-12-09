# Arkeo Subscriber Admin (Docker Image)

Containerized admin UI + API that runs a subscriber hot wallet, builds a local cache of the Arkeo Data Marketplace, and exposes listener proxies that automatically create and fulfill pay-as-you-go contracts against top providers so your apps can consume node data securely, cost-effectively, and easily.

![Subscriber admin UI overview](../images/readme-subscribers-1.png)

## Install Docker on you host
Before you start, install Docker on your host and be comfortable with basic Docker commands (start/stop, logs, pull). Use your OS vendor’s Docker docs.

## Create a `subscriber.env` for the docker
Save this file next to where you run Docker (e.g., `~/subscriber-core/subscriber.env` so the volume mount works):
```
SUBSCRIBER_NAME=Arkeo Core Subscriber

KEY_NAME=subscriber
KEY_KEYRING_BACKEND=test
KEY_MNEMONIC=
CHAIN_ID="arkeo-main-v1"

ARKEOD_HOME=~/.arkeo
EXTERNAL_ARKEOD_NODE=tcp://provider1.innovationtheory.com:26657
EXTERNAL_ARKEO_REST_API=http://provider1.innovationtheory.com:1317
EXTERNAL_SENTINEL_NODE=http://docker.innovationtheory.com:3636

ADMIN_PORT=8079
ADMIN_API_PORT=9998
```
If you don’t have a mnemonic, leave `KEY_MNEMONIC` empty. On first start the container will print a generated mnemonic—copy it from the logs and paste it back into `subscriber.env` for next runs.

## Run the Subscriber Core docker image
```bash
# create host dirs
mkdir -p ~/subscriber-core/config ~/subscriber-core/cache ~/subscriber-core/arkeo

# stop/remove any existing container with this name
docker stop subscriber-core || true
docker rm subscriber-core || true

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/subscriber-core:latest

# run
docker run -d --name subscriber-core --restart=unless-stopped \
  --env-file ~/subscriber-core/subscriber.env \
  -e ENV_ADMIN_PORT=8079 \
  -p 8079:8079 -p 9998:9998 -p 62001-62100:62001-62100 \
  -v ~/subscriber-core/config:/app/config \
  -v ~/subscriber-core/cache:/app/cache \
  -v ~/subscriber-core/arkeo:/root/.arkeo \
  ghcr.io/arkeonetwork/subscriber-core:latest
```
Make sure these ports are open in your firewall.

## Using the Subscriber Core Admin
Browse to `http://localhost:8079` (or your host IP:8079).
- The header shows your subscriber pubkey and address. Fund the hot wallet with a small amount of ARKEO (it’s a hot wallet).
- The admin sync runs for a while on first load (pulls providers/contracts/services, filters inactive, builds marketplace cache). By default it repeats about every 5 minutes. To disable the background loop, set `CACHE_FETCH_INTERVAL=0` (manual “Refresh” still works).

## Add listeners (proxies)
- Each listener exposes a port that wraps Arkeo subscriber contract handling (auto PAYG contract creation when needed).
- When you add a listener, it auto-selects top providers from the Arkeo Data Marketplace for that service.
- Set a per-listener whitelist to restrict who can hit the exposed port.
- Your external app points at this subscriber’s IP and listener port. Use the “Test” action on the listener row to see the exact curl and payload format.

That’s it—you’re consuming the Arkeo Data Marketplace through your subscriber listeners. Cache and listener state live under `/app/cache` (host-mounted to `~/subscriber-core/cache`). Config is under `/app/config` (host-mounted to `~/subscriber-core/config`). Listener data is in `/root/.arkeo` (host-mounted to `~/subscriber-core/arkeo`).

## Getting ARKEO Tokens (using the Keplr wallet)
In Keplr, add the Osmosis chain, swap for `ARKEO` on Osmosis, then IBC-transfer it to your Arkeo address via the `ARKEO (Arkeo/channel-103074)` route. After it lands, it appears as native `ARKEO` on Arkeo. Start with a small test send and keep a little OSMO for fees.
