# Arkeo Data Engine - Subscriber

This Docker image provides an Admin UI and API to operate a subscriber hot wallet, build a local cache of the Arkeo Data Marketplace, and expose listener proxies that automatically create and fulfill pay-as-you-go contracts with top providers. This lets your apps consume node data securely and cost-effectively.

<details>
<summary><strong>Preview the Arkeo Data Engine - Subscriber admin UI</strong></summary>
<a href="../images/arkeo-data-engine-subscriber-2.jpg">
  <img src="../images/arkeo-data-engine-subscriber-2.jpg" alt="Subscriber admin UI overview" width="800" />
</a>
</details>

## Install Docker on Your Host
Before you start, install Docker on your host and be familiar with basic Docker commands such as start/stop, logs, and pull. Use your OS vendor's Docker docs.

## Run the Latest Arkeo Data Engine - Subscriber Docker Image
```
#!/usr/bin/env bash
set -euo pipefail

# create host dirs
mkdir -p ~/arkeo-data-engine-subscriber/config \
         ~/arkeo-data-engine-subscriber/cache \
         ~/arkeo-data-engine-subscriber/arkeo

# stop/remove any existing container with this name (race-safe)
docker rm -f arkeo-data-engine-subscriber 2>/dev/null || true

# wait until Docker fully releases the name
while docker ps -a --format '{{.Names}}' | grep -q '^arkeo-data-engine-subscriber$'; do
  sleep 1
done

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/arkeo-data-engine-subscriber:latest

# run
docker run -d --name arkeo-data-engine-subscriber --restart=unless-stopped \
  -e ADMIN_PORT=8079 \
  -e ADMIN_API_PORT=9998 \
  -p 8079:8079 \
  -p 9998:9998 \
  -p 62001-62100:62001-62100 \
  -v ~/arkeo-data-engine-subscriber/config:/app/config \
  -v ~/arkeo-data-engine-subscriber/cache:/app/cache \
  -v ~/arkeo-data-engine-subscriber/arkeo:/root/.arkeo \
  ghcr.io/arkeonetwork/arkeo-data-engine-subscriber:latest
```

## Configure Subscriber Settings
Settings are persisted in `/app/config/subscriber-settings.json` (host-mounted to `~/arkeo-data-engine-subscriber/config/subscriber-settings.json`). Manage them in the Admin UI (Settings) or preseed the file before first run; no `subscriber.env` is required.

## Secure the Admin Endpoints
- The Admin UI and API are HTTP only and manage the hot wallet. Treat them as sensitive and do not expose them to the public internet.
- Restrict ports 8079 and 9998 to your IP using firewall or security group rules, or keep them behind a private network/VPN.
- Expose listener ports (62001-62100) publicly only if required.
- Optional: bind the admin ports to localhost only (for example, `-p 127.0.0.1:8079:8079 -p 127.0.0.1:9998:9998`).

## Getting ARKEO Tokens
In the Hot Wallets panel, use the buttons to bridge funds from other chains into Osmosis and Arkeo. Keplr provides secure signing for Osmosis transactions. Keep some OSMO for gas.

## Using the Admin UI
- Admin UI (HTTP): `http://<host>:8079` (or `http://localhost:8079`).
- The header shows your subscriber pubkey and address. Fund the hot wallet with a small amount of ARKEO; this is a hot wallet.
- The initial sync may take several minutes. By default it refreshes about every 150 seconds. To disable the background loop, set `CACHE_FETCH_INTERVAL=0` (manual "Refresh" still works).

## Add Listeners (Proxies)
- Each listener exposes a port that wraps Arkeo subscriber contract handling, including automatic PAYG contract creation when needed.
- When you add a listener, it auto-selects top providers from the Arkeo Data Marketplace for that service.
- Set a per-listener IP whitelist to restrict who can access the exposed port.
- Your external app points at this subscriber's IP and listener port. Use the "Test" action on the listener row to see the exact curl and payload format.

## Cache, Config, and Logs
- Cache and listener state: `/app/cache` (host-mounted to `~/arkeo-data-engine-subscriber/cache`).
- Config: `/app/config` (host-mounted to `~/arkeo-data-engine-subscriber/config`).
- Listener data: `/root/.arkeo` (host-mounted to `~/arkeo-data-engine-subscriber/arkeo`).
- Logs: `/var/log` in the container (for example, `/var/log/subscriber-api.log`).

## That’s It
- You are now consuming the [Arkeo Data Marketplace](https://marketplace.builtonarkeo.com/).
