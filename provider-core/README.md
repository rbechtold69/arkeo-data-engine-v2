# Arkeo Data Engine - Provider

This Docker image includes an admin UI and API paired with the Arkeo sentinel reverse proxy. It onboards your node as an Arkeo provider, manages the provider hot wallet, bonds services, and announces them to the Arkeo Data Marketplace for pay-as-you-go access.

<details>
<summary><strong>🖼️ Preview the "Arkeo Data Engine - Provider" admin UI</strong></summary>
<a href="../images/arkeo-data-engine-provider-2.jpg">
  <img src="../images/arkeo-data-engine-provider-2.jpg" alt="Provider admin UI overview" width="800" />
</a>
</details>

## 🔹 Install Docker on Your Host
Before you start, install Docker on your host and be comfortable with basic Docker commands (start/stop, logs, pull). Use your OS vendor's Docker docs.

## 🔹 Run the Latest "Arkeo Data Engine - Provider" Docker Image
```
#!/usr/bin/env bash
set -euo pipefail

# create host dirs
mkdir -p ~/arkeo-data-engine-provider/config \
         ~/arkeo-data-engine-provider/cache \
         ~/arkeo-data-engine-provider/arkeo

# stop/remove any existing container with this name (race-safe)
docker rm -f arkeo-data-engine-provider 2>/dev/null || true

# wait until Docker fully releases the name
while docker ps -a --format '{{.Names}}' | grep -q '^arkeo-data-engine-provider$'; do
  sleep 1
done

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/arkeo-data-engine-provider:latest

# run
docker run -d --name arkeo-data-engine-provider --restart=unless-stopped \
  -e ADMIN_PORT=8080 \
  -e ADMIN_API_PORT=9999 \
  -p 8080:8080 \
  -p 3636:3636 \
  -p 9999:9999 \
  -v ~/arkeo-data-engine-provider/config:/app/config \
  -v ~/arkeo-data-engine-provider/cache:/app/cache \
  -v ~/arkeo-data-engine-provider/arkeo:/root/.arkeo \
  ghcr.io/arkeonetwork/arkeo-data-engine-provider:latest
```

## 🔹 Secure the Admin URLs
- The Admin UI and API are HTTP-only and manage the hot wallet, so treat these endpoints like credentials and do not expose them to the public internet.
- Restrict ports 8080 and 9999 to your IP via firewall/security group rules, or keep them behind a private network/VPN.
- Only expose the sentinel port (3636) publicly if required.
- Optional: bind the admin ports to localhost only (for example, `-p 127.0.0.1:8080:8080 -p 127.0.0.1:9999:9999`).

## 🔹 Getting ARKEO Tokens
In the Hot Wallets area, use the buttons to move funds from other chains into Osmosis and Arkeo using exchanges, bridges, and wallets. Keplr provides secure signing for Osmosis actions. Be sure to add a little OSMO for gas.

## 🔹 Using the Provider Core Admin
- Start in the Admin UI to set the RPC, REST, mnemonic, and other provider settings before proceeding (Admin UI is HTTP at `http://<host>:8080`).
- Once the mnemonic you want to use is set, copy the Arkeo address in the Hot Wallets area and fund it with a small amount of ARKEO.
- In the Admin UI, configure the Sentinel so your provider is discoverable.
- Add your provider services: pick the service type, set the RPC URI, and optional username/password.
- If your node is firewalled, allow the Docker host IP; the host must be able to reach your node.
- Each provider service requires a minimum bond of 1 ARKEO to prevent spam.

## 🔹 Cache, Config, and Logs
- Cache files live under /app/cache (host-mounted to ~/provider-core/cache). Config is under /app/config (host-mounted to ~/provider-core/config). Listener data is in /root/.arkeo (host-mounted to ~/provider-core/arkeo).

## 🔹 That’s It
- You're now on the [Arkeo Data Marketplace](https://marketplace.builtonarkeo.com/).
