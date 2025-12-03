#!/usr/bin/env bash
set -e

strip_quotes() {
  local val="$1"
  case "$val" in
    \"*\") val=${val#\"}; val=${val%\"} ;;
    \'*\') val=${val#\'}; val=${val%\'} ;;
  esac
  printf '%s' "$val"
}

expand_tilde() {
  local val="$1"
  # Expand leading tilde to $HOME
  case "$val" in
    "~"*) val="${val/#\~/$HOME}" ;;
  esac
  printf '%s' "$val"
}

echo "Provider-core Admin Mode (hot wallet + web UI only)"

KEY_NAME=${KEY_NAME:-provider}
RAW_KEY_MNEMONIC=${KEY_MNEMONIC:-}
KEY_KEYRING_BACKEND=${KEY_KEYRING_BACKEND:-test}

ARKEOD_HOME=${ARKEOD_HOME:-~/.arkeo}
# Expand leading tilde if provided via env (e.g. "~/.arkeo")
ARKEOD_HOME=${ARKEOD_HOME/#\~/$HOME}
ARKEOD_NODE=${ARKEOD_NODE:-${EXTERNAL_ARKEOD_NODE:-tcp://provider1.innovationtheory.com:26657}}
RPC_URL_DEFAULT=${SENTINEL_RPC_URL:-$ARKEOD_NODE}
# If rpc url is tcp:// convert to http:// for sentinel
RPC_URL_DEFAULT=${RPC_URL_DEFAULT/tcp:\/\//http:\/\/}
ADMIN_PORT=${ADMIN_PORT:-8080}
# If provided, prefer ARKEO_REST_API_PORT as the provider hub URI default
PROVIDER_HUB_URI=${PROVIDER_HUB_URI:-${ARKEO_REST_API_PORT:-}}

# Default sentinel-related envs (used by sentinel binary)
# EVENT_STREAM_HOST needs host:port (no scheme); derive from ARKEOD_NODE if unset.
if [ -z "$EVENT_STREAM_HOST" ]; then
  EVENT_STREAM_HOST=$(printf "%s" "$ARKEOD_NODE" | sed 's~^[a-zA-Z]*://~~')
fi
EVENT_STREAM_HOST=${EVENT_STREAM_HOST:-127.0.0.1:26657}
export EVENT_STREAM_HOST

echo "Using:"
echo "  KEY_NAME              = $KEY_NAME"
echo "  KEY_KEYRING_BACKEND   = $KEY_KEYRING_BACKEND"
echo "  KEY_MNEMONIC          = (hidden for security)"
echo "  ARKEOD_HOME           = $ARKEOD_HOME"
echo "  ARKEOD_NODE           = $ARKEOD_NODE"
echo "  ADMIN_PORT            = $ADMIN_PORT"

# Ensure home directory exists
mkdir -p "$ARKEOD_HOME"
mkdir -p /app/config
# Ensure supervisor runtime dirs exist (for supervisorctl socket/logs)
mkdir -p /var/run /var/log/supervisor

# Check if key already exists in the keyring
if arkeod --home "$ARKEOD_HOME" \
          --keyring-backend "$KEY_KEYRING_BACKEND" \
          keys show "$KEY_NAME" >/dev/null 2>&1; then

  echo "Key '$KEY_NAME' already exists in keyring '$KEY_KEYRING_BACKEND'."

# Restore from mnemonic
elif KEY_MNEMONIC=$(printf "%s" "$RAW_KEY_MNEMONIC" | sed 's/^ *//;s/ *$//' ); [ -n "$KEY_MNEMONIC" ]; then

  echo "Key '$KEY_NAME' not found – importing from KEY_MNEMONIC..."
  printf "%s\n" "$KEY_MNEMONIC" \
    | arkeod --home "$ARKEOD_HOME" \
             --keyring-backend "$KEY_KEYRING_BACKEND" \
             keys add "$KEY_NAME" --recover

# Create new key if mnemonic not provided
else
  echo ""
  echo "***************************************************************"
  echo " NO KEY_MNEMONIC PROVIDED"
  echo " Creating a NEW HOT WALLET for: $KEY_NAME"
  echo "***************************************************************"
  echo " IMPORTANT: Copy and store the mnemonic shown below."
  echo " It will NOT be displayed again by this container."
  echo "***************************************************************"
  echo ""

  # Create the key and capture all output (including the mnemonic)
  MNEMONIC_OUTPUT=$(arkeod --home "$ARKEOD_HOME" \
                           --keyring-backend "$KEY_KEYRING_BACKEND" \
                           keys add "$KEY_NAME")

  # Echo the original output so the user sees the standard arkeod message
  echo "$MNEMONIC_OUTPUT"

  # Try to extract the mnemonic section and save it to a file for convenience
  echo "$MNEMONIC_OUTPUT" | grep -A 50 "Important" > "$ARKEOD_HOME/${KEY_NAME}_mnemonic.txt" || true

  echo ""
  echo "---------------------------------------------------------------"
  echo " The mnemonic (and related output) has been saved to:"
  echo "   $ARKEOD_HOME/${KEY_NAME}_mnemonic.txt"
  echo " Please back this up securely and treat it like a private key."
  echo "---------------------------------------------------------------"

fi

# Derive pubkey for sentinel/config use (robustly)
derive_pubkeys() {
  local raw_output raw bech
  raw_output=$(arkeod --home "$ARKEOD_HOME" --keyring-backend "$KEY_KEYRING_BACKEND" keys show "$KEY_NAME" -p 2>/dev/null || true)
  raw=""
  # Try jq first if available
  if command -v jq >/dev/null 2>&1; then
    raw=$(printf "%s" "$raw_output" | jq -r '(.key // .pub_key // .pubkey // .public_key // empty)' 2>/dev/null || true)
  fi
  # Fallback to python JSON/regex parsing
  if [ -z "$raw" ]; then
    raw=$(printf "%s" "$raw_output" | python3 - <<'PY' 2>/dev/null
import sys, json, re
data = sys.stdin.read()
raw = ""
try:
    obj = json.loads(data)
    for key in ("key", "pub_key", "pubkey", "public_key"):
        raw = obj.get(key) or ""
        if raw:
            break
except Exception:
    pass
if not raw:
    m = re.search(r'"?key"?\s*[:=]\s*"?(?P<k>[A-Za-z0-9+/=]+)"?', data)
    if m:
        raw = m.group("k")
print(raw)
PY
)
  fi
  # Final fallback: plain grep/sed
  if [ -z "$raw" ]; then
    raw=$(printf "%s" "$raw_output" | sed -n 's/.*"key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  fi
  bech=""
  if [ -n "$raw" ] && [ "$raw" != "null" ]; then
    bech=$(arkeod debug pubkey-raw "$raw" | awk -F': ' '/Bech32 Acc:/ {print $2}' | head -n1)
  fi
  RAW_PUBKEY="$raw"
  BECH32_PUBKEY="$bech"
}
derive_pubkeys
echo "  Derived pubkey (raw)    = ${RAW_PUBKEY:-<empty>}"
echo "  Derived pubkey (bech32) = ${BECH32_PUBKEY:-<empty>}"
if [ -z "$BECH32_PUBKEY" ]; then
  echo "WARNING: could not derive bech32 pubkey for $KEY_NAME; sentinel config may be missing pubkey."
fi

# Build a minimal sentinel config if none exists
DEFAULT_PROVIDER_NAME="Default Provider"
DEFAULT_MONIKER="Default Provider"
DEFAULT_WEBSITE="http://defaultprovider.com"
DEFAULT_DESCRIPTION="Default provider description."
DEFAULT_LOCATION="Default Location"
DEFAULT_SOURCE_CHAIN=${SENTINEL_SOURCE_CHAIN:-"arkeo-main-v1"}
DEFAULT_FREE_RATE_LIMIT=10
DEFAULT_FREE_RATE_LIMIT_DURATION="1m"
DEFAULT_CLAIM_STORE_LOCATION=${CLAIM_STORE_LOCATION:-"~/.arkeo/claims"}
DEFAULT_CONTRACT_CONFIG_STORE_LOCATION=${CONTRACT_CONFIG_STORE_LOCATION:-"~/.arkeo/contract_configs"}
DEFAULT_PROVIDER_CONFIG_STORE_LOCATION=${PROVIDER_CONFIG_STORE_LOCATION:-"~/.arkeo/provider_configs"}
DEFAULT_LOG_LEVEL=${LOG_LEVEL:-"debug"}
SENTINEL_CONFIG_PATH=/app/config/sentinel.yaml
if [ ! -f "$SENTINEL_CONFIG_PATH" ]; then
  PROVIDER_NAME=${DEFAULT_PROVIDER_NAME}
  SERVICE_NAME=${SENTINEL_SERVICE_NAME:-arkeo-mainnet-fullnode}
  SERVICE_ID=${SENTINEL_SERVICE_ID:-2}
  SERVICE_TYPE=${SENTINEL_SERVICE_TYPE:-arkeo}
  LISTEN_ADDR=${SENTINEL_LISTEN_ADDR:-0.0.0.0:3636}
  cat > "$SENTINEL_CONFIG_PATH" <<EOF
provider:
  pubkey: "${BECH32_PUBKEY}"
  name: "${PROVIDER_NAME}"

services:
  - name: ${SERVICE_NAME}
    id: ${SERVICE_ID}
    type: ${SERVICE_TYPE}
    rpc_url: ${RPC_URL_DEFAULT}
    rpc_user:
    rpc_pass:

api:
  listen_addr: "${LISTEN_ADDR}"
EOF
  echo "Wrote default sentinel config to $SENTINEL_CONFIG_PATH"
else
  # If config exists, ensure pubkey defaults to the hotwallet and name has a sane default
  python3 - <<'PY'
import yaml
path = "${SENTINEL_CONFIG_PATH}"
pub = "${BECH32_PUBKEY}".strip()
default_name = "${DEFAULT_PROVIDER_NAME}".strip()
key_name = "${KEY_NAME}".strip()
if not any((pub, default_name)):
    raise SystemExit
try:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
except Exception:
    raise SystemExit
prov = data.get("provider") or {}
changed = False
current_pub = (prov.get("pubkey") or "").strip()
if pub and not current_pub:
    prov["pubkey"] = pub
    changed = True
current_name = (prov.get("name") or "").strip()
if default_name and (not current_name or current_name == key_name):
    prov["name"] = default_name
    changed = True
if changed:
    data["provider"] = prov
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
PY
fi

# Sync services in sentinel.yaml with on-chain registered services for this provider
python3 - <<'PY'
import json, yaml, subprocess, sys
from copy import deepcopy

config_path = "${SENTINEL_CONFIG_PATH}"
bech32 = "${BECH32_PUBKEY}".strip()
default_rpc = "${RPC_URL_DEFAULT}"

if not bech32 or not config_path:
    sys.exit(0)

# Load current config
try:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
except Exception:
    sys.exit(0)

existing_services = cfg.get("services") or []
svc_by_id = {str(s.get("id")): s for s in existing_services if isinstance(s, dict) and s.get("id") is not None}
svc_by_name = {str(s.get("name")): s for s in existing_services if isinstance(s, dict) and s.get("name")}

# Query on-chain providers
cmd = ["arkeod", "--home", "${ARKEOD_HOME}"]
node = "${ARKEOD_NODE}"
if node:
    cmd.extend(["--node", node])
cmd.extend(["query", "arkeo", "list-providers", "--output", "json"])

try:
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
except subprocess.CalledProcessError:
    sys.exit(0)

try:
    data = json.loads(out)
except json.JSONDecodeError:
    sys.exit(0)

providers = data.get("provider") or data.get("providers") or []
matched = []
for p in providers:
    if not isinstance(p, dict):
        continue
    pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
    if pk == bech32:
        matched.append(p)

services = []
for p in matched:
    svc_list = []
    if isinstance(p.get("services"), list):
        svc_list = p.get("services")
    elif isinstance(p.get("service"), list):
        svc_list = p.get("service")
    if not svc_list and p.get("service") and p.get("service_id"):
        svc_list = [p]
    for s in svc_list:
        if not isinstance(s, dict):
            continue
        name = s.get("service") or s.get("name")
        sid = s.get("service_id") or s.get("id")
        stype = s.get("type") or "arkeo"
        rpc_url = default_rpc
        # preserve rpc_url if we already have an entry
        if sid is not None and str(sid) in svc_by_id:
            rpc_url = svc_by_id[str(sid)].get("rpc_url") or rpc_url
        elif name and name in svc_by_name:
            rpc_url = svc_by_name[name].get("rpc_url") or rpc_url
        services.append(
            {
                "name": name,
                "id": sid,
                "type": stype,
                "rpc_url": rpc_url,
                "rpc_user": "",  # preserved below if available
                "rpc_pass": "",
            }
        )

# custom dumper to indent sequences under mappings
class IndentDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)

# If none matched, optionally seed a placeholder stub when none exist
if not services:
    placeholder = {
        "name": "default-placeholder",
        "id": 0,
        "type": "default-placeholder",
        "rpc_url": default_rpc,
        "rpc_user": "",
        "rpc_pass": "",
    }
    cfg["services"] = [placeholder]
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, Dumper=IndentDumper, sort_keys=False, default_flow_style=False, indent=2)
    print("No on-chain services found; wrote placeholder service stub to sentinel.yaml")
    sys.exit(0)

# Preserve rpc_user/pass if present in existing entries
for svc in services:
    sid = str(svc.get("id"))
    name = svc.get("name")
    if sid in svc_by_id:
        svc["rpc_user"] = svc_by_id[sid].get("rpc_user", "")
        svc["rpc_pass"] = svc_by_id[sid].get("rpc_pass", "")
    elif name in svc_by_name:
        svc["rpc_user"] = svc_by_name[name].get("rpc_user", "")
        svc["rpc_pass"] = svc_by_name[name].get("rpc_pass", "")

if services != existing_services:
    cfg["services"] = services
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, Dumper=IndentDumper, sort_keys=False, default_flow_style=False, indent=2)
    print("Synced services in sentinel.yaml with on-chain providers")
PY

# Write sentinel env file if missing (used by run_sentinel.sh)
CLEAN_MONIKER=$(strip_quotes "${MONIKER:-$DEFAULT_MONIKER}")
CLEAN_WEBSITE=$(strip_quotes "${WEBSITE:-$DEFAULT_WEBSITE}")
CLEAN_DESCRIPTION=$(strip_quotes "${DESCRIPTION:-$DEFAULT_DESCRIPTION}")
CLEAN_LOCATION=$(strip_quotes "${LOCATION:-$DEFAULT_LOCATION}")
CLEAN_FREE_RATE_LIMIT=$(strip_quotes "${FREE_RATE_LIMIT:-$DEFAULT_FREE_RATE_LIMIT}")
CLEAN_FREE_RATE_LIMIT_DURATION=$(strip_quotes "${FREE_RATE_LIMIT_DURATION:-$DEFAULT_FREE_RATE_LIMIT_DURATION}")
CLEAN_PROVIDER_HUB_URI=$(strip_quotes "${PROVIDER_HUB_URI:-$ARKEO_REST_API_PORT}")
CLEAN_EVENT_STREAM_HOST=$(strip_quotes "${EVENT_STREAM_HOST:-127.0.0.1:26657}")
CLEAN_CLAIM_STORE_LOCATION=$(strip_quotes "${CLAIM_STORE_LOCATION:-$DEFAULT_CLAIM_STORE_LOCATION}")
CLEAN_CONTRACT_CONFIG_STORE_LOCATION=$(strip_quotes "${CONTRACT_CONFIG_STORE_LOCATION:-$DEFAULT_CONTRACT_CONFIG_STORE_LOCATION}")
CLEAN_PROVIDER_CONFIG_STORE_LOCATION=$(strip_quotes "${PROVIDER_CONFIG_STORE_LOCATION:-$DEFAULT_PROVIDER_CONFIG_STORE_LOCATION}")
CLEAN_LOG_LEVEL=$(strip_quotes "${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}")
CLEAN_PROVIDER_PUBKEY=$(strip_quotes "${PROVIDER_PUBKEY:-$BECH32_PUBKEY}")
CLEAN_PROVIDER_NAME=$(strip_quotes "${PROVIDER_NAME:-$DEFAULT_PROVIDER_NAME}")
# Expand any leading tilde so sentinel sees absolute paths
CLEAN_CLAIM_STORE_LOCATION=$(expand_tilde "$CLEAN_CLAIM_STORE_LOCATION")
CLEAN_CONTRACT_CONFIG_STORE_LOCATION=$(expand_tilde "$CLEAN_CONTRACT_CONFIG_STORE_LOCATION")
CLEAN_PROVIDER_CONFIG_STORE_LOCATION=$(expand_tilde "$CLEAN_PROVIDER_CONFIG_STORE_LOCATION")

SENTINEL_ENV_PATH=/app/config/sentinel.env
if [ ! -f "$SENTINEL_ENV_PATH" ]; then
  cat > "$SENTINEL_ENV_PATH" <<EOF
PROVIDER_NAME="${CLEAN_PROVIDER_NAME}"
MONIKER="${CLEAN_MONIKER}"
WEBSITE="${CLEAN_WEBSITE}"
DESCRIPTION="${CLEAN_DESCRIPTION}"
LOCATION="${CLEAN_LOCATION}"
PORT=${PORT:-3636}
SOURCE_CHAIN="${SOURCE_CHAIN:-$DEFAULT_SOURCE_CHAIN}"
PROVIDER_HUB_URI="${CLEAN_PROVIDER_HUB_URI}"
EVENT_STREAM_HOST="${CLEAN_EVENT_STREAM_HOST}"
FREE_RATE_LIMIT=${CLEAN_FREE_RATE_LIMIT}
FREE_RATE_LIMIT_DURATION="${CLEAN_FREE_RATE_LIMIT_DURATION}"
CLAIM_STORE_LOCATION="${CLEAN_CLAIM_STORE_LOCATION}"
CONTRACT_CONFIG_STORE_LOCATION="${CLEAN_CONTRACT_CONFIG_STORE_LOCATION}"
PROVIDER_CONFIG_STORE_LOCATION="${CLEAN_PROVIDER_CONFIG_STORE_LOCATION}"
LOG_LEVEL="${CLEAN_LOG_LEVEL}"
PROVIDER_PUBKEY="${CLEAN_PROVIDER_PUBKEY}"
EOF
  echo "Wrote default sentinel env to $SENTINEL_ENV_PATH"
else
# Patch existing env file with defaults where missing/empty
  python3 - <<'PY'
import shlex
from pathlib import Path
path = Path("${SENTINEL_ENV_PATH}")
if not path.is_file():
    raise SystemExit
lines = path.read_text(encoding="utf-8").splitlines()
data = {}
def dequote(val: str) -> str:
    val = (val or "").strip()
    # strip matching leading/trailing quotes repeatedly
    while len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1].strip()
    return val
def requote(val: str) -> str:
    val = dequote(val)
    safe = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{safe}"'
for line in lines:
    if not line or line.strip().startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    data[k.strip()] = dequote(v)
defaults = {
    "PROVIDER_NAME": "${CLEAN_PROVIDER_NAME}",
    "MONIKER": "${CLEAN_MONIKER}",
    "WEBSITE": "${CLEAN_WEBSITE}",
    "DESCRIPTION": "${CLEAN_DESCRIPTION}",
    "LOCATION": "${CLEAN_LOCATION}",
    "PORT": "3636",
    "SOURCE_CHAIN": "${DEFAULT_SOURCE_CHAIN}",
    "PROVIDER_HUB_URI": "${CLEAN_PROVIDER_HUB_URI}",
    "EVENT_STREAM_HOST": "${CLEAN_EVENT_STREAM_HOST}",
    "FREE_RATE_LIMIT": "${CLEAN_FREE_RATE_LIMIT}",
    "FREE_RATE_LIMIT_DURATION": "${CLEAN_FREE_RATE_LIMIT_DURATION}",
    "CLAIM_STORE_LOCATION": "${CLEAN_CLAIM_STORE_LOCATION}",
    "CONTRACT_CONFIG_STORE_LOCATION": "${CLEAN_CONTRACT_CONFIG_STORE_LOCATION}",
    "PROVIDER_CONFIG_STORE_LOCATION": "${CLEAN_PROVIDER_CONFIG_STORE_LOCATION}",
    "LOG_LEVEL": "${CLEAN_LOG_LEVEL}",
    "PROVIDER_PUBKEY": "${CLEAN_PROVIDER_PUBKEY}",
}
changed = False
for k, v in defaults.items():
    if not v:
        continue
    current = (data.get(k) or "").strip()
    if not current:
        data[k] = v
        changed = True
# If any value contains whitespace and is unquoted, force rewrite with quoting
if not changed:
    for val in data.values():
        if any(ch.isspace() for ch in val):
            changed = True
            break
if not changed:
    raise SystemExit
with path.open("w", encoding="utf-8") as f:
    for k, v in data.items():
        f.write(f"{k}={requote(v)}\\n")
PY
fi

echo "Starting supervisord (web admin only)..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
