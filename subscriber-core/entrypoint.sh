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

echo "Subscriber-core Admin Mode (hot wallet + web UI only)"

KEY_NAME=${KEY_NAME:-subscriber}
KEY_MNEMONIC=${KEY_MNEMONIC:-}
KEY_KEYRING_BACKEND=${KEY_KEYRING_BACKEND:-test}

ARKEOD_HOME=${ARKEOD_HOME:-/root/.arkeod}
# Expand leading tilde if provided via env (e.g. "~/.arkeod")
ARKEOD_HOME=${ARKEOD_HOME/#\~/$HOME}
ARKEOD_NODE=${ARKEOD_NODE:-${EXTERNAL_ARKEOD_NODE:-tcp://provider1.innovationtheory.com:26657}}
RPC_URL_DEFAULT=${SENTINEL_RPC_URL:-$ARKEOD_NODE}
# If rpc url is tcp:// convert to http:// for sentinel
RPC_URL_DEFAULT=${RPC_URL_DEFAULT/tcp:\/\//http:\/\/}
ADMIN_PORT=${ADMIN_PORT:-8080}
# If provided, prefer ARKEO_REST_API_PORT as the provider hub URI default
PROVIDER_HUB_URI=${PROVIDER_HUB_URI:-${ARKEO_REST_API_PORT:-}}
CACHE_DIR=${CACHE_DIR:-/app/cache}
CACHE_FETCH_INTERVAL=${CACHE_FETCH_INTERVAL:-300}
# Default off to avoid any startup hangs; rely on background fetcher or manual refresh.
CACHE_WARM_ON_START=${CACHE_WARM_ON_START:-0}

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
echo "  CACHE_DIR             = $CACHE_DIR"
echo "  CACHE_FETCH_INTERVAL  = ${CACHE_FETCH_INTERVAL}s"
echo "  CACHE_WARM_ON_START   = $CACHE_WARM_ON_START"

# Ensure home directory exists
mkdir -p "$ARKEOD_HOME"
mkdir -p /app/config
mkdir -p "$CACHE_DIR"
# Ensure supervisor runtime dirs exist (for supervisorctl socket/logs)
mkdir -p /var/run /var/log/supervisor

# Optional one-time cache warm on start (disabled by default)
if [ "${CACHE_WARM_ON_START}" != "0" ]; then
  echo "Priming cache on start..."
  python3 /app/cache_fetcher.py --once || true
fi

# Check if key already exists in the keyring
if arkeod --home "$ARKEOD_HOME" \
          --keyring-backend "$KEY_KEYRING_BACKEND" \
          keys show "$KEY_NAME" >/dev/null 2>&1; then

  echo "Key '$KEY_NAME' already exists in keyring '$KEY_KEYRING_BACKEND'."

# Restore from mnemonic
elif [ -n "$KEY_MNEMONIC" ]; then

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

echo "Starting supervisord (web admin only)..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
