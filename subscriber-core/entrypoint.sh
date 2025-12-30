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

ARKEOD_HOME=${ARKEOD_HOME:-/root/.arkeo}
# Expand leading tilde if provided via env (e.g. "~/.arkeo")
ARKEOD_HOME=${ARKEOD_HOME/#\~/$HOME}
ARKEOD_NODE=${ARKEOD_NODE:-${EXTERNAL_ARKEOD_NODE:-tcp://provider1.innovationtheory.com:26657}}
RPC_URL_DEFAULT=${SENTINEL_RPC_URL:-$ARKEOD_NODE}
# If rpc url is tcp:// convert to http:// for sentinel
RPC_URL_DEFAULT=${RPC_URL_DEFAULT/tcp:\/\//http:\/\/}
ADMIN_PORT=${ADMIN_PORT:-${ENV_ADMIN_PORT:-8080}}
export ADMIN_PORT
# Provider hub URI default (user may set PROVIDER_HUB_URI explicitly)
PROVIDER_HUB_URI=${PROVIDER_HUB_URI:-}
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
# signhere expects ~/.arkeo; if ARKEOD_HOME differs, ensure ~/.arkeo points there
if [ "$ARKEOD_HOME" != "$HOME/.arkeo" ]; then
  ln -sfn "$ARKEOD_HOME" "$HOME/.arkeo"
fi

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
  echo ""

  # Create the key (capture JSON so we can persist the mnemonic)
  KEY_RAW=$(arkeod --home "$ARKEOD_HOME" \
          --keyring-backend "$KEY_KEYRING_BACKEND" \
          keys add "$KEY_NAME" --output json 2>&1 || true)

  echo "$KEY_RAW" > /app/config/arkeod_key_raw.txt

  # Try to pretty-print if JSON; otherwise fall back to raw
  echo "$KEY_RAW" | jq -r '. | "name: \(.name)\naddress: \(.address)\npubkey: \(.pubkey)\nmnemonic: \(.mnemonic)"' 2>/dev/null || echo "$KEY_RAW"

  # Persist mnemonic/address to subscriber-settings.json so the UI can display it
  if [ -n "$KEY_RAW" ]; then
    printf '%s' "$KEY_RAW" | python3 - <<'PY'
import json, os, re, sys
text = sys.stdin.read()
print(f"[entrypoint] raw len from stdin: {len(text)}")
# If empty, try the saved raw file
if not text.strip():
    try:
        with open("/app/config/arkeod_key_raw.txt", "r", encoding="utf-8") as f:
            text = f.read()
        print(f"[entrypoint] loaded raw from file, len={len(text)}")
    except Exception as e:
        print(f"[entrypoint] failed to load raw from file: {e}")
mn = ""
addr = ""

# Strip ANSI color codes if any
clean_text = re.sub(r"\x1b\[[0-9;]*m", "", text)

# Try JSON first, then fallback parsing
try:
    payload = json.loads(clean_text)
    mn = payload.get("mnemonic") or ""
    addr = payload.get("address") or ""
    print(f"[entrypoint] parsed JSON payload (mn_len={len(mn.split()) if mn else 0})")
except Exception as e:
    print(f"[entrypoint] json parse failed, using fallback: {e}")

# Line-based scan first
if not mn or not addr:
    for line in clean_text.splitlines():
        lower = line.lower()
        if not mn and "mnemonic:" in lower:
            mn = line.split(":", 1)[1].strip()
            print(f"[entrypoint] mnemonic extracted via line scan (len={len(mn.split())})")
        if not addr and "address:" in lower:
            addr = line.split(":", 1)[1].strip()
            print(f"[entrypoint] address extracted via line scan: {addr}")
        if mn and addr:
            break

# Regex for explicit mnemonic/address lines
if not mn:
    m = re.search(r"mnemonic:\s*([A-Za-z]+(?:\s+[A-Za-z]+){11,23})", clean_text, re.IGNORECASE)
    if m:
        mn = m.group(1).strip()
        print(f"[entrypoint] mnemonic extracted via line regex (len={len(mn.split())})")
if not addr:
    m = re.search(r"address:\s*(arkeo1[a-z0-9]+)", clean_text, re.IGNORECASE)
    if m:
        addr = m.group(1).strip()
        print(f"[entrypoint] address extracted via line regex: {addr}")

# Generic word/addr regex fallback
if not mn:
    words = re.findall(r"[a-zA-Z]+(?: [a-zA-Z]+){11,23}", clean_text)
    if words:
        mn = words[-1].strip()
        print(f"[entrypoint] mnemonic extracted via generic regex (len={len(mn.split())})")
if not addr:
    m_addr = re.search(r"(arkeo1[a-z0-9]+)", clean_text)
    if m_addr:
        addr = m_addr.group(1)
        print(f"[entrypoint] address extracted via generic regex: {addr}")

path = "/app/config/subscriber-settings.json"
data = {}
if os.path.isfile(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[entrypoint] warning: could not read existing settings: {e}")
        data = {}
if mn:
    data["KEY_MNEMONIC"] = mn
if addr:
    data["KEY_ADDRESS"] = addr
data.setdefault("KEY_NAME", os.environ.get("KEY_NAME", "subscriber"))
data.setdefault("KEY_KEYRING_BACKEND", os.environ.get("KEY_KEYRING_BACKEND", "test"))
data.setdefault("ARKEOD_HOME", os.environ.get("ARKEOD_HOME", "/root/.arkeo"))
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
print(f"[entrypoint] saved Arkeo mnemonic to {path} (mnemonic_len={len(mn.split()) if mn else 0})")
try:
    with open(path, "r", encoding="utf-8") as f:
        saved = json.load(f)
    print(f"[entrypoint] settings now has KEY_MNEMONIC? {'KEY_MNEMONIC' in saved and bool(saved.get('KEY_MNEMONIC'))}")
except Exception:
    pass
# Clean up raw file once persisted
try:
    if os.path.isfile("/app/config/arkeod_key_raw.txt"):
        os.remove("/app/config/arkeod_key_raw.txt")
        print("[entrypoint] removed /app/config/arkeod_key_raw.txt after persisting mnemonic")
except Exception as e:
    print(f"[entrypoint] could not remove /app/config/arkeod_key_raw.txt: {e}")
PY
  else
    echo "[entrypoint] warning: failed to capture Arkeo mnemonic (empty output)"
  fi

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
