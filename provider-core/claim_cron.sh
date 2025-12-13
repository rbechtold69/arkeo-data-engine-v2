#!/bin/sh
# Periodically trigger provider claims via the local admin API.

set -u

INTERVAL="${CLAIM_CRON_INTERVAL:-60}"  # seconds; default 1 minute
API_HOST="${ADMIN_API_HOST:-127.0.0.1}"
API_PORT="${ADMIN_API_PORT:-9999}"

# Prefer runtime-ports.json (written by entrypoint) if available
if [ -f /app/admin/runtime-ports.json ]; then
  runtime_port="$(python3 - <<'PY'
import json,sys
try:
    with open("/app/admin/runtime-ports.json","r",encoding="utf-8") as f:
        data=json.load(f)
    val = data.get("ADMIN_API_PORT")
    if val:
        print(val)
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY
)"
  if [ $? -eq 0 ] && [ -n "$runtime_port" ]; then
    API_PORT="$runtime_port"
  fi
fi

CLAIMS_URL="http://${API_HOST}:${API_PORT}/api/provider-claims"
CONTRACTS_URL="http://${API_HOST}:${API_PORT}/api/provider-contracts-summary"

echo "Starting provider-claims cron loop: interval=${INTERVAL}s claims=${CLAIMS_URL} contracts=${CONTRACTS_URL}"

# Wait for admin API to come up before entering the loop
wait_attempt=0
until curl -4 -sS --max-time 5 "${CLAIMS_URL%/api/provider-claims}/api/version" >/dev/null 2>&1; do
    wait_attempt=$((wait_attempt + 1))
    echo "Waiting for admin API on ${CLAIMS_URL%/api/provider-claims} (attempt ${wait_attempt})"
    sleep 3
    if [ $wait_attempt -ge 20 ]; then
        echo "Admin API still unreachable; continuing to retry in main loop."
        break
    fi
done

while true; do
    TS="$(date -Iseconds)"
    attempt=1
    success=0
    while [ $attempt -le 3 ]; do
        if RESP="$(curl -4 --retry 3 --retry-connrefused --retry-delay 3 -sS --max-time 60 -X POST "${CLAIMS_URL}")"; then
            echo "${TS} provider-claims response: ${RESP}"
            success=1
            break
        else
            echo "${TS} provider-claims attempt ${attempt} failed"
            sleep 3
        fi
        attempt=$((attempt + 1))
    done
    if [ $success -ne 1 ]; then
        echo "${TS} provider-claims request failed after retries"
    fi

    # Give the chain a moment to include any claim txs, then refresh contract summary
    sleep 10
    TS2="$(date -Iseconds)"
    if RESP2="$(curl -sS --max-time 60 -X POST -H "Content-Type: application/json" -d "{}" "${CONTRACTS_URL}")"; then
        echo "${TS2} provider-contracts-summary response: ${RESP2}"
    else
        echo "${TS2} provider-contracts-summary request failed"
    fi

    sleep "${INTERVAL}"
done
