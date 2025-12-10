#!/usr/bin/env python3
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import secrets
import urllib.error
import urllib.request
import urllib.parse
import yaml
import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
# Configure logging to stdout at INFO so supervisor captures our app logs
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
app.logger.setLevel(logging.INFO)
if not app.logger.handlers:
    app.logger.addHandler(handler)
app.logger.propagate = False

def _build_sentinel_uri() -> str:
    port = os.getenv("SENTINEL_PORT") or "3636"
    external = os.getenv("SENTINEL_NODE")
    if external:
        parsed = urllib.parse.urlparse(external)
        scheme = parsed.scheme or "http"
        host = parsed.netloc or parsed.path or external
        if ":" not in host:
            host = f"{host}:{port}"
        return f"{scheme}://{host}/metadata.json"
    # Default to localhost bind for in-container checks
    host = os.getenv("SENTINEL_BIND_HOST") or "127.0.0.1"
    return f"http://{host}:{port}/metadata.json"

DEFAULT_KEY_NAME = "provider"
DEFAULT_KEYRING = "test"
DEFAULT_CHAIN_ID = "arkeo-main-v1"
DEFAULT_ARKEOD_HOME = "~/.arkeo"
DEFAULT_ARKEOD_NODE = "tcp://127.0.0.1:26657"
DEFAULT_ARKEO_REST = "http://127.0.0.1:1317"
DEFAULT_SENTINEL_NODE = "http://127.0.0.1"
DEFAULT_SENTINEL_PORT = "3636"
DEFAULT_ADMIN_PORT = "8080"
DEFAULT_ADMIN_API_PORT = "9999"
DEFAULT_MNEMONIC = ""

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", DEFAULT_ARKEOD_HOME))
KEY_NAME = os.getenv("KEY_NAME", DEFAULT_KEY_NAME)
KEYRING = os.getenv("KEY_KEYRING_BACKEND", DEFAULT_KEYRING)
def _strip_quotes(val: str | None) -> str:
    if not val:
        return ""
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    return val


def _ensure_tcp_scheme(url: str | None) -> str:
    """Force RPC URLs to use tcp:// scheme; leave empty or already-tcp unchanged."""
    if not url:
        return ""
    s = str(url).strip()
    lower = s.lower()
    if lower.startswith("tcp://"):
        return s
    if lower.startswith("http://"):
        return "tcp://" + s[len("http://") :]
    if lower.startswith("https://"):
        return "tcp://" + s[len("https://") :]
    return s

ARKEOD_NODE = _strip_quotes(
    os.getenv("ARKEOD_NODE")
    or os.getenv("EXTERNAL_ARKEOD_NODE")
    or DEFAULT_ARKEOD_NODE
)
CHAIN_ID = _strip_quotes(os.getenv("CHAIN_ID") or os.getenv("ARKEOD_CHAIN_ID") or DEFAULT_CHAIN_ID)
NODE_ARGS = ["--node", ARKEOD_NODE] if ARKEOD_NODE else []
CHAIN_ARGS = ["--chain-id", CHAIN_ID] if CHAIN_ID else []
# Use the packaged supervisord config unless overridden
SUPERVISOR_CONF = os.getenv("SUPERVISOR_CONF", "/etc/supervisor/conf.d/supervisord.conf")
SUPERVISORCTL = ["supervisorctl", "-c", SUPERVISOR_CONF]
SUPERVISORCTL_FALLBACK = ["supervisorctl"]
SENTINEL_URI_DEFAULT = os.getenv("SENTINEL_URI") or _build_sentinel_uri()
METADATA_NONCE_DEFAULT = os.getenv("METADATA_NONCE") or "1"
BOND_DEFAULT = os.getenv("BOND_AMOUNT") or "1"
FEES_DEFAULT = os.getenv("TX_FEES") or "200uarkeo"
API_PORT = int(os.getenv("ADMIN_API_PORT", "9999"))
SENTINEL_CONFIG_PATH = os.getenv("SENTINEL_CONFIG_PATH", "/app/config/sentinel.yaml")
SENTINEL_ENV_PATH = os.getenv("SENTINEL_ENV_PATH", "/app/config/sentinel.env")
PROVIDER_ENV_PATH = os.getenv("PROVIDER_ENV_PATH", "/app/provider.env")
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
PROVIDER_SETTINGS_PATH = os.getenv("PROVIDER_SETTINGS_PATH") or (
    os.path.join(CACHE_DIR or "/app/cache", "provider-settings.json")
)
ADMIN_PASSWORD_PATH = os.getenv("ADMIN_PASSWORD_PATH") or (
    os.path.join(CACHE_DIR or "/app/cache", "admin_password.txt")
)
ADMIN_SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET") or secrets.token_hex(16)
ADMIN_SESSION_NAME = os.getenv("ADMIN_SESSION_NAME") or "admin_session"
# UI origin used for CORS (allow credentials)
ADMIN_UI_ORIGIN = os.getenv("ADMIN_UI_ORIGIN") or "http://localhost:8080"
# token -> expiry_ts
ADMIN_SESSIONS: dict[str, float] = {}
CLAIMS_HEARTBEAT_PATH = os.path.join(CACHE_DIR, "claims-heartbeat.json") if CACHE_DIR else "claims-heartbeat.json"
ENV_EXPORT_KEYS = [
    "PROVIDER_NAME",
    "MONIKER",
    "WEBSITE",
    "DESCRIPTION",
    "LOCATION",
    "PORT",
    "SOURCE_CHAIN",
    "ARKEO_REST_API_PORT",
    "EVENT_STREAM_HOST",
    "FREE_RATE_LIMIT",
    "FREE_RATE_LIMIT_DURATION",
    "CLAIM_STORE_LOCATION",
    "CONTRACT_CONFIG_STORE_LOCATION",
    "PROVIDER_CONFIG_STORE_LOCATION",
    "LOG_LEVEL",
    "PROVIDER_PUBKEY",
    "ARKEOD_NODE",
    "EXTERNAL_ARKEOD_NODE",
    "SENTINEL_NODE",
    "SENTINEL_PORT",
]

def _normalize_base(url: str | None, default_port: str | None = None, default_scheme: str = "http") -> str:
    """Return a normalized base URL with scheme/port if provided."""
    if not url:
        return ""
    url = url.strip()
    # Convert tcp:// to http:// for probing
    if url.startswith("tcp://"):
        url = "http://" + url[len("tcp://") :]
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        parsed = None
    if parsed:
        scheme = parsed.scheme or default_scheme
        netloc = parsed.netloc or parsed.path or ""
        if default_port and ":" not in netloc:
            netloc = f"{netloc}:{default_port}"
        return f"{scheme}://{netloc}"
    # Fallback simple join
    if default_port and ":" not in url:
        url = f"{url}:{default_port}"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"{default_scheme}://{url}"
    return url


def _probe_url(base: str, path_override: str | None = None, timeout: float = 4.0, headers: dict | None = None) -> dict:
    """Probe a URL from inside the container."""
    base = (base or "").strip()
    if not base:
        return {"ok": False, "url": "", "error": "not set"}
    try:
        parsed = urllib.parse.urlparse(base)
        if path_override:
            parsed = parsed._replace(path=path_override)
        target = parsed.geturl()
    except Exception:
        target = base
        if path_override:
            sep = "" if base.endswith("/") or path_override.startswith("/") else "/"
            target = f"{base}{sep}{path_override}"
    start = time.time()
    try:
        req = urllib.request.Request(target, method="GET", headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            ok = 200 <= (status or 0) < 400
            # Treat 401 as reachable but unauthorized so status pills don't go red when auth is enabled.
            if status == 401:
                ok = True
            return {
                "ok": ok,
                "url": base,
                "target": target,
                "status": status,
                "elapsed_ms": int((time.time() - start) * 1000),
            }
    except Exception as e:
        return {
            "ok": False,
            "url": base,
            "target": target,
            "error": str(e),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
SENTINEL_EXPORT_PATH = os.getenv("SENTINEL_EXPORT_PATH") or os.path.join(
    CACHE_DIR or (os.path.dirname(SENTINEL_ENV_PATH) or "."),
    "sentinel-export.json",
)
PROVIDER_EXPORT_PATH = os.getenv("PROVIDER_EXPORT_PATH") or os.path.join(
    CACHE_DIR or (os.path.dirname(PROVIDER_ENV_PATH) or "."),
    "provider-export.json",
)


def run(cmd: str) -> tuple[int, str]:
    """Run a shell command and return (exit_code, output)."""
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return 0, out.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode("utf-8")


def run_list(cmd: list[str]) -> tuple[int, str]:
    """Run a command without a shell and return (exit_code, output)."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return 0, out.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode("utf-8")


def run_with_input(cmd: list[str], input_text: str) -> tuple[int, str]:
    """Run a command with stdin content."""
    try:
        proc = subprocess.run(
            cmd,
            input=input_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        return proc.returncode, proc.stdout.decode("utf-8")
    except Exception as e:
        return 1, str(e)


def _is_local_request() -> bool:
    """Return True when the caller is loopback/localhost."""
    addr = (request.remote_addr or "").strip()
    return addr in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")


def _auth_exempt(path: str) -> bool:
    if not path.startswith("/api/"):
        return True
    exempt = {
        "/api/admin-password",
        "/api/admin-password/check",
        "/api/session",
        "/api/login",
        "/api/ping",
    }
    internal_exempt = {
        "/api/provider-claims",
        "/api/provider-contracts-summary",
    }
    if path in exempt:
        return True
    # Allow loopback callers for specific internal endpoints even when auth is enabled
    if path in internal_exempt and _is_local_request():
        return True
    return False


@app.before_request
def _require_auth():
    """Require session auth when admin password is set."""
    if request.method == "OPTIONS":
        resp = app.make_response(("", 204, _cors_headers()))
        return resp
    if _auth_exempt(request.path):
        return
    if not _is_auth_required():
        return
    token = request.cookies.get(ADMIN_SESSION_NAME)
    if _validate_session(token):
        return
    return jsonify({"error": "unauthorized"}), 401

def ensure_cache_dir():
    """Ensure CACHE_DIR exists."""
    if CACHE_DIR and not os.path.isdir(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
        except OSError:
            pass

def write_cache_json(name: str, data: dict | list | str):
    """Write JSON data to /app/cache/{name}.json."""
    ensure_cache_dir()
    path = os.path.join(CACHE_DIR, f"{name}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            if isinstance(data, (dict, list)):
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))
    except OSError:
        pass

def write_heartbeat(path: str, payload: dict):
    """Write a small JSON heartbeat to the given path."""
    ensure_cache_dir()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError:
        pass

def read_heartbeat(path: str):
    """Read a small JSON heartbeat file."""
    if not path:
        return None
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def read_cache_json(name: str):
    """Read JSON data from /app/cache/{name}.json if present."""
    path = os.path.join(CACHE_DIR, f"{name}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@app.after_request
def add_cors(resp):
    headers = _cors_headers()
    for k, v in headers.items():
        resp.headers[k] = v
    return resp


def derive_pubkeys(user: str, keyring_backend: str) -> tuple[str, str, str | None]:
    """Return (raw_pubkey, bech32_pubkey, error)."""
    pubkey_cmd = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "keys",
        "show",
        user,
        "-p",
        "--keyring-backend",
        keyring_backend,
    ]
    code, pubkey_out = run_list(pubkey_cmd)
    if code != 0:
        return "", "", f"failed to fetch raw pubkey: {pubkey_out}"

    try:
        raw_pubkey = json.loads(pubkey_out).get("key", "").strip()
    except json.JSONDecodeError:
        raw_pubkey = ""
    if not raw_pubkey:
        return "", "", f"could not parse raw pubkey: {pubkey_out}"

    bech32_cmd = ["arkeod", "debug", "pubkey-raw", raw_pubkey]
    code, bech32_out = run_list(bech32_cmd)
    if code != 0:
        return raw_pubkey, "", f"failed to convert pubkey: {bech32_out}"

    bech32_pubkey = ""
    for line in bech32_out.splitlines():
        if line.startswith("Bech32 Acc:"):
            bech32_pubkey = line.replace("Bech32 Acc:", "").strip()
            break
    if not bech32_pubkey:
        return raw_pubkey, "", f"Bech32 pubkey not found: {bech32_out}"

    return raw_pubkey, bech32_pubkey, None


def provider_pubkeys_response(user: str, keyring_backend: str):
    """Helper to return pubkey info even if derivation fails."""
    raw_pubkey, bech32_pubkey, pubkey_err = derive_pubkeys(user, keyring_backend)
    resp = {
        "user": user,
        "keyring_backend": keyring_backend,
        "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
    }
    if pubkey_err:
        resp["pubkey_error"] = pubkey_err
    return resp


@app.get("/api/ping")
def ping():
    return jsonify({"status": "ok"})

@app.get("/api/version")
def version():
    code, out = run("arkeod version")
    if code != 0:
        return jsonify({"error": "failed to get arkeod version", "detail": out}), 500
    ver = out.strip()
    if not ver:
        ver = "unknown"
    return jsonify({"arkeod_version": ver})

@app.get("/api/block-height")
def block_height():
    """Return the latest block height from the configured node."""
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.append("status")
    code, out = run_list(cmd)
    if code != 0:
        return jsonify({"error": "failed to fetch status", "detail": out, "cmd": cmd}), 500
    try:
        data = json.loads(out)
        # handle common casing
        sync_info = data.get("SyncInfo") or data.get("sync_info") or {}
        height = sync_info.get("latest_block_height") or sync_info.get("latest_block")
        return jsonify({"height": str(height) if height is not None else None, "status": data})
    except json.JSONDecodeError:
        return jsonify({"error": "invalid JSON from status", "detail": out, "cmd": cmd}), 500


@app.get("/api/key")
def get_key():
    cmd = (
        f"arkeod --home {ARKEOD_HOME} "
        f"--keyring-backend {KEYRING} "
        f"keys show {KEY_NAME} -a"
    )
    code, out = run(cmd)
    if code != 0:
        return jsonify({"address": None, "error": "failed to get key address", "detail": out}), 200

    address = out.strip()
    return jsonify({"address": address})


@app.get("/api/balance")
def get_balance():
    # first get address
    addr_cmd = (
        f"arkeod --home {ARKEOD_HOME} "
        f"--keyring-backend {KEYRING} "
        f"keys show {KEY_NAME} -a"
    )
    code, addr_out = run(addr_cmd)
    if code != 0:
        return jsonify({"address": None, "error": "failed to get key address", "detail": addr_out}), 200

    address = addr_out.strip()

    # then query balances in JSON form
    bal_cmd = (
        f"arkeod query bank balances {address} "
        f"{'--node ' + ARKEOD_NODE if ARKEOD_NODE else ''} "
        f"-o json"
    )
    code, bal_out = run(bal_cmd)

    if code != 0:
        return jsonify(
            {
                "address": address,
                "error": "failed to query balance",
                "detail": bal_out,
            }
        ), 200

    try:
        data = json.loads(bal_out)
    except json.JSONDecodeError:
        data = {"raw": bal_out}

    return jsonify({"address": address, "balance": data})


@app.post("/api/bond-provider")
def bond_provider():
    payload = request.get_json(force=True, silent=True) or {}
    user = KEY_NAME
    service = payload.get("service")
    bond = str(payload.get("bond") or BOND_DEFAULT)
    keyring_backend = KEYRING
    fees = FEES_DEFAULT

    if not service:
        return jsonify({"error": "service is required"}), 400

    app.logger.info(
        "bond-provider start service=%s bond=%s user=%s keyring=%s",
        service,
        bond,
        user,
        keyring_backend,
    )

    # Step 1: get raw pubkey for the user
    raw_pubkey, bech32_pubkey, pubkey_err = derive_pubkeys(user, keyring_backend)
    if pubkey_err:
        return jsonify(
            {
                "error": pubkey_err,
                "pubkey_error": pubkey_err,
                "user": user,
                "keyring_backend": keyring_backend,
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
                "inputs": {
                    "service": service,
                    "bond": bond,
                    "keyring_backend": keyring_backend,
                    "fees": fees,
                },
            }
        ), 500

    # Step 3: send the bond-provider tx
    bond_cmd = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "tx",
        "arkeo",
        "bond-provider",
        bech32_pubkey,
        service,
        bond,
        *NODE_ARGS,
        "--from",
        user,
        "--fees",
        fees,
        "--keyring-backend",
        keyring_backend,
        "-y",
    ]
    code, bond_out = run_list(bond_cmd)
    app.logger.info("bond-provider result code=%s service=%s", code, service)
    if code != 0:
        return jsonify(
            {
                "error": "failed to bond provider",
                "detail": bond_out,
                "inputs": {
                    "service": service,
                    "bond": bond,
                    "keyring_backend": keyring_backend,
                    "fees": fees,
                },
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
                "user": user,
            }
        ), 500

    return jsonify(
        {
            "status": "bond_submitted",
            "tx_output": bond_out,
            "inputs": {
                "service": service,
                "bond": bond,
                "keyring_backend": keyring_backend,
                "fees": fees,
            },
            "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            "user": user,
            "pubkey_error": pubkey_err,
        }
    )


@app.post("/api/bond-mod-provider")
def bond_and_mod_provider():
    """Bond a provider then mod-provider using supplied parameters."""
    payload = request.get_json(force=True, silent=True) or {}
    user = KEY_NAME
    service = payload.get("service")
    bond = str(payload.get("bond") or BOND_DEFAULT)
    keyring_backend = KEYRING
    fees = FEES_DEFAULT

    sentinel_uri = payload.get("sentinel_uri") or SENTINEL_URI_DEFAULT
    metadata_nonce = str(payload.get("metadata_nonce") or METADATA_NONCE_DEFAULT)
    status = str(payload.get("status") or "1")
    min_contract_dur = str(payload.get("min_contract_dur") or "5")
    max_contract_dur = str(payload.get("max_contract_dur") or "432000")
    subscription_rates = payload.get("subscription_rates") or "200uarkeo"
    pay_as_you_go_rates = payload.get("pay_as_you_go_rates") or "200uarkeo"
    settlement_dur = str(payload.get("settlement_dur") or "1000")
    location = payload.get("location")

    if not service:
        return jsonify({"error": "service is required"}), 400

    app.logger.info(
        "bond-mod-provider start service=%s bond=%s status=%s rpc_url=%s sentinel_uri=%s",
        service,
        bond,
        status,
        payload.get("rpc_url"),
        sentinel_uri,
    )

    # Resolve numeric service IDs to the service name (CLI expects name)
    resolved_service = service
    lookup_note = ""
    if isinstance(service, str) and service.strip().isdigit():
        svc_id = service.strip()
        def _lookup_service_name_by_id(sid: str) -> str | None:
            cmd = ["arkeod", "--home", ARKEOD_HOME]
            if ARKEOD_NODE:
                cmd.extend(["--node", ARKEOD_NODE])
            cmd.extend(["query", "arkeo", "all-services", "-o", "json"])
            code, out = run_list(cmd)
            if code != 0:
                return None
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                return None
            services = data.get("services") or data.get("service") or data.get("result") or []
            if isinstance(services, dict):
                services = services.get("services") or services.get("service") or []
            for item in services if isinstance(services, list) else []:
                if not isinstance(item, dict):
                    continue
                sid_val = str(item.get("id") or item.get("service_id") or item.get("serviceID") or "")
                if sid_val == sid:
                    return item.get("service") or item.get("name") or sid
            return None
        looked_up = _lookup_service_name_by_id(svc_id)
        if looked_up:
            resolved_service = looked_up
        else:
            lookup_note = f"could not resolve service id {svc_id} to name"

    raw_pubkey, bech32_pubkey, pubkey_err = derive_pubkeys(user, keyring_backend)
    if pubkey_err:
        return jsonify(
            {
                "error": pubkey_err,
                "pubkey_error": pubkey_err,
                "user": user,
                "keyring_backend": keyring_backend,
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            }
        ), 500

    def fetch_sequence(bech32: str, min_expected: int | None = None, attempts: int = 5, delay: float = 1.0) -> list[str]:
        """Fetch account sequence with retries; optionally wait until it reaches min_expected."""
        seq_val = None
        for _ in range(attempts):
            try:
                acct_cmd = ["arkeod", "--home", ARKEOD_HOME, "query", "auth", "account", bech32, "-o", "json"]
                if ARKEOD_NODE:
                    acct_cmd.extend(["--node", ARKEOD_NODE])
                code, acct_out = run_list(acct_cmd)
                if code == 0:
                    acct = json.loads(acct_out)
                    if isinstance(acct, dict):
                        account_info = acct.get("account") or acct.get("result") or {}
                        if isinstance(account_info, dict):
                            val = account_info.get("value") or account_info
                            if isinstance(val, dict):
                                seq_val = val.get("sequence")
                    if seq_val is not None:
                        seq_int = int(seq_val)
                        if min_expected is None or seq_int >= min_expected:
                            return ["--sequence", str(seq_int)]
            except Exception:
                pass
            time.sleep(delay)
        return ["--sequence", str(seq_val)] if seq_val is not None else []

    # If provider already exists, skip rebond and go straight to mod.
    skip_bond = False
    bond_cmd: list[str] | None = None
    bond_code = 0
    bond_out = "skipped: provider already bonded"
    initial_seq_arg: list[str] = fetch_sequence(bech32_pubkey, attempts=2, delay=0.5)
    initial_seq_val = None
    try:
        if initial_seq_arg:
            initial_seq_val = int(initial_seq_arg[1])
    except Exception:
        initial_seq_val = None
    try:
        lookup_cmd = [
            "arkeod",
            "--home",
            ARKEOD_HOME,
            "query",
            "arkeo",
            "provider",
            bech32_pubkey,
            resolved_service,
            "-o",
            "json",
        ]
        if ARKEOD_NODE:
            lookup_cmd.extend(["--node", ARKEOD_NODE])
        code, lookup_out = run_list(lookup_cmd)
        if code == 0:
            skip_bond = True
            bond_out = "skipped: provider already exists"
        else:
            skip_bond = False
    except Exception:
        skip_bond = False

    if not skip_bond:
        bond_cmd = [
            "arkeod",
            "--home",
            ARKEOD_HOME,
            "tx",
            "arkeo",
            "bond-provider",
            bech32_pubkey,
            resolved_service,
            bond,
            *NODE_ARGS,
            *CHAIN_ARGS,
            "--from",
            user,
            "--fees",
            fees,
            "--keyring-backend",
            keyring_backend,
            "-y",
        ]
        bond_code, bond_out = run_list(bond_cmd)
        if bond_code != 0:
            return jsonify(
                {
                    "error": "failed to bond provider",
                    "detail": bond_out,
                    "cmd": bond_cmd,
                    "inputs": {
                        "service": service,
                        "resolved_service": resolved_service,
                        "lookup_note": lookup_note,
                        "bond": bond,
                        "keyring_backend": keyring_backend,
                        "fees": fees,
                    },
                    "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
                    "user": user,
                }
            ), 500

        # Give the bond a moment to settle before mod-provider
        time.sleep(6)

    # Fetch account sequence to avoid mismatch (with retries to catch fresh state)
    min_expected_seq = None
    if not skip_bond and initial_seq_val is not None:
        min_expected_seq = initial_seq_val + 1
    sequence_arg: list[str] = fetch_sequence(bech32_pubkey, min_expected=min_expected_seq, attempts=5, delay=1.0)

    mod_cmd_base = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "tx",
        "arkeo",
        "mod-provider",
        bech32_pubkey,
        resolved_service,
        sentinel_uri,
        metadata_nonce,
        status,
        min_contract_dur,
        max_contract_dur,
        subscription_rates,
        pay_as_you_go_rates,
        settlement_dur,
        *NODE_ARGS,
        *CHAIN_ARGS,
        "--from",
        user,
        "--fees",
        fees,
        "--keyring-backend",
        keyring_backend,
        "-y",
    ]

    def run_mod_with_sequence(seq_arg: list[str]):
        cmd = mod_cmd_base.copy()
        # insert sequence args just before the --from flag
        try:
            insert_at = cmd.index("--from")
        except ValueError:
            insert_at = len(cmd)
        cmd[insert_at:insert_at] = seq_arg
        return cmd, *run_list(cmd)

    app.logger.info("bond-mod-provider mod sequence arg=%s", sequence_arg)
    mod_cmd, mod_code, mod_out = run_mod_with_sequence(sequence_arg)
    app.logger.info("bond-mod-provider mod cmd=%s", mod_cmd)

    # Retry once on account-sequence mismatch by refetching or using the expected sequence
    if "account sequence mismatch" in str(mod_out):
        time.sleep(1)
        retry_seq: list[str] = []
        # First, try to parse the expected sequence from the error text
        m = re.search(r"expected\s+(\d+)", str(mod_out))
        if m:
            retry_seq = ["--sequence", m.group(1)]
        # If not found, re-query the account for the latest sequence
        if not retry_seq:
            for _ in range(2):
                try:
                    acct_cmd = ["arkeod", "--home", ARKEOD_HOME, "query", "auth", "account", bech32_pubkey, "-o", "json"]
                    if ARKEOD_NODE:
                        acct_cmd.extend(["--node", ARKEOD_NODE])
                    code, acct_out = run_list(acct_cmd)
                    if code == 0:
                        acct = json.loads(acct_out)
                        seq_val = None
                        if isinstance(acct, dict):
                            account_info = acct.get("account") or acct.get("result") or {}
                            if isinstance(account_info, dict):
                                val = account_info.get("value") or account_info
                                if isinstance(val, dict):
                                    seq_val = val.get("sequence")
                        if seq_val is not None:
                            retry_seq = ["--sequence", str(seq_val)]
                            break
                except Exception:
                    pass
                time.sleep(1)
        mod_cmd, mod_code, mod_out = run_mod_with_sequence(retry_seq)
        app.logger.info("bond-mod-provider retry mod with sequence=%s code=%s", retry_seq, mod_code)

    if mod_code != 0:
        return jsonify(
            {
                "error": "failed to mod provider",
                "detail": mod_out,
                "cmd": mod_cmd,
                "inputs": {
                    "service": service,
                    "resolved_service": resolved_service,
                    "sentinel_uri": sentinel_uri,
                    "metadata_nonce": metadata_nonce,
                    "status": status,
                    "min_contract_dur": min_contract_dur,
                    "max_contract_dur": max_contract_dur,
                    "subscription_rates": subscription_rates,
                    "pay_as_you_go_rates": pay_as_you_go_rates,
                    "settlement_dur": settlement_dur,
                    "bond": bond,
                    "keyring_backend": keyring_backend,
                    "fees": fees,
                },
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
                "user": user,
                "bond_tx": {"exit_code": bond_code, "output": bond_out},
            }
        ), 500

    # Sync provider name/moniker to sentinel env so they stay aligned
    try:
        env_file = _load_env_file(SENTINEL_ENV_PATH)
        name_val = env_file.get("MONIKER") or env_file.get("PROVIDER_NAME") or os.getenv("MONIKER") or os.getenv("PROVIDER_NAME") or "Arkeo Provider"
        env_file["MONIKER"] = name_val
        env_file["PROVIDER_NAME"] = name_val
        _write_env_file(SENTINEL_ENV_PATH, env_file)
        app.logger.info("bond-mod-provider synced MONIKER/PROVIDER_NAME to %s", name_val)
    except Exception as e:
        app.logger.warning("bond-mod-provider failed to sync MONIKER/PROVIDER_NAME: %s", e)

    # Persist the provider form/export bundle (includes sentinel_uri) for UI reloads/imports
    try:
        _write_export_bundle(provider_form=payload)
    except Exception:
        app.logger.warning("bond-mod-provider failed to persist provider form export", exc_info=True)

    return jsonify(
        {
            "status": "bond_and_mod_submitted",
            "user": user,
            "inputs": {
                "service": service,
                "resolved_service": resolved_service,
                "lookup_note": lookup_note,
                "sentinel_uri": sentinel_uri,
                "metadata_nonce": metadata_nonce,
                "status": status,
                "min_contract_dur": min_contract_dur,
                "max_contract_dur": max_contract_dur,
                "subscription_rates": subscription_rates,
                "pay_as_you_go_rates": pay_as_you_go_rates,
                "settlement_dur": settlement_dur,
                "bond": bond,
                "keyring_backend": keyring_backend,
                "fees": fees,
            },
            "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            "bond_cmd": bond_cmd,
            "mod_cmd": mod_cmd,
            "bond_tx": {"exit_code": bond_code, "output": bond_out},
            "mod_tx": {"exit_code": mod_code, "output": mod_out},
        }
    )


@app.get("/api/provider-info")
def provider_info():
    """Return hotwallet provider info including pubkeys and defaults."""
    user = KEY_NAME
    keyring_backend = KEYRING
    fees = FEES_DEFAULT
    bond = BOND_DEFAULT

    export_bundle = _load_export_bundle()
    provider_metadata = (export_bundle and export_bundle.get("env_file")) or _load_env_file(SENTINEL_ENV_PATH)

    base = provider_pubkeys_response(user, keyring_backend)
    base.update(
        {
            "fees": fees,
            "bond": bond,
            "sentinel_uri": SENTINEL_URI_DEFAULT,
            "metadata_nonce": METADATA_NONCE_DEFAULT,
            "arkeod_node": ARKEOD_NODE,
            "provider_metadata": provider_metadata,
            "provider_export": export_bundle,
            "provider_export_path": PROVIDER_EXPORT_PATH,
        }
    )
    return jsonify(base)


@app.get("/api/services")
def list_services():
    """Return available services (REST first, CLI fallback)."""
    # Try REST first
    rest_base = _normalize_base(os.getenv("ARKEO_REST_API_PORT"))
    if rest_base:
        try:
            url = f"{rest_base}/arkeo/services"
            with urllib.request.urlopen(url, timeout=6) as resp:
                body = resp.read().decode("utf-8")
            parsed = json.loads(body)
            entries = parsed.get("services") or parsed.get("service") or []
            services = []
            for item in entries:
                if not isinstance(item, dict):
                    continue
                sid = item.get("id") or item.get("service_id") or item.get("serviceID")
                name = item.get("service") or item.get("name") or item.get("label")
                desc = item.get("description") or item.get("desc") or ""
                if sid is None and name is None:
                    continue
                services.append({"id": sid, "name": name, "description": desc})
            if services:
                return jsonify({"services": services, "raw": parsed, "source": url})
        except Exception:
            pass

    # Fallback to CLI
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "all-services", "-o", "json", "--limit", "5000", "--count-total"])

    code, out = run_list(cmd)
    if code != 0:
        return jsonify({"error": "failed to list services", "detail": out, "cmd": cmd}), 500

    raw_out = out

    def parse_json(text: str):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            first_brace = text.find("{")
            first_bracket = text.find("[")
            candidates = [i for i in (first_brace, first_bracket) if i >= 0]
            if not candidates:
                return None
            start = min(candidates)
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                return None

    parsed = parse_json(raw_out)
    if parsed is None:
        parsed = raw_out

    services = []
    # Try common shapes; fall back to raw data if not recognized
    candidates = []
    if isinstance(parsed, dict):
        for key in ("services", "result", "data"):
            val = parsed.get(key)
            if isinstance(val, list):
                candidates = val
                break
    if not candidates and isinstance(parsed, list):
        candidates = parsed

    for item in candidates:
        if not isinstance(item, dict):
            continue
        sid = item.get("id") or item.get("service_id") or item.get("serviceID")
        name = item.get("service") or item.get("name") or item.get("label")
        desc = item.get("description") or item.get("desc") or ""
        if sid is None and name is None:
            continue
        services.append({"id": sid, "name": name, "description": desc})

    # If parsing failed, try to extract minimal info from text lines
    if not services and isinstance(parsed, str):
        text_pattern = re.compile(
            r"^\s*-\s*(?P<service>[^:]+?)\s*:\s*(?P<id>[0-9]+)\s*\\((?P<desc>.*)\\)\\s*$"
        )
        for line in parsed.splitlines():
            m = text_pattern.match(line)
            if not m:
                continue
            sid = m.group("id").strip()
            svc = m.group("service").strip()
            desc = m.group("desc").strip()
            services.append({"id": sid, "name": svc, "description": desc})

    return jsonify({"services": services, "raw": parsed, "cmd": cmd})


@app.get("/api/provider-services")
def provider_services():
    """List services for the current provider (filtered by pubkey)."""
    user = KEY_NAME
    keyring_backend = KEYRING
    raw_pubkey, bech32_pubkey, pubkey_err = derive_pubkeys(user, keyring_backend)
    if pubkey_err:
        return jsonify(
            {
                "error": pubkey_err,
                "user": user,
                "keyring_backend": keyring_backend,
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            }
        ), 500

    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-providers", "--output", "json"])

    code, out = run_list(cmd)
    if code != 0:
        return jsonify(
            {
                "error": "failed to list providers",
                "detail": out,
                "cmd": cmd,
                "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            }
        ), 500

    providers = []
    try:
        data = json.loads(out)
        providers = data.get("provider") or data.get("providers") or []
    except json.JSONDecodeError:
        providers = []

    matched = []
    for p in providers:
        if not isinstance(p, dict):
            continue
        pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        if pk and pk == bech32_pubkey:
            matched.append(p)

    services = []
    def _rate_to_string(rate_val):
        """Normalize rate structures into a compact string."""
        if isinstance(rate_val, list):
            parts = []
            for r in rate_val:
                if not isinstance(r, dict):
                    continue
                amount = r.get("amount")
                denom = r.get("denom") or ""
                if amount is None:
                    continue
                parts.append(f"{amount}{denom}")
            return ",".join(parts) if parts else ""
        if isinstance(rate_val, dict):
            amount = rate_val.get("amount")
            denom = rate_val.get("denom") or ""
            if amount is None:
                return ""
            return f"{amount}{denom}"
        return str(rate_val) if rate_val is not None else ""

    for p in matched:
        svc_list = []
        if isinstance(p.get("services"), list):
            svc_list = p.get("services")
        elif isinstance(p.get("service"), list):
            svc_list = p.get("service")
        # If the provider entry itself looks like a single service entry
        if svc_list:
            for s in svc_list:
                if not isinstance(s, dict):
                    continue
                min_dur = s.get("min_contract_duration") or s.get("min_contract_dur")
                max_dur = s.get("max_contract_duration") or s.get("max_contract_dur")
                sub_rate_raw = s.get("subscription_rate") or s.get("subscription_rates")
                paygo_rate_raw = s.get("pay_as_you_go_rate") or s.get("pay_as_you_go_rates")
                sub_rate = _rate_to_string(sub_rate_raw)
                paygo_rate = _rate_to_string(paygo_rate_raw)
                settle = s.get("settlement_duration") or s.get("settlement_dur")
                status_val = s.get("status")
                # Normalized id/name: if id missing, fall back to service field
                sid = s.get("service_id") or s.get("id") or s.get("service")
                sname = s.get("service") or s.get("name")
                bond_val = s.get("bond") or p.get("bond")
                services.append(
                    {
                        "name": sname,
                        "id": sid,
                        "service": s.get("service"),
                        "metadata_uri": s.get("metadata_uri") or s.get("metadataUri"),
                        "metadata_nonce": s.get("metadata_nonce") or s.get("metadataNonce"),
                        "status": status_val,
                        "min_contract_dur": min_dur,
                        "max_contract_dur": max_dur,
                        "subscription_rates": sub_rate,
                        "pay_as_you_go_rates": paygo_rate,
                        "settlement_dur": settle,
                        "bond": bond_val,
                    }
                )
        else:
            min_dur = p.get("min_contract_duration") or p.get("min_contract_dur")
            max_dur = p.get("max_contract_duration") or p.get("max_contract_dur")
            sub_rate_raw = p.get("subscription_rate") or p.get("subscription_rates")
            paygo_rate_raw = p.get("pay_as_you_go_rate") or p.get("pay_as_you_go_rates")
            sub_rate = _rate_to_string(sub_rate_raw)
            paygo_rate = _rate_to_string(paygo_rate_raw)
            settle = p.get("settlement_duration") or p.get("settlement_dur")
            status_val = p.get("status")
            sid = p.get("service_id") or p.get("id") or p.get("service")
            sname = p.get("service") or p.get("name")
            bond_val = p.get("bond")
            services.append(
                {
                    "name": sname,
                    "id": sid,
                    "service": p.get("service"),
                    "metadata_uri": p.get("metadata_uri") or p.get("metadataUri"),
                    "metadata_nonce": p.get("metadata_nonce") or p.get("metadataNonce"),
                    "status": status_val,
                    "min_contract_dur": min_dur,
                    "max_contract_dur": max_dur,
                    "subscription_rates": sub_rate,
                    "pay_as_you_go_rates": paygo_rate,
                    "settlement_dur": settle,
                    "bond": bond_val,
                }
            )

    return jsonify(
        {
            "services": services,
            "matched_providers": matched,
            "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            "cmd": cmd,
        }
    )


@app.get("/api/sentinel-status")
def sentinel_status():
    """Return sentinel process status (supervisor + short logs)."""
    status = ""
    log_tail = ""
    err_tail = ""
    try:
        code, out = run_list([*SUPERVISORCTL, "status", "sentinel"])
        status = out.strip()
    except Exception:
        try:
            code, out = run_list([*SUPERVISORCTL_FALLBACK, "status", "sentinel"])
            status = out.strip()
        except Exception as e:
            status = f"status error: {e}"
    try:
        code, out = run_list(["tail", "-n", "80", "/var/log/provider-sentinel.log"])
        log_tail = out
    except Exception as e:
        log_tail = f"log error: {e}"
    try:
        code, out = run_list(["tail", "-n", "80", "/var/log/provider-sentinel.err.log"])
        err_tail = out
    except Exception as e:
        err_tail = f"errlog error: {e}"
    return jsonify({"status": status, "log": log_tail, "err_log": err_tail})


@app.post("/api/sentinel-control")
def sentinel_control():
    """Start/stop/restart sentinel via supervisorctl."""
    payload = request.get_json(force=True, silent=True) or {}
    action = (payload.get("action") or "").lower()
    if action not in {"start", "stop", "restart"}:
        return jsonify({"error": "action must be one of start, stop, restart"}), 400
    try:
        code, out = run_list([*SUPERVISORCTL, action, "sentinel"])
        return jsonify({"status": "ok", "action": action, "exit_code": code, "output": out})
    except Exception:
        try:
            code, out = run_list([*SUPERVISORCTL_FALLBACK, action, "sentinel"])
            return jsonify({"status": "ok", "action": action, "exit_code": code, "output": out})
        except Exception as e:
            return jsonify({"error": f"failed to {action} sentinel", "detail": str(e)}), 500


@app.get("/api/sentinel-metadata")
def sentinel_metadata():
    """Fetch sentinel metadata.json from the given URL (or default)."""
    force_loopback = request.args.get("loopback") not in (None, "", "0", "false", "False")
    quiet = request.args.get("quiet") not in (None, "", "0", "false", "False")
    if force_loopback:
        url = "http://127.0.0.1:3636/metadata.json"
    else:
        url = request.args.get("url") or request.args.get("sentinel_uri") or SENTINEL_URI_DEFAULT
    if not url:
        return jsonify({"error": "sentinel uri not provided"}), 400
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        status = 200 if quiet else 500
        return jsonify({"error": "failed to fetch sentinel metadata", "detail": str(e), "url": url}), status
    parsed = None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if parsed is None:
        return jsonify({"url": url, "raw": body})
    return jsonify({"url": url, "metadata": parsed})


def _load_sentinel_config():
    """Load sentinel YAML config if present."""
    if not SENTINEL_CONFIG_PATH or not os.path.isfile(SENTINEL_CONFIG_PATH):
        return None, None
    try:
        with open(SENTINEL_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError:
            parsed = None
        return parsed, raw
    except OSError:
        return None, None


def _load_env_file(path: str) -> dict:
    data: dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return data
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
                    v = v[1:-1]
                data[k.strip()] = v
    except OSError:
        pass
    return data

def _write_env_file(path: str, data: dict) -> None:
    """Write env-style file from a dict."""
    if not path or not isinstance(data, dict):
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            for k, v in data.items():
                f.write(f"{k}={shlex.quote(str(v))}\n")
    except OSError:
        pass

def _expand_tilde(val: str) -> str:
    """Expand leading tilde to $HOME."""
    if not isinstance(val, str):
        return val
    if val.startswith("~"):
        return os.path.expanduser(val)
    return val


def _load_provider_settings_file() -> dict:
    """Load persisted provider settings JSON (replacement for provider.env)."""
    if not PROVIDER_SETTINGS_PATH or not os.path.isfile(PROVIDER_SETTINGS_PATH):
        return {}
    try:
        with open(PROVIDER_SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_provider_settings_file(data: dict) -> None:
    """Persist provider settings JSON."""
    if not PROVIDER_SETTINGS_PATH or not isinstance(data, dict):
        return
    try:
        os.makedirs(os.path.dirname(PROVIDER_SETTINGS_PATH), exist_ok=True)
        with open(PROVIDER_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _load_admin_password() -> str:
    """Return stored admin password (plain) or empty string."""
    if not ADMIN_PASSWORD_PATH or not os.path.isfile(ADMIN_PASSWORD_PATH):
        return ""
    try:
        with open(ADMIN_PASSWORD_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_admin_password(password: str) -> bool:
    """Persist admin password; returns True on success."""
    if not ADMIN_PASSWORD_PATH:
        return False
    try:
        os.makedirs(os.path.dirname(ADMIN_PASSWORD_PATH), exist_ok=True)
        with open(ADMIN_PASSWORD_PATH, "w", encoding="utf-8") as f:
            f.write(password.strip())
        return True
    except OSError:
        return False


def _remove_admin_password() -> bool:
    """Remove stored admin password; returns True on success or not present."""
    if not ADMIN_PASSWORD_PATH:
        return False
    try:
        if os.path.isfile(ADMIN_PASSWORD_PATH):
            os.remove(ADMIN_PASSWORD_PATH)
        return True
    except OSError:
        return False


def _is_auth_required() -> bool:
    return bool(_load_admin_password())


def _purge_sessions() -> None:
    now = time.time()
    expired = [tok for tok, exp in ADMIN_SESSIONS.items() if exp <= now]
    for tok in expired:
        ADMIN_SESSIONS.pop(tok, None)


def _generate_session_token(ttl_seconds: int = 3600) -> str:
    _purge_sessions()
    token = secrets.token_hex(32)
    ADMIN_SESSIONS[token] = time.time() + ttl_seconds
    return token


def _validate_session(token: str | None) -> bool:
    if not token:
        return False
    _purge_sessions()
    exp = ADMIN_SESSIONS.get(token)
    if not exp:
        return False
    if exp <= time.time():
        ADMIN_SESSIONS.pop(token, None)
        return False
    return True


def _origin_allowed(origin: str | None) -> bool:
    if not origin:
        return False
    try:
        parsed = urllib.parse.urlparse(origin)
    except Exception:
        return False
    origin_host = parsed.netloc or parsed.path
    if not origin_host:
        return False
    try:
        ui_parsed = urllib.parse.urlparse(ADMIN_UI_ORIGIN)
        ui_host = ui_parsed.netloc or ui_parsed.path
        if origin_host == ui_host:
            return True
    except Exception:
        pass
    # Allow same host as API
    api_host = request.host.split(":")[0] if request.host else ""
    if api_host and origin_host.startswith(api_host):
        return True
    return False


def _cors_headers():
    origin = request.headers.get("Origin")
    headers = {}
    if _origin_allowed(origin):
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Cache-Control"
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        headers["Access-Control-Max-Age"] = "3600"
    return headers


def _default_provider_settings() -> dict:
    """Return defaults from env + sane fallbacks."""
    defaults = {
        "KEY_NAME": os.getenv("KEY_NAME", DEFAULT_KEY_NAME),
        "KEY_KEYRING_BACKEND": os.getenv("KEY_KEYRING_BACKEND", DEFAULT_KEYRING),
        "KEY_MNEMONIC": os.getenv("KEY_MNEMONIC", DEFAULT_MNEMONIC),
        "CHAIN_ID": _strip_quotes(os.getenv("CHAIN_ID") or os.getenv("ARKEOD_CHAIN_ID") or DEFAULT_CHAIN_ID),
        "ARKEOD_HOME": _expand_tilde(os.getenv("ARKEOD_HOME") or DEFAULT_ARKEOD_HOME),
        "ARKEOD_NODE": _strip_quotes(os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or DEFAULT_ARKEOD_NODE),
        "ARKEO_REST_API_PORT": os.getenv("ARKEO_REST_API_PORT") or DEFAULT_ARKEO_REST,
        "SENTINEL_NODE": os.getenv("SENTINEL_NODE") or DEFAULT_SENTINEL_NODE,
        "SENTINEL_PORT": os.getenv("SENTINEL_PORT") or DEFAULT_SENTINEL_PORT,
        "ADMIN_PORT": os.getenv("ADMIN_PORT") or DEFAULT_ADMIN_PORT,
        "ADMIN_API_PORT": os.getenv("ADMIN_API_PORT") or DEFAULT_ADMIN_API_PORT,
        "EVENT_STREAM_HOST": os.getenv("EVENT_STREAM_HOST") or "",
    }
    return defaults


def _merge_provider_settings(overrides: dict | None = None) -> dict:
    """Merge defaults, persisted file, and optional overrides."""
    merged = _default_provider_settings()
    saved = _load_provider_settings_file()
    if isinstance(saved, dict):
        merged.update(saved)
    if overrides and isinstance(overrides, dict):
        merged.update(overrides)
    # Normalize legacy PROVIDER_HUB_URI into ARKEO_REST_API_PORT and drop it
    if not merged.get("ARKEO_REST_API_PORT") and merged.get("PROVIDER_HUB_URI"):
        merged["ARKEO_REST_API_PORT"] = merged.get("PROVIDER_HUB_URI")
    merged.pop("PROVIDER_HUB_URI", None)
    # Prefer ARKEOD_NODE; drop EXTERNAL_ARKEOD_NODE
    if merged.get("EXTERNAL_ARKEOD_NODE") and not merged.get("ARKEOD_NODE"):
        merged["ARKEOD_NODE"] = merged["EXTERNAL_ARKEOD_NODE"]
    merged.pop("EXTERNAL_ARKEOD_NODE", None)
    merged["ARKEOD_HOME"] = _expand_tilde(merged.get("ARKEOD_HOME") or ARKEOD_HOME)
    if not merged.get("ARKEOD_NODE"):
        merged["ARKEOD_NODE"] = ARKEOD_NODE
    return merged


def _apply_provider_settings(settings: dict) -> None:
    """Apply provider settings to globals and os.environ for runtime use."""
    global KEY_NAME, KEYRING, ARKEOD_HOME, ARKEOD_NODE, CHAIN_ID, NODE_ARGS, CHAIN_ARGS
    if not isinstance(settings, dict):
        return
    KEY_NAME = settings.get("KEY_NAME", KEY_NAME)
    KEYRING = settings.get("KEY_KEYRING_BACKEND", KEYRING)
    ARKEOD_HOME = _expand_tilde(settings.get("ARKEOD_HOME") or ARKEOD_HOME)
    node_val = settings.get("ARKEOD_NODE") or ARKEOD_NODE
    ARKEOD_NODE = _ensure_tcp_scheme(_strip_quotes(node_val))
    CHAIN_ID = _strip_quotes(settings.get("CHAIN_ID") or CHAIN_ID)
    NODE_ARGS = ["--node", ARKEOD_NODE] if ARKEOD_NODE else []
    CHAIN_ARGS = ["--chain-id", CHAIN_ID] if CHAIN_ID else []

    env_overrides = {
        "KEY_NAME": KEY_NAME,
        "KEY_KEYRING_BACKEND": KEYRING,
        "CHAIN_ID": CHAIN_ID,
        "ARKEOD_HOME": ARKEOD_HOME,
        "ARKEOD_NODE": ARKEOD_NODE,
        "ARKEO_REST_API_PORT": settings.get("ARKEO_REST_API_PORT", ""),
        "SENTINEL_NODE": settings.get("SENTINEL_NODE", ""),
        "SENTINEL_PORT": settings.get("SENTINEL_PORT", ""),
        "ADMIN_PORT": settings.get("ADMIN_PORT", ""),
        "ADMIN_API_PORT": settings.get("ADMIN_API_PORT", ""),
        "EVENT_STREAM_HOST": settings.get("EVENT_STREAM_HOST", ""),
        "KEY_MNEMONIC": settings.get("KEY_MNEMONIC", ""),
    }
    for k, v in env_overrides.items():
        if v is None:
            continue
        os.environ[k] = str(v)


# Apply persisted provider settings at import time (if present)
_apply_provider_settings(_merge_provider_settings())


def _mnemonic_file_path(settings: dict | None = None) -> str:
    cfg = settings or _merge_provider_settings()
    home = _expand_tilde(cfg.get("ARKEOD_HOME") or ARKEOD_HOME)
    key_name = cfg.get("KEY_NAME") or KEY_NAME
    return os.path.join(home, f"{key_name}_mnemonic.txt")


def _extract_mnemonic(text: str) -> str:
    """Best-effort extraction of a 12-24 word mnemonic from text."""
    if not text:
        return ""
    text_lower = text.lower()
    candidates: list[tuple[int, int, str]] = []
    for idx, line in enumerate(text_lower.splitlines()):
        words = [w for w in line.strip().split() if w.isalpha()]
        if 12 <= len(words) <= 24:
            candidates.append((len(words), idx, " ".join(words)))
    for match_idx, m in enumerate(re.finditer(r"([a-z]+(?: [a-z]+){11,23})", text_lower)):
        phrase = m.group(1)
        word_count = len(phrase.split())
        candidates.append((word_count, 10000 + match_idx, phrase))
    if not candidates:
        return ""
    # Prefer highest word count; if tie, prefer later occurrence
    candidates.sort(key=lambda t: (t[0], t[1]))
    return candidates[-1][2]


def _read_hotwallet_mnemonic(settings: dict | None = None) -> tuple[str, str]:
    """Return mnemonic and source (settings/env/file/none)."""
    cfg = _merge_provider_settings(settings or {})
    mnemonic = (cfg.get("KEY_MNEMONIC") or os.getenv("KEY_MNEMONIC") or "").strip()
    if mnemonic:
        return mnemonic, "settings"
    path = _mnemonic_file_path(cfg)
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            mnemonic = _extract_mnemonic(text)
            if mnemonic:
                return mnemonic, "file"
        except OSError:
            pass
    return "", "none"


def _write_hotwallet_mnemonic(settings: dict, mnemonic: str) -> None:
    """Write mnemonic to the default file for later retrieval."""
    path = _mnemonic_file_path(settings)
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mnemonic.strip() + "\n")
    except OSError:
        pass


def _delete_hotwallet(key_name: str, keyring_backend: str, home: str) -> tuple[int, str]:
    """Delete the existing key if present."""
    cmd = [
        "arkeod",
        "--home",
        home,
        "--keyring-backend",
        keyring_backend,
        "keys",
        "delete",
        key_name,
        "--force",
        "--yes",
    ]
    return run_list(cmd)


def _import_hotwallet_from_mnemonic(
    mnemonic: str, key_name: str, keyring_backend: str, home: str
) -> tuple[int, str]:
    """Import (recover) a hotwallet from mnemonic."""
    cmd = [
        "arkeod",
        "--home",
        home,
        "--keyring-backend",
        keyring_backend,
        "keys",
        "add",
        key_name,
        "--recover",
    ]
    return run_with_input(cmd, mnemonic.strip() + "\n")


def _create_hotwallet(
    key_name: str, keyring_backend: str, home: str
) -> tuple[int, str, str]:
    """Create a new hotwallet and return (exit_code, output, mnemonic)."""
    # Remove existing key first to avoid conflicts
    _delete_hotwallet(key_name, keyring_backend, home)
    cmd = [
        "arkeod",
        "--home",
        home,
        "--keyring-backend",
        keyring_backend,
        "keys",
        "add",
        key_name,
    ]
    code, out = run_list(cmd)
    mnemonic = _extract_mnemonic(out)
    return code, out, mnemonic


def _sync_sentinel_pubkey(bech32_pubkey: str) -> bool:
    """Update sentinel config provider pubkey to match hotwallet."""
    if not bech32_pubkey:
        return False
    parsed, raw = _load_sentinel_config()
    if parsed is None or not isinstance(parsed, dict):
        return False
    provider = parsed.get("provider")
    if provider is None or not isinstance(provider, dict):
        provider = {}
        parsed["provider"] = provider
    provider["pubkey"] = bech32_pubkey
    try:
        with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(parsed, f, sort_keys=False)
        return True
    except OSError:
        return False


def _load_export_bundle() -> dict | None:
    """Load cached provider export if present."""
    path = PROVIDER_EXPORT_PATH
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_export_bundle(
    provider_form: dict | None = None,
    env_file: dict | None = None,
    sentinel_config_override: dict | None = None,
    sentinel_config_raw_override: str | None = None,
) -> dict:
    """Persist a reusable config bundle next to provider.env."""
    parsed_cfg, raw_cfg = _load_sentinel_config()
    if sentinel_config_override is not None:
        parsed_cfg = sentinel_config_override
    if sentinel_config_raw_override is not None:
        raw_cfg = sentinel_config_raw_override
    if env_file is None:
        env_file = _load_env_file(SENTINEL_ENV_PATH)
    provider_env_file = _load_env_file(PROVIDER_ENV_PATH)
    provider_settings = _load_provider_settings_file()
    bundle = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sentinel_env_path": SENTINEL_ENV_PATH,
        "sentinel_config_path": SENTINEL_CONFIG_PATH,
        "export_path": PROVIDER_EXPORT_PATH,
        "sentinel_config": parsed_cfg,
        "sentinel_config_raw": raw_cfg,
        "env_file": env_file,
        "provider_env_file": provider_env_file,
        "provider_env_path": PROVIDER_ENV_PATH,
        "provider_settings": provider_settings,
        "provider_settings_path": PROVIDER_SETTINGS_PATH,
    }
    if provider_form:
        bundle["provider_form"] = provider_form
    try:
        export_dir = os.path.dirname(PROVIDER_EXPORT_PATH)
        if export_dir and not os.path.isdir(export_dir):
            os.makedirs(export_dir, exist_ok=True)
        with open(PROVIDER_EXPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
    except OSError:
        pass
    return bundle


def _fetch_provider_services_internal(bech32_pubkey: str) -> list[dict]:
    """Return provider services for a given pubkey (tries REST first, CLI fallback)."""
    # Try REST (if hub URI provided)
    rest_base = _normalize_base(os.getenv("ARKEO_REST_API_PORT"))
    if rest_base:
        try:
            url = f"{rest_base}/arkeo/services"
            with urllib.request.urlopen(url, timeout=6) as resp:
                body = resp.read().decode("utf-8")
            data = json.loads(body)
            entries = data.get("services") or data.get("service") or []
            services: list[dict] = []
            for s in entries:
                if not isinstance(s, dict):
                    continue
                provider_pk = s.get("provider") or s.get("provider_pubkey") or s.get("provider_pub_key")
                if provider_pk != bech32_pubkey:
                    continue
                sid = s.get("service_id") or s.get("id") or s.get("service")
                sname = s.get("service") or s.get("name")
                services.append(
                    {
                        "id": sid,
                        "name": sname,
                        "status": s.get("status"),
                    }
                )
            if services:
                return services
        except Exception:
            pass

    # Fallback to CLI query
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-providers", "--output", "json", "--limit", "5000", "--count-total"])
    code, out = run_list(cmd)
    if code != 0:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    providers = data.get("provider") or data.get("providers") or []
    services: list[dict] = []
    for p in providers:
        if not isinstance(p, dict):
            continue
        pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        if pk != bech32_pubkey:
            continue
        entries = []
        if isinstance(p.get("services"), list):
            entries = p.get("services")
        elif isinstance(p.get("service"), list):
            entries = p.get("service")
        if not entries:
            entries = [p]
        for s in entries:
            if not isinstance(s, dict):
                continue
            sid = s.get("service_id") or s.get("id") or s.get("service")
            sname = s.get("service") or s.get("name")
            services.append(
                {
                    "id": sid,
                    "name": sname,
                    "status": s.get("status"),
                }
            )
    return services


def _filter_sentinel_services_with_onchain(parsed_cfg: dict, bech32_pubkey: str) -> tuple[list[dict], list[str], list[dict]]:
    """Filter sentinel services to include only on-chain active services for this provider."""
    active = _fetch_provider_services_internal(bech32_pubkey)
    active_ids: set[str] = set()
    active_names: set[str] = set()
    annotated: list[dict] = []
    for s in active:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        sname = s.get("name") or s.get("service")
        status_val = s.get("status")
        status_str = str(status_val).lower()
        is_active = status_str in ("1", "active", "online", "true")
        annotated.append({"id": sid, "name": sname, "status": status_val, "is_active": is_active})
        if is_active:
            if sid is not None:
                active_ids.add(str(sid))
            if sname:
                active_names.add(str(sname).lower())
    filtered = []
    skipped = []
    for svc in parsed_cfg.get("services") or []:
        if not isinstance(svc, dict):
            continue
        sid = str(svc.get("id")) if svc.get("id") is not None else ""
        sname = str(svc.get("name") or svc.get("service") or svc.get("type") or "")
        sname_lower = sname.lower()
        keep = False
        if sid and sid in active_ids:
            keep = True
        if sname_lower and sname_lower in active_names:
            keep = True
        if keep:
            filtered.append(svc)
        else:
            skipped.append(sname or sid or "(unknown)")
    return filtered, skipped, annotated


def _all_services_lookup() -> dict[str, str]:
    """Return a mapping of service id -> service name from arkeod all-services."""
    lookup: dict[str, str] = {}
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "all-services", "-o", "json"])
    code, out = run_list(cmd)
    if code != 0:
        return lookup
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return lookup
    services = data.get("services") or data.get("result") or data.get("data") or []
    if not isinstance(services, list):
        services = []
    for item in services:
        if not isinstance(item, dict):
            continue
        sid = item.get("id") or item.get("service_id") or item.get("serviceID")
        name = item.get("name") or item.get("service") or item.get("label")
        if sid is None:
            continue
        lookup[str(sid)] = name
    return lookup


@app.post("/api/sentinel-rebuild")
def sentinel_rebuild():
    """Update or add a single service entry in sentinel.yaml (rpc settings) and restart sentinel."""
    payload = request.get_json(silent=True) or {}
    overrides = payload.get("service_overrides") or []
    target = None
    if isinstance(overrides, list) and overrides:
        target = overrides[0] if isinstance(overrides[0], dict) else None
    if not target:
        return jsonify({"error": "no service override provided"}), 400
    target_name = str(target.get("name") or target.get("service") or target.get("type") or "").strip()
    target_id = str(target.get("id") or target.get("service_id") or target.get("service") or "").strip()
    target_name_lower = target_name.lower()
    if not target_name and not target_id:
        return jsonify({"error": "service name or id required"}), 400
    if not target_name and target_id:
        lookup = _all_services_lookup()
        target_name = lookup.get(target_id, "")
        target_name_lower = target_name.lower()
    status_raw = str(target.get("status") or "").lower()
    should_remove = status_raw in ("0", "inactive", "offline")
    app.logger.info(
        "sentinel-rebuild override target id=%s name=%s rpc_url=%s rpc_user=%s rpc_pass=%s remove=%s",
        target_id,
        target_name,
        target.get("rpc_url"),
        target.get("rpc_user"),
        "***" if target.get("rpc_pass") else "",
        should_remove,
    )

    raw_pubkey, bech32_pubkey, pub_err = derive_pubkeys(KEY_NAME, KEYRING)
    if pub_err:
        return jsonify({"error": pub_err}), 500

    parsed, raw = _load_sentinel_config()
    if parsed is None or not isinstance(parsed, dict):
        parsed = {}
    existing_services = parsed.get("services") if isinstance(parsed.get("services"), list) else []
    provider_cfg = parsed.get("provider") if isinstance(parsed.get("provider"), dict) else {}
    api_cfg = parsed.get("api") if isinstance(parsed.get("api"), dict) else {}

    def _normalize_id(val):
        """Coerce numeric-looking ids to int to satisfy yaml expectations."""
        if isinstance(val, int):
            return val
        try:
            ival = int(str(val))
            return ival
        except (TypeError, ValueError):
            return val

    def _is_placeholder(entry: dict) -> bool:
        if not isinstance(entry, dict):
            return False
        name = str(entry.get("name") or entry.get("service") or "").strip()
        sid = str(entry.get("id") or entry.get("service_id") or entry.get("service") or "").strip()
        return name == "default-placeholder" or sid in ("0", 0)

    def _svc_matches(svc: dict) -> bool:
        if not isinstance(svc, dict):
            return False
        sid = str(svc.get("id")) if svc.get("id") is not None else ""
        sname = str(svc.get("name") or svc.get("service") or svc.get("type") or "")
        sname_lower = sname.lower()
        stype_lower = str(svc.get("type") or "").lower()
        if target_id and sid and target_id == sid:
            return True
        if target_name_lower and sname_lower and sname_lower == target_name_lower:
            return True
        if target_name_lower and stype_lower and stype_lower == target_name_lower:
            return True
        return False

    new_services = []
    updated = False
    for svc in existing_services:
        if not isinstance(svc, dict):
            new_services.append(svc)
            continue
        match = _svc_matches(svc)
        if match:
            app.logger.info("sentinel-rebuild matched service id=%s name=%s", svc.get("id"), svc.get("name"))
            if should_remove:
                updated = True
                continue
            entry = dict(svc)
            if target.get("rpc_url") is not None:
                entry["rpc_url"] = target.get("rpc_url")
            if target.get("rpc_user") is not None:
                entry["rpc_user"] = target.get("rpc_user")
            if target.get("rpc_pass") is not None:
                entry["rpc_pass"] = target.get("rpc_pass")
            if target_id:
                entry["id"] = _normalize_id(target_id)
            if target_name:
                entry["name"] = target_name
            if target_name:
                entry["type"] = target_name
            entry.setdefault("rpc_url", "")
            entry.setdefault("rpc_user", "")
            entry.setdefault("rpc_pass", "")
            new_services.append(entry)
            app.logger.info(
                "sentinel-rebuild updated service id=%s name=%s rpc_url=%s rpc_user=%s rpc_pass=%s",
                entry.get("id"),
                entry.get("name"),
                entry.get("rpc_url"),
                entry.get("rpc_user"),
                "***" if entry.get("rpc_pass") else "",
            )
            updated = True
        else:
            new_services.append(svc)

    if should_remove:
        new_services = [svc for svc in new_services if not _svc_matches(svc)]

    if not updated and not should_remove:
        entry = {}
        if target_id:
            entry["id"] = _normalize_id(target_id)
        if target_name:
            entry["name"] = target_name
            entry["type"] = target_name
        entry["rpc_url"] = target.get("rpc_url") or ""
        entry["rpc_user"] = target.get("rpc_user") or ""
        entry["rpc_pass"] = target.get("rpc_pass") or ""
        new_services.append(entry)

    # Normalize ids to ints where possible to avoid quoted strings in YAML
    normalized_services = []
    for svc in new_services:
        if isinstance(svc, dict) and "id" in svc:
            svc = dict(svc)
            svc["id"] = _normalize_id(svc.get("id"))
        normalized_services.append(svc)

    active_services = [s for s in normalized_services if not _is_placeholder(s)]
    if active_services:
        normalized_services = active_services
    if not normalized_services:
        new_services.append(
            {
                "name": "default-placeholder",
                "id": 0,
                "type": "default-placeholder",
                "rpc_url": "http://provider1.innovationtheory.com:26657",
                "rpc_user": "",
                "rpc_pass": "",
            }
        )
        normalized_services = new_services

    parsed["provider"] = {
        "pubkey": bech32_pubkey,
        "name": provider_cfg.get("name") or os.getenv("PROVIDER_NAME") or "Arkeo Provider",
    }
    parsed["services"] = normalized_services
    parsed["api"] = api_cfg or {"listen_addr": "0.0.0.0:3636"}

    try:
        with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(parsed, f, sort_keys=False)
    except OSError as e:
        return jsonify({"error": "failed to write sentinel config", "detail": str(e)}), 500

    try:
        code, out = run_list([*SUPERVISORCTL, "restart", "sentinel"])
    except Exception as e:
        return jsonify({"error": "failed to restart sentinel", "detail": str(e)}), 500

    app.logger.info("sentinel-rebuild wrote config and restarted sentinel code=%s", code)

    return jsonify(
        {
            "status": "ok",
            "services_written": new_services,
            "pubkey": {"raw": raw_pubkey, "bech32": bech32_pubkey},
            "restart_exit_code": code,
            "restart_output": out,
            "sentinel_config_path": SENTINEL_CONFIG_PATH,
        }
    )


@app.get("/api/sentinel-config")
def sentinel_config():
    """Return sentinel-related env values and parsed sentinel.yaml if present."""
    env_data = {k.lower(): os.getenv(k) for k in ENV_EXPORT_KEYS}
    export_bundle = _load_export_bundle()
    env_file = (export_bundle and export_bundle.get("env_file")) or _load_env_file(SENTINEL_ENV_PATH)
    parsed, raw = _load_sentinel_config()
    return jsonify(
        {
            "env": env_data,
            "env_file": env_file,
            "config_path": SENTINEL_CONFIG_PATH,
            "config": parsed,
            "raw": raw,
            "sentinel_uri_default": SENTINEL_URI_DEFAULT,
            "provider_export": export_bundle,
            "provider_export_path": PROVIDER_EXPORT_PATH,
        }
    )


@app.get("/api/provider-settings")
def provider_settings_get():
    """Return provider settings (replacement for provider.env) plus mnemonic if available."""
    settings = _merge_provider_settings()
    mnemonic, mnemonic_source = _read_hotwallet_mnemonic(settings)
    generated = False
    if mnemonic:
        settings["KEY_MNEMONIC"] = mnemonic
    else:
        # No mnemonic available; create a new hotwallet
        code, out, gen_mnemonic = _create_hotwallet(
            settings.get("KEY_NAME") or KEY_NAME,
            settings.get("KEY_KEYRING_BACKEND") or KEYRING,
            settings.get("ARKEOD_HOME") or ARKEOD_HOME,
        )
        if code != 0 or not gen_mnemonic:
            return jsonify({"error": "failed to create hotwallet", "detail": out}), 500
        settings["KEY_MNEMONIC"] = gen_mnemonic
        _write_hotwallet_mnemonic(settings, gen_mnemonic)
        _apply_provider_settings(settings)
        _write_provider_settings_file(settings)
        mnemonic = gen_mnemonic
        mnemonic_source = "generated"
        generated = True
    raw_pk, bech32_pk, pub_err = derive_pubkeys(
        settings.get("KEY_NAME") or KEY_NAME, settings.get("KEY_KEYRING_BACKEND") or KEYRING
    )
    return jsonify(
        {
            "settings": settings,
            "provider_settings_path": PROVIDER_SETTINGS_PATH,
            "mnemonic_source": mnemonic_source,
            "mnemonic_found": bool(mnemonic),
            "mnemonic_generated": generated,
            "pubkey": {"raw": raw_pk, "bech32": bech32_pk, "error": pub_err},
            "admin_password": _load_admin_password(),
        }
    )


@app.post("/api/provider-settings")
def provider_settings_save():
    """Persist provider settings and optionally rotate hotwallet mnemonic."""
    payload = request.get_json(force=True, silent=True) or {}
    incoming = payload.get("settings") if isinstance(payload, dict) else None
    data = incoming if isinstance(incoming, dict) else payload
    if not isinstance(data, dict):
        return jsonify({"error": "invalid payload"}), 400

    merged = _merge_provider_settings(data)
    new_mnemonic = (data.get("KEY_MNEMONIC") or data.get("mnemonic") or "").strip()
    current_mnemonic, mnemonic_source = _read_hotwallet_mnemonic(merged)
    rotate = bool(new_mnemonic)
    delete_result: tuple[int, str] | None = None
    import_result: tuple[int, str] | None = None
    generated_result: tuple[int, str, str] | None = None

    if rotate:
        delete_result = _delete_hotwallet(
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            merged.get("ARKEOD_HOME") or ARKEOD_HOME,
        )
        delete_code, delete_out = delete_result
        if delete_code not in (0, 1) and "not found" not in delete_out.lower():
            return jsonify({"error": "failed to delete existing hotwallet", "detail": delete_out}), 500

        import_result = _import_hotwallet_from_mnemonic(
            new_mnemonic,
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            merged.get("ARKEOD_HOME") or ARKEOD_HOME,
        )
        import_code, import_out = import_result
        if import_code != 0:
            return jsonify({"error": "failed to import mnemonic", "detail": import_out}), 500
        merged["KEY_MNEMONIC"] = new_mnemonic
        mnemonic_source = "uploaded"
        _write_hotwallet_mnemonic(merged, new_mnemonic)
    elif current_mnemonic:
        merged["KEY_MNEMONIC"] = current_mnemonic
    else:
        # No mnemonic available; generate a new hotwallet
        delete_result = _delete_hotwallet(
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            merged.get("ARKEOD_HOME") or ARKEOD_HOME,
        )
        gen_code, gen_out, gen_mnemonic = _create_hotwallet(
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            merged.get("ARKEOD_HOME") or ARKEOD_HOME,
        )
        generated_result = (gen_code, gen_out, gen_mnemonic)
        if gen_code != 0 or not gen_mnemonic:
            return jsonify({"error": "failed to generate new mnemonic", "detail": gen_out}), 500
        merged["KEY_MNEMONIC"] = gen_mnemonic
        mnemonic_source = "generated"
        rotate = True
        _write_hotwallet_mnemonic(merged, gen_mnemonic)

    _apply_provider_settings(merged)
    _write_provider_settings_file(merged)

    raw_pk, bech32_pk, pub_err = derive_pubkeys(
        merged.get("KEY_NAME") or KEY_NAME, merged.get("KEY_KEYRING_BACKEND") or KEYRING
    )
    sentinel_updated = _sync_sentinel_pubkey(bech32_pk) if bech32_pk else False

    return jsonify(
        {
            "status": "saved",
            "provider_settings_path": PROVIDER_SETTINGS_PATH,
            "mnemonic_rotated": rotate,
            "mnemonic_source": mnemonic_source,
            "pubkey": {"raw": raw_pk, "bech32": bech32_pk, "error": pub_err},
            "sentinel_pubkey_updated": sentinel_updated,
            "delete_result": delete_result,
            "import_result": import_result,
            "generated_result": generated_result,
            "settings": merged,
        }
    )


@app.get("/api/admin-password")
def admin_password_get():
    """Return whether an admin password is set and the current value (for local UI use)."""
    pwd = _load_admin_password()
    return jsonify({"enabled": bool(pwd), "path": ADMIN_PASSWORD_PATH, "password": pwd})


@app.post("/api/admin-password")
def admin_password_set():
    """Set or clear admin password (empty disables)."""
    payload = request.get_json(force=True, silent=True) or {}
    password = (payload.get("password") or "").strip() if isinstance(payload, dict) else ""
    if _is_auth_required():
        # If a password is set, require valid session to change it
        token = request.cookies.get(ADMIN_SESSION_NAME)
        if not _validate_session(token):
            return jsonify({"error": "unauthorized"}), 401
    if not password:
        ok = _remove_admin_password()
        ADMIN_SESSIONS.clear()
        return jsonify({"status": "disabled", "enabled": False, "ok": ok, "path": ADMIN_PASSWORD_PATH})
    ok = _write_admin_password(password)
    if not ok:
        return jsonify({"error": "failed to write admin password", "path": ADMIN_PASSWORD_PATH}), 500
    return jsonify({"status": "saved", "enabled": True, "ok": True, "path": ADMIN_PASSWORD_PATH})


@app.post("/api/admin-password/check")
def admin_password_check():
    """Validate submitted admin password."""
    payload = request.get_json(force=True, silent=True) or {}
    submitted = (payload.get("password") or "").strip() if isinstance(payload, dict) else ""
    stored = _load_admin_password()
    if not stored:
        return jsonify({"ok": True, "enabled": False})
    ok = stored == submitted
    return jsonify({"ok": ok, "enabled": True})


@app.post("/api/login")
def admin_login():
    """Login and set session cookie if password is correct."""
    payload = request.get_json(force=True, silent=True) or {}
    submitted = (payload.get("password") or "").strip() if isinstance(payload, dict) else ""
    stored = _load_admin_password()
    if not stored:
        # If no password set, treat as open and do not set a session
        resp = jsonify({"ok": True, "enabled": False})
        return resp
    if submitted != stored:
        return jsonify({"ok": False, "enabled": True, "error": "invalid_password"}), 401
    token = _generate_session_token()
    resp = jsonify({"ok": True, "enabled": True})
    resp.set_cookie(
        ADMIN_SESSION_NAME,
        token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=3600,
        path="/",
    )
    return resp


@app.post("/api/logout")
def admin_logout():
    token = request.cookies.get(ADMIN_SESSION_NAME)
    if token:
        ADMIN_SESSIONS.pop(token, None)
    resp = jsonify({"ok": True})
    resp.set_cookie(ADMIN_SESSION_NAME, "", expires=0, path="/")
    return resp


@app.get("/api/session")
def admin_session_status():
    """Return whether auth is enabled and whether current session is valid."""
    enabled = _is_auth_required()
    authed = _validate_session(request.cookies.get(ADMIN_SESSION_NAME)) if enabled else True
    return jsonify({"enabled": enabled, "authed": authed})


@app.get("/api/endpoint-checks")
def endpoint_checks():
    """Probe key endpoints from inside the container and report reachability."""
    env_file = _load_env_file(SENTINEL_ENV_PATH)
    provider_settings = _merge_provider_settings()

    def pick(key: str) -> str:
        return provider_settings.get(key) or env_file.get(key) or os.getenv(key, "")

    sentinel_port = pick("SENTINEL_PORT") or "3636"
    sentinel_node = pick("SENTINEL_NODE")
    sentinel_external = _normalize_base(sentinel_node, sentinel_port)
    sentinel_internal = _normalize_base("127.0.0.1", sentinel_port)

    arkeod_node = pick("ARKEOD_NODE")
    arkeod_base = _normalize_base(arkeod_node)

    rest_api = pick("ARKEO_REST_API_PORT")
    rest_base = _normalize_base(rest_api)

    admin_api_port = pick("ADMIN_API_PORT") or "9999"
    admin_port = pick("ADMIN_PORT") or "8080"
    admin_api_base = _normalize_base("127.0.0.1", admin_api_port)
    admin_ui_base = _normalize_base("127.0.0.1", admin_port)
    token = request.cookies.get(ADMIN_SESSION_NAME)
    admin_api_headers = {"Cookie": f"{ADMIN_SESSION_NAME}={token}"} if token else None

    endpoints = {
        "arkeod_status": _probe_url(arkeod_base, "/status"),
        "arkeorpc": _probe_url(rest_base, "/cosmos/base/tendermint/v1beta1/node_info"),
        "sentinel_external": _probe_url(sentinel_external, "/metadata.json"),
        "sentinel_internal": _probe_url(sentinel_internal, "/metadata.json"),
        "admin_api": _probe_url(admin_api_base, "/api/version", headers=admin_api_headers),
        "admin_ui": _probe_url(admin_ui_base, "/"),
    }
    return jsonify({"endpoints": endpoints})


@app.post("/api/provider-export")
def export_provider_bundle():
    """Write env + sentinel config + provider form cache to provider-export.json."""
    bundle = _write_export_bundle()
    try:
        size = os.path.getsize(PROVIDER_EXPORT_PATH)
    except OSError:
        size = None
    return jsonify(
        {
            "status": "ok",
            "path": PROVIDER_EXPORT_PATH,
            "bytes": size,
            "export": bundle,
        }
    )


@app.post("/api/provider-import")
def import_provider_bundle():
    """Import provider-export bundle from request body and persist it."""
    payload = request.get_json(force=True, silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid payload"}), 400
    sentinel_cfg_obj = payload.get("sentinel_config")
    sentinel_cfg_raw = payload.get("sentinel_config_raw")
    env_file = payload.get("env_file")
    provider_settings = payload.get("provider_settings")
    skipped_services = []

    # Parse and filter sentinel.yaml if provided
    parsed_cfg = None
    raw_cfg = sentinel_cfg_raw
    if sentinel_cfg_raw:
        try:
            parsed_cfg = yaml.safe_load(sentinel_cfg_raw) or {}
        except Exception:
            parsed_cfg = None
    elif sentinel_cfg_obj:
        parsed_cfg = sentinel_cfg_obj

    bech32_pubkey = ""
    try:
        _, bech32_pubkey, _ = derive_pubkeys(KEY_NAME, KEYRING)
    except Exception:
        bech32_pubkey = ""

    if parsed_cfg is not None and isinstance(parsed_cfg, dict):
        filtered_services, skipped, annotated = _filter_sentinel_services_with_onchain(parsed_cfg, bech32_pubkey)
        if filtered_services is not None:
            parsed_cfg["services"] = filtered_services
        skipped_services = skipped
        try:
            raw_cfg = yaml.safe_dump(parsed_cfg, sort_keys=False)
        except Exception:
            raw_cfg = sentinel_cfg_raw

    if raw_cfg:
        try:
            with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
                f.write(raw_cfg)
        except OSError as e:
            return jsonify({"error": "failed to write sentinel config", "detail": str(e)}), 500
    elif parsed_cfg is not None:
        try:
            with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(parsed_cfg, f, sort_keys=False)
        except OSError as e:
            return jsonify({"error": "failed to write sentinel config", "detail": str(e)}), 500

    # Write sentinel.env if provided
    if isinstance(env_file, dict):
        try:
            with open(SENTINEL_ENV_PATH, "w", encoding="utf-8") as f:
                for k, v in env_file.items():
                    f.write(f"{k}={shlex.quote(str(v))}\n")
        except OSError as e:
            return jsonify({"error": "failed to write sentinel env", "detail": str(e)}), 500

    # Persist provider settings if provided (mnemonic rotation must be done separately)
    if isinstance(provider_settings, dict):
        merged_provider_settings = _merge_provider_settings(provider_settings)
        _apply_provider_settings(merged_provider_settings)
        _write_provider_settings_file(merged_provider_settings)

    restart_output = ""
    try:
        code, out = run_list([*SUPERVISORCTL, "restart", "sentinel"])
        restart_output = out
    except Exception as e:
        restart_output = f"restart failed: {e}"

    bundle = _write_export_bundle(
        provider_form=payload.get("provider_form"),
        sentinel_config_override=sentinel_cfg_obj,
        sentinel_config_raw_override=sentinel_cfg_raw,
        env_file=env_file if isinstance(env_file, dict) else None,
    )
    try:
        size = os.path.getsize(PROVIDER_EXPORT_PATH)
    except OSError:
        size = None
    return jsonify(
        {
            "status": "imported",
            "path": PROVIDER_EXPORT_PATH,
            "bytes": size,
            "export": bundle,
            "restart_output": restart_output,
            "skipped_services": skipped_services,
        }
    )


@app.post("/api/sentinel-sync")
def sentinel_sync():
    """Remove services from sentinel.yaml that are not active on-chain for this provider."""
    _, bech32_pubkey, pub_err = derive_pubkeys(KEY_NAME, KEYRING)
    if pub_err:
        return jsonify({"error": pub_err}), 500
    parsed, raw = _load_sentinel_config()
    if parsed is None or not isinstance(parsed, dict):
        return jsonify({"error": "sentinel config not found or invalid"}), 404
    original_services = parsed.get("services") or []
    filtered_services, skipped, annotated = _filter_sentinel_services_with_onchain(parsed, bech32_pubkey)
    parsed["services"] = filtered_services
    try:
        with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(parsed, f, sort_keys=False)
    except OSError as e:
        return jsonify({"error": "failed to write sentinel config", "detail": str(e)}), 500
    restart_output = ""
    try:
        code, out = run_list([*SUPERVISORCTL, "restart", "sentinel"])
        restart_output = out
    except Exception as e:
        restart_output = f"restart failed: {e}"
    return jsonify(
        {
            "status": "synced",
            "removed_services": skipped,
            "onchain_services": annotated,
            "original_services": original_services,
            "filtered_services": filtered_services,
            "sentinel_services_before": original_services,
            "sentinel_services_after": filtered_services,
            "restart_output": restart_output,
            "sentinel_config_path": SENTINEL_CONFIG_PATH,
        }
    )


@app.post("/api/sentinel-config")
def update_sentinel_config():
    """Update sentinel.yaml provider/api fields (services remain untouched)."""
    payload = request.get_json(force=True, silent=True) or {}
    provider_pubkey = payload.get("provider_pubkey")
    provider_name = payload.get("provider_name")
    listen_addr = payload.get("listen_addr")
    moniker = payload.get("moniker")
    website = payload.get("website")
    description = payload.get("description")
    location = payload.get("location")
    free_rate_limit = payload.get("free_rate_limit")
    free_rate_limit_duration = payload.get("free_rate_limit_duration")
    provider_settings = _merge_provider_settings()
    settings_node = _ensure_tcp_scheme(provider_settings.get("ARKEOD_NODE") or "")
    settings_rest = provider_settings.get("ARKEO_REST_API_PORT") or ""
    settings_sentinel_node = provider_settings.get("SENTINEL_NODE") or ""
    settings_sentinel_port = provider_settings.get("SENTINEL_PORT") or ""
    settings_chain_id = provider_settings.get("CHAIN_ID") or ""

    if not os.path.isfile(SENTINEL_CONFIG_PATH):
        return jsonify({"error": f"sentinel config not found at {SENTINEL_CONFIG_PATH}"}), 404

    try:
        with open(SENTINEL_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        return jsonify({"error": "failed to read sentinel config", "detail": str(e)}), 500

    # Update env file for UI-managed fields
    env_file = _load_env_file(SENTINEL_ENV_PATH)
    def _set_env(key, value):
        if value is None:
            return
        env_file[key] = value
    _set_env("MONIKER", moniker)
    _set_env("WEBSITE", website)
    _set_env("DESCRIPTION", description)
    _set_env("LOCATION", location)
    _set_env("FREE_RATE_LIMIT", free_rate_limit)
    _set_env("FREE_RATE_LIMIT_DURATION", free_rate_limit_duration)
    # Keep provider settings in sync for sentinel dependencies
    _set_env("ARKEOD_NODE", settings_node)
    _set_env("EXTERNAL_ARKEOD_NODE", provider_settings.get("EXTERNAL_ARKEOD_NODE"))
    _set_env("SENTINEL_NODE", settings_sentinel_node)
    _set_env("SENTINEL_PORT", settings_sentinel_port)
    _set_env("ARKEO_REST_API_PORT", settings_rest)
    _set_env("PORT", settings_sentinel_port)
    _set_env("SOURCE_CHAIN", settings_chain_id)
    # Sync from provider env vars if present (EXTERNAL_ARKEOD_NODE, ARKEO_REST_API_PORT, SENTINEL_NODE)
    def _normalize_hostport(url: str, default_port: str | None = None) -> str:
        if not url:
            return ""
        url = url.strip()
        if url.startswith("tcp://"):
            url = "http://" + url[len("tcp://") :]
        try:
            parsed = urllib.parse.urlparse(url)
            hostport = parsed.netloc or parsed.path
            if hostport and default_port and ":" not in hostport:
                hostport = f"{hostport}:{default_port}"
            return hostport
        except Exception:
            return url

    provider_node = settings_node or _ensure_tcp_scheme(os.getenv("ARKEOD_NODE"))
    if provider_node:
        hostport = _normalize_hostport(provider_node, "26657")
        if hostport:
            # EVENT_STREAM_HOST should be host:port (no scheme)
            hostport_no_scheme = hostport
            if hostport_no_scheme.startswith("tcp://"):
                hostport_no_scheme = hostport_no_scheme[len("tcp://") :]
            if hostport_no_scheme.startswith("http://"):
                hostport_no_scheme = hostport_no_scheme[len("http://") :]
            if hostport_no_scheme.startswith("https://"):
                hostport_no_scheme = hostport_no_scheme[len("https://") :]
            _set_env("EVENT_STREAM_HOST", hostport_no_scheme)
    hub_env = settings_rest or os.getenv("ARKEO_REST_API_PORT")
    if hub_env:
        _set_env("ARKEO_REST_API_PORT", hub_env)
    sentinel_node_env = provider_settings.get("SENTINEL_NODE") or os.getenv("SENTINEL_NODE")
    if sentinel_node_env:
        _set_env("SENTINEL_NODE", sentinel_node_env)

    # Sync MONIKER/PROVIDER_NAME to the same value (prefer payload provider_name, then moniker)
    name_val = provider_name or moniker or env_file.get("MONIKER") or env_file.get("PROVIDER_NAME") or os.getenv("MONIKER") or os.getenv("PROVIDER_NAME") or ""
    if name_val:
        env_file["MONIKER"] = name_val
        env_file["PROVIDER_NAME"] = name_val

    # Expand tilde paths for store locations
    for key in ("CLAIM_STORE_LOCATION", "CONTRACT_CONFIG_STORE_LOCATION", "PROVIDER_CONFIG_STORE_LOCATION"):
        if key in env_file:
            env_file[key] = _expand_tilde(env_file[key])

    # Prefer explicit provider_name for the YAML provider.name; do not fall back to moniker
    effective_provider_name = provider_name or config.get("provider", {}).get("name") or os.getenv("PROVIDER_NAME") or env_file.get("PROVIDER_NAME")

    if provider_pubkey:
        config.setdefault("provider", {})
        config["provider"]["pubkey"] = provider_pubkey
    if effective_provider_name:
        config.setdefault("provider", {})
        config["provider"]["name"] = effective_provider_name
    # listen_addr and provider_pubkey are not user-editable in the UI anymore; we keep them unchanged unless provided explicitly

    try:
        with open(SENTINEL_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False)
    except Exception as e:
        return jsonify({"error": "failed to write sentinel config", "detail": str(e)}), 500

    try:
        with open(SENTINEL_ENV_PATH, "w", encoding="utf-8") as f:
            for k, v in env_file.items():
                # Quote values to keep spaces safe when sourced
                f.write(f"{k}={shlex.quote(str(v))}\n")
    except Exception as e:
        return jsonify({"error": "failed to write sentinel env", "detail": str(e)}), 500

    restart_output = ""
    try:
        app.logger.info("Restarting sentinel via supervisorctl")
        code, out = run_list([*SUPERVISORCTL, "restart", "sentinel"])
        restart_output = out
        app.logger.info("Sentinel restart exited code=%s output=%s", code, out.strip())
    except Exception as e:
        restart_output = f"restart failed: {e}"
        app.logger.warning("Sentinel restart failed: %s", e)

    return jsonify(
        {
            "status": "updated",
            "config_path": SENTINEL_CONFIG_PATH,
            "config": config,
            "restart_output": restart_output,
        }
    )


@app.post("/api/provider-claims")
def provider_claims():
    """Submit open claims via arkeod using current provider env/config."""
    # Derive provider account address
    key_cmd = ["arkeod", "--home", ARKEOD_HOME, "keys", "show", KEY_NAME, "--bech", "acc", "--keyring-backend", KEYRING, "--address"]
    code, out = run_list(key_cmd)
    if code != 0:
        return jsonify({"error": "failed to get provider address", "detail": out}), 500
    provider_account = out.strip()

    # Sentinel API (open-claims / mark-claimed)
    sentinel_port = os.getenv("SENTINEL_PORT") or "3636"
    sentinel_host = os.getenv("SENTINEL_BIND_HOST") or "127.0.0.1"
    sentinel_api = f"http://{sentinel_host}:{sentinel_port}"

    def current_sequence():
        qcmd = ["arkeod", "--home", ARKEOD_HOME, "query", "auth", "account", provider_account, "-o", "json", *NODE_ARGS]
        c, o = run_list(qcmd)
        if c != 0:
            return None, o
        try:
            data = json.loads(o)
        except Exception:
            return None, o
        seq = (
            data.get("account", {})
            .get("base_account", {})
            .get("sequence")
            or data.get("account", {})
            .get("value", {})
            .get("sequence")
            or data.get("account", {})
            .get("sequence")
        )
        return seq, o

    def fetch_open_claims():
        try:
            with urllib.request.urlopen(f"{sentinel_api}/open-claims", timeout=10) as resp:
                claims_raw = resp.read().decode("utf-8")
                claims = json.loads(claims_raw)
            return [c for c in claims if isinstance(c, dict) and (not c.get("claimed"))], None
        except Exception as e:
            return None, str(e)

    results = []
    iterations = 0
    max_iterations = 10
    total_processed = 0

    def poll_tx(txhash: str, attempts: int = 15, delay: float = 1.0) -> tuple[int | None, str, str]:
        """Poll tx until a DeliverTx result is available. Returns (code, raw_log, height)."""
        if not txhash:
            return None, "", ""
        cmd = ["arkeod", "q", "tx", txhash, "-o", "json", *NODE_ARGS]
        for _ in range(attempts):
            try:
                code, out = run_list(cmd)
            except Exception:
                code = 1
                out = ""
            if code != 0 or not out:
                time.sleep(delay)
                continue
            try:
                txobj = json.loads(out)
            except Exception:
                time.sleep(delay)
                continue
            deliver_code = txobj.get("code")
            raw_log = txobj.get("raw_log") or ""
            height = txobj.get("height") or ""
            if deliver_code is None:
                time.sleep(delay)
                continue
            return deliver_code, raw_log, height
        return None, "", ""

    while iterations < max_iterations:
        iterations += 1
        pending, err = fetch_open_claims()
        if err:
            return jsonify({"error": "failed to fetch open claims", "detail": err}), 500
        if not pending:
            break

        processed_this_iter = 0

        for claim in pending:
            contract_id = claim.get("contract_id")
            nonce = claim.get("nonce")
            signature = claim.get("signature")
            if contract_id is None or nonce is None or signature is None:
                results.append({"claim": claim, "error": "missing fields"})
                continue

            sig_str = str(signature)
            sig_len = len(sig_str)
            sig_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", sig_str))
            app.logger.info(
                "provider-claims: claim candidate cid=%s nonce=%s sig_len=%s is_hex=%s sig_prefix=%s sig_suffix=%s spender=%s",
                contract_id,
                nonce,
                sig_len,
                sig_hex,
                sig_str[:12],
                sig_str[-12:] if sig_len >= 12 else sig_str,
                claim.get("spender") or "",
            )

            seq, seq_raw = current_sequence()
            if seq is None:
                results.append({"claim": claim, "error": "failed to fetch sequence", "detail": seq_raw})
                continue

            def submit(seq_override):
                cmd = [
                    "arkeod",
                    "--home",
                    ARKEOD_HOME,
                    "tx",
                    "arkeo",
                    "claim-contract-income",
                    str(contract_id),
                    str(nonce),
                    str(signature),
                    "nil",
                    "--from",
                    KEY_NAME,
                    "--keyring-backend",
                    KEYRING,
                    *CHAIN_ARGS,
                    *NODE_ARGS,
                    "--fees",
                    FEES_DEFAULT,
                    "--gas",
                    os.getenv("CLAIM_GAS", "120000"),
                    "--sequence",
                    str(seq_override),
                    "-b",
                    "sync",
                    "-y",
                    "-o",
                    "json",
                ]
                return run_list(cmd)

            exit_code, tx_out = submit(seq)
            tx_json = {}
            try:
                tx_json = json.loads(tx_out)
            except Exception:
                tx_json = {"raw": tx_out}

            txhash = ""
            if isinstance(tx_json, dict):
                txhash = tx_json.get("txhash") or tx_json.get("hash") or ""

            raw_log = ""
            if isinstance(tx_json, dict):
                raw_log = tx_json.get("raw_log") or tx_json.get("rawlog") or ""
            if "account sequence mismatch" in str(raw_log):
                expected = None
                m = re.search(r"expected\s+(\d+)", str(raw_log))
                if m:
                    expected = m.group(1)
                if expected is not None:
                    exit_code, tx_out = submit(expected)
                    try:
                        tx_json = json.loads(tx_out)
                    except Exception:
                        tx_json = {"raw": tx_out}

            # Poll for deliver_tx result if we have a txhash (since sync mode only gives CheckTx)
            deliver_code = None
            deliver_raw = ""
            deliver_height = ""
            if txhash:
                deliver_code, deliver_raw, deliver_height = poll_tx(txhash)
                if isinstance(tx_json, dict):
                    tx_json["deliver_tx"] = {
                        "code": deliver_code,
                        "raw_log": deliver_raw,
                        "height": deliver_height,
                    }

            # Mark claimed on sentinel if success code=0
            code_val = tx_json.get("code") if isinstance(tx_json, dict) else None
            effective_code = deliver_code if deliver_code is not None else code_val
            if effective_code == 0:
                try:
                    req = urllib.request.Request(
                        f"{sentinel_api}/mark-claimed",
                        method="POST",
                        data=json.dumps({"contract_id": contract_id, "nonce": nonce}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=5).read()
                except Exception:
                    pass

            results.append({"claim": claim, "exit_code": exit_code, "tx": tx_json})
            processed_this_iter += 1
            total_processed += 1

        if processed_this_iter == 0:
            break

    # Heartbeat: record last claims run
    try:
        now_ts = datetime.datetime.utcnow().isoformat() + "Z"
        write_heartbeat(CLAIMS_HEARTBEAT_PATH, {"last_claims_run": now_ts, "claims_processed": total_processed})
    except Exception:
        pass

    return jsonify({"status": "ok", "iterations": iterations, "claims_processed": total_processed, "results": results})


@app.get("/api/claims-heartbeat")
def claims_heartbeat():
    """Return the last provider-claims heartbeat if available."""
    hb = read_heartbeat(CLAIMS_HEARTBEAT_PATH) or {}
    return jsonify(hb)

@app.get("/api/claims-ledger")
def claims_ledger():
    """List settled PAYG claims (EventSettleContract) for this provider."""
    service_filter = request.args.get("service") or ""
    from_h = str(request.args.get("from_height") or request.args.get("from") or 0)
    to_h = str(request.args.get("to_height") or request.args.get("to") or 999_999_999)

    # Derive provider pubkey (bech32)
    key_cmd = ["arkeod", "--home", ARKEOD_HOME, "keys", "show", KEY_NAME, "-p", "--keyring-backend", KEYRING]
    code, out = run_list(key_cmd)
    if code != 0:
        return jsonify({"error": "failed to get provider pubkey", "detail": out}), 500
    raw_pub = ""
    try:
        raw_pub = json.loads(out).get("key") or ""
    except Exception:
        pass
    bech_pub = ""
    if raw_pub:
        c2, o2 = run_list(["arkeod", "debug", "pubkey-raw", raw_pub])
        if c2 == 0:
            for line in o2.splitlines():
                if "Bech32 Acc:" in line:
                    bech_pub = line.split("Bech32 Acc:")[-1].strip()
                    break
    provider_pubkey = bech_pub or raw_pub
    provider_pubkey_alts = {provider_pubkey.strip(), raw_pub.strip()}
    if not provider_pubkey:
        return jsonify({"error": "failed to derive provider pubkey", "detail": out}), 500

    node = ARKEOD_NODE
    query = f"message.action='/arkeo.arkeo.MsgClaimContractIncome' AND tx.height>={from_h} AND tx.height<={to_h}"
    rows = []
    page = 1
    while True:
        tx_cmd = [
            "arkeod",
            "q",
            "txs",
            "--order_by",
            "asc",
            "--limit",
            "1000",
            "--page",
            str(page),
            "--query",
            query,
            "-o",
            "json",
        ]
        if node:
            tx_cmd.extend(["--node", node])
        code, out = run_list(tx_cmd)
        if code != 0:
            return jsonify(
                {
                    "error": "failed to query txs",
                    "detail": out,
                    "cmd": tx_cmd,
                    "exit_code": code,
                    "provider_pubkey": provider_pubkey,
                    "service_filter": service_filter or None,
                    "from_height": from_h,
                    "to_height": to_h,
                }
            ), 500
        try:
            data = json.loads(out)
        except Exception:
            break
        txs = data.get("txs") or []
        if not txs:
            break
        for tx in txs:
            events = tx.get("events") or []
            height = int(tx.get("height") or 0)
            txhash = tx.get("txhash") or tx.get("hash") or ""
            for ev in events:
                if ev.get("type") != "arkeo.arkeo.EventSettleContract":
                    continue
                attrs = ev.get("attributes") or []
                attr_map = {a.get("key"): a.get("value") for a in attrs if isinstance(a, dict)}
                provider_val = (attr_map.get("provider") or "").strip('"')
                service_val = (attr_map.get("service") or "").strip('"')
                if provider_val != provider_pubkey:
                    continue
                if service_filter and service_val != service_filter:
                    continue
                try:
                    contract_id = attr_map.get("contract_id", "").strip('"')
                    nonce = int(str(attr_map.get("nonce", "0")).strip('"'))
                    paid = int(str(attr_map.get("paid", "0")).strip('"'))
                except Exception:
                    continue
                rows.append(
                    {
                        "height": height,
                        "txhash": txhash,
                        "contract_id": contract_id,
                        "nonce": nonce,
                        "paid": paid,
                        "provider": provider_val,
                        "service": service_val,
                    }
                )
        page += 1

    return jsonify(
        {
            "provider_pubkey": provider_pubkey,
            "service_filter": service_filter or None,
            "node": node,
            "from_height": from_h,
            "to_height": to_h,
            "settlements": rows,
            "count": len(rows),
        }
    )

def _parse_int(val, default: int = 0) -> int:
    try:
        if val is None:
            return default
        if isinstance(val, bool):
            return default
        return int(str(val).strip().strip('"'))
    except Exception:
        return default


@app.post("/api/provider-contracts-summary")
def provider_contracts_summary():
    """Summarize contracts for this provider (optional service filter)."""
    body = request.get_json(silent=True) or {}

    def empty_summary(provider_pubkey: str = "", err: str | None = None, detail=None):
        # Use the last-known requested range if available
        fh = str(body.get("from_height") or body.get("from") or 0)
        th = str(body.get("to_height") or body.get("to") or 999_999_999)
        service_filter = (body.get("service") or "").strip()
        heartbeat = read_heartbeat(CLAIMS_HEARTBEAT_PATH) or {}
        return jsonify(
            {
                "provider_pubkey": provider_pubkey or None,
                "service_filter": service_filter or None,
                "node": ARKEOD_NODE,
                "from_height": fh,
                "to_height": th,
                "tokens_paid_total_uarkeo": 0,
                "tokens_paid_finalized_uarkeo": 0,
                "payg_requests_total": 0,
                "active_contracts": 0,
                "settled_contracts": 0,
                "remaining_uarkeo": 0,
                "contracts": [],
                "service_totals": [],
                "last_claims_run": heartbeat.get("last_claims_run"),
                "error": err,
                "detail": detail,
            }
        ), 200

    try:
        service_filter = (body.get("service") or "").strip()
        from_h = str(body.get("from_height") or body.get("from") or 0)
        to_h = str(body.get("to_height") or body.get("to") or 999_999_999)
        from_h_int = _parse_int(from_h, 0)
        to_h_int = _parse_int(to_h, 999_999_999)
        heartbeat = read_heartbeat(CLAIMS_HEARTBEAT_PATH) or {}

        provider_pubkey = ""
        # Derive provider pubkey (bech32)
        key_cmd = ["arkeod", "--home", ARKEOD_HOME, "keys", "show", KEY_NAME, "-p", "--keyring-backend", KEYRING]
        code, out = run_list(key_cmd)
        if code != 0:
            return empty_summary("", "failed to get provider pubkey", out)
        raw_pub = ""
        try:
            raw_pub = json.loads(out).get("key") or ""
        except Exception:
            raw_pub = ""
        bech_pub = ""
        if raw_pub:
            c2, o2 = run_list(["arkeod", "debug", "pubkey-raw", raw_pub])
            if c2 == 0:
                for line in o2.splitlines():
                    if "Bech32 Acc:" in line:
                        bech_pub = line.split("Bech32 Acc:")[-1].strip()
                        break
        provider_pubkey = bech_pub or raw_pub
        if not provider_pubkey:
            return empty_summary("", "failed to derive provider pubkey", out)
        provider_pubkey_alts = {provider_pubkey.strip(), raw_pub.strip()}

        node = ARKEOD_NODE
        contracts_cmd = [
            "arkeod",
            "--home",
            ARKEOD_HOME,
            "query",
            "arkeo",
            "list-contracts",
            "--output",
            "json",
            "--limit",
            "5000",
            "--count-total",
        ]
        if node:
            contracts_cmd.extend(["--node", node])
        code, out = run_list(contracts_cmd)
        if code != 0:
            return empty_summary(
                provider_pubkey,
                "failed to list contracts",
                {"cmd": contracts_cmd, "exit_code": code, "detail": out},
            )
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        # Cache raw contract list for troubleshooting / reuse
        try:
            write_cache_json("provider-contracts", data)
        except Exception:
            pass
        contracts = []
        if isinstance(data, dict):
            for key in ("contracts", "contract", "result"):
                val = data.get(key)
                if isinstance(val, list):
                    contracts = val
                    break
        if not isinstance(contracts, list):
            contracts = []

        filtered = []
        for c in contracts:
            if not isinstance(c, dict):
                continue
            prov_val = (c.get("provider") or c.get("provider_pubkey") or c.get("provider_pub_key") or "").strip().strip('"')
            if prov_val not in provider_pubkey_alts:
                continue
            service_val = c.get("service") or c.get("service_id") or c.get("serviceID") or c.get("name") or ""
            service_val = str(service_val).strip()
            if service_filter and service_val != service_filter:
                continue
            contract_id = c.get("contract_id") or c.get("id") or c.get("contractID") or c.get("contractId") or ""
            contract_type = (c.get("type") or c.get("authorization") or "").upper()
            settlement_height = _parse_int(
                c.get("settlement_height")
                or c.get("settlementHeight")
                or c.get("settlementheight")
                or 0,
                0,
            )
            # Filter by height range if provided (use settlement or any available height field)
            height_for_filter = None
            for key in ("settlement_height", "settlementHeight", "settlementheight", "height"):
                if key in c and c.get(key) is not None:
                    try:
                        height_for_filter = int(str(c.get(key)).strip().strip('"'))
                        break
                    except Exception:
                        height_for_filter = None
            if height_for_filter is None:
                try:
                    raw_h = c.get("raw", {}).get("height")
                    if raw_h is not None:
                        height_for_filter = int(str(raw_h).strip().strip('"'))
                except Exception:
                    height_for_filter = None
            if from_h_int > 0 or to_h_int < 999_999_999:
                if height_for_filter is not None:
                    if height_for_filter < from_h_int or height_for_filter > to_h_int:
                        continue
                else:
                    # No height info; skip when a range was requested
                    continue

            settlement_duration = _parse_int(c.get("settlement_duration") or c.get("settlementDuration") or c.get("settlementduration") or 0, 0)
            paid = _parse_int(c.get("paid"), 0)
            deposit = _parse_int(c.get("deposit"), 0)
            nonce = _parse_int(c.get("nonce"), 0)
            # Ignore nonce == 0 contracts
            if nonce == 0:
                continue
            rate_amount = 0
            rate_val = c.get("rate") or c.get("rates") or c.get("pay_as_you_go_rate") or c.get("pay_as_you_go_rates")
            if isinstance(rate_val, list) and rate_val:
                try:
                    rate_amount = _parse_int((rate_val[0] or {}).get("amount"), 0)
                except Exception:
                    rate_amount = 0
            elif isinstance(rate_val, dict):
                rate_amount = _parse_int(rate_val.get("amount"), 0)
            tx_count = nonce if "PAY" in contract_type else 0
            filtered.append(
                {
                    "contract_id": str(contract_id),
                    "service": service_val,
                    "type": contract_type,
                    "paid": paid,
                    "deposit": deposit,
                    "remaining": max(0, deposit - paid),
                    "nonce": nonce,
                    "tx_count": tx_count,
                    "settlement_height": settlement_height,
                    "settlement_duration": settlement_duration,
                    "rate_amount": rate_amount,
                }
            )

        if not filtered:
            return empty_summary(provider_pubkey)

        tokens_paid_total = sum(c["paid"] for c in filtered)
        tokens_paid_finalized = sum(c["paid"] for c in filtered if c["settlement_height"] > 0)
        payg_requests_total = sum(c["nonce"] for c in filtered if "PAY" in c["type"])
        active_contracts = sum(1 for c in filtered if c["settlement_height"] == 0)
        settled_contracts = sum(1 for c in filtered if c["settlement_height"] > 0)
        remaining_total = sum(c["remaining"] for c in filtered)

        service_totals_map: dict[str, dict] = {}
        for c in filtered:
            svc = c["service"] or ""
            st = service_totals_map.setdefault(
                svc,
                {
                    "service": svc,
                    "tokens_paid_total_uarkeo": 0,
                    "tokens_paid_finalized_uarkeo": 0,
                    "payg_requests_total": 0,
                    "tx_count": 0,
                    "active_contracts": 0,
                    "settled_contracts": 0,
                    "remaining_uarkeo": 0,
                    "deposit_total_uarkeo": 0,
                    "contracts": [],
                },
            )
            st["tokens_paid_total_uarkeo"] += c["paid"]
            if c["settlement_height"] > 0:
                st["tokens_paid_finalized_uarkeo"] += c["paid"]
                st["settled_contracts"] += 1
            else:
                st["active_contracts"] += 1
            st["payg_requests_total"] += c["nonce"] if "PAY" in c["type"] else 0
            st["tx_count"] += c.get("tx_count", 0)
            st["remaining_uarkeo"] += c["remaining"]
            st["deposit_total_uarkeo"] += c["deposit"]
            st["contracts"].append(
                {
                    "contract_id": c["contract_id"],
                    "service": c["service"],
                    "type": c["type"],
                    "paid": c["paid"],
                    "deposit": c["deposit"],
                    "remaining": c["remaining"],
                    "nonce": c["nonce"],
                    "settlement_height": c["settlement_height"],
                    "settlement_duration": c["settlement_duration"],
                }
            )

        for st in service_totals_map.values():
            st["contracts"].sort(key=lambda x: int(x["contract_id"]) if str(x["contract_id"]).isdigit() else str(x["contract_id"]))

        service_totals = sorted(service_totals_map.values(), key=lambda x: x["service"])

        return jsonify(
            {
                "provider_pubkey": provider_pubkey,
                "service_filter": service_filter or None,
                "node": node,
                "from_height": from_h,
                "to_height": to_h,
                "tokens_paid_total_uarkeo": tokens_paid_total,
                "tokens_paid_finalized_uarkeo": tokens_paid_finalized,
                "payg_requests_total": payg_requests_total,
                "active_contracts": active_contracts,
                "settled_contracts": settled_contracts,
                "remaining_uarkeo": remaining_total,
                "contracts": filtered,
                "service_totals": service_totals,
                "last_claims_run": heartbeat.get("last_claims_run"),
            }
        )
    except Exception as e:
        return empty_summary(provider_pubkey, "unexpected error", str(e))

@app.post("/api/provider-totals")
def provider_totals():
    """Summarize PAYG claim spending for this provider (and optional service) over a height range."""
    body = request.get_json(silent=True) or {}
    service_filter = body.get("service") or ""
    from_h = str(body.get("from_height") or body.get("from") or 0)
    to_h = str(body.get("to_height") or body.get("to") or 999_999_999)

    def empty_totals(provider_pubkey: str = "", err: str | None = None, detail=None):
        return jsonify(
            {
                "provider_pubkey": provider_pubkey,
                "service_filter": service_filter or None,
                "node": ARKEOD_NODE,
                "from_height": from_h,
                "to_height": to_h,
                "tx_count": 0,
                "contracts": [],
                "total_paid_uarkeo": 0,
                "total_paid_arkeo": 0,
                "service_totals": [],
                "error": err,
                "detail": detail,
            }
        )

    # Derive provider pubkey (bech32)
    key_cmd = ["arkeod", "--home", ARKEOD_HOME, "keys", "show", KEY_NAME, "-p", "--keyring-backend", KEYRING]
    code, out = run_list(key_cmd)
    if code != 0:
        return empty_totals("", "failed to get provider pubkey", out), 200
    raw_pub = ""
    try:
        raw_pub = json.loads(out).get("key") or ""
    except Exception:
        pass
    bech_pub = ""
    if raw_pub:
        c2, o2 = run_list(["arkeod", "debug", "pubkey-raw", raw_pub])
        if c2 == 0:
            for line in o2.splitlines():
                if "Bech32 Acc:" in line:
                    bech_pub = line.split("Bech32 Acc:")[-1].strip()
                    break
    provider_pubkey = bech_pub or raw_pub
    if not provider_pubkey:
        return empty_totals("", "failed to derive provider pubkey", out), 200
    provider_pubkey_alts = {provider_pubkey.strip(), raw_pub.strip()}

    node = ARKEOD_NODE
    query = f"message.action='/arkeo.arkeo.MsgClaimContractIncome' AND tx.height>={from_h} AND tx.height<={to_h}"
    all_rows = []
    page = 1
    while True:
        tx_cmd = [
            "arkeod",
            "q",
            "txs",
            "--order_by",
            "asc",
            "--limit",
            "1000",
            "--page",
            str(page),
            "--query",
            query,
            "-o",
            "json",
        ]
        if node:
            tx_cmd.extend(["--node", node])
        code, out = run_list(tx_cmd)
        if code != 0:
            return empty_totals(
                provider_pubkey,
                "failed to query txs",
                {
                    "cmd": tx_cmd,
                    "exit_code": code,
                    "detail": out,
                },
            ), 200
        try:
            data = json.loads(out)
        except Exception:
            break
        txs = data.get("txs") or []
        if not txs:
            break
        for tx in txs:
            events = tx.get("events") or []
            height = int(tx.get("height") or 0)
            for ev in events:
                if ev.get("type") != "arkeo.arkeo.EventSettleContract":
                    continue
                attrs = ev.get("attributes") or []
                attr_map = {a.get("key"): a.get("value") for a in attrs if isinstance(a, dict)}
                provider_val = (attr_map.get("provider") or "").strip('"')
                service_val = (attr_map.get("service") or "").strip('"')
                if provider_val not in provider_pubkey_alts:
                    continue
                if service_filter and service_val != service_filter:
                    continue
                try:
                    contract_id = attr_map.get("contract_id", "").strip('"')
                    nonce = _parse_int(attr_map.get("nonce"), 0)
                    if nonce <= 0:
                        continue
                    paid = _parse_int(attr_map.get("paid"), 0)
                except Exception:
                    continue
                all_rows.append(
                    {
                        "height": height,
                        "contract_id": contract_id,
                        "nonce": nonce,
                        "paid": paid,
                        "provider": provider_val,
                        "service": service_val,
                    }
                )
        page += 1

    # Summaries
    totals = {}
    for r in all_rows:
        if not r or r.get("nonce") is None or r.get("nonce") <= 0:
            continue
        cid = r["contract_id"]
        t = totals.setdefault(
            cid,
            {
                "contract_id": cid,
                "tx_count": 0,
                "total": 0,
                "first_nonce": r["nonce"],
                "last_nonce": r["nonce"],
                "first_height": r["height"],
                "last_height": r["height"],
            },
        )
        t["tx_count"] += 1
        t["total"] += r["paid"]
        t["first_nonce"] = min(t["first_nonce"], r["nonce"])
        t["last_nonce"] = max(t["last_nonce"], r["nonce"])
        t["first_height"] = min(t["first_height"], r["height"])
        t["last_height"] = max(t["last_height"], r["height"])

    totals_list = sorted(totals.values(), key=lambda x: (int(x["contract_id"]) if str(x["contract_id"]).isdigit() else x["contract_id"]))
    grand_total = sum(t["total"] for t in totals_list)

    # Per-service summary
    service_totals = {}
    for r in all_rows:
        if not r or r.get("nonce") is None or r.get("nonce") <= 0:
            continue
        svc = r.get("service") or ""
        if not svc:
            continue
        st = service_totals.setdefault(
            svc,
            {
                "service": svc,
                "tx_count": 0,
                "total": 0,
                "first_height": r["height"],
                "last_height": r["height"],
                "contracts": set(),
            },
        )
        st["tx_count"] += 1
        st["total"] += r["paid"]
        st["first_height"] = min(st["first_height"], r["height"])
        st["last_height"] = max(st["last_height"], r["height"])
        st["contracts"].add(r["contract_id"])
    # Convert contract sets to lists and sort
    service_totals_list = []
    for svc, st in service_totals.items():
        st = dict(st)
        st["contracts"] = sorted(st["contracts"], key=lambda x: int(x) if str(x).isdigit() else str(x))
        st["total_paid_uarkeo"] = st["total"]
        st["total_paid_arkeo"] = st["total"] / 1_000_000
        service_totals_list.append(st)
    service_totals_list.sort(key=lambda x: x["service"])

    return jsonify(
        {
            "provider_pubkey": provider_pubkey,
            "service_filter": service_filter or None,
            "node": node,
            "from_height": from_h,
            "to_height": to_h,
            "tx_count": len(all_rows),
            "contracts": totals_list,
            "total_paid_uarkeo": grand_total,
            "total_paid_arkeo": grand_total / 1_000_000,
            "service_totals": service_totals_list,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT)
