#!/usr/bin/env python3
import base64
import binascii
import json
import os
from pathlib import Path
import re
import shlex
import socket
import socketserver
import subprocess
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
import yaml
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from flask import Flask, jsonify, request

from cache_fetcher import (
    build_commands as cache_build_commands,
    ensure_cache_dir as cache_ensure_cache_dir,
    fetch_once as cache_fetch_once,
    STATUS_FILE as CACHE_STATUS_FILE,
)

app = Flask(__name__)
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
LISTENERS_FILE = os.path.join(CACHE_DIR, "listeners.json")
LISTENER_PORT_START = int(os.getenv("LISTENER_PORT_START", "62001"))
LISTENER_PORT_END = int(os.getenv("LISTENER_PORT_END", "62100"))
ACTIVE_SERVICE_TYPES_FILE = os.path.join(CACHE_DIR, "active_service_types.json")
SUBSCRIBER_INFO_FILE = os.path.join(CACHE_DIR, "subscriber_info.json")
LOG_DIR = os.path.join(CACHE_DIR, "logs")
_LISTENER_SERVERS: dict[int, dict] = {}
_LISTENER_LOCK = threading.Lock()

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

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeo"))
KEY_NAME = os.getenv("KEY_NAME", "subscriber")
KEYRING = os.getenv("KEY_KEYRING_BACKEND", "test")
KEY_MNEMONIC = os.getenv("KEY_MNEMONIC", "")
def _strip_quotes(val: str | None) -> str:
    if not val:
        return ""
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    return val

ARKEOD_NODE = _strip_quotes(
    os.getenv("ARKEOD_NODE")
    or os.getenv("EXTERNAL_ARKEOD_NODE")
    or "tcp://provider1.innovationtheory.com:26657"
)
CHAIN_ID = _strip_quotes(os.getenv("CHAIN_ID") or os.getenv("ARKEOD_CHAIN_ID") or "")
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
API_PORT = int(os.getenv("ADMIN_API_PORT", "9998"))
SENTINEL_CONFIG_PATH = os.getenv("SENTINEL_CONFIG_PATH", "/app/config/sentinel.yaml")
SENTINEL_ENV_PATH = os.getenv("SENTINEL_ENV_PATH", "/app/config/sentinel.env")

# PAYG proxy defaults (can be overridden via env; per-listener overrides later)
PROXY_AUTO_CREATE = True
# Default to 0 so we compute deposit = duration * qpm * rate when unset.
PROXY_CREATE_DEPOSIT = os.getenv("PROXY_CREATE_DEPOSIT", "0")
PROXY_CREATE_DURATION = os.getenv("PROXY_CREATE_DURATION", "5000")
PROXY_CREATE_RATE = os.getenv("PROXY_CREATE_RATE", FEES_DEFAULT)
PROXY_CREATE_QPM = os.getenv("PROXY_CREATE_QPM", "10")
PROXY_CREATE_SETTLEMENT = os.getenv("PROXY_CREATE_SETTLEMENT", "1000")
PROXY_CREATE_AUTHZ = os.getenv("PROXY_CREATE_AUTHZ", "0")
PROXY_CREATE_DELEGATE = os.getenv("PROXY_CREATE_DELEGATE", "")
PROXY_CREATE_FEES = os.getenv("PROXY_CREATE_FEES", FEES_DEFAULT)
PROXY_CREATE_TIMEOUT = int(os.getenv("PROXY_CREATE_TIMEOUT", "30"))
PROXY_CREATE_BACKOFF = int(os.getenv("PROXY_CREATE_BACKOFF", "2"))
PROXY_MAX_DEPOSIT = os.getenv("PROXY_MAX_DEPOSIT", "50000000")
PROXY_SIGN_TEMPLATE = os.getenv("PROXY_SIGN_TEMPLATE", "{contract_id}:{nonce}:")
PROXY_ARKAUTH_FORMAT = os.getenv("PROXY_ARKAUTH_FORMAT", "4part")
PROXY_TIMEOUT_SECS = int(os.getenv("PROXY_TIMEOUT_SECS", "15"))
PROXY_WHITELIST_IPS = os.getenv("PROXY_WHITELIST_IPS", "0.0.0.0")
PROXY_TRUST_FORWARDED = str(os.getenv("PROXY_TRUST_FORWARDED", "true")).lower() in ("1", "true", "yes", "on")
PROXY_DECORATE_RESPONSE = str(os.getenv("PROXY_DECORATE_RESPONSE", "true")).lower() in ("1", "true", "yes", "on")
PROXY_ARKAUTH_AS_HEADER = str(os.getenv("PROXY_ARKAUTH_AS_HEADER", "false")).lower() in ("1", "true", "yes", "on")
PROXY_CONTRACT_TIMEOUT = int(os.getenv("PROXY_CONTRACT_TIMEOUT", "10"))
PROXY_CONTRACT_LIMIT = int(os.getenv("PROXY_CONTRACT_LIMIT", "5000"))
PROXY_OPEN_COOLDOWN = int(os.getenv("PROXY_OPEN_COOLDOWN", "300"))  # seconds to cool down a provider after open failure
PROXY_CONTRACT_CACHE_TTL = int(os.getenv("PROXY_CONTRACT_CACHE_TTL", "45"))  # seconds; 0 disables TTL check
SIGNHERE_HOME = os.path.join(Path.home(), ".arkeo")


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


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def derive_pubkeys(user: str, keyring_backend: str) -> tuple[str, str, str | None]:
    """Return (raw_pubkey, bech32_pubkey, error)."""
    pubkey_cmd = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "keys",
        "show",
        user,
        "--keyring-backend",
        keyring_backend,
    ]
    # Request JSON to get the pubkey field
    pubkey_cmd.extend(["--output", "json"])
    code, pubkey_out = run_list(pubkey_cmd)
    if code != 0:
        return "", "", f"failed to fetch raw pubkey: {pubkey_out}"

    try:
        pub_json = json.loads(pubkey_out)
        raw_pubkey = pub_json.get("pubkey")
        pk_type = ""
        if isinstance(raw_pubkey, str):
            raw_pubkey = raw_pubkey.strip()
            # handle JSON-encoded pubkey string
            if raw_pubkey.startswith("{") and raw_pubkey.endswith("}"):
                try:
                    inner = json.loads(raw_pubkey)
                    pk_type = inner.get("@type") or pk_type
                    raw_pubkey = inner.get("key", "") or ""
                except Exception:
                    pass
        elif isinstance(raw_pubkey, dict):
            pk_type = raw_pubkey.get("@type") or ""
            raw_pubkey = raw_pubkey.get("key", "") or ""
        else:
            raw_pubkey = ""
    except json.JSONDecodeError:
        raw_pubkey = ""
    if not raw_pubkey:
        return "", "", f"could not parse raw pubkey: {pubkey_out}"

    # Use secp256k1 unless explicitly signaled otherwise
    bech32_cmd = ["arkeod", "debug", "pubkey-raw", raw_pubkey]
    pk_type_lower = (pk_type or "").lower()
    if "secp256k1" in pk_type_lower or not pk_type_lower:
        bech32_cmd.extend(["-t", "secp256k1"])

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


def derive_address(user: str, keyring_backend: str) -> tuple[str, str | None]:
    """Return (address, error) for the given key."""
    cmd = (
        f"arkeod --home {ARKEOD_HOME} "
        f"--keyring-backend {keyring_backend} "
        f"keys show {user} -a"
    )
    code, out = run(cmd)
    if code != 0:
        return "", out
    return out.strip(), None


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


def _latest_block_height() -> tuple[str | None, str | None]:
    """Return (height_str, error_str)."""
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.append("status")
    code, out = run_list(cmd)
    if code != 0:
        return None, f"status exit={code}: {out}"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None, "invalid JSON from status"
    sync_info = data.get("SyncInfo") or data.get("sync_info") or {}
    height = sync_info.get("latest_block_height") or sync_info.get("latest_block")
    return (str(height) if height is not None else None), None


@app.get("/api/key")
def get_key():
    cmd = (
        f"arkeod --home {ARKEOD_HOME} "
        f"--keyring-backend {KEYRING} "
        f"keys show {KEY_NAME} -a"
    )
    code, out = run(cmd)
    if code != 0:
        return jsonify({"error": "failed to get key address", "detail": out}), 500

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
        return jsonify({"error": "failed to get key address", "detail": addr_out}), 500

    address = addr_out.strip()

    # then query balances in JSON form
    bal_cmd = (
        f"arkeod query bank balances {address} "
        f"--node {ARKEOD_NODE} "
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
        ), 500

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

    if not service:
        return jsonify({"error": "service is required"}), 400

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

    mod_cmd, mod_code, mod_out = run_mod_with_sequence(sequence_arg)

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

    base = provider_pubkeys_response(user, keyring_backend)
    address, addr_err = derive_address(user, keyring_backend)
    base.update(
        {
            "fees": fees,
            "bond": bond,
            "sentinel_uri": SENTINEL_URI_DEFAULT,
            "metadata_nonce": METADATA_NONCE_DEFAULT,
            "arkeod_node": ARKEOD_NODE,
            "provider_metadata": _load_env_file(SENTINEL_ENV_PATH),
            "subscriber_name": os.getenv("SUBSCRIBER_NAME") or "",
            "address": address,
        }
    )
    if addr_err:
        base["address_error"] = addr_err
    return jsonify(base)

@app.get("/api/subscriber-info")
def subscriber_info():
    """Alias for subscriber UI; returns the same payload as provider_info."""
    # Also write to subscriber_info.json for faster local reads
    resp = provider_info().get_json()
    try:
        height, h_err = _latest_block_height()
    except Exception:
        height, h_err = None, "failed to fetch height"
    payload = {
        "fetched_at": _timestamp(),
        "pubkey": resp.get("pubkey") if isinstance(resp, dict) else {},
        "address": resp.get("address") if isinstance(resp, dict) else "",
        "subscriber_name": resp.get("subscriber_name") if isinstance(resp, dict) else "",
        "arkeod_node": ARKEOD_NODE,
        "latest_block": height,
    }
    if h_err:
        payload["latest_block_error"] = h_err
    try:
        _write_json_atomic(SUBSCRIBER_INFO_FILE, payload)
    except Exception:
        pass
    return jsonify(resp)


@app.get("/api/payg-status")
def payg_status():
    """Quick status endpoint for PAYG proxy: key, homes, and height."""
    _ensure_signhere_home()
    resp = provider_info().get_json()
    addr, addr_err = derive_address(KEY_NAME, KEYRING)
    height, h_err = _latest_block_height()
    signhere_target = None
    try:
        signhere_target = str(Path(SIGNHERE_HOME).resolve())
    except Exception:
        pass
    payload = {
        "key_name": KEY_NAME,
        "keyring_backend": KEYRING,
        "address": addr,
        "address_error": addr_err,
        "pubkey": resp.get("pubkey") if isinstance(resp, dict) else {},
        "pubkey_error": resp.get("pubkey_error") if isinstance(resp, dict) else None,
        "arkeod_home": ARKEOD_HOME,
        "signhere_home": SIGNHERE_HOME,
        "signhere_points_to": signhere_target,
        "latest_block": height,
        "latest_block_error": h_err,
    }
    return jsonify(payload)


@app.get("/api/services")
def list_services():
    """Return available services from arkeod."""
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "all-services", "-o", "json"])

    code, out = run_list(cmd)
    if code != 0:
        return jsonify({"error": "failed to list services", "detail": out}), 500

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
        if sid is None and name is None:
            continue
        services.append({"id": sid, "name": name})

    # If parsing failed, try to extract minimal info from text lines
    if not services and isinstance(parsed, str):
        text_pattern = re.compile(
            r"^\s*-\s*(?P<service>[^:]+?)\s*:\s*(?P<id>[0-9]+)\s*\((?P<desc>.*)\)\s*$"
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


def _fetch_provider_services_internal(bech32_pubkey: str) -> list[dict]:
    """Return provider services for a given pubkey (lightweight helper)."""
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-providers", "--output", "json"])
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


def _load_cached(name: str) -> dict:
    path = os.path.join(CACHE_DIR, f"{name}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _ensure_listeners_file() -> dict:
    """Load listeners.json; if missing, return an empty structure."""
    cache_ensure_cache_dir()
    payload = {"fetched_at": _timestamp(), "listeners": []}
    try:
        with open(LISTENERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("listeners"), list):
                return data
    except (OSError, json.JSONDecodeError):
        pass
    try:
        with open(LISTENERS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
    except OSError:
        pass
    return payload


def _write_listeners(data: dict) -> None:
    """Write listeners.json atomically."""
    cache_ensure_cache_dir()
    path = LISTENERS_FILE
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=True, indent=2)
        os.replace(tmp_path, path)
    except OSError:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(str(val))
    except Exception:
        return default


def _build_arkeo_meta(active_contract: dict | None, nonce: int | None) -> dict:
    """Build a debug meta block similar to the standalone proxy script."""
    meta: dict = {
        "contract_id": "",
        "service_id": None,
        "provider": "",
        "client": "",
        "nonce_request": nonce,
        "cost_request": "",
        "deposit": None,
        "qpm": None,
        "duration": None,
        "opened_height": None,
    }
    if not isinstance(active_contract, dict):
        return meta
    try:
        rate = active_contract.get("rate") or {}
        rate_amt = _safe_int(rate.get("amount"), 0)
        rate_denom = rate.get("denom") or ""
        meta.update(
            {
                "contract_id": str(active_contract.get("id", "")),
                "service_id": _safe_int(active_contract.get("service")),
                "provider": str(active_contract.get("provider", "")),
                "client": str(active_contract.get("client", "")),
                "nonce_request": nonce,
                "cost_request": f"{rate_amt}{rate_denom}" if (rate_amt or rate_denom) else "",
                "deposit": _safe_int(active_contract.get("deposit"), None),
                "qpm": _safe_int(active_contract.get("queries_per_minute"), None),
                "duration": _safe_int(active_contract.get("duration"), None),
                "opened_height": _safe_int(active_contract.get("height"), None),
            }
        )
    except Exception:
        meta.update({"contract_id": str(active_contract.get("id", "")), "nonce_request": nonce})
    return meta


def _parse_rate_amount(rate_val) -> int:
    """Extract integer amount from rate string or dict."""
    if isinstance(rate_val, dict):
        return _safe_int(rate_val.get("amount"), 0)
    if isinstance(rate_val, str):
        # Expect e.g. "200uarkeo"
        digits = "".join(ch for ch in rate_val if ch.isdigit())
        return _safe_int(digits, 0)
    return _safe_int(rate_val, 0)


def _listener_logger(port: int):
    """Return a rotating file logger for a listener port."""
    cache_ensure_cache_dir()
    os.makedirs(LOG_DIR, exist_ok=True)
    name = f"listener-{port}"
    logger = logging.getLogger(name)
    if getattr(logger, "_initialized", False):
        return logger
    logger.setLevel(logging.INFO)
    log_path = os.path.join(LOG_DIR, f"listener-{port}.log")
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [port=%(port)s] %(message)s"))
    handler.addFilter(lambda record: setattr(record, "port", port) or True)
    logger.addHandler(handler)
    logger.propagate = False
    logger._initialized = True  # type: ignore
    return logger


def _parse_whitelist(csv: str | None) -> list[str]:
    if not csv:
        return []
    return [ip.strip() for ip in csv.split(",") if ip.strip()]


def _is_external(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        parsed = urllib.parse.urlparse(uri)
        host = (parsed.hostname or "").lower()
        if not parsed.scheme or not host:
            return False
        if host == "localhost":
            return False
        if host.startswith("127."):
            return False
        return True
    except Exception:
        return False


def _is_listener_active(entry: dict) -> bool:
    """Return True if listener status is active-like."""
    status = str(entry.get("status") or "").strip().lower()
    return status in ("active", "1", "true", "on", "yes")


class _HelloHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"hello world\n")
        except Exception:
            pass
        try:
            self.request.close()
        except Exception:
            pass


class _HelloServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start_listener_server(listener: dict) -> tuple[bool, str | None]:
    """Start a background PAYG proxy for the given entry."""
    port_val = listener.get("port")
    try:
        port = int(port_val)
    except (TypeError, ValueError):
        return False, "invalid port"

    provider_pubkey, sentinel_url, provider_moniker = _resolve_listener_target(listener)
    if not sentinel_url:
        sentinel_url = SENTINEL_URI_DEFAULT
    if not sentinel_url:
        return False, "no sentinel URL available for listener"

    service_meta = _service_lookup(listener.get("service_id"))
    service_name = service_meta.get("service_name") or listener.get("service_name") or listener.get("service_id")
    service_desc = service_meta.get("service_description") or listener.get("service_description") or ""

    cfg = {
        "node_rpc": ARKEOD_NODE,
        "chain_id": CHAIN_ID,
        "listener_id": listener.get("id"),
        "client_key": KEY_NAME,
        "keyring_backend": KEYRING,
        "provider_pubkey": provider_pubkey,
        "provider_moniker": provider_moniker,
        "provider_sentinel_api": sentinel_url,
        "service_name": service_name,
        "service_description": service_desc,
        "service_id": listener.get("service_id"),
        "whitelist_ips": listener.get("whitelist_ips") or PROXY_WHITELIST_IPS,
        "trust_forwarded": listener.get("trust_forwarded", PROXY_TRUST_FORWARDED),
        "decorate_response": listener.get("decorate_response", PROXY_DECORATE_RESPONSE),
        "arkauth_as_header": listener.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER),
        "auto_create": listener.get("auto_create", PROXY_AUTO_CREATE),
        "create_provider_pubkey": provider_pubkey or listener.get("create_provider_pubkey"),
        "create_service_name": service_name,
        "create_type": listener.get("create_type", 1),
        "create_deposit": listener.get("create_deposit", PROXY_CREATE_DEPOSIT),
        "create_duration": listener.get("create_duration", PROXY_CREATE_DURATION),
        "create_rate": listener.get("create_rate", PROXY_CREATE_RATE),
        "create_qpm": listener.get("create_qpm", PROXY_CREATE_QPM),
        "create_settlement": listener.get("create_settlement", PROXY_CREATE_SETTLEMENT),
        "create_authz": listener.get("create_authz", PROXY_CREATE_AUTHZ),
        "create_delegate": listener.get("create_delegate", PROXY_CREATE_DELEGATE),
        "create_fees": listener.get("create_fees", PROXY_CREATE_FEES),
        "max_deposit": listener.get("max_deposit", PROXY_MAX_DEPOSIT),
        "create_timeout_sec": listener.get("create_timeout_sec", PROXY_CREATE_TIMEOUT),
        "create_backoff_sec": listener.get("create_backoff_sec", PROXY_CREATE_BACKOFF),
        "sign_template": listener.get("sign_template", PROXY_SIGN_TEMPLATE),
        "arkauth_format": listener.get("arkauth_format", PROXY_ARKAUTH_FORMAT),
        "timeout_secs": listener.get("timeout_secs", PROXY_TIMEOUT_SECS),
        "top_services": listener.get("top_services") or [],
    }

    try:
        srv = PaygProxyServer(("0.0.0.0", port), PaygProxyHandler)
    except OSError as e:
        return False, f"failed to bind port {port}: {e}"
    srv.cfg = cfg
    srv.logger = _listener_logger(port)
    srv.client_pubkey = None
    srv.active_contract = None
    srv.active_contracts = {}
    srv.last_code = None
    srv.last_nonce = None

    with _LISTENER_LOCK:
        if port in _LISTENER_SERVERS:
            srv.server_close()
            return True, None
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
        _LISTENER_SERVERS[port] = {"server": srv, "thread": thread, "listener_id": listener.get("id")}
        thread.start()
    return True, None


def _stop_listener_server(port: int) -> None:
    """Stop a running listener server if present."""
    srv_entry = None
    with _LISTENER_LOCK:
        srv_entry = _LISTENER_SERVERS.pop(port, None)
    if not srv_entry:
        return
    srv = srv_entry.get("server")
    try:
        if srv:
            srv.shutdown()
            srv.server_close()
    except Exception:
        pass


def _ensure_listener_runtime(listener: dict, previous_port: int | None = None, previous_status=None, previous_entry: dict | None = None) -> tuple[bool, str | None]:
    """Ensure background process matches desired status/port."""
    try:
        port = int(listener.get("port"))
    except (TypeError, ValueError):
        return False, "invalid port"
    active = _is_listener_active(listener)
    prev_active = _is_listener_active({"status": previous_status}) if previous_status is not None else None

    config_changed = False
    if previous_entry:
        # Detect changes that require a restart to apply (service, providers, top_services ordering, whitelist, sentinel).
        keys_to_check = [
            "service_id",
            "provider_pubkey",
            "sentinel_url",
            "top_services",
            "whitelist_ips",
        ]
        for k in keys_to_check:
            if previous_entry.get(k) != listener.get(k):
                config_changed = True
                break

    # If staying on the same port and already active, skip restart only when config is unchanged.
    if active and prev_active and previous_port is not None and previous_port == port and not config_changed:
        return True, None
    if active and prev_active and previous_port is not None and previous_port == port and config_changed:
        # same port but config changed (e.g., reordered top_services) → stop before restart to avoid bind errors
        _stop_listener_server(previous_port)

    if not active:
        # Stop current or previous port
        if previous_port is not None:
            _stop_listener_server(previous_port)
        else:
            _stop_listener_server(port)
        return True, None

    # If port changed, stop the old one before starting
    if previous_port is not None and previous_port != port:
        _stop_listener_server(previous_port)

    ok, err = _start_listener_server(listener)
    if not ok:
        # best-effort restart old port if we disabled it and it was active
        if previous_port is not None and prev_active:
            try:
                _start_listener_server({"port": previous_port, "id": listener.get("id")})
            except Exception:
                pass
    return ok, err


def _next_available_port(used: set[int]) -> int | None:
    for p in range(LISTENER_PORT_START, LISTENER_PORT_END + 1):
        if p not in used:
            return p
    return None


def _load_active_service_types_lookup() -> dict[str, dict]:
    try:
        with open(ACTIVE_SERVICE_TYPES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    items = data.get("active_service_types") if isinstance(data, dict) else []
    if not isinstance(items, list):
        return {}
    lookup: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        sid = item.get("service_id") or item.get("id") or item.get("service")
        st = item.get("service_type") or {}
        if sid is None:
            continue
        lookup[str(sid)] = {
            "service_id": str(sid),
            "service_name": st.get("name") or "",
            "service_description": st.get("description") or st.get("desc") or "",
        }
    return lookup


def _collect_used_ports(listeners: list, skip_id: str | None = None) -> set[int]:
    used: set[int] = set()
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if skip_id is not None and str(l.get("id")) == str(skip_id):
            continue
        port_val = l.get("port")
        try:
            if port_val is None or port_val == "":
                continue
            used.add(int(port_val))
        except (TypeError, ValueError):
            continue
    return used


def _bootstrap_listeners_from_cache():
    """Start background listeners for any active entries in listeners.json."""
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return
        for l in listeners:
            if not isinstance(l, dict) or not _is_listener_active(l):
                continue
            ok, err = _start_listener_server(l)
            if not ok:
                print(f"[listeners] failed to start listener on port {l.get('port')}: {err}")
    except Exception as e:
        print(f"[listeners] bootstrap error: {e}")


# ─────────────────────────────────────
# PAYG Proxy helpers
# ─────────────────────────────────────
def _service_lookup(service_id: str | int) -> dict:
    """Return service name/description from active_service_types."""
    try:
        with open(ACTIVE_SERVICE_TYPES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    items = data.get("active_service_types") if isinstance(data, dict) else []
    if not isinstance(items, list):
        return {}
    sid_str = str(service_id)
    for item in items:
        if not isinstance(item, dict):
            continue
        if sid_str == str(item.get("service_id") or item.get("id") or item.get("service")):
            st = item.get("service_type") or {}
            return {
                "service_id": sid_str,
                "service_name": st.get("name") or "",
                "service_description": st.get("description") or "",
            }
    return {}


def _sentinel_from_metadata_uri(uri: str | None) -> str | None:
    if not uri:
        return None
    # strip trailing metadata.json and slashes
    base = uri
    if base.endswith("metadata.json"):
        base = base[: -len("metadata.json")]
    return base.rstrip("/")


def _tail_file(path: str, max_lines: int = 200) -> str:
    """Return the last max_lines from a text file."""
    try:
        from collections import deque
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(deque(f, maxlen=max_lines))
    except FileNotFoundError:
        return ""
    except Exception as e:
        return f"[log read error: {e}]"


def _set_top_service_status(listener_id: str | None, provider_pubkey: str | None, status: str | None):
    """Persist status for a provider entry inside listeners.json top_services."""
    if not listener_id or not provider_pubkey or status is None:
        return
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return
        changed = False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            ts = l.get("top_services")
            if not isinstance(ts, list):
                continue
            for entry in ts:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("provider_pubkey")) != str(provider_pubkey):
                    continue
                if entry.get("status") != status:
                    entry["status"] = status
                    entry["status_updated_at"] = _timestamp()
                    changed = True
                break
            break
        if changed:
            _write_listeners(data)
    except Exception:
        pass


def _update_top_service_metrics(listener_id: str | None, provider_pubkey: str | None, response_time_sec: float | None):
    """Incrementally update avg response time for a provider entry in listeners.json."""
    if not listener_id or not provider_pubkey or response_time_sec is None:
        return
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return
        changed = False
        rt_ms = int(response_time_sec * 1000)
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            ts = l.get("top_services")
            if not isinstance(ts, list):
                continue
            for entry in ts:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("provider_pubkey")) != str(provider_pubkey):
                    continue
                cnt = _safe_int(entry.get("rt_count"), 0)
                avg = float(entry.get("rt_avg_ms") or 0)
                new_cnt = cnt + 1
                new_avg = ((avg * cnt) + rt_ms) / new_cnt if new_cnt else rt_ms
                entry["rt_avg_ms"] = new_avg
                entry["rt_count"] = new_cnt
                entry["rt_last_ms"] = rt_ms
                entry["rt_updated_at"] = _timestamp()
                changed = True
                break
            break
        if changed:
            _write_listeners(data)
    except Exception:
        pass


def _lookup_settlement_duration(provider_pubkey: str | None, service_id: str | int | None) -> str | None:
    """Try to find settlement_duration for a provider/service from active_services cache."""
    if not provider_pubkey or service_id is None:
        return None
    try:
        data = _load_cached("active_services")
    except Exception:
        return None
    entries = data.get("active_services") if isinstance(data, dict) else []
    if not isinstance(entries, list):
        return None
    sid_str = str(service_id)
    for e in entries:
        if not isinstance(e, dict):
            continue
        if str(e.get("provider_pubkey")) != provider_pubkey:
            continue
        sid_val = e.get("service_id") or e.get("service") or e.get("id")
        if sid_str != str(sid_val):
            continue
        # prefer explicit field, else raw blob
        settle = e.get("settlement_duration")
        if settle is not None:
            return settle
        raw = e.get("raw") if isinstance(e.get("raw"), dict) else {}
        if isinstance(raw, dict):
            settle = raw.get("settlement_duration")
            if settle is not None:
                return settle
    return None


def _candidate_providers(cfg: dict) -> list[dict]:
    """Build an ordered list of provider candidates for failover."""
    candidates: list[dict] = []
    top = cfg.get("top_services")
    if isinstance(top, list):
        for ts in top:
            if not isinstance(ts, dict):
                continue
            pk = ts.get("provider_pubkey")
            if not pk:
                continue
            mu = ts.get("metadata_uri")
            sentinel_url = _sentinel_from_metadata_uri(mu) if _is_external(mu) else None
            settle = ts.get("settlement_duration")
            if settle is None:
                settle = _lookup_settlement_duration(pk, cfg.get("service_id") or cfg.get("service"))
            rate = ts.get("pay_as_you_go_rate") if isinstance(ts.get("pay_as_you_go_rate"), dict) else None
            candidates.append(
                {
                    "provider_pubkey": pk,
                    "provider_moniker": ts.get("provider_moniker"),
                    "sentinel_url": sentinel_url,
                    "settlement_duration": settle,
                    "pay_as_you_go_rate": rate,
                    "queries_per_minute": ts.get("queries_per_minute"),
                    "min_contract_duration": ts.get("min_contract_duration"),
                    "max_contract_duration": ts.get("max_contract_duration"),
                }
            )
    # ensure configured provider is included (first if not already)
    cfg_pk = cfg.get("provider_pubkey")
    cfg_sent = cfg.get("provider_sentinel_api")
    if cfg_pk:
        exists = any(c.get("provider_pubkey") == cfg_pk for c in candidates)
        if not exists:
            candidates.insert(0, {"provider_pubkey": cfg_pk, "provider_moniker": cfg.get("provider_moniker"), "sentinel_url": cfg_sent})
    if not candidates:
        candidates.append({"provider_pubkey": cfg_pk, "provider_moniker": cfg.get("provider_moniker"), "sentinel_url": cfg_sent})
    # dedupe while preserving order
    seen = set()
    deduped = []
    for c in candidates:
        pk = c.get("provider_pubkey")
        if pk in seen:
            continue
        seen.add(pk)
        deduped.append(c)
    return deduped


def _resolve_listener_target(listener: dict) -> tuple[str | None, str | None, str | None]:
    """Return (provider_pubkey, sentinel_url, provider_moniker)."""
    if not isinstance(listener, dict):
        return None, None, None
    # Prefer stored values if present
    pk = listener.get("provider_pubkey")
    sent = listener.get("sentinel_url")
    mon = listener.get("provider_moniker")
    if pk and sent:
        return pk, sent, mon
    top = listener.get("top_services") or []
    if isinstance(top, list):
        for ts in top:
            if not isinstance(ts, dict):
                continue
            meta_uri = ts.get("metadata_uri")
            if not _is_external(meta_uri):
                continue
            sentinel_url = _sentinel_from_metadata_uri(meta_uri)
            if sentinel_url:
                return ts.get("provider_pubkey") or pk, sentinel_url, ts.get("provider_moniker") or mon
    return pk, sent, mon


def _get_current_height(node: str) -> int:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if node:
        cmd.extend(["--node", node])
    cmd.append("status")
    code, out = run_list(cmd)
    if code != 0:
        return 0
    try:
        data = json.loads(out)
        sync_info = data.get("sync_info") or data.get("SyncInfo") or {}
        return _safe_int(sync_info.get("latest_block_height") or sync_info.get("latest_block"))
    except Exception:
        return 0


def _fetch_contracts(node: str, timeout: int | None = None, active_only: bool = True, limit: int | None = None, client_filter: str | None = None) -> list:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if node:
        cmd.extend(["--node", node])
    cmd.extend(["query", "arkeo", "list-contracts", "-o", "json"])
    use_limit = limit if limit is not None else PROXY_CONTRACT_LIMIT
    if use_limit:
        try:
            cmd.extend(["--limit", str(use_limit)])
        except Exception:
            pass
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if completed.returncode != 0:
            return []
        out = completed.stdout
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    contracts = data.get("contract") or data.get("contracts")
    if not isinstance(contracts, list):
        return []
    filtered = []
    for c in contracts:
        if not isinstance(c, dict):
            continue
        if active_only:
            sh = c.get("settlement_height")
            # keep only active/open contracts (settlement_height == 0)
            if not (str(sh) == "0" or sh == 0 or sh is None):
                continue
        if client_filter and str(c.get("client")) != str(client_filter):
            continue
        filtered.append(c)
    return filtered


def _select_active_contract(contracts: list, client_pub: str, svc_id: int, cur_height: int, provider_filter: str | None = None):
    """Pick newest usable contract for this client/service (optionally provider)."""
    def is_active(c):
        if not isinstance(c, dict):
            return False
        if client_pub and str(c.get("client")) != client_pub:
            return False
        if _safe_int(c.get("service")) != svc_id:
            return False
        if provider_filter and str(c.get("provider")) != provider_filter:
            return False
        if _safe_int(c.get("settlement_height")) != 0:
            return False
        if _safe_int(c.get("deposit")) <= 0:
            return False
        if (_safe_int(c.get("height")) + _safe_int(c.get("duration"))) <= cur_height:
            return False
        return True

    usable = [c for c in contracts if is_active(c)]
    usable.sort(key=lambda x: _safe_int(x.get("id")), reverse=True)
    return usable[0] if usable else None


def _claims_highest_nonce(sentinel: str, contract_id: str, client_pub: str) -> int:
    failed = 0
    for key in ("client", "spender"):
        url = f"{sentinel.rstrip('/')}/claims?contract_id={contract_id}&{key}={urllib.parse.quote(client_pub)}"
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode() or "{}")
                n = data.get("highestNonce") or data.get("highest_nonce")
                return _safe_int(n)
        except Exception:
            failed += 1
    return 0 if failed else 0


def _der_to_rs_hex(der: bytes) -> str:
    if len(der) < 2 or der[0] != 0x30:
        raise ValueError("not DER")
    idx = 1
    if der[idx] & 0x80:
        nlen = der[idx] & 0x7F
        idx += 1 + nlen
    else:
        idx += 1
    if der[idx] != 0x02:
        raise ValueError("no r")
    lr = der[idx + 1]
    r = der[idx + 2 : idx + 2 + lr]
    idx += 2 + lr
    if der[idx] != 0x02:
        raise ValueError("no s")
    ls = der[idx + 1]
    s = der[idx + 2 : idx + 2 + ls]
    r = r.lstrip(b"\x00")[:32]
    s = s.lstrip(b"\x00")[:32]
    r = (b"\x00" * (32 - len(r))) + r
    s = (b"\x00" * (32 - len(s))) + s
    return (r + s).hex()


def _b64_or_hex_to_rs_hex(sig_text: str) -> str:
    s = (sig_text or "").strip()
    try:
        b = bytes.fromhex(s)
        if len(b) == 64:
            return b.hex()
        if len(b) and b[0] == 0x30:
            return _der_to_rs_hex(b)
        return b.hex()
    except ValueError:
        pass
    sb64 = s.replace("-", "+").replace("_", "/")
    sb64 += "=" * ((4 - len(sb64) % 4) % 4)
    try:
        b = base64.b64decode(sb64, validate=False)  # type: ignore
    except Exception:
        return ""
    if len(b) == 64:
        return b.hex()
    if len(b) and b[0] == 0x30:
        return _der_to_rs_hex(b)
    return b.hex()


def _ensure_signhere_home():
    """signhere has no --home flag; ensure ~/.arkeo points at ARKEOD_HOME."""
    try:
        target = Path(SIGNHERE_HOME)
        arkeod_home = Path(ARKEOD_HOME)
        if target.resolve() == arkeod_home.resolve():
            return
        if target.exists() or target.is_symlink():
            try:
                target.unlink()
            except Exception:
                pass
        if arkeod_home.exists():
            target.symlink_to(arkeod_home)
    except Exception:
        pass


def _build_arkeo_meta_clean(active: dict | None, nonce: int | None, svc_id: int, service: str, provider: str, client: str, sentinel: str, response_time_sec: float):
    base = _build_arkeo_meta(active, nonce)
    # strip noisy fields
    for k in ("provider", "client", "duration", "deposit", "nonce_used_for_this_request", "arkeod_node"):
        base.pop(k, None)
    meta = {
        **base,
        "contract_id": str(active.get("id")) if active else "",
        "nonce_request": base.get("nonce_request") or nonce,
        "provider_pubkey": provider,
        "response_time_sec": response_time_sec,
        "sentinel": sentinel,
        "service_id": svc_id,
        "service_name": service,
        "subscriber_pubkey": client,
    }
    return {k: meta[k] for k in sorted(meta.keys())}


def _sign_message(
    client_key: str, contract_id: str, nonce: int, sign_template: str = PROXY_SIGN_TEMPLATE
) -> tuple[str | None, str]:
    preimage = sign_template.format(contract_id=contract_id, nonce=nonce)
            # signhere has no home/keyring flags; ensure ~/.arkeo -> ARKEOD_HOME exists, then call plainly.
    _ensure_signhere_home()
    cmd = f'signhere -u "{client_key}" -m "{preimage}" | tail -n 1'
    code, out = run(cmd)
    out_clean = out.strip() if isinstance(out, str) else ""
    if code != 0 or not out_clean:
        return None, f"signhere_exit={code} output={out_clean}"
    sig_hex = _b64_or_hex_to_rs_hex(out_clean).lower()
    if not sig_hex or len(sig_hex) != 128:
        return None, f"sig_parse_failed len={len(sig_hex)} raw={out_clean}"
    return sig_hex, ""


def _forward_to_sentinel(sentinel: str, service: str, body: bytes, arkauth: str, timeout: int = PROXY_TIMEOUT_SECS, as_header: bool = False):
    url = f"{sentinel.rstrip('/')}/{service}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if as_header:
        headers["arkauth"] = arkauth
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    else:
        url = f"{url}?arkauth={urllib.parse.quote(arkauth, safe='')}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:
        return 502, json.dumps({"error": "proxy_upstream_error", "detail": str(e)}).encode(), {"Content-Type": "application/json"}


_TXHASH_RE = re.compile(r'(?i)\btxhash\b[:\s"]+([0-9A-Fa-f]{64})')


def _create_contract_now(cfg: dict, client_pub: str) -> tuple[str | None, str, int]:
    max_dep = _safe_int(cfg.get("max_deposit", PROXY_MAX_DEPOSIT), _safe_int(PROXY_MAX_DEPOSIT, 0))
    dep_raw = _safe_int(cfg.get("create_deposit", "0"), 0)
    if dep_raw <= 0:
        rate_amt = _parse_rate_amount(cfg.get("create_rate", PROXY_CREATE_RATE))
        dur = _safe_int(cfg.get("create_duration", PROXY_CREATE_DURATION), _safe_int(PROXY_CREATE_DURATION, 0))
        qpm = _safe_int(cfg.get("create_qpm", PROXY_CREATE_QPM), _safe_int(PROXY_CREATE_QPM, 0))
        dep_raw = rate_amt * dur * qpm
    dep = dep_raw
    if max_dep and dep > max_dep:
        dep = max_dep
    cmd = (
        'arkeod tx arkeo open-contract '
        f'--home "{ARKEOD_HOME}" '
        f'"{cfg.get("create_provider_pubkey","")}" '
        f'"{cfg.get("service_name","")}" '
        f'"{client_pub}" '
        f'"{_safe_int(cfg.get("create_type","1"))}" '
        f'"{dep}" '
        f'"{_safe_int(cfg.get("create_duration", PROXY_CREATE_DURATION))}" '
        f'"{cfg.get("create_rate", PROXY_CREATE_RATE)}" '
        f'"{_safe_int(cfg.get("create_qpm", PROXY_CREATE_QPM))}" '
        f'"{_safe_int(cfg.get("create_settlement", PROXY_CREATE_SETTLEMENT))}" '
        f'"{_safe_int(cfg.get("create_authz","0"))}" '
        f'"{cfg.get("create_delegate","")}" '
        f'--from="{cfg.get("client_key","")}" '
        f'--fees="{cfg.get("create_fees", PROXY_CREATE_FEES)}" '
        f'--keyring-backend="{cfg.get("keyring_backend","test")}" '
        f'--node "{cfg.get("node_rpc")}" '
        f'--chain-id "{cfg.get("chain_id")}" '
        "--gas auto --gas-adjustment 1.2 "
        "--yes --output json"
    )
    code, out = run(cmd)
    if code != 0:
        return None, out, dep
    try:
        j = json.loads(out)
        txh = j.get("txhash") or j.get("TxHash") or ""
        if isinstance(txh, list):
            txh = txh[0] if txh else ""
        if txh:
            return txh, out, dep
    except json.JSONDecodeError:
        pass
    m = _TXHASH_RE.search(out)
    if m:
        return m.group(1), out, dep
    return None, out, dep


def _wait_for_new_contract(cfg: dict, client_pub: str, svc_id: int, start_height: int, wait_sec: int) -> dict | None:
    deadline = time.time() + wait_sec
    node = cfg.get("node_rpc") or ARKEOD_NODE
    provider_filter = cfg.get("create_provider_pubkey") or cfg.get("provider_pubkey")
    while time.time() < deadline:
        contracts = _fetch_contracts(node, active_only=True, client_filter=client_pub)
        cur_h = _get_current_height(node)
        c = _select_active_contract(contracts, client_pub, svc_id, cur_h, provider_filter=provider_filter)
        if c and _safe_int(c.get("height")) >= start_height:
            return c
        time.sleep(_safe_int(cfg.get("create_backoff_sec", 2), 2))
    return None


class PaygProxyHandler(BaseHTTPRequestHandler):
    server_version = "ArkeoPaygProxy/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Silence default stderr logging; handled via per-listener logger
        if hasattr(self.server, "logger") and self.server.logger:
            try:
                self.server.logger.info(format % args)
            except Exception:
                pass

    def _log(self, level: str, msg: str):
        logger = getattr(self.server, "logger", None)
        if not logger:
            return
        fn = getattr(logger, level, None)
        if callable(fn):
            try:
                fn(msg)
            except Exception:
                pass

    def _near_log_rotation(self) -> bool:
        """Return True if a rotation would occur for this log write."""
        logger = getattr(self.server, "logger", None)
        if not logger:
            return False
        try:
            record = logger.makeRecord(logger.name, logging.INFO, __file__, 0, "probe", None, None)
            for h in logger.handlers:
                if isinstance(h, RotatingFileHandler):
                    try:
                        if h.shouldRollover(record):
                            return True
                    except Exception:
                        continue
        except Exception:
            return False
        return False

    def _should_record_metrics(self, code: int, auto_created: bool) -> bool:
        """Gate metric recording to avoid skew."""
        if auto_created:
            return False
        if not (200 <= int(code) < 300):
            return False
        # skip first request after start to avoid cold-start skew
        if not hasattr(self.server, "metrics_warm"):
            self.server.metrics_warm = False
        if not self.server.metrics_warm:
            self.server.metrics_warm = True
            return False
        # avoid logging a sample if log rotation is imminent
        if self._near_log_rotation():
            return False
        return True

    def _client_ip(self, trust_forwarded: bool) -> str:
        if trust_forwarded:
            xr = self.headers.get("X-Real-Ip", "")
            if xr:
                return xr.split(",")[0].strip()
            xf = self.headers.get("X-Forwarded-For", "")
            if xf:
                return xf.split(",")[0].strip()
        ip = self.client_address[0]
        if ":" in ip and ip.count(":") == 1:
            ip = ip.split(":")[0]
        return ip

    def _send_json(self, status: int, payload: dict, extra_headers: dict | None = None):
        body_bytes = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body_bytes)
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    def do_GET(self):
        if self.path.strip("/").split("?")[0] == "status":
            payload = {
                "client_pub_local": getattr(self.server, "client_pubkey", ""),
                "active_contract": getattr(self.server, "active_contract", None),
                "last_code": getattr(self.server, "last_code", None),
                "last_nonce": getattr(self.server, "last_nonce", None),
                "provider_pubkey": self.server.cfg.get("provider_pubkey"),
                "service_id": self.server.cfg.get("service_id"),
                "service_name": self.server.cfg.get("service_name"),
                "sentinel": self.server.cfg.get("provider_sentinel_api"),
                "height": None,
            }
            try:
                payload["height"] = _get_current_height(self.server.cfg.get("node_rpc"))
            except Exception:
                payload["height"] = None
            return self._send_json(200, payload)
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        cfg = self.server.cfg
        node = cfg.get("node_rpc") or ARKEOD_NODE
        sentinel = cfg.get("provider_sentinel_api") or SENTINEL_URI_DEFAULT
        service = cfg.get("service_name") or cfg.get("service_slug") or cfg.get("service_id") or ""
        svc_id = _safe_int(cfg.get("service_id"), 0)
        client_key = cfg.get("client_key") or KEY_NAME
        try:
            length = _safe_int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        body = self.rfile.read(length) if length > 0 else b"{}"
        response_time_sec = 0
        t_total_start = time.time()
        self._log("info", f"req start service={service} svc_id={svc_id} provider_filter={cfg.get('provider_pubkey')} sentinel={sentinel} bytes={len(body)}")

        # IP whitelist
        wl = _parse_whitelist(cfg.get("whitelist_ips") or PROXY_WHITELIST_IPS)
        allow_all = any(ip == "0.0.0.0" for ip in wl)
        if not allow_all:
            client_ip = self._client_ip(str(cfg.get("trust_forwarded", PROXY_TRUST_FORWARDED)).lower() in ("1", "true", "yes", "on"))
            if client_ip not in wl:
                self._log("warning", f"whitelist block ip={client_ip} wl={wl}")
                meta = _build_arkeo_meta(getattr(self.server, "active_contract", None), None)
                headers = {
                    "X-Arkeo-Contract-Id": meta.get("contract_id", ""),
                    "X-Arkeo-Nonce": str(meta.get("nonce_request", "")),
                    "X-Arkeo-Cost": meta.get("cost_request", ""),
                }
                return self._send_json(403, {"arkeo": meta_full_clean, "error": "ip not whitelisted", "ip": client_ip}, extra_headers=headers)
        self._log("info", "whitelist ok")

        # ensure we have client pubkey
        client_pub = getattr(self.server, "client_pubkey", "") or ""
        if not client_pub:
            raw, bech, err = derive_pubkeys(client_key, KEYRING)
            if err:
                self._log("error", f"client_pubkey_error: {err}")
                return self._send_json(500, {"error": "client_pubkey_error", "detail": err})
            client_pub = bech
            self.server.client_pubkey = bech

        # Contract cache: populated lazily; avoid refetching every request
        contracts = None
        fetch_ms = 0
        fetched_once = False

        candidates = _candidate_providers(cfg)
        try:
            cand_desc = []
            for c in candidates:
                pk = c.get("provider_pubkey") or "?"
                sent = c.get("sentinel_url") or cfg.get("provider_sentinel_api") or SENTINEL_URI_DEFAULT
                cand_desc.append(f"{pk}@{sent}")
            self._log("info", f"provider candidates (ordered): {', '.join(cand_desc)}")
        except Exception:
            pass
        last_err = None
        last_meta = None
        # cooldown map: provider_pubkey -> unix timestamp until retry allowed
        if not hasattr(self.server, "provider_cooldowns"):
            self.server.provider_cooldowns = {}
        cooldowns = self.server.provider_cooldowns

        for idx, cand in enumerate(candidates, start=1):
            provider_filter = cand.get("provider_pubkey") or cfg.get("provider_pubkey")
            sentinel = cand.get("sentinel_url") or cfg.get("provider_sentinel_api") or SENTINEL_URI_DEFAULT
            if not provider_filter:
                continue
            auto_created_this_request = False
            select_ms = 0
            sign_ms = 0
            forward_ms = 0
            t_candidate_start = time.time()
            self._log("info", f"candidate {idx}/{len(candidates)} provider={provider_filter} sentinel={sentinel}")

            # cooldown check
            now = time.time()
            cool_until = cooldowns.get(provider_filter)
            if cool_until and cool_until > now:
                self._log("warning", f"candidate {idx} provider={provider_filter} on cooldown until {cool_until:.0f}; skipping")
                last_err = "provider_cooldown"
                last_meta = _build_arkeo_meta_clean(None, None, svc_id, service, provider_filter, client_pub, sentinel, 0)
                continue

            # ensure cache map exists
            if not hasattr(self.server, "contract_cache"):
                self.server.contract_cache = {}
            contract_cache = self.server.contract_cache

            cur_h = _get_current_height(node)
            active = None

            def _cached_contract_still_active(cobj) -> bool:
                if not isinstance(cobj, dict):
                    return False
                if _safe_int(cobj.get("settlement_height")) != 0:
                    return False
                if _safe_int(cobj.get("deposit")) <= 0:
                    return False
                if (_safe_int(cobj.get("height")) + _safe_int(cobj.get("duration"))) <= cur_h:
                    return False
                return True

            cache_entry = contract_cache.get(provider_filter)
            if cache_entry:
                ttl_ok = PROXY_CONTRACT_CACHE_TTL <= 0 or (time.time() - cache_entry.get("cached_at", 0) < PROXY_CONTRACT_CACHE_TTL)
                if ttl_ok and _cached_contract_still_active(cache_entry.get("contract")):
                    active = cache_entry.get("contract")
                    self._log("info", f"using cached contract id={active.get('id')} provider={provider_filter}")
                else:
                    try:
                        contract_cache.pop(provider_filter, None)
                    except Exception:
                        pass

            if not active and hasattr(self.server, "active_contracts"):
                active = self.server.active_contracts.get(provider_filter)
                if active and not _cached_contract_still_active(active):
                    active = None

            if not active:
                if not fetched_once:
                    t0_fetch = time.time()
                    contracts = _fetch_contracts(node, timeout=PROXY_CONTRACT_TIMEOUT, active_only=True, client_filter=client_pub)
                    fetch_ms = int((time.time() - t0_fetch) * 1000)
                    fetched_once = True
                    if not contracts and fetch_ms >= PROXY_CONTRACT_TIMEOUT * 1000:
                        self._log("error", "contract_lookup_timeout")
                        return self._send_json(503, {"error": "contract_lookup_timeout"})
                    self._log("info", f"contracts fetched count={len(contracts) if isinstance(contracts,list) else 0}")
                active = _select_active_contract(contracts or [], client_pub, svc_id, cur_h, provider_filter=provider_filter)

            if not active and str(cfg.get("auto_create", PROXY_AUTO_CREATE)).lower() in ("1", "true", "yes", "on"):
                self._log("info", f"no active contract -> attempting auto-create (provider={provider_filter})")
                start_h = _get_current_height(node)
                cfg_override = dict(cfg)
                cfg_override["create_provider_pubkey"] = provider_filter
                cand_settle = cand.get("settlement_duration")
                if cand_settle:
                    cfg_override["create_settlement"] = cand_settle
                cand_rate = cand.get("pay_as_you_go_rate")
                if cand_rate and cand_rate.get("amount") is not None and cand_rate.get("denom"):
                    cfg_override["create_rate"] = f"{cand_rate.get('amount')}{cand_rate.get('denom')}"
                cand_qpm = cand.get("queries_per_minute")
                if cand_qpm:
                    cfg_override["create_qpm"] = cand_qpm
                try:
                    min_dur = _safe_int(cand.get("min_contract_duration"), None)
                    max_dur = _safe_int(cand.get("max_contract_duration"), None)
                    cur_dur = _safe_int(cfg_override.get("create_duration", PROXY_CREATE_DURATION), PROXY_CREATE_DURATION)
                    if max_dur and cur_dur > max_dur:
                        cur_dur = max_dur
                    if min_dur and cur_dur < min_dur:
                        cur_dur = min_dur
                    cfg_override["create_duration"] = cur_dur
                except Exception:
                    pass
                auto_created_this_request = True
                txh, tx_raw, dep_used = _create_contract_now(cfg_override, client_pub)
                self._log("info", f"open-contract attempt deposit={dep_used} rate={cfg_override.get('create_rate', cfg.get('create_rate', PROXY_CREATE_RATE))} dur={cfg_override.get('create_duration', cfg.get('create_duration', PROXY_CREATE_DURATION))} qpm={cfg_override.get('create_qpm', cfg.get('create_qpm', PROXY_CREATE_QPM))} settlement={cfg_override.get('create_settlement', cfg.get('create_settlement', PROXY_CREATE_SETTLEMENT))} provider={provider_filter}")
                if tx_raw:
                    self._log("info", f"open-contract response: {tx_raw[:400]}")
                if txh:
                    self._log("info", f"open-contract txhash={txh}")
                    nc = _wait_for_new_contract(cfg_override, client_pub, svc_id, start_h, _safe_int(cfg.get("create_timeout_sec", PROXY_CREATE_TIMEOUT), PROXY_CREATE_TIMEOUT))
                    if nc:
                        active = nc
                        self._log("info", f"auto-created contract id={nc.get('id')} height={nc.get('height')} provider={provider_filter}")
                if not active:
                    last_err = "contract_open_failed"
                    detail = tx_raw[:400] if isinstance(tx_raw, str) else str(tx_raw)
                    last_meta = _build_arkeo_meta_clean(None, None, svc_id, service, provider_filter, client_pub, sentinel, 0)
                    last_meta["detail"] = detail
                    try:
                        _set_top_service_status(cfg.get("listener_id"), provider_filter, "Down")
                    except Exception:
                        pass
                    # set cooldown on open failure
                    if PROXY_OPEN_COOLDOWN > 0:
                        cooldowns[provider_filter] = time.time() + PROXY_OPEN_COOLDOWN
                        self._log("warning", f"cooling down provider={provider_filter} for {PROXY_OPEN_COOLDOWN}s due to contract_open_failed")
                    self._log("warning", f"candidate {idx} open-contract failed; trying next candidate")
                    continue

            if not active:
                last_err = "no_active_contract"
                last_meta = _build_arkeo_meta_clean(None, None, svc_id, service, provider_filter, client_pub, sentinel, 0)
                self._log("warning", f"candidate {idx} has no active contract; trying next candidate")
                continue

            cid = str(active.get("id"))
            contract_client = str(active.get("client", ""))
            select_ms = int((time.time() - t_candidate_start) * 1000)
            if contract_client and contract_client != client_pub:
                self._log("error", f"client_key_mismatch contract_client={contract_client} local={client_pub}")
                meta = _build_arkeo_meta_clean(active, None, svc_id, service, active.get("provider") if active else "", contract_client, sentinel, 0)
                headers = {
                    "X-Arkeo-Contract-Id": meta.get("contract_id", ""),
                    "X-Arkeo-Nonce": str(meta.get("nonce_request", "")),
                    "X-Arkeo-Cost": meta.get("cost_request", ""),
                }
                return self._send_json(503, {"arkeo": meta, "error": "client_key_mismatch"}, extra_headers=headers)

            nonce = _claims_highest_nonce(sentinel, cid, contract_client) + 1
            sign_start = time.time()
            sig_hex, sig_err = _sign_message(
                client_key, cid, nonce, cfg.get("sign_template", PROXY_SIGN_TEMPLATE)
            )
            sign_ms = int((time.time() - sign_start) * 1000)
            if not sig_hex:
                self._log("error", f"sign_failed: {sig_err} timing_ms fetch={fetch_ms} select={select_ms} sign={sign_ms}")
                meta = _build_arkeo_meta_clean(active, nonce, svc_id, service, active.get("provider") if active else "", contract_client, sentinel, response_time_sec)
                headers = {
                    "X-Arkeo-Contract-Id": meta.get("contract_id", ""),
                    "X-Arkeo-Nonce": str(meta.get("nonce_request", "")),
                    "X-Arkeo-Cost": meta.get("cost_request", ""),
                }
                return self._send_json(
                    500,
                    {"arkeo": meta, "error": "sign_failed", "detail": sig_err},
                    extra_headers=headers,
                )

            arkauth4 = f"{cid}:{contract_client}:{nonce}:{sig_hex}"
            self._log("info", f"forwarding 4-part to sentinel={sentinel} svc={service} cid={cid} nonce={nonce} provider={provider_filter}")
            t0 = time.time()
            code, resp_body, _ = _forward_to_sentinel(
                sentinel,
                service,
                body,
                arkauth4,
                timeout=_safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS),
                as_header=bool(cfg.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER)),
            )
            if code == 401:
                self._log("warning", "401 on 4-part arkauth -> retrying 3-part")
                arkauth3 = f"{cid}:{nonce}:{sig_hex}"
                code, resp_body, _ = _forward_to_sentinel(
                    sentinel,
                    service,
                    body,
                    arkauth3,
                    timeout=_safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS),
                    as_header=bool(cfg.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER)),
                )
            response_time_sec = time.time() - t0
            total_time_sec = time.time() - t_total_start
            # Prefer total time for metrics if available
            if total_time_sec > response_time_sec:
                response_time_sec = total_time_sec
            forward_ms = int((time.time() - t0) * 1000)

            self._log("info", f"timings total_ms={int(total_time_sec*1000)} fetch_ms={fetch_ms} select_ms={select_ms} sign_ms={sign_ms} forward_ms={forward_ms} auto_create={auto_created_this_request}")

            meta_full = _build_arkeo_meta_clean(active, nonce, svc_id, service, provider_filter, contract_client, sentinel, response_time_sec)
            self.server.last_code = code
            self.server.last_nonce = nonce
            # success → clear cooldown for this provider
            if provider_filter in cooldowns:
                try:
                    del cooldowns[provider_filter]
                except Exception:
                    pass
            try:
                _set_top_service_status(cfg.get("listener_id"), provider_filter, "Up")
            except Exception:
                pass
            try:
                # Do not include auto-create paths in latency stats; they skew averages
                if self._should_record_metrics(code, auto_created_this_request):
                    _update_top_service_metrics(cfg.get("listener_id"), provider_filter, response_time_sec)
            except Exception:
                pass
            self.server.active_contract = active
            if hasattr(self.server, "active_contracts"):
                self.server.active_contracts[provider_filter] = active
            try:
                contract_cache[provider_filter] = {"contract": active, "cached_at": time.time(), "height_cached": _safe_int(active.get("height"))}
            except Exception:
                pass
            self._log("info", f"proxy done code={code} cid={cid} nonce={nonce} provider={provider_filter}")
            decorate = str(cfg.get("decorate_response", PROXY_DECORATE_RESPONSE)).lower() in ("1", "true", "yes", "on")

            try:
                body_text = resp_body.decode() if isinstance(resp_body, (bytes, bytearray)) else str(resp_body)
            except Exception:
                body_text = ""

            if decorate:
                try:
                    upstream = json.loads(body_text)
                except Exception:
                    upstream = body_text
                return self._send_json(code, {"arkeo": meta_full, "response": upstream})

            if isinstance(resp_body, (bytes, bytearray)):
                out_bytes = resp_body
            else:
                out_bytes = str(resp_body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_bytes)))
            self.send_header("Connection", "close")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-Arkeo-Contract-Id", cid)
            self.send_header("X-Arkeo-Nonce", str(nonce))
            if meta_full.get("cost_request"):
                self.send_header("X-Arkeo-Cost", meta_full.get("cost_request"))
            self.end_headers()
            try:
                self.wfile.write(out_bytes)
                self.wfile.flush()
            except Exception:
                pass
            self.close_connection = True
            return

        # all candidates failed
        meta = last_meta or _build_arkeo_meta_clean(None, None, svc_id, service, "", client_pub, sentinel, 0)
        err = last_err or "no_active_contract"
        headers = {
            "X-Arkeo-Contract-Id": meta.get("contract_id", ""),
            "X-Arkeo-Nonce": str(meta.get("nonce_request", "")),
            "X-Arkeo-Cost": meta.get("cost_request", ""),
        }
        return self._send_json(503, {"arkeo": meta, "error": err}, extra_headers=headers)


class PaygProxyServer(socketserver.ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True



def _test_payload_for_service(service_id, service_name):
    """Return (body_bytes, headers_dict, method_label) for a simple test."""
    name = (service_name or "").lower()
    sid = str(service_id or "").strip()

    # Service-id buckets (strings for easy match)
    evm_ids = {
        # Ethereum + variants
        "16", "147", "17", "18", "150", "19", "20", "21", "154", "40", "151", "152", "153", "155",
        # Avalanche
        "3", "4", "41", "80", "81",
        # Arbitrum
        "65", "66", "67", "68", "69",
        # Base
        "88", "89", "90", "91", "92",
        # BSC
        "8", "9", "36", "107", "108",
        # Optimism
        "24", "45", "279",
        # Polygon
        "29", "30", "291", "289", "290",
        # Scroll
        "302", "303", "304", "305", "306",
        # zkSync / zkFair / Zircuit / Taiko / Linea / Mantle / Manta / Blast / Fraxtal / Kava EVM / Klay / Fuse / Fantom / etc.
        "237", "238", "239", "240", "241",
        "245", "246", "247",
        "243", "244",
        "102", "103", "104", "105", "106",
        "172", "173", "174", "175", "176",
        "178", "179", "180", "181", "182",
        "183", "184", "185", "186",
        "226", "227", "228", "229",
        "230", "231", "232", "233", "234",
        "302", "303", "304", "305", "306",
        "338", "339", "340", "341", "342",
        "372", "373", "374", "375", "376",
        "377", "378", "379", "380",
        "382", "383", "384", "385", "386",
        "327", "328", "329", "330",
        "360", "361", "362", "363", "364",
    }
    base_ids = {"88", "89", "90", "91", "92"}
    btc_ids = {"10", "11", "110", "111", "47", "48", "49", "50", "93", "94", "95", "96", "109", "112", "300", "371", "292", "297", "358", "359", "365"}
    cosmos_ids = {
        # Arkeo
        "2", "74", "76", "77",
        # Osmosis
        "25", "280",
        # Gaia / Cosmos Hub
        "187", "188", "189", "46", "13", "191",
        # Thorchain / Stride / Celestia / Secret / Neutron / Jackal / Injective / Juno / Paloma / Nomic / Nibiru / Persistence / etc.
        "32", "44", "343", "344", "345", "346", "347", "348",
        "331", "332",
        "368", "369",
        "310", "311", "312", "313", "314",
        "264", "265", "266",
        "281", "282",
        "219", "220",
        "221", "222", "223", "224", "225",
        "210", "211", "212", "213", "214",
        "217", "218",
        "271", "272",
        "264", "265", "266",
        "331", "332",
        "368", "369",
        "307", "308",
        "281", "282",
        "264", "265", "266",
    }
    polkadot_ids = {"26", "27", "28", "286", "287", "288"}
    solana_ids = {"31", "323", "324"}
    sui_ids = {"333", "334"}
    near_ids = {"261", "262", "263"}

    headers = {"Content-Type": "application/json"}

    def evm_payload(method: str = "eth_blockNumber"):
        body = {"jsonrpc": "2.0", "method": method, "params": [], "id": 1}
        return json.dumps(body).encode(), headers, f"{method} JSON-RPC"

    def btc_payload():
        body = {"jsonrpc": "1.0", "id": "curltext", "method": "getblockcount", "params": []}
        return json.dumps(body).encode(), headers, "getblockcount JSON-RPC"

    def cosmos_payload():
        body = {"jsonrpc": "2.0", "method": "status", "params": [], "id": 1}
        return json.dumps(body).encode(), headers, "status JSON-RPC"

    def polkadot_payload():
        body = {"jsonrpc": "2.0", "method": "chain_getBlockHash", "params": [], "id": 1}
        return json.dumps(body).encode(), headers, "chain_getBlockHash JSON-RPC"

    def solana_payload():
        body = {"jsonrpc": "2.0", "id": 1, "method": "getSlot", "params": []}
        return json.dumps(body).encode(), headers, "getSlot JSON-RPC"

    def sui_payload():
        body = {"jsonrpc": "2.0", "id": 1, "method": "sui_getLatestCheckpointSequenceNumber", "params": []}
        return json.dumps(body).encode(), headers, "sui_getLatestCheckpointSequenceNumber JSON-RPC"

    def near_payload():
        body = {"jsonrpc": "2.0", "method": "status", "params": [], "id": "dontcare"}
        return json.dumps(body).encode(), headers, "status JSON-RPC"

    # ID-based routing first
    if sid in evm_ids:
        return evm_payload()
    if sid in base_ids:
        return evm_payload()
    if sid in btc_ids:
        return btc_payload()
    if sid in cosmos_ids:
        return cosmos_payload()
    if sid in polkadot_ids:
        return polkadot_payload()
    if sid in solana_ids:
        return solana_payload()
    if sid in sui_ids:
        return sui_payload()
    if sid in near_ids:
        return near_payload()

    # Name-based fallback
    if name.startswith("eth") or "ethereum" in name or "evm" in name:
        return evm_payload()
    if name.startswith("base"):
        return evm_payload()
    if name.startswith("btc") or "bitcoin" in name:
        return btc_payload()
    if any(prefix in name for prefix in ("osmosis", "gaia", "arkeo", "cosmos")):
        return cosmos_payload()
    if "polkadot" in name or name.startswith("dot"):
        return polkadot_payload()
    if name.startswith("sol"):
        return solana_payload()
    if name.startswith("sui"):
        return sui_payload()
    if name.startswith("near"):
        return near_payload()

    # Default EVM-style test
    return evm_payload()


def _test_listener_port(port: int, payload: bytes, headers: dict, timeout: float = 12.0) -> tuple[bool, str | None, str | None]:
    """Attempt a JSON-RPC POST against the listener."""
    url = f"http://127.0.0.1:{port}/"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return True, body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = None
        return False, body, f"HTTP {e.code}: {e.reason}"
    except Exception as e:
        return False, None, str(e)


def _min_payg_rate(raw: dict) -> tuple[int | None, str | None]:
    """Return (amount_int, denom) for the lowest pay_as_you_go_rate entry, or (None, None) if missing."""
    if not isinstance(raw, dict):
        return None, None
    rates = raw.get("pay_as_you_go_rate") or raw.get("pay_as_you_go_rates") or []
    if not isinstance(rates, list):
        return None, None
    best_amt = None
    best_denom = None
    for r in rates:
        if not isinstance(r, dict):
            continue
        denom = r.get("denom") or r.get("Denom")
        amt = r.get("amount") or r.get("Amount")
        if amt is None:
            continue
        try:
            amt_int = int(amt)
        except (TypeError, ValueError):
            continue
        if best_amt is None or amt_int < best_amt:
            best_amt = amt_int
            best_denom = denom
    return best_amt, best_denom


def _top_active_services_by_payg(service_id: str, limit: int = 3) -> list[dict]:
    """Return up to `limit` active services for the given service_id, sorted by lowest pay-as-you-go rate."""
    if not service_id:
        return []
    # build provider lookup for moniker/status
    provider_lookup: dict[str, str] = {}
    try:
        ap = _load_cached("active_providers")
        prov_list = ap.get("providers") if isinstance(ap, dict) else []
        if isinstance(prov_list, list):
            for p in prov_list:
                if not isinstance(p, dict):
                    continue
                pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
                if not pk:
                    continue
                meta = p.get("metadata") or {}
                moniker = (
                    (meta.get("config") or {}).get("moniker")
                    or meta.get("moniker")
                    or (p.get("provider") or {}).get("moniker")
                )
                provider_lookup[pk] = moniker or ""
    except Exception:
        pass
    try:
        data = _load_cached("active_services")
    except Exception:
        data = {}
    entries = data.get("active_services") or []
    if not isinstance(entries, list):
        return []
    candidates: list[dict] = []
    sid_str = str(service_id)
    for e in entries:
        if not isinstance(e, dict):
            continue
        sid_val = e.get("service_id") or e.get("id") or e.get("service")
        if sid_str != str(sid_val):
            continue
        raw = e.get("raw") if isinstance(e.get("raw"), dict) else e
        settle = e.get("settlement_duration") or (raw.get("settlement_duration") if isinstance(raw, dict) else None)
        qpm = None
        min_dur = None
        max_dur = None
        if isinstance(raw, dict):
            qpm = raw.get("queries_per_minute")
            min_dur = raw.get("min_contract_duration")
            max_dur = raw.get("max_contract_duration")
        amt, denom = _min_payg_rate(raw or {})
        moniker = provider_lookup.get(e.get("provider_pubkey") or "") or "(Inactive)"
        candidates.append(
            {
                "provider_pubkey": e.get("provider_pubkey"),
                "provider_moniker": moniker,
                "metadata_uri": e.get("metadata_uri"),
                "pay_as_you_go_rate": {"amount": amt, "denom": denom},
                "queries_per_minute": qpm,
                "min_contract_duration": min_dur,
                "max_contract_duration": max_dur,
                "settlement_duration": settle,
                "raw": e,
            }
        )
    # sort: first by missing rate (push down), then by amount asc
    def _sort_key(item: dict):
        rate = item.get("pay_as_you_go_rate") or {}
        amt = rate.get("amount")
        # push None to bottom by treating None as very large
        amt_key = amt if isinstance(amt, int) else (1 << 62)
        return (amt_key, item.get("provider_pubkey") or "")

    candidates.sort(key=_sort_key)
    return candidates[:limit]


def _write_json_atomic(path: str, payload: dict) -> None:
    cache_ensure_cache_dir()
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
        os.replace(tmp_path, path)
    except OSError:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@app.get("/api/providers-with-contracts")
def providers_with_contracts():
    """Return providers joined with contracts (by pubkey) and service names from cache."""
    providers_raw = _load_cached("active_providers")
    contracts_raw = _load_cached("provider-contracts")
    services_raw = _load_cached("service-types")
    provider_services_raw = _load_cached("provider-services")

    providers_list = providers_raw.get("providers") or []
    if not isinstance(providers_list, list):
        providers_list = []
    # filter to active providers (status == 1 or "1")
    providers_list = [p for p in providers_list if isinstance(p, dict) and (p.get("status") == 1 or p.get("status") == "1")]
    contracts_list = contracts_raw.get("data", {}).get("contracts") or contracts_raw.get("data", {}).get("contract") or []
    if not isinstance(contracts_list, list):
        contracts_list = []
    services_list = []
    if isinstance(services_raw.get("data"), list):
        services_list = services_raw.get("data")
    elif isinstance(services_raw.get("data"), dict):
        services_list = services_raw["data"].get("services") or services_raw["data"].get("service") or services_raw["data"].get("result") or []
    if not isinstance(services_list, list):
        services_list = []

    svc_lookup: dict[str, dict[str, str]] = {}
    for s in services_list:
        if not isinstance(s, dict):
            continue
        sid = s.get("id") or s.get("service_id") or s.get("serviceID") or s.get("service")
        if sid is None:
            continue
        key = str(sid)
        slug = (s.get("name") or s.get("service") or s.get("label") or s.get("type") or key) or key
        desc = s.get("description") or s.get("desc") or s.get("label")
        display = desc or slug.replace("-", " ").strip().title()
        svc_lookup[key] = {
            "id": key,
            "name": slug,
            "slug": slug,
            "type": s.get("type") or slug,
            "description": desc,
            "display": display,
        }

    def service_info_for(val) -> dict[str, str]:
        if val is None:
            return {"id": "", "name": "", "type": ""}
        key = str(val)
        info = svc_lookup.get(key)
        if info:
            return info
        # fallback formatting: use id with dash->space, title-cased
        fallback_name = key.replace("-", " ").strip().title() if key else ""
        return {
            "id": key,
            "name": fallback_name or key,
            "slug": fallback_name or key,
            "type": "",
            "description": "",
            "display": fallback_name or key,
        }

    def service_is_active(svc: dict) -> bool:
        if not isinstance(svc, dict):
            return False
        status_val = svc.get("status")
        if status_val is None:
            return True  # default to active if missing
        if isinstance(status_val, bool):
            return bool(status_val)
        status_str = str(status_val).strip().lower()
        return status_str in ("1", "active", "online", "true", "on", "up", "running")

    # Build provider -> services lookup from provider-services cache
    prov_services_lookup: dict[str, list] = {}
    prov_services_list = []
    data_ps = provider_services_raw.get("data")
    if isinstance(data_ps, dict):
        prov_services_list = data_ps.get("providers") or data_ps.get("provider") or []
    if not isinstance(prov_services_list, list):
        prov_services_list = []
    for ps in prov_services_list:
        if not isinstance(ps, dict):
            continue
        pk = ps.get("pub_key") or ps.get("pubkey") or ps.get("pubKey")
        if not pk:
            continue
        entries = []
        if isinstance(ps.get("services"), list):
            entries = ps["services"]
        elif isinstance(ps.get("service"), list):
            entries = ps["service"]
        elif entries := [ps]:
            pass
        if pk in prov_services_lookup:
            prov_services_lookup[pk].extend(entries)
        else:
            prov_services_lookup[pk] = entries

    def contract_matches_provider(contract: dict, pubkey: str) -> bool:
        if not isinstance(contract, dict):
            return False
        cpk = (
            contract.get("provider")
            or contract.get("provider_pubkey")
            or contract.get("provider_pub_key")
            or contract.get("providerPubKey")
        )
        return cpk == pubkey

    combined = []
    for p in providers_list:
        if not isinstance(p, dict):
            continue
        pubkey = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
        if not pubkey:
            continue
        services_for_provider = prov_services_lookup.get(pubkey) or []
        services_normalized = []
        for s in services_for_provider:
            if not isinstance(s, dict) or not service_is_active(s):
                continue
            sid = s.get("service_id") or s.get("id") or s.get("service")
            status_raw = s.get("status") or p.get("provider", {}).get("status") or p.get("status")
            info = service_info_for(sid)
            services_normalized.append(
                {
                    "id": sid,
                    "name": info.get("name") or info.get("slug"),
                    "slug": info.get("slug") or info.get("name"),
                    "type": info.get("type"),
                    "description": info.get("description"),
                    "display": info.get("display") or info.get("description") or info.get("name"),
                    "metadata_uri": s.get("metadata_uri") or s.get("metadataUri"),
                    "status": status_raw,
                    "raw": s,
                }
            )
        matched_contracts = []
        for c in contracts_list:
            if not contract_matches_provider(c, pubkey):
                continue
            svc_id = c.get("service") or c.get("service_id") or c.get("serviceID")
            svc_info = service_info_for(svc_id)
            matched_contracts.append(
                {
                    "contract_id": c.get("contract_id") or c.get("id") or c.get("cid"),
                    "service_id": svc_id,
                    "service_info": svc_info,
                    "subscriber": c.get("subscriber"),
                    "provider": c.get("provider"),
                    "status": c.get("status"),
                }
            )
        combined.append(
            {
                "pubkey": pubkey,
                "provider": p.get("provider") or p,
                "metadata_uri": p.get("metadata_uri"),
                "metadata": p.get("metadata"),
                "metadata_error": p.get("metadata_error"),
                "status": p.get("status"),
                "services": services_normalized,
                "contracts": matched_contracts,
            }
        )

    return jsonify({"providers": combined, "counts": {"providers": len(combined), "contracts": len(contracts_list), "services": len(services_list)}})


@app.post("/api/cache-refresh")
def cache_refresh():
    """Trigger a one-time cache fetch for providers, contracts, and services."""
    try:
        cache_ensure_cache_dir()
        commands = cache_build_commands()
        results = cache_fetch_once(commands, record_status=True)
        # Include derived active caches in the response for UI counts
        providers_cache = _load_cached("active_providers")
        if providers_cache:
            results["active_providers"] = {"data": providers_cache, "exit_code": 0}
        active_services_cache = _load_cached("active_services")
        if active_services_cache:
            results["active_services"] = {"data": active_services_cache, "exit_code": 0}
        active_service_types_cache = _load_cached("active_service_types")
        if active_service_types_cache:
            results["active_service_types"] = {"data": active_service_types_cache, "exit_code": 0}
        subscribers_cache = _load_cached("subscribers")
        if subscribers_cache:
            results["subscribers"] = {"data": subscribers_cache, "exit_code": 0}
        # refresh subscriber_info.json as part of refresh
        try:
            height, h_err = _latest_block_height()
            info_payload = {
                "fetched_at": _timestamp(),
                "arkeod_node": ARKEOD_NODE,
                "latest_block": height,
            }
            raw_pubkey, bech32_pubkey, pub_err = derive_pubkeys(KEY_NAME, KEYRING)
            addr, addr_err = derive_address(KEY_NAME, KEYRING)
            info_payload["pubkey"] = {"raw": raw_pubkey, "bech32": bech32_pubkey}
            info_payload["address"] = addr
            if pub_err:
                info_payload["pubkey_error"] = pub_err
            if addr_err:
                info_payload["address_error"] = addr_err
            if h_err:
                info_payload["latest_block_error"] = h_err
            _write_json_atomic(SUBSCRIBER_INFO_FILE, info_payload)
        except Exception:
            pass
        return jsonify({"status": "ok", "results": results})
    except Exception as e:
        return jsonify({"error": "cache_refresh_failed", "detail": str(e)}), 500


@app.get("/api/cache-status")
def cache_status():
    """Return the current cache sync status."""
    payload = {"in_progress": False}
    try:
        if os.path.isfile(CACHE_STATUS_FILE):
            with open(CACHE_STATUS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                payload.update(data)
    except Exception:
        pass
    return jsonify(payload)


@app.get("/api/cache-counts")
def cache_counts():
    """Return counts derived from cached files (active providers/services/contracts/chains)."""
    def _safe_load(name: str):
        try:
            return _load_cached(name) or {}
        except Exception:
            return {}

    active_providers = _safe_load("active_providers")
    active_services = _safe_load("active_services")
    contracts = _safe_load("provider-contracts")
    service_types = _safe_load("service-types")
    subscribers_cache = _safe_load("subscribers")

    counts = {
        "active_providers": 0,
        "active_services": 0,
        "contracts": 0,
        "supported_chains": 0,
        "subscribers": 0,
    }

    providers_list = active_providers.get("providers") or []
    if isinstance(providers_list, list):
        counts["active_providers"] = len(providers_list)

    active_services_list = active_services.get("active_services") or []
    if isinstance(active_services_list, list):
        counts["active_services"] = len(active_services_list)

    contracts_list = contracts.get("data", {}).get("contracts") or contracts.get("data", {}).get("contract") or []
    if isinstance(contracts_list, list):
        counts["contracts"] = len(contracts_list)

    services_list = []
    data_st = service_types.get("data")
    if isinstance(data_st, list):
        services_list = data_st
    elif isinstance(data_st, dict):
        services_list = data_st.get("services") or data_st.get("service") or data_st.get("result") or []
    if isinstance(services_list, list):
        counts["supported_chains"] = len(services_list)

    subscribers_list = subscribers_cache.get("subscribers") or []
    if isinstance(subscribers_list, list):
        counts["subscribers"] = len(subscribers_list)

    return jsonify(counts)


def _sanitize_listener_payload(payload: dict, existing_ports: set[int], current_id: str | None = None):
    """Validate listener payload and return (listener_dict, error_str_or_None)."""
    target = ""  # notes removed
    status = (payload.get("status") or "").strip() or "inactive"
    service_id_val = payload.get("service_id") or payload.get("service")
    service_id = str(service_id_val).strip() if service_id_val not in (None, "") else ""
    provider_pubkey = (payload.get("provider_pubkey") or "").strip()
    sentinel_url = (payload.get("sentinel_url") or "").strip()
    whitelist_ips = (payload.get("whitelist_ips") or "").strip()
    port_val = payload.get("port")
    port: int | None = None
    if port_val not in (None, ""):
        try:
            port = int(port_val)
        except (TypeError, ValueError):
            return None, "port must be an integer"
        if port < LISTENER_PORT_START or port > LISTENER_PORT_END:
            return None, f"port must be between {LISTENER_PORT_START} and {LISTENER_PORT_END}"
        if port in existing_ports:
            return None, f"port {port} already in use"
    return {
        "target": target,
        "status": status,
        "port": port,
        "service_id": service_id,
        "provider_pubkey": provider_pubkey,
        "sentinel_url": sentinel_url,
        "whitelist_ips": whitelist_ips,
    }, None


@app.get("/api/listeners")
def get_listeners():
    """Return current listeners registry."""
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    listeners = listeners if isinstance(listeners, list) else []
    used_ports = _collect_used_ports(listeners)
    next_port = _next_available_port(used_ports)
    return jsonify({
        "listeners": listeners,
        "port_range": [LISTENER_PORT_START, LISTENER_PORT_END],
        "next_port": next_port,
    })


@app.post("/api/listeners")
def create_listener():
    payload = request.get_json(silent=True) or {}
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    used_ports = _collect_used_ports(listeners)
    clean, err = _sanitize_listener_payload(payload, used_ports)
    if err:
        return jsonify({"error": err}), 400
    # prevent duplicate service_id
    existing_service_ids = {
        str(l.get("service_id")) for l in listeners if isinstance(l, dict) and l.get("service_id") not in (None, "")
    }
    if clean.get("service_id") and str(clean["service_id"]) in existing_service_ids:
        return jsonify({"error": "service_already_used"}), 400
    port = clean["port"] or _next_available_port(used_ports)
    if port is None:
        return jsonify({"error": "no ports available in configured range"}), 400
    now = _timestamp()
    svc_lookup = _load_active_service_types_lookup()
    svc_meta = svc_lookup.get(clean.get("service_id") or "", {})
    best = _top_active_services_by_payg(clean.get("service_id") or "", limit=5)
    provider_pk = (clean.get("provider_pubkey") or "").strip() or None
    provider_mon = None
    sentinel_url = (clean.get("sentinel_url") or "").strip() or None
    if best and not provider_pk:
        provider_pk = best[0].get("provider_pubkey")
        provider_mon = best[0].get("provider_moniker")
        mu = best[0].get("metadata_uri")
        if _is_external(mu):
            sentinel_url = _sentinel_from_metadata_uri(mu)
    if not sentinel_url:
        sentinel_url = SENTINEL_URI_DEFAULT
    new_entry = {
        "id": payload.get("id") or str(int(time.time() * 1000)),
        "target": "",
        "status": clean["status"],
        "port": port,
        "service_id": clean.get("service_id") or "",
        "service_name": svc_meta.get("service_name", ""),
        "service_description": svc_meta.get("service_description", ""),
        "provider_pubkey": provider_pk,
        "provider_moniker": provider_mon,
        "sentinel_url": sentinel_url,
        "top_services": best,
        "whitelist_ips": clean.get("whitelist_ips") or "",
        "created_at": now,
        "updated_at": now,
    }
    ok, err = _ensure_listener_runtime(new_entry, previous_port=None, previous_status=None, previous_entry=None)
    if not ok:
        return jsonify({"error": err or "failed to start listener"}), 500
    listeners.append(new_entry)
    listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = listeners
    data["fetched_at"] = now
    _write_listeners(data)
    return jsonify({"listener": new_entry, "next_port": _next_available_port(used_ports | {port})})


@app.put("/api/listeners/<listener_id>")
def update_listener(listener_id: str):
    payload = request.get_json(silent=True) or {}
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    payload_top_services = payload.get("top_services") if isinstance(payload, dict) else None
    custom_top = payload_top_services if isinstance(payload_top_services, list) else None
    existing_ports = _collect_used_ports(listeners, skip_id=listener_id)
    clean, err = _sanitize_listener_payload(payload, existing_ports, current_id=listener_id)
    if err:
        return jsonify({"error": err}), 400
    # prevent duplicate service_id (excluding current)
    existing_service_ids = {
        str(l.get("service_id"))
        for l in listeners
        if isinstance(l, dict) and str(l.get("id")) != str(listener_id) and l.get("service_id") not in (None, "")
    }
    if clean.get("service_id") and str(clean["service_id"]) in existing_service_ids:
        return jsonify({"error": "service_already_used"}), 400
    svc_lookup = _load_active_service_types_lookup()
    svc_meta = svc_lookup.get(clean.get("service_id") or "", {})
    best = _top_active_services_by_payg(clean.get("service_id") or "", limit=5)
    updated = None
    old_snapshot = None
    provider_pk = (clean.get("provider_pubkey") or "").strip() or None
    provider_mon = None
    sentinel_url = (clean.get("sentinel_url") or "").strip() or None
    if best and not provider_pk:
        provider_pk = best[0].get("provider_pubkey")
        provider_mon = best[0].get("provider_moniker")
        mu = best[0].get("metadata_uri")
        if _is_external(mu):
            sentinel_url = _sentinel_from_metadata_uri(mu)
    if not sentinel_url:
        sentinel_url = SENTINEL_URI_DEFAULT
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if str(l.get("id")) != str(listener_id):
            continue
        old_snapshot = dict(l)
        if clean["port"] is not None:
            l["port"] = clean["port"]
        l["target"] = ""
        l["status"] = clean["status"]
        l["service_id"] = clean.get("service_id") or ""
        l["service_name"] = svc_meta.get("service_name", "")
        l["service_description"] = svc_meta.get("service_description", "")
        # top services ordering: use custom if provided, else keep existing unless service changed or empty
        existing_top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
        new_top = custom_top if custom_top is not None else existing_top
        if (str(l.get("service_id")) != str(clean.get("service_id") or "")) or not new_top:
            new_top = best
        l["top_services"] = new_top
        # derive provider/sentinel from top services primary (new order wins)
        if new_top:
            primary = new_top[0]
            if isinstance(primary, dict):
                provider_pk = primary.get("provider_pubkey") or provider_pk
                provider_mon = primary.get("provider_moniker") or provider_mon
                mu = primary.get("metadata_uri")
                if _is_external(mu):
                    sentinel_url = _sentinel_from_metadata_uri(mu)
        l["provider_pubkey"] = provider_pk or l.get("provider_pubkey")
        l["provider_moniker"] = provider_mon or l.get("provider_moniker")
        l["sentinel_url"] = sentinel_url or l.get("sentinel_url")
        l["whitelist_ips"] = clean.get("whitelist_ips") if clean.get("whitelist_ips") is not None else l.get("whitelist_ips", "")
        l["updated_at"] = _timestamp()
        updated = l
        break
    if updated is None:
        return jsonify({"error": "listener not found"}), 404
    old_port = None
    old_status = None
    if old_snapshot:
        try:
            old_port = int(old_snapshot.get("port"))
        except Exception:
            old_port = old_snapshot.get("port")
        old_status = old_snapshot.get("status")
    ok, err = _ensure_listener_runtime(updated, previous_port=old_port, previous_status=old_status, previous_entry=old_snapshot)
    if not ok:
        if old_snapshot is not None:
            # revert the in-memory entry to its previous state to avoid persisting a broken change
            updated.clear()
            updated.update(old_snapshot)
        return jsonify({"error": err or "failed to start listener"}), 500
    listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = listeners
    _write_listeners(data)
    used_ports = existing_ports | ({updated["port"]} if isinstance(updated.get("port"), int) else set())
    return jsonify({"listener": updated, "next_port": _next_available_port(used_ports)})


@app.delete("/api/listeners/<listener_id>")
def delete_listener(listener_id: str):
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    removed_entry = None
    for l in listeners:
        if str(l.get("id")) == str(listener_id):
            removed_entry = l
            break
    new_list = [l for l in listeners if str(l.get("id")) != str(listener_id)]
    if len(new_list) == len(listeners):
        return jsonify({"error": "listener not found"}), 404
    if removed_entry:
        try:
            _stop_listener_server(int(removed_entry.get("port")))
        except Exception:
            _stop_listener_server(removed_entry.get("port"))
    new_list.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = new_list
    data["fetched_at"] = _timestamp()
    _write_listeners(data)
    used_ports = _collect_used_ports(new_list)
    return jsonify({"status": "ok", "next_port": _next_available_port(used_ports)})


@app.get("/api/active-service-types")
def get_active_service_types():
    """Return active service types cache."""
    try:
        with open(ACTIVE_SERVICE_TYPES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {"active_service_types": []}
    return jsonify(data)


@app.post("/api/listeners/<listener_id>/refresh-top-services")
def refresh_listener_top_services(listener_id: str):
    """Recompute top_services for a single listener."""
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    found = None
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if str(l.get("id")) != str(listener_id):
            continue
        found = l
        break
    if not found:
        return jsonify({"error": "listener not found"}), 404

    svc_id = found.get("service_id") or ""
    best = _top_active_services_by_payg(svc_id, limit=3)
    found["top_services"] = best
    found["updated_at"] = _timestamp()
    listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = listeners
    _write_listeners(data)
    return jsonify({"listener": found})


@app.get("/api/listeners/<listener_id>/test")
def test_listener(listener_id: str):
    """Test connectivity to a listener port (eth_blockNumber JSON-RPC)."""
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    target = None
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if str(l.get("id")) == str(listener_id):
            target = l
            break
    if not target:
        return jsonify({"error": "listener not found"}), 404
    try:
        port = int(target.get("port"))
    except Exception:
        return jsonify({"error": "invalid port"}), 400
    payload_bytes, headers, label = _test_payload_for_service(target.get("service_id"), target.get("service_name"))
    ok, resp, err = _test_listener_port(port, payload_bytes, headers)
    headers_cli = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
    cmd = (
        "curl -X POST http://127.0.0.1:"
        f"{port} {headers_cli} "
        f"--data '{payload_bytes.decode()}'"
    )
    payload = {"ok": ok, "port": port, "command": cmd}
    if label:
        payload["test"] = label
    if resp:
        payload["response"] = resp
    if err:
        payload["error"] = err
    status = 200 if ok else 500
    return jsonify(payload), status


@app.get("/api/listeners/<listener_id>/logs")
def listener_logs(listener_id: str):
    """Return tail of a listener's log file."""
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    target = None
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if str(l.get("id")) == str(listener_id):
            target = l
            break
    if not target:
        return jsonify({"error": "listener not found"}), 404
    try:
        port = int(target.get("port"))
    except Exception:
        return jsonify({"error": "invalid port"}), 400
    max_lines = request.args.get("lines")
    try:
        max_lines_int = int(max_lines) if max_lines else 200
    except Exception:
        max_lines_int = 200
    log_path = os.path.join(LOG_DIR, f"listener-{port}.log")
    text = _tail_file(log_path, max_lines_int)
    return jsonify({"port": port, "lines": max_lines_int, "log": text})


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
    target_name = str(target.get("name") or target.get("service") or "").strip()
    target_id = str(target.get("id") or target.get("service_id") or target.get("service") or "").strip()
    if not target_name and not target_id:
        return jsonify({"error": "service name or id required"}), 400
    if not target_name and target_id:
        lookup = _all_services_lookup()
        target_name = lookup.get(target_id, "")
    status_raw = str(target.get("status") or "").lower()
    should_remove = status_raw in ("0", "inactive", "offline")

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

    new_services = []
    updated = False
    for svc in existing_services:
        if not isinstance(svc, dict):
            new_services.append(svc)
            continue
        sid = str(svc.get("id")) if svc.get("id") is not None else ""
        sname = str(svc.get("name") or svc.get("service") or "")
        match = False
        if target_id and sid and target_id == sid:
            match = True
        if target_name and sname and target_name == sname:
            match = True
        if match:
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
            updated = True
        else:
            new_services.append(svc)

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
    env_keys = [
        "PROVIDER_NAME",
        "MONIKER",
        "WEBSITE",
        "DESCRIPTION",
        "LOCATION",
        "PORT",
        "SOURCE_CHAIN",
        "PROVIDER_HUB_URI",
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
    env_data = {k.lower(): os.getenv(k) for k in env_keys}
    env_file = _load_env_file(SENTINEL_ENV_PATH)
    parsed, raw = _load_sentinel_config()
    return jsonify(
        {
            "env": env_data,
            "env_file": env_file,
            "config_path": SENTINEL_CONFIG_PATH,
            "config": parsed,
            "raw": raw,
            "sentinel_uri_default": SENTINEL_URI_DEFAULT,
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
    # Keep ARKEO_REST_API_PORT in sync with PROVIDER_HUB_URI if provided
    if payload.get("provider_hub_uri"):
        _set_env("PROVIDER_HUB_URI", payload.get("provider_hub_uri"))
        _set_env("ARKEO_REST_API_PORT", payload.get("provider_hub_uri"))

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

    # Fetch open claims
    try:
        with urllib.request.urlopen(f"{sentinel_api}/open-claims", timeout=10) as resp:
            claims_raw = resp.read().decode("utf-8")
            claims = json.loads(claims_raw)
    except Exception as e:
        return jsonify({"error": "failed to fetch open claims", "detail": str(e)}), 500
    pending = [c for c in claims if isinstance(c, dict) and (not c.get("claimed"))]
    if not pending:
        return jsonify({"status": "ok", "message": "No open claims to process.", "claims_processed": 0, "results": []})

    results = []

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

    for claim in pending:
        contract_id = claim.get("contract_id")
        nonce = claim.get("nonce")
        signature = claim.get("signature")
        if contract_id is None or nonce is None or signature is None:
            results.append({"claim": claim, "error": "missing fields"})
            continue

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

        # Mark claimed on sentinel if success code=0
        code_val = tx_json.get("code") if isinstance(tx_json, dict) else None
        if code_val == 0:
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

    return jsonify({"status": "ok", "claims_processed": len(results), "results": results})


@app.post("/api/provider-totals")
def provider_totals():
    """Summarize PAYG claim spending for this provider (and optional service) over a height range."""
    body = request.get_json(silent=True) or {}
    service_filter = body.get("service") or ""
    from_h = str(body.get("from_height") or body.get("from") or 0)
    to_h = str(body.get("to_height") or body.get("to") or 999_999_999)

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
    if not provider_pubkey:
        return jsonify({"error": "failed to derive provider pubkey", "detail": out}), 500

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
            break
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
        }
    )


_bootstrap_thread = threading.Thread(target=_bootstrap_listeners_from_cache, daemon=True)
_bootstrap_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT)
