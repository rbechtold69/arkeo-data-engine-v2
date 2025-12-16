#!/usr/bin/env python3
import base64
import binascii
import json
import os
import shutil
from pathlib import Path
import secrets
import re
import shlex
import socket
import socketserver
import subprocess
import threading
import time
import traceback
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
CONFIG_DIR = os.getenv("CONFIG_DIR", "/app/config")
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
LISTENERS_FILE = os.path.join(CACHE_DIR, "listeners.json")
HOTWALLET_LOG = os.path.join(CACHE_DIR, "hotwallet_status.log")
HOTWALLET_LOG_MAX_BYTES = int(os.getenv("HOTWALLET_LOG_MAX_BYTES") or "524288")  # ~512KB cap before rotation
LISTENER_PORT_START = int(os.getenv("LISTENER_PORT_START", "62001"))
LISTENER_PORT_END = int(os.getenv("LISTENER_PORT_END", "62100"))
LISTENER_PORT_CONFIG = os.path.join(CACHE_DIR, "listener_port_config.json")
ACTIVE_SERVICE_TYPES_FILE = os.path.join(CACHE_DIR, "active_service_types.json")
SUBSCRIBER_INFO_FILE = os.path.join(CACHE_DIR, "subscriber_info.json")
LOG_DIR = os.path.join(CACHE_DIR, "logs")
ADMIN_PASSWORD_PATH = os.getenv("ADMIN_PASSWORD_PATH") or (
    os.path.join(CACHE_DIR or "/app/cache", "admin_password.txt")
)
ADMIN_SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET") or secrets.token_hex(16)
ADMIN_SESSION_NAME = os.getenv("ADMIN_SESSION_NAME") or "admin_session"
ADMIN_UI_ORIGIN = os.getenv("ADMIN_UI_ORIGIN") or "http://localhost:8079"
# token -> expiry_ts
ADMIN_SESSIONS: dict[str, float] = {}
_LISTENER_SERVERS: dict[int, dict] = {}
_LISTENER_LOCK = threading.Lock()
_PORT_FLOOR = None
HOTWALLET_LOG = os.path.join(CACHE_DIR, "logs", "hotwallet-tx.log")
AXELAR_CONFIG_CACHE = os.path.join(CONFIG_DIR, "axelar", "eth-mainnet.json")


def _load_port_floor() -> int:
    """Return the current starting port (persisted), falling back to env default."""
    global _PORT_FLOOR
    if _PORT_FLOOR is not None:
        return _PORT_FLOOR
    # 1) subscriber-settings.json
    try:
        saved = _load_subscriber_settings_file()
        if isinstance(saved, dict) and "LISTENER_PORT_START" in saved:
            val = int(saved.get("LISTENER_PORT_START"))
            if LISTENER_PORT_START <= val <= LISTENER_PORT_END:
                _PORT_FLOOR = val
                return _PORT_FLOOR
    except Exception:
        pass
    # 2) legacy listener_port_config.json (backward compatibility)
    try:
        with open(LISTENER_PORT_CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
        val = int(data.get("start_port"))
        if LISTENER_PORT_START <= val <= LISTENER_PORT_END:
            _PORT_FLOOR = val
            return _PORT_FLOOR
    except Exception:
        pass
    # 3) env/default
    _PORT_FLOOR = LISTENER_PORT_START
    return _PORT_FLOOR


def _save_port_floor(val: int):
    """Persist the starting port selection."""
    global _PORT_FLOOR
    _PORT_FLOOR = val
    # write to subscriber-settings.json
    try:
        settings = _merge_subscriber_settings()
        settings["LISTENER_PORT_START"] = val
        _write_subscriber_settings_file(settings)
    except Exception:
        pass
    # legacy file (best effort)
    try:
        Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)
        with open(LISTENER_PORT_CONFIG, "w", encoding="utf-8") as f:
            json.dump({"start_port": val}, f, indent=2)
    except Exception:
        pass

def _service_slug_for_id(service_id: str) -> str:
    """Return the service name/slug for a given service_id, if known."""
    sid = str(service_id or "").strip()
    if not sid:
        return ""
    # 1) active_service_types (derived from active_services)
    try:
        with open(ACTIVE_SERVICE_TYPES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("active_service_types") if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("service_id")) != sid:
                continue
            st = item.get("service_type") if isinstance(item.get("service_type"), dict) else {}
            name = item.get("service_name") or st.get("name") or st.get("service_name") or ""
            if name:
                return str(name).strip()
    except Exception:
        pass

    # 2) full service-types cache (supports inactive/REST services)
    try:
        svc_types_path = os.path.join(CACHE_DIR, "service-types.json")
        with open(svc_types_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        svc_data = data.get("data") if isinstance(data, dict) else {}
        items = []
        if isinstance(svc_data, list):
            items = svc_data
        elif isinstance(svc_data, dict):
            items = svc_data.get("services") or svc_data.get("service") or svc_data.get("result") or []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                sid_val = item.get("service_id") or item.get("id") or item.get("service")
                if str(sid_val) != sid:
                    continue
                name = item.get("name") or item.get("service") or ""
                if name:
                    return str(name).strip()
    except Exception:
        pass

    # 3) best-effort RPC lookup
    try:
        lookup = _all_services_lookup()
        if sid in lookup and lookup[sid]:
            return str(lookup[sid]).strip()
    except Exception:
        pass
    return ""
_NONCE_CACHE: dict[str, int] = {}
_NONCE_LOCK = threading.Lock()


def _read_persisted_nonce(listener_id: str | None, contract_id: str | int | None) -> int | None:
    """Return persisted nonce for a listener/contract from listeners.json if present."""
    if not listener_id or contract_id is None:
        return None
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return None
        cid_str = str(contract_id)
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            nc = l.get("nonce_cache")
            if isinstance(nc, dict) and cid_str in nc:
                try:
                    return int(nc[cid_str])
                except Exception:
                    return None
        return None
    except Exception:
        return None


def _persist_listener_nonce(listener_id: str | None, contract_id: str | int | None, nonce: int | None) -> None:
    """Persist the last nonce used for a contract into listeners.json."""
    if not listener_id or contract_id is None or nonce is None:
        return
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return
        cid_str = str(contract_id)
        changed = False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            nc = l.get("nonce_cache")
            if not isinstance(nc, dict):
                nc = {}
                l["nonce_cache"] = nc
            try:
                nc[cid_str] = int(nonce)
            except Exception:
                nc[cid_str] = nonce
            l["updated_at"] = _timestamp()
            changed = True
            break
        if changed:
            _write_listeners(data)
    except Exception:
        pass

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

def _strip_quotes(val: str | None) -> str:
    if not val:
        return ""
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    return val

def _safe_float(val, default: float = 0.0) -> float:
    """Convert to float, returning default on failure."""
    try:
        return float(val)
    except Exception:
        return default

def _pick_executable(name: str, candidates: list[str]) -> str | None:
    """Return the first existing executable for name or candidates."""
    found = shutil.which(name)
    if found and os.path.isfile(found):
        return found
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return None


def _append_hotwallet_log(entry: dict) -> None:
    """Append a JSONL entry to the hotwallet log (best effort)."""
    try:
        # rotate if too large
        if os.path.isfile(HOTWALLET_LOG) and os.path.getsize(HOTWALLET_LOG) > HOTWALLET_LOG_MAX_BYTES:
            try:
                backup = f"{HOTWALLET_LOG}.bak.{int(time.time())}"
                os.rename(HOTWALLET_LOG, backup)
                # keep the last 500 lines from the backup to seed the new log
                try:
                    with open(backup, "r", encoding="utf-8", errors="replace") as bf:
                        tail_lines = bf.readlines()[-500:]
                    with open(HOTWALLET_LOG, "w", encoding="utf-8") as nf:
                        nf.writelines(tail_lines)
                except Exception:
                    # fallback to empty new log
                    open(HOTWALLET_LOG, "w").close()
            except Exception:
                pass

        os.makedirs(os.path.dirname(HOTWALLET_LOG), exist_ok=True)
        with open(HOTWALLET_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False))
            f.write("\n")
    except Exception:
        pass


def _read_hotwallet_logs(limit: int = 50) -> list[dict]:
    """Return the last N log entries in chronological order (oldest first)."""
    if not os.path.isfile(HOTWALLET_LOG):
        return []
    try:
        with open(HOTWALLET_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        lines = lines[-limit:]
        out: list[dict] = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return out
    except Exception:
        return []


def _parse_tx_hash(out: str) -> str | None:
    if not out:
        return None
    # Prefer an explicit transactionHash=... if present
    m_tx = re.search(r"transactionHash\s+0x[a-fA-F0-9]{64}", out)
    if m_tx:
        m_val = re.search(r"0x[a-fA-F0-9]{64}", m_tx.group(0))
        if m_val:
            return m_val.group(0)
    # Fallback: pick the last 0x64 hex string (cast output lists blockHash first)
    matches = re.findall(r"0x[a-fA-F0-9]{64}", out)
    if matches:
        return matches[-1]
    return None


def _run_cast_with_log(cmd: list[str], label: str) -> tuple[int, str, str | None]:
    """Run cast command and return (code, output, txhash)."""
    code, out = run_list(cmd)
    txh = _parse_tx_hash(out)
    return code, out, txh


def _mask_cmd_sensitive(cmd: list[str]) -> list[str]:
    """Return a copy of cmd with sensitive args (mnemonic, rpc-url) masked."""
    if not isinstance(cmd, list):
        return cmd
    masked = []
    skip_next = False
    for i, part in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        lower = str(part).lower()
        if lower in ("--mnemonic", "--rpc-url"):
            masked.append(part)
            if i + 1 < len(cmd):
                masked.append("***")
                skip_next = True
            continue
        masked.append(part)
    return masked


def _mask_cmd_sensitive(cmd: list[str]) -> list[str]:
    """Return a copy of cmd with sensitive args (mnemonic, rpc-url) masked."""
    if not isinstance(cmd, list):
        return cmd
    masked = []
    skip_next = False
    for i, part in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        lower = str(part).lower()
        if lower in ("--mnemonic", "--rpc-url"):
            # mask value
            masked.append(part)
            if i + 1 < len(cmd):
                masked.append("***")
                skip_next = True
            continue
        masked.append(part)
    return masked


def _resolve_axelar_eth_config() -> dict:
    """
    Resolve Axelar Gateway/Gas addresses for Ethereum mainnet.
    Order: env override -> cached file -> fetch -> fallback defaults.
    """
    env_gateway = _strip_quotes(os.getenv("AXELAR_GATEWAY_ADDRESS") or "")
    env_gas = _strip_quotes(os.getenv("AXELAR_GAS_SERVICE_ADDRESS") or "")
    def _is_addr(a: str) -> bool:
        return bool(a) and a.startswith("0x") and len(a) == 42 and all(ch in "0123456789abcdefABCDEF" for ch in a[2:])
    # If both envs provided and valid, use them
    if _is_addr(env_gateway) and _is_addr(env_gas):
        return {"gateway": env_gateway, "gas_service": env_gas, "source": "env"}

    # Try cache file
    try:
        if os.path.isfile(AXELAR_CONFIG_CACHE):
            with open(AXELAR_CONFIG_CACHE, "r", encoding="utf-8") as f:
                data = json.load(f)
            gw = data.get("gateway")
            gs = data.get("gas_service")
            if _is_addr(gw) and _is_addr(gs):
                return {"gateway": gw, "gas_service": gs, "source": "cache"}
    except Exception:
        pass

    # Fetch from Axelar mainnet config
    try:
        url = "https://axelar-mainnet.s3.us-east-2.amazonaws.com/configs/mainnet-config-1.x.json"
        with urllib.request.urlopen(url, timeout=8) as resp:
            cfg = json.loads(resp.read())
        eth_cfg = (cfg.get("evm") or {}).get("Ethereum") or (cfg.get("Evm") or {}).get("Ethereum") or {}
        gw = eth_cfg.get("gateway") or eth_cfg.get("gatewayAddress") or ""
        gs = eth_cfg.get("gasService") or eth_cfg.get("gasServiceAddress") or ""
        if _is_addr(gw) and _is_addr(gs):
            os.makedirs(os.path.dirname(AXELAR_CONFIG_CACHE), exist_ok=True)
            with open(AXELAR_CONFIG_CACHE, "w", encoding="utf-8") as f:
                json.dump({"gateway": gw, "gas_service": gs, "source": "fetched"}, f, indent=2)
            return {"gateway": gw, "gas_service": gs, "source": "fetched"}
    except Exception:
        pass

    # Fallback defaults (known-good)
    fallback_gw = "0x4F4495243837681061C4743b74B3eEdf548D56A5"
    fallback_gs = "0x2d5d7d31F671F86C782533cc367F14109a082712"
    return {"gateway": fallback_gw, "gas_service": fallback_gs, "source": "fallback"}


@app.get("/api/hotwallet/logs")
def hotwallet_logs():
    """Return recent hotwallet log entries (JSONL file)."""
    try:
        limit = int(request.args.get("limit", "50"))
    except Exception:
        limit = 50
    logs = _read_hotwallet_logs(limit=limit)
    return jsonify({"logs": logs, "path": HOTWALLET_LOG})


@app.post("/api/hotwallet/log-note")
def hotwallet_log_note():
    """Allow UI to append a short note into the hotwallet log for continuity with modal status."""
    payload = request.get_json(silent=True) or {}
    msg = str(payload.get("msg") or "").strip()
    if not msg:
        return jsonify({"error": "msg required"}), 400
    # cap length to avoid abuse
    msg = msg[:500]
    _append_hotwallet_log({"action": "client_note", "msg": msg, "source": "ui"})
    return jsonify({"ok": True})


@app.post("/api/hotwallet/send-usdc")
def hotwallet_send_usdc():
    """
    Send USDC from ETH hot wallet to Osmosis via Axelar (token-only bridge).
    Flow: approve(USDC -> gateway) then gateway.sendToken("osmosis", osmo_addr, "USDC", amount).
    """
    return jsonify({"error": "USDC bridge via Gravity not yet implemented"}), 501

    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    gas_amount_val = payload.get("gas_amount_eth")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    if MIN_OSMO_BRIDGE_USDC and amt_float < MIN_OSMO_BRIDGE_USDC:
        return jsonify({"error": f"amount must be >= {MIN_OSMO_BRIDGE_USDC} USDC"}), 400
    amt_base = int(round(amt_float * (10 ** ETH_USDC_DECIMALS)))
    gas_amount_eth = _safe_float(
        gas_amount_val if gas_amount_val not in (None, "") else (os.getenv("AXELAR_GAS_AMOUNT_ETH") or AXELAR_GAS_AMOUNT_ETH),
        0.0,
    )
    if gas_amount_eth < 0:
        gas_amount_eth = 0.0
    gas_amount_wei = int(round(gas_amount_eth * 1e18)) if gas_amount_eth else 0

    if not ETH_RPC:
        return jsonify({"error": "ETH_RPC not configured"}), 400
    if not ETH_USDC_CONTRACT:
        return jsonify({"error": "USDC contract not configured"}), 400

    # Ensure wallets/addresses
    settings = _merge_subscriber_settings()
    settings, eth_err = _ensure_eth_wallet(settings)
    settings, osmo_err = _ensure_osmo_wallet(settings)
    if eth_err:
        return jsonify({"error": f"eth wallet: {eth_err}"}), 400
    if osmo_err:
        return jsonify({"error": f"osmo wallet: {osmo_err}"}), 400
    eth_addr = settings.get("ETH_ADDRESS")
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    if not eth_addr:
        return jsonify({"error": "ETH_ADDRESS missing"}), 400
    if not osmo_addr:
        return jsonify({"error": "OSMOSIS_ADDRESS missing"}), 400

    ax = _resolve_axelar_eth_config()
    gw_addr = ax.get("gateway")
    if not gw_addr:
        return jsonify({"error": "Axelar gateway not resolved"}), 500
    gs_addr = ax.get("gas_service")

    mnemonic = settings.get("ETH_MNEMONIC") or ""
    if not mnemonic:
        return jsonify({"error": "ETH_MNEMONIC missing"}), 400

    gas_tx = None
    gas_cmd: list[str] | None = None
    gas_out = ""
    if gas_amount_wei > 0:
        if not gs_addr:
            return jsonify({"error": "Axelar gas service not resolved"}), 500
        gas_cmd = [
            CAST_BIN,
            "send",
            gs_addr,
            "payNativeGasForContractCallWithToken(address,string,string,bytes,string,uint256,address)",
            eth_addr,
            "osmosis",
            osmo_addr,
            "0x",
            "USDC",
            str(amt_base),
            eth_addr,
            "--rpc-url",
            ETH_RPC,
            "--mnemonic",
            mnemonic,
            "--mnemonic-index",
            "0",
            "--value",
            str(gas_amount_wei),
        ]
        gas_code, gas_out, gas_tx = _run_cast_with_log(gas_cmd, "gas_pay")
        if gas_code != 0 or not gas_tx:
            log_entry = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "action": "send_usdc",
                "stage": "gas_pay",
                "amount_usdc": amt_float,
                "amount_base_units": amt_base,
                "gas_amount_eth": gas_amount_eth,
                "gas_amount_wei": gas_amount_wei,
                "eth_address": eth_addr,
                "osmosis_address": osmo_addr,
                "axelar_gateway": gw_addr,
                "axelar_gas_service": gs_addr,
                "status": "failed",
                "error": gas_out,
                "exit_code": gas_code,
                "cmd": _mask_cmd_sensitive(gas_cmd),
            }
            _append_hotwallet_log(log_entry)
            return jsonify({"error": "gas payment failed", "detail": gas_out}), 500

    approve_cmd = [
        CAST_BIN,
        "send",
        ETH_USDC_CONTRACT,
        "approve(address,uint256)",
        gw_addr,
        str(amt_base),
        "--rpc-url",
        ETH_RPC,
        "--mnemonic",
        mnemonic,
        "--mnemonic-index",
        "0",
    ]
    send_cmd = [
        CAST_BIN,
        "send",
        gw_addr,
        "sendToken(string,string,string,uint256)",
        "osmosis",
        osmo_addr,
        "USDC",
        str(amt_base),
        "--rpc-url",
        ETH_RPC,
        "--mnemonic",
        mnemonic,
        "--mnemonic-index",
        "0",
    ]

    approve_code, approve_out, approve_tx = _run_cast_with_log(approve_cmd, "approve")
    if approve_code != 0 or not approve_tx:
        log_entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "send_usdc",
            "stage": "approve",
            "amount_usdc": amt_float,
            "amount_base_units": amt_base,
            "eth_address": eth_addr,
            "osmosis_address": osmo_addr,
            "axelar_gateway": gw_addr,
            "axelar_gas_service": gs_addr,
            "gas_amount_eth": gas_amount_eth,
            "gas_amount_wei": gas_amount_wei,
            "gas_tx": gas_tx,
            "gas_cmd": _mask_cmd_sensitive(gas_cmd) if gas_cmd else None,
            "gas_out": gas_out,
            "status": "failed",
            "error": approve_out,
            "exit_code": approve_code,
            "cmd": _mask_cmd_sensitive(approve_cmd),
        }
        _append_hotwallet_log(log_entry)
        return jsonify({"error": "approve failed", "detail": approve_out}), 500

    send_code, send_out, send_tx = _run_cast_with_log(send_cmd, "sendToken")
    if send_code != 0 or not send_tx:
        log_entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "send_usdc",
            "stage": "sendToken",
            "amount_usdc": amt_float,
            "amount_base_units": amt_base,
            "eth_address": eth_addr,
            "osmosis_address": osmo_addr,
            "axelar_gateway": gw_addr,
            "axelar_gas_service": gs_addr,
            "gas_amount_eth": gas_amount_eth,
            "gas_amount_wei": gas_amount_wei,
            "gas_tx": gas_tx,
            "gas_cmd": _mask_cmd_sensitive(gas_cmd) if gas_cmd else None,
            "gas_out": gas_out,
            "approve_tx": approve_tx,
            "status": "failed",
            "error": send_out,
            "exit_code": send_code,
            "cmd": _mask_cmd_sensitive(send_cmd),
        }
        _append_hotwallet_log(log_entry)
        return jsonify(
            {
                "error": "sendToken failed",
                "detail": send_out,
                "approve_tx": approve_tx,
                "exit_code": send_code,
                "send_cmd": _mask_cmd_sensitive(send_cmd),
                "send_out": send_out,
            }
        ), 500

    log_entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": "send_usdc",
        "amount_usdc": amt_float,
        "amount_base_units": amt_base,
        "eth_address": eth_addr,
        "osmosis_address": osmo_addr,
        "eth_usdc_contract": ETH_USDC_CONTRACT,
        "eth_usdc_decimals": ETH_USDC_DECIMALS,
        "axelar_gateway": gw_addr,
        "axelar_source": ax.get("source"),
        "axelar_gas_service": gs_addr,
        "gas_amount_eth": gas_amount_eth,
        "gas_amount_wei": gas_amount_wei,
        "gas_tx": gas_tx,
        "gas_cmd": _mask_cmd_sensitive(gas_cmd) if gas_cmd else None,
        "gas_out": gas_out,
        "approve_tx": approve_tx,
        "send_tx": send_tx,
        "approve_cmd": _mask_cmd_sensitive(approve_cmd),
        "send_cmd": _mask_cmd_sensitive(send_cmd),
        "approve_out": approve_out,
        "send_out": send_out,
        "status": "submitted",
    }
    _append_hotwallet_log(log_entry)
    return jsonify(
        {
            "status": "submitted",
            "approve_tx": approve_tx,
            "send_tx": send_tx,
            "gas_tx": gas_tx,
            "approve_out": approve_out,
            "send_out": send_out,
            "approve_cmd": _mask_cmd_sensitive(approve_cmd),
            "send_cmd": _mask_cmd_sensitive(send_cmd),
            "gas_cmd": _mask_cmd_sensitive(gas_cmd) if gas_cmd else None,
            "gas_out": gas_out,
            "log_entry": log_entry,
        }
    )


def _fetch_axelarscan_gmp(tx_hash: str) -> dict:
    """Fetch GMP status from axelarscan (best effort)."""
    urls = [
        f"https://api.axelarscan.io/gmp?txHash={urllib.parse.quote(tx_hash)}",
        f"https://axelarscan.io/api/gmp?txHash={urllib.parse.quote(tx_hash)}",
    ]
    last_err: dict | None = None
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
                # Axelar returns a swagger descriptor when the hash is unknown; detect and convert to a clearer error.
                if isinstance(data, dict) and data.get("methods"):
                    last_err = {"error": "not_found", "detail": "tx hash not indexed on AxelarScan", "url": url}
                    continue
                return data
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8")
            except Exception:
                detail = ""
            last_err = {"error": str(e), "http_status": e.code, "detail": detail.strip(), "url": url}
            # 404/not found can happen for unindexed hashes; continue to fallback
            if e.code >= 500:
                break
        except Exception as e:
            last_err = {"error": str(e), "url": url}
            break
    return last_err or {"error": "unknown"}

def _fetch_squid_status(tx_hash: str, from_chain: str | None, to_chain: str | None) -> dict:
    """Fetch status from Squid router v2 (best effort)."""
    if not from_chain or not to_chain:
        return {"error": "missing_chain_ids"}
    try:
        url = (
            "https://v2.api.squidrouter.com/v2/status?"
            + urllib.parse.urlencode(
                {
                    "transactionId": tx_hash,
                    "fromChainId": from_chain,
                    "toChainId": to_chain,
                }
            )
        )
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")
        except Exception:
            detail = ""
        return {"error": str(e), "http_status": e.code, "detail": detail.strip()}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/hotwallet/gmp-status")
def hotwallet_gmp_status():
    """Return Axelar GMP status for a given tx hash."""
    return jsonify({"error": "GMP status unavailable; Gravity bridge pending"}), 501


@app.post("/api/hotwallet/topup-gas")
def hotwallet_topup_gas():
    """
    Top up Axelar gas for a prior sendToken tx (GMP) on Ethereum.
    Inputs: tx_hash (sendToken tx hash), gas_amount_eth (>0).
    """
    return jsonify({"error": "Axelar gas top-up disabled; Gravity bridge pending"}), 501


# ---------- Osmosis USDC -> ARKEO swap + IBC (Gravity-less path) ----------
def _osmosis_balances_raw(addr: str) -> list[dict]:
    """Return raw balances list for an Osmosis address."""
    cmd = [
        "osmosisd",
        "query",
        "bank",
        "balances",
        addr,
        "--node",
        OSMOSIS_RPC,
        "--output",
        "json",
    ]
    code, out = run_list(cmd)
    if code != 0:
        raise RuntimeError(f"osmosis balances exit={code}: {out}")
    data = json.loads(out)
    return data.get("balances") or data.get("result") or []


def _load_osmo_cache() -> dict:
    try:
        os.makedirs(os.path.dirname(OSMOSIS_DENOM_CACHE) or ".", exist_ok=True)
        if os.path.exists(OSMOSIS_DENOM_CACHE):
            with open(OSMOSIS_DENOM_CACHE, "r") as f:
                return json.load(f)
    except Exception:
        return {}
    return {}


def _save_osmo_cache(cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(OSMOSIS_DENOM_CACHE) or ".", exist_ok=True)
        with open(OSMOSIS_DENOM_CACHE, "w") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
    except Exception:
        pass


def _query_denom_trace_cached(ibc_hash: str, cache: dict) -> tuple[dict, dict, bool]:
    """Return (trace, cache, cache_updated)."""
    if not ibc_hash:
        return {}, cache, False
    if ibc_hash in cache:
        return cache.get(ibc_hash) or {}, cache, False
    try:
        cmd = [
            "osmosisd",
            "query",
            "ibc-transfer",
            "denom-trace",
            ibc_hash,
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            return {}, cache, False
        data = json.loads(out)
        trace = data.get("denom_trace") or {}
        cache[ibc_hash] = trace
        return trace, cache, True
    except Exception:
        return {}, cache, False


def _resolve_base_denom(denom: str, cache: dict) -> tuple[str, dict, bool]:
    """Return (base_denom, cache, cache_updated)."""
    if not denom:
        return "", cache, False
    if not denom.startswith("ibc/"):
        return denom, cache, False
    ibc_hash = denom.split("/", 1)[1] if "/" in denom else ""
    trace, cache, updated = _query_denom_trace_cached(ibc_hash, cache)
    base = trace.get("base_denom") or denom
    return base, cache, updated


def _query_all_denom_metadata() -> list[dict]:
    try:
        cmd = [
            "osmosisd",
            "query",
            "bank",
            "denom-metadata",
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            return []
        data = json.loads(out)
        return data.get("metadatas") or []
    except Exception:
        return []


def _build_metadata_index(metadatas: list[dict]) -> dict:
    """base_denom -> (symbol, decimals)"""
    idx: dict[str, tuple[str, int]] = {}
    for md in metadatas:
        base = md.get("base")
        display = md.get("display")
        denom_units = md.get("denom_units") or []
        decimals = None
        for du in denom_units:
            if du.get("denom") == display:
                try:
                    decimals = int(du.get("exponent", 0))
                except Exception:
                    decimals = 0
                break
        if decimals is None and denom_units:
            try:
                decimals = max(int(du.get("exponent", 0)) for du in denom_units)
            except Exception:
                decimals = None
        if base and display and decimals is not None:
            idx[base] = (str(display).upper(), int(decimals))
    return idx


def _heuristic_symbol_and_decimals(base_denom: str | None, denom: str) -> tuple[str | None, int | None]:
    if base_denom:
        b = base_denom.lower()
        if b == "uosmo":
            return "OSMO", 6
        if b in ("uusdc", "usdc"):
            return "USDC", 6
        if b in ("uarkeo", "arkeo"):
            return "ARKEO", 8
        if b.startswith("u") and len(b) > 1:
            return b[1:].upper(), 6
        return b.upper(), None
    if denom.lower() == "uosmo":
        return "OSMO", 6
    return None, None


def _resolve_osmo_assets(addr: str) -> tuple[list[dict] | None, str | None]:
    """Resolve Osmosis assets with denom-traces/metadata."""
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"
    cache = _load_osmo_cache()
    cache_updated = False
    try:
        bal_cmd = [
            "osmosisd",
            "query",
            "bank",
            "balances",
            addr,
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ]
        code, out = run_list(bal_cmd)
        if code != 0:
            return None, f"osmosis balance exit={code}: {out}"
        data = json.loads(out)
        balances = data.get("balances") or data.get("result") or []
    except Exception as e:
        return None, str(e)

    md_idx = _build_metadata_index(_query_all_denom_metadata())
    assets: list[dict] = []

    for b in balances:
        denom = b.get("denom", "")
        amt = b.get("amount", "0")
        try:
            amount_int = int(amt)
        except Exception:
            amount_int = 0
        is_ibc = denom.startswith("ibc/")
        base_denom = None
        path = None
        if is_ibc:
            ibc_hash = denom.split("/", 1)[1] if "/" in denom else ""
            trace, cache, updated = _query_denom_trace_cached(ibc_hash, cache)
            cache_updated = cache_updated or updated
            base_denom = trace.get("base_denom")
            path = trace.get("path")

        symbol = None
        decimals = None
        if base_denom and base_denom in md_idx:
            symbol, decimals = md_idx.get(base_denom) or (None, None)
        elif denom in md_idx:
            symbol, decimals = md_idx.get(denom) or (None, None)
        else:
            symbol, decimals = _heuristic_symbol_and_decimals(base_denom, denom)

        # Override known ARKEO to 8 decimals regardless of metadata quirks
        if (base_denom or "").lower() in ("uarkeo", "arkeo") or denom.lower() == "uarkeo":
            symbol = "ARKEO"
            decimals = 8

        display_amount = None
        if decimals is not None:
            display_amount = amount_int / (10 ** decimals)
        label = symbol
        if is_ibc and symbol:
            label = f"{symbol} (IBC)"

        assets.append(
            {
                "denom": denom,
                "amount": amount_int,
                "is_ibc": is_ibc,
                "base_denom": base_denom,
                "path": path,
                "symbol": symbol,
                "decimals": decimals,
                "display_amount": display_amount,
                "label": label or denom,
            }
        )

    if cache_updated:
        _save_osmo_cache(cache)

    return assets, None


def _resolve_osmo_denoms(addr: str) -> tuple[dict, str | None]:
    """Resolve and cache USDC/ARKEO Osmosis denoms from balances."""
    assets, err = _resolve_osmo_assets(addr)
    if err:
        return {}, err
    settings = _merge_subscriber_settings()
    usdc_denom = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    arkeo_denom = settings.get("ARKEO_OSMO_DENOM") or os.getenv("ARKEO_OSMO_DENOM") or ""
    usdc_best_amt = 0
    arkeo_best_amt = 0

    for a in assets or []:
        denom = a.get("denom") or ""
        base = (a.get("base_denom") or denom or "").lower()
        amt = int(a.get("amount") or 0)
        if "usdc" in base and amt >= usdc_best_amt:
            usdc_best_amt = amt
            usdc_denom = denom
        if "arkeo" in base and amt >= arkeo_best_amt:
            arkeo_best_amt = amt
            arkeo_denom = denom

    if usdc_denom or arkeo_denom:
        try:
            _write_bridge_denoms(usdc_denom, arkeo_denom)
        except Exception:
            pass

    return {"usdc_denom": usdc_denom, "arkeo_denom": arkeo_denom, "assets": assets}, None


def _osmosis_price_estimate() -> tuple[dict | None, str | None]:
    """Estimate spot price ARKEO per USDC from pool 2977 reserves."""
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"
    pool_state, err = _pool_2977_state()
    if err or not pool_state:
        return None, err or "pool unavailable"
    usdc_amt = pool_state.get("reserve_usdc") or 0
    arkeo_amt = pool_state.get("reserve_arkeo") or 0
    if not usdc_amt or not arkeo_amt or usdc_amt <= 0:
        return None, "unable to derive reserves for USDC/ARKEO"
    price_arkeo_per_usdc = (arkeo_amt / 1e8) / (usdc_amt / 1e6)
    price_usdc_per_arkeo = (usdc_amt / 1e6) / (arkeo_amt / 1e8) if arkeo_amt > 0 else None
    return (
        {
            "pool_id": "2977",
            "price_arkeo_per_usdc": price_arkeo_per_usdc,
            "price_usdc_per_arkeo": price_usdc_per_arkeo,
            "usdc_denom": pool_state.get("usdc_denom"),
            "arkeo_denom": pool_state.get("arkeo_denom"),
            "reserve_usdc": usdc_amt,
            "reserve_arkeo": arkeo_amt,
        },
        None,
    )


def _discover_osmo_to_arkeo_channel() -> str | None:
    """Best-effort discovery of transfer channel from Osmosis to Arkeo."""
    if not OSMOSIS_RPC:
        return None
    try:
        cmd = [
            "osmosisd",
            "query",
            "ibc",
            "channel",
            "channels",
            "--node",
            OSMOSIS_RPC,
            "--limit",
            "2000",
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            return None
        data = json.loads(out)
        chans = data.get("channels") or []
        for ch in chans:
            if ch.get("port_id") != "transfer":
                continue
            cparty = ch.get("counterparty") or {}
            if cparty.get("port_id") != "transfer":
                continue
            chan_id = ch.get("channel_id")
            if chan_id:
                return chan_id
    except Exception:
        return None
    return None

def _pool_2977_state() -> tuple[dict | None, str | None]:
    """Return reserves and denoms for pool 2977 (USDC/ARKEO)."""
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"
    cache = _load_osmo_cache()
    cache_updated = False
    try:
        cmd = [
            "osmosisd",
            "query",
            "gamm",
            "pool",
            "2977",
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            return None, f"pool query exit={code}: {out}"
        data = json.loads(out)
        pool = data.get("pool") or {}
        assets = pool.get("pool_assets") or pool.get("assets") or []
        swap_fee_str = pool.get("pool_params", {}).get("swap_fee") or pool.get("swap_fee") or "0"
    except Exception as e:
        return None, str(e)

    usdc_amt = None
    arkeo_amt = None
    usdc_denom = None
    arkeo_denom = None

    for a in assets:
        token = a.get("token") or a.get("asset") or {}
        denom = token.get("denom") or ""
        amt_raw = token.get("amount") or "0"
        try:
            amt_int = int(amt_raw)
        except Exception:
            amt_int = 0
        base, cache, updated = _resolve_base_denom(denom, cache)
        cache_updated = cache_updated or updated
        b_lower = base.lower()
        if "usdc" in b_lower and usdc_amt is None:
            usdc_amt = amt_int
            usdc_denom = denom
        elif "arkeo" in b_lower and arkeo_amt is None:
            arkeo_amt = amt_int
            arkeo_denom = denom

    if cache_updated:
        _save_osmo_cache(cache)

    try:
        swap_fee = float(swap_fee_str)
    except Exception:
        swap_fee = 0.0

    if usdc_amt is None or arkeo_amt is None:
        return None, "unable to derive pool reserves"

    return (
        {
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "reserve_usdc": usdc_amt,
            "reserve_arkeo": arkeo_amt,
            "swap_fee": swap_fee,
        },
        None,
    )


def _osmosis_quote_usdc_to_arkeo(amount_float: float) -> tuple[dict | None, str | None]:
    """Quote ARKEO out for a given USDC in (pool 2977)."""
    if amount_float <= 0:
        return None, "amount must be > 0"
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"

    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return None, err
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    balances = []
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances = []

    # Resolve denoms
    usdc_denom = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    if not usdc_denom:
        usdc_denom, _ = _pick_usdc_osmo_denom(balances)
    arkeo_denom = _discover_arkeo_osmo_denom(balances)
    if not arkeo_denom:
        return None, "ARKEO denom on Osmosis not found"
    if not usdc_denom:
        return None, "USDC denom on Osmosis not found"

    amt_in_base = int(round(amount_float * 1_000_000))
    if amt_in_base <= 0:
        return None, "amount too small"

    # Try gamm first (older binaries), then poolmanager variants as fallback
    quote_cmds = [
        [
            "osmosisd",
            "query",
            "gamm",
            "estimate-swap-exact-amount-in",
            "--pool-id",
            "2977",
            "--token-in",
            f"{amt_in_base}{usdc_denom}",
            "--token-out-denom",
            arkeo_denom,
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ],
        [
            "osmosisd",
            "query",
            "poolmanager",
            "estimate-swap-exact-amount-in",
            "2977",
            f"{amt_in_base}{usdc_denom}",
            arkeo_denom,
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ],
        [
            "osmosisd",
            "query",
            "poolmanager",
            "estimate-swap-exact-amount-in",
            f"{amt_in_base}{usdc_denom}",
            arkeo_denom,
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ],
    ]
    code = 1
    out = ""
    for cmd in quote_cmds:
        code, out = run_list(cmd)
        if code == 0:
            break
    if code != 0:
        # Fallback: compute using pool reserves if available
        pool_state, pool_err = _pool_2977_state()
        if pool_err or not pool_state:
            return None, f"quote failed exit={code}: {out}"
        usdc_res = pool_state.get("reserve_usdc") or 0
        arkeo_res = pool_state.get("reserve_arkeo") or 0
        swap_fee = pool_state.get("swap_fee") or 0.0
        fee_adj_in = amt_in_base * (1 - swap_fee)
        out_base = int((fee_adj_in * arkeo_res) / (usdc_res + fee_adj_in)) if (usdc_res + fee_adj_in) > 0 else 0
        min_out_base = max(1, int(out_base * (1 - (DEFAULT_SLIPPAGE_BPS / 10_000.0))))
        return (
            {
                "amount_in": amount_float,
                "amount_in_base": amt_in_base,
                "amount_out": out_base / 1e8,
                "amount_out_base": out_base,
                "min_amount_out": min_out_base / 1e8,
                "min_amount_out_base": min_out_base,
                "slippage_bps": DEFAULT_SLIPPAGE_BPS,
                "usdc_denom": usdc_denom,
                "arkeo_denom": arkeo_denom,
                "pool_id": "2977",
                "swap_fee": swap_fee,
                "mode": "computed",
            },
            None,
        )
    try:
        data = json.loads(out)
    except Exception:
        return None, "quote parse error"
    # Support different keys
    out_str = (
        data.get("token_out_amount")
        or data.get("amount_out")
        or data.get("amount")
        or data.get("token_out")
        or ""
    )
    try:
        out_base = int(out_str)
    except Exception:
        return None, f"quote invalid amount: {out_str}"

    min_out_base = max(1, int(out_base * (1 - (DEFAULT_SLIPPAGE_BPS / 10_000.0))))
    return (
        {
            "amount_in": amount_float,
            "amount_in_base": amt_in_base,
            "amount_out": out_base / 1e8,  # ARKEO has 8 decimals
            "amount_out_base": out_base,
            "min_amount_out": min_out_base / 1e8,
            "min_amount_out_base": min_out_base,
            "slippage_bps": DEFAULT_SLIPPAGE_BPS,
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "pool_id": "2977",
        },
        None,
    )


def _osmosis_quote_arkeo_to_usdc(amount_float: float) -> tuple[dict | None, str | None]:
    """Quote USDC out for a given ARKEO in (pool 2977, reverse direction)."""
    if amount_float <= 0:
        return None, "amount must be > 0"
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"

    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return None, err
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    balances = []
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances = []

    usdc_denom = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    if not usdc_denom:
        usdc_denom, _ = _pick_usdc_osmo_denom(balances)
    arkeo_denom = _discover_arkeo_osmo_denom(balances)
    if not arkeo_denom:
        return None, "ARKEO denom on Osmosis not found"
    if not usdc_denom:
        return None, "USDC denom on Osmosis not found"

    amt_in_base = int(round(amount_float * 100_000_000))  # ARKEO 8 decimals
    if amt_in_base <= 0:
        return None, "amount too small"

    # Compute directly from pool reserves to avoid CLI flag differences
    pool_state, pool_err = _pool_2977_state()
    if pool_err or not pool_state:
        return None, pool_err or "pool unavailable"
    usdc_res = pool_state.get("reserve_usdc") or 0
    arkeo_res = pool_state.get("reserve_arkeo") or 0
    if usdc_res <= 0 or arkeo_res <= 0:
        return None, "pool reserves unavailable"
    swap_fee = pool_state.get("swap_fee") or 0.003  # default if missing
    fee_adj_in = amt_in_base * (1 - swap_fee)
    out_base = int((fee_adj_in * usdc_res) / (arkeo_res + fee_adj_in)) if (arkeo_res + fee_adj_in) > 0 else 0
    if out_base <= 0:
        return None, "quote returned zero"
    min_out_base = max(1, int(out_base * (1 - (DEFAULT_SLIPPAGE_BPS / 10_000.0))))
    return (
        {
            "amount_in": amount_float,
            "amount_in_base": amt_in_base,
            "amount_out": out_base / 1e6,  # USDC 6 decimals
            "amount_out_base": out_base,
            "min_amount_out": min_out_base / 1e6,
            "min_amount_out_base": min_out_base,
            "slippage_bps": DEFAULT_SLIPPAGE_BPS,
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "pool_id": "2977",
            "swap_fee": swap_fee,
            "mode": "computed",
        },
        None,
    )

def _pool_contains_denoms(pool: dict, denom_a: str, denom_b: str) -> bool:
    assets = (pool.get("pool") or {}).get("pool_assets") or (pool.get("pool_assets") or [])
    found_a = False
    found_b = False
    for pa in assets:
        token = pa.get("token") if isinstance(pa, dict) else {}
        d = token.get("denom", "")
        if d == denom_a:
            found_a = True
        if d == denom_b:
            found_b = True
    return found_a and found_b


def _pick_best_usdc_osmo_pool(usdc_denom: str) -> tuple[str | None, dict | None]:
    """Pick best USDC-uosmo pool by liquidity score (usdc*osmo), filter dust/high-fee. Returns (pool_id, meta)."""
    if not OSMOSIS_RPC or not usdc_denom:
        return None, None
    try:
        code, out = run_list(
            [
                "osmosisd",
                "query",
                "poolmanager",
                "all-pools",
                "--node",
                OSMOSIS_RPC,
                "--output",
                "json",
            ]
        )
        if code != 0:
            return None, None
        data = json.loads(out)
        pools = data.get("pools") or []
        best = None
        best_meta = None
        for p in pools:
            try:
                if not _pool_contains_denoms(p, usdc_denom, "uosmo"):
                    continue
                assets = (p.get("pool") or {}).get("pool_assets") or (p.get("pool_assets") or [])
                usdc_res = 0
                osmo_res = 0
                for pa in assets:
                    token = pa.get("token") if isinstance(pa, dict) else {}
                    d = token.get("denom", "")
                    amt = token.get("amount", "0")
                    try:
                        amt_int = int(amt)
                    except Exception:
                        amt_int = 0
                    if d == usdc_denom:
                        usdc_res = amt_int
                    elif d == "uosmo":
                        osmo_res = amt_int
                # filter dust: require >= 100 USDC equivalent
                if usdc_res < 100 * 1_000_000:
                    continue
                # fee
                fee = 0.0
                try:
                    fee_raw = ((p.get("pool") or {}).get("pool_params") or {}).get("swap_fee")
                    if fee_raw is not None:
                        fee = float(fee_raw)
                except Exception:
                    fee = 0.0
                if fee > 0.01:
                    continue
                score = usdc_res * osmo_res
                pid = str(p.get("id") or (p.get("pool") or {}).get("id") or "")
                if not pid:
                    continue
                if best is None or score > best:
                    best = score
                    best_meta = {"pool_id": pid, "usdc_res": usdc_res, "osmo_res": osmo_res, "fee": fee}
            except Exception:
                continue
        if best_meta:
            try:
                _append_hotwallet_log(
                    {
                        "action": "select_usdc_osmo_pool",
                        "pool_id": best_meta.get("pool_id"),
                        "usdc_res": best_meta.get("usdc_res"),
                        "osmo_res": best_meta.get("osmo_res"),
                        "fee": best_meta.get("fee"),
                        "score": best,
                    }
                )
            except Exception:
                pass
            return str(best_meta.get("pool_id")), best_meta
    except Exception:
        return None, None
    return None, None



def _osmosis_quote_usdc_to_osmo(amount_float: float) -> tuple[dict | None, str | None]:
    """Quote OSMO out for a given USDC in using pool 678 (single hop)."""
    if amount_float <= 0:
        return None, "amount must be > 0"
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"

    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return None, err
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    balances = []
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances = []

    usdc_denom = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    if not usdc_denom:
        usdc_denom, _ = _pick_usdc_osmo_denom(balances)
    if not usdc_denom:
        return None, "USDC denom on Osmosis not found"

    amt_in_base = int(round(amount_float * 1_000_000))  # USDC 6 decimals
    if amt_in_base <= 0:
        return None, "amount too small"

    # Determine best pool for USDC->OSMO
    best_pool, best_meta = _pick_best_usdc_osmo_pool(usdc_denom)
    pool_id = best_pool or USDC_OSMO_POOL_ID

    # Try CLI estimators first (poolmanager with flags, then gamm with flags)
    quote_cmds = [
        [
            "osmosisd",
            "query",
            "poolmanager",
            "estimate-swap-exact-amount-in",
            "--swap-route-pool-ids",
            str(pool_id),
            "--swap-route-denoms",
            "uosmo",
            "--token-in",
            f"{amt_in_base}{usdc_denom}",
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ],
        [
            "osmosisd",
            "query",
            "gamm",
            "estimate-swap-exact-amount-in",
            f"{amt_in_base}{usdc_denom}",
            "1",
            "--swap-route-pool-ids",
            str(pool_id),
            "--swap-route-denoms",
            "uosmo",
            "--node",
            OSMOSIS_RPC,
            "--output",
            "json",
        ],
    ]
    code = 1
    out = ""
    for cmd in quote_cmds:
        code, out = run_list(cmd)
        if code == 0:
            break
    if code != 0:
        # Fallback: compute directly from pool reserves (constant product)
        try:
            code_pool, out_pool = run_list(
                [
                    "osmosisd",
                "query",
                "gamm",
                "pool",
                str(pool_id),
                "--node",
                OSMOSIS_RPC,
                "--output",
                "json",
            ]
            )
            if code_pool != 0:
                return None, f"pool query failed exit={code_pool}: {out_pool}"
            pool = json.loads(out_pool)
            pool_assets = (pool.get("pool") or {}).get("pool_assets") or (pool.get("pool_assets") or [])
            usdc_res = 0
            osmo_res = 0
            for pa in pool_assets:
                token = pa.get("token") if isinstance(pa, dict) else {}
                denom = token.get("denom", "")
                amt = token.get("amount", "0")
                try:
                    amt_int = int(amt)
                except Exception:
                    amt_int = 0
                if denom == usdc_denom:
                    usdc_res = amt_int
                elif denom == "uosmo":
                    osmo_res = amt_int
            swap_fee = 0.003
            try:
                swap_fee_raw = ((pool.get("pool") or {}).get("pool_params") or {}).get("swap_fee")
                if swap_fee_raw is not None:
                    swap_fee = float(swap_fee_raw)
            except Exception:
                pass
            if usdc_res <= 0 or osmo_res <= 0:
                return None, "pool reserves unavailable"
            fee_adj_in = amt_in_base * (1 - swap_fee)
            out_base = int((fee_adj_in * osmo_res) / (usdc_res + fee_adj_in)) if (usdc_res + fee_adj_in) > 0 else 0
            if out_base <= 0:
                return None, "quote returned zero"
        except Exception as e:
            return None, f"quote error: {e}"
    else:
        try:
            data = json.loads(out)
        except Exception:
            return None, "quote parse error"
        out_str = data.get("token_out_amount") or data.get("amount_out") or data.get("amount") or data.get("token_out") or ""
        try:
            out_base = int(out_str)
        except Exception:
            return None, f"quote invalid amount: {out_str}"
        swap_fee = None

    # For uosmo (6 decimals), apply slippage
    min_out_base = max(1, int(out_base * (1 - (DEFAULT_SLIPPAGE_BPS / 10_000.0))))
    return (
        {
            "amount_in": amount_float,
            "amount_in_base": amt_in_base,
            "amount_out": out_base / 1e6,
            "amount_out_base": out_base,
            "min_amount_out": min_out_base / 1e6,
            "min_amount_out_base": min_out_base,
            "slippage_bps": DEFAULT_SLIPPAGE_BPS,
            "usdc_denom": usdc_denom,
            "osmo_denom": "uosmo",
            "pool_id": str(pool_id),
            "swap_fee": swap_fee,
            "mode": "computed" if code != 0 else "cli",
            "pool_meta": best_meta or {},
        },
        None,
    )


def _pick_usdc_osmo_denom(balances: list[dict]) -> tuple[str | None, int]:
    """Pick a USDC denom from balances; returns (denom, available_base_units)."""
    best = None
    best_amt = 0
    allow = set(OSMOSIS_USDC_DENOMS or [])
    for b in balances:
        denom = b.get("denom", "")
        amt = b.get("amount", "0")
        try:
            amt_int = int(amt)
        except Exception:
            continue
        d_lower = denom.lower()
        if allow and denom in allow:
            if amt_int > best_amt:
                best = denom
                best_amt = amt_int
            continue
        if "usdc" in d_lower:
            if amt_int > best_amt:
                best = denom
                best_amt = amt_int
    return best, best_amt


def _discover_arkeo_osmo_denom(balances: list[dict]) -> str | None:
    """Try to discover wrapped ARKEO denom on Osmosis."""
    settings = _merge_subscriber_settings()
    cached = settings.get("ARKEO_OSMO_DENOM") or os.getenv("ARKEO_OSMO_DENOM") or ""
    if cached:
        return cached
    for b in balances:
        denom = b.get("denom", "")
        if "arkeo" in denom.lower():
            return denom
    return None


def _write_bridge_denoms(usdc_denom: str | None, arkeo_denom: str | None):
    """Persist discovered Osmosis denoms to subscriber settings."""
    if not usdc_denom and not arkeo_denom:
        return
    settings = _merge_subscriber_settings()
    if usdc_denom:
        settings["USDC_OSMO_DENOM"] = usdc_denom
    if arkeo_denom:
        settings["ARKEO_OSMO_DENOM"] = arkeo_denom
    try:
        _write_subscriber_settings_file(settings)
    except Exception:
        pass


def _extract_txhash(out: str) -> str | None:
    """Extract txhash: <hash> from osmosisd/arkeod output (json or text)."""
    if not out:
        return None
    # JSON payload?
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            txh = data.get("txhash") or data.get("txHash")
            if txh and re.fullmatch(r"[0-9A-Fa-f]{64}", txh):
                return txh
            tx_resp = data.get("tx_response") or {}
            txh = tx_resp.get("txhash")
            if txh and re.fullmatch(r"[0-9A-Fa-f]{64}", txh):
                return txh
    except Exception:
        pass
    m = re.search(r"txhash:\s*([0-9A-Fa-f]{64})", out)
    return m.group(1) if m else None


def _query_osmo_tx(txhash: str, attempts: int = 5, sleep_s: float = 2.0) -> tuple[bool, dict | None]:
    """Poll osmosisd for a txhash; returns (found, tx_response dict or None)."""
    if not txhash:
        return False, None
    cmd = [
        "osmosisd",
        "query",
        "tx",
        txhash,
        "--node",
        OSMOSIS_RPC,
        "-o",
        "json",
    ]
    for _ in range(max(1, attempts)):
        code, out = run_list(cmd)
        if code == 0 and out:
            try:
                data = json.loads(out)
                tx_resp = data.get("tx_response") if isinstance(data, dict) else None
                return True, tx_resp or data
            except Exception:
                return False, None
        time.sleep(sleep_s)
    return False, None


def _parse_send_packet(data: dict) -> dict | None:
    """Parse send_packet event (packet sequence + channels) from an osmosisd tx JSON."""
    if not isinstance(data, dict):
        return None
    logs = []
    if "logs" in data:
        logs = data.get("logs") or []
    elif "tx_response" in data:
        logs = data.get("tx_response", {}).get("logs") or []
    for log in logs:
        events = log.get("events") or []
        for ev in events:
            if ev.get("type") != "send_packet":
                continue
            attrs = {a.get("key"): a.get("value") for a in ev.get("attributes") or []}
            seq = attrs.get("packet_sequence")
            src_ch = attrs.get("packet_src_channel")
            dst_ch = attrs.get("packet_dst_channel")
            if seq and src_ch and dst_ch:
                return {
                    "packet_sequence": seq,
                    "src_channel": src_ch,
                    "dst_channel": dst_ch,
                    "src_port": attrs.get("packet_src_port"),
                    "dst_port": attrs.get("packet_dst_port"),
                }
    return None


def _wait_for_osmo_balance_increase(addr: str, denom: str, base: int, attempts: int = 12, sleep_s: int = 5) -> tuple[bool, int]:
    """Poll Osmosis balance until denom increases by at least base units; returns (ok, final_amt)."""
    try:
        start_balances = _osmosis_balances_raw(addr)
        start_amt = 0
        for b in start_balances:
            if b.get("denom") == denom:
                try:
                    start_amt = int(b.get("amount", "0"))
                except Exception:
                    start_amt = 0
        last_amt = start_amt
        for _ in range(attempts):
            time.sleep(sleep_s)
            bals = _osmosis_balances_raw(addr)
            for b in bals:
                if b.get("denom") == denom:
                    try:
                        amt = int(b.get("amount", "0"))
                    except Exception:
                        amt = 0
                    last_amt = amt
                    if amt >= start_amt + base:
                        return True, amt
        return False, last_amt
    except Exception:
        return False, 0


def _wait_for_osmo_tx_success(tx_hash: str, attempts: int = 10, sleep_s: int = 3) -> tuple[bool, str | None]:
    """Poll osmosisd query tx until success or failure; returns (success, raw_log_or_error)."""
    if not tx_hash:
        return False, "missing tx hash"
    last_err: str | None = None
    for _ in range(attempts):
        try:
            code, out = run_list(
                [
                    "osmosisd",
                    "query",
                    "tx",
                    tx_hash,
                    "--node",
                    OSMOSIS_RPC,
                    "--output",
                    "json",
                ]
            )
            if code != 0:
                last_err = out or f"query exit {code}"
                time.sleep(sleep_s)
                continue
            data = json.loads(out)
            tx_resp = data.get("tx_response") or data
            tx_code = tx_resp.get("code", 0)
            raw_log = tx_resp.get("raw_log", "")
            if tx_code == 0:
                return True, raw_log
            return False, raw_log or f"tx failed code={tx_code}"
        except Exception as e:
            last_err = str(e)
            time.sleep(sleep_s)
            continue
    return False, last_err or "tx not found or not included"


def _arkeo_balance(addr: str) -> tuple[int, str | None]:
    """Return (amount_base_units, error) for Arkeo wallet."""
    try:
        cmd = [
            "arkeod",
            "--home",
            ARKEOD_HOME,
            "query",
            "bank",
            "balances",
            addr,
            "--node",
            ARKEOD_NODE,
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            return 0, f"arkeod query exit={code}: {out}"
        data = json.loads(out)
        balances = data.get("balances") or data.get("result") or []
        for b in balances:
            denom = b.get("denom", "")
            if denom == "uarkeo":
                try:
                    return int(b.get("amount", "0")), None
                except Exception:
                    return 0, None
        return 0, None
    except Exception as e:
        return 0, str(e)


def _wait_for_arkeo_balance_increase(
    addr: str, expected_base: int, tolerance_bps: int = 100, attempts: int = 6, sleep_s: int = 5, start_amt: int | None = None
) -> tuple[bool, int, int]:
    """Poll Arkeo balance until uarkeo increases close to expected_base; returns (ok, final_amt, error_count)."""
    err_count = 0
    try:
        if start_amt is None:
            start_amt, err = _arkeo_balance(addr)
            if err:
                return False, 0, err_count
        last_amt = start_amt
        min_delta = max(1, int(expected_base * (1 - (tolerance_bps / 10_000.0))))
        for _ in range(attempts):
            time.sleep(sleep_s)
            amt, err2 = _arkeo_balance(addr)
            if err2:
                err_count += 1
                continue
            last_amt = amt
            if amt >= start_amt + min_delta:
                return True, amt, err_count
        return False, last_amt, err_count
    except Exception:
        err_count += 1
        return False, 0, err_count


@app.post("/api/hotwallet/convert-usdc-to-arkeo")
def hotwallet_convert_usdc_to_arkeo():
    """
    Swap Osmosis USDC -> wrapped ARKEO via pool 2977, then IBC to Arkeo hot wallet.
    Requires OSMO gas and USDC on Osmosis.
    """
    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    amt_base = int(round(amt_float * 1_000_000))

    if not OSMOSIS_RPC:
        return jsonify({"error": "OSMOSIS_RPC not configured"}), 400
    if not OSMO_TO_ARKEO_CHANNEL:
        return jsonify({"error": "OSMO_TO_ARKEO_CHANNEL not configured"}), 400

    # Ensure wallets
    settings = _merge_subscriber_settings()
    settings, osmo_err = _ensure_osmo_wallet(settings)
    settings, arkeo_err = _ensure_arkeo_mnemonic(settings)
    if osmo_err:
        return jsonify({"error": f"osmo wallet: {osmo_err}"}), 400
    if arkeo_err:
        return jsonify({"error": f"arkeo wallet: {arkeo_err}"}), 400
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    arkeo_addr, addr_err = derive_address(KEY_NAME, KEYRING)
    if addr_err:
        return jsonify({"error": f"arkeo address: {addr_err}"}), 400

    # Balances
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception as e:
        return jsonify({"error": f"osmosis balances: {e}"}), 500

    # Log start
    _append_hotwallet_log(
        {
            "action": "convert_usdc_to_arkeo",
            "stage": "start",
            "amount": amt_float,
        }
    )

    # Gas check
    osmo_gas = 0
    for b in balances:
        if b.get("denom") == "uosmo":
            try:
                osmo_gas = int(b.get("amount", "0"))
            except Exception:
                osmo_gas = 0
            break
    if osmo_gas < int(MIN_OSMO_GAS * 1_000_000):
        return jsonify({"error": f"insufficient OSMO for gas (need >= {MIN_OSMO_GAS} OSMO)"}), 400

    # USDC denom discovery
    usdc_denom_override = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    usdc_denom = usdc_denom_override
    usdc_avail = 0
    if usdc_denom:
        for b in balances:
            if b.get("denom") == usdc_denom:
                try:
                    usdc_avail = int(b.get("amount", "0"))
                except Exception:
                    usdc_avail = 0
                break
    if not usdc_denom:
        usdc_denom, usdc_avail = _pick_usdc_osmo_denom(balances)
    if not usdc_denom:
        return jsonify({"error": "USDC denom not found on Osmosis"}), 400
    if usdc_avail < amt_base:
        return jsonify({"error": f"insufficient USDC (have {usdc_avail/1e6:.6f}, need {amt_float:.6f})"}), 400

    # ARKEO denom discovery (may still be None; we'll try pool lookup)
    arkeo_denom = _discover_arkeo_osmo_denom(balances)
    if not arkeo_denom:
        return jsonify({"error": "ARKEO denom on Osmosis not found; ensure pool 2977 available"}), 400

    # Slippage: minimal out (best effort; no price estimate)
    min_out = max(1, int(amt_base * (1 - (DEFAULT_SLIPPAGE_BPS / 10_000.0))))

    # Build swap route (single-hop pool 2977). Use gamm CLI style for compatibility.
    swap_cmd = [
        "osmosisd",
        "tx",
        "gamm",
        "swap-exact-amount-in",
        f"{amt_base}{usdc_denom}",
        str(min_out),
        "--broadcast-mode",
        "sync",
        "--swap-route-pool-ids",
        "2977",
        "--swap-route-denoms",
        arkeo_denom,
        "--from",
        settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME,
        "--keyring-backend",
        "test",
        "--home",
        settings.get("OSMOSIS_HOME") or OSMOSIS_HOME,
        "--chain-id",
        "osmosis-1",
        "--node",
        OSMOSIS_RPC,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--gas-prices",
        "0.035uosmo",
        "-y",
    ]
    swap_code, swap_out = run_list(swap_cmd)
    swap_tx = _extract_txhash(swap_out)
    if swap_code != 0 or not swap_tx:
        _append_hotwallet_log(
            {
                "action": "convert_usdc_to_arkeo",
                "stage": "swap_failed",
                "amount": amt_float,
                "detail": swap_out,
            }
        )
        return jsonify(
            {
                "error": "swap failed",
                "detail": swap_out,
                "swap_cmd": swap_cmd,
                "swap_cmd": swap_cmd,
                "swap_exit": swap_code,
            }
        ), 500
    # If txhash missing (older CLI may not print), try query to confirm inclusion
    if not swap_tx:
        # best effort parse
        m = re.search(r"txhash[:\s]+([0-9A-Fa-f]{64})", swap_out)
        if m:
            swap_tx = m.group(1)
    ok, tx_log = _wait_for_osmo_tx_success(swap_tx, attempts=20, sleep_s=3)
    if not ok:
        _append_hotwallet_log(
            {
                "action": "convert_usdc_to_arkeo",
                "stage": "swap_not_included",
                "amount": amt_float,
                "swap_tx": swap_tx,
                "raw_log": tx_log,
            }
        )
        return jsonify(
            {
                "error": "swap failed on-chain or not included",
                "swap_tx": swap_tx,
                "swap_out": swap_out,
                "raw_log": tx_log,
            }
        ), 500

    # Use latest ARKEO balance for transfer (send whatever is available)
    try:
        balances_after = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances_after = balances
    arkeo_avail = 0
    for b in balances_after:
        if b.get("denom") == arkeo_denom:
            try:
                arkeo_avail = int(b.get("amount", "0"))
            except Exception:
                arkeo_avail = 0
            break
    transfer_amt = arkeo_avail
    if transfer_amt <= 0:
        _append_hotwallet_log(
            {
                "action": "convert_usdc_to_arkeo",
                "stage": "no_arkeo_post_swap",
                "swap_tx": swap_tx,
            }
        )
        return jsonify({"error": "no ARKEO available after swap", "swap_tx": swap_tx, "swap_out": swap_out}), 500

    # Snapshot Arkeo balance before IBC to avoid racing with fast arrivals
    start_arkeo_bal, start_err = _arkeo_balance(arkeo_addr)
    if start_err:
        return jsonify({"error": f"arkeo balance: {start_err}"}), 500

    ibc_cmd = [
        "osmosisd",
        "tx",
        "ibc-transfer",
        "transfer",
        "transfer",
        OSMO_TO_ARKEO_CHANNEL,
        arkeo_addr,
        f"{transfer_amt}{arkeo_denom}",
        "--from",
        settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME,
        "--keyring-backend",
        "test",
        "--home",
        settings.get("OSMOSIS_HOME") or OSMOSIS_HOME,
        "--chain-id",
        "osmosis-1",
        "--node",
        OSMOSIS_RPC,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--gas-prices",
        "0.025uosmo",
        "-y",
    ]
    ibc_code, ibc_out = run_list(ibc_cmd)
    ibc_tx = _extract_txhash(ibc_out)
    if ibc_code != 0 or not ibc_tx:
        _append_hotwallet_log(
            {
                "action": "convert_usdc_to_arkeo",
                "stage": "ibc_failed",
                "swap_tx": swap_tx,
                "detail": ibc_out,
            }
        )
        return jsonify(
            {
                "error": "ibc transfer failed",
                "detail": ibc_out,
                "swap_tx": swap_tx,
                "ibc_cmd": ibc_cmd,
                "ibc_exit": ibc_code,
            }
        ), 500

    # Briefly wait for Arkeo arrival (short window to avoid blocking UI too long)
    _append_hotwallet_log(
        {
            "action": "convert_usdc_to_arkeo",
            "stage": "waiting_arkeo",
            "swap_tx": swap_tx,
            "ibc_tx": ibc_tx,
            "expected": transfer_amt,
        }
    )
    arrived, arkeo_final, arkeo_poll_errors = _wait_for_arkeo_balance_increase(
        arkeo_addr, transfer_amt, tolerance_bps=ARRIVAL_TOLERANCE_BPS, attempts=6, sleep_s=5, start_amt=start_arkeo_bal
    )

    # Persist discovered denoms
    _write_bridge_denoms(usdc_denom, arkeo_denom)

    _append_hotwallet_log(
        {
            "action": "convert_usdc_to_arkeo",
            "stage": "submitted",
            "swap_tx": swap_tx,
            "ibc_tx": ibc_tx,
            "arkeo_start": start_arkeo_bal,
            "arkeo_final": arkeo_final,
            "arkeo_expected": transfer_amt,
            "arrival_confirmed": arrived,
            "arkeo_poll_errors": arkeo_poll_errors,
        }
    )

    return jsonify(
        {
            "status": "submitted",
            "swap_tx": swap_tx,
            "ibc_tx": ibc_tx,
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "swap_cmd": _mask_cmd_sensitive(swap_cmd),
            "ibc_cmd": _mask_cmd_sensitive(ibc_cmd),
            "arrival_confirmed": arrived,
            "arkeo_start": start_arkeo_bal,
            "arkeo_final": arkeo_final,
            "arkeo_expected": transfer_amt,
            "arrival_tolerance_bps": ARRIVAL_TOLERANCE_BPS,
            "arkeo_poll_errors": arkeo_poll_errors,
        }
    )


@app.post("/api/hotwallet/convert-arkeo-to-usdc")
def hotwallet_convert_arkeo_to_usdc():
    """
    Swap Osmosis ARKEO -> USDC via pool 2977 (reverse direction).
    Requires OSMO gas and ARKEO on Osmosis.
    """
    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    amt_base = int(round(amt_float * 100_000_000))  # ARKEO on Osmosis uses 8 decimals

    if not OSMOSIS_RPC:
        return jsonify({"error": "OSMOSIS_RPC not configured"}), 400

    # Ensure wallet
    settings = _merge_subscriber_settings()
    settings, osmo_err = _ensure_osmo_wallet(settings)
    if osmo_err:
        return jsonify({"error": f"osmo wallet: {osmo_err}"}), 400
    osmo_addr = settings.get("OSMOSIS_ADDRESS")

    # Balances
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception as e:
        return jsonify({"error": f"osmosis balances: {e}"}), 500

    # Gas check
    osmo_gas = 0
    for b in balances:
        if b.get("denom") == "uosmo":
            try:
                osmo_gas = int(b.get("amount", "0"))
            except Exception:
                osmo_gas = 0
            break
    if osmo_gas < int(MIN_OSMO_GAS * 1_000_000):
        return jsonify({"error": f"insufficient OSMO for gas (need >= {MIN_OSMO_GAS} OSMO)"}), 400

    # Denoms
    arkeo_denom = _discover_arkeo_osmo_denom(balances)
    if not arkeo_denom:
        return jsonify({"error": "ARKEO denom on Osmosis not found; ensure pool 2977 available"}), 400
    usdc_denom_override = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    usdc_denom = usdc_denom_override or ""
    usdc_avail = 0
    if usdc_denom:
        for b in balances:
            if b.get("denom") == usdc_denom:
                try:
                    usdc_avail = int(b.get("amount", "0"))
                except Exception:
                    usdc_avail = 0
                break
    if not usdc_denom:
        usdc_denom, usdc_avail = _pick_usdc_osmo_denom(balances)
    if not usdc_denom:
        return jsonify({"error": "USDC denom not found on Osmosis"}), 400

    # ARKEO available
    arkeo_avail = 0
    for b in balances:
        if b.get("denom") == arkeo_denom:
            try:
                arkeo_avail = int(b.get("amount", "0"))
            except Exception:
                arkeo_avail = 0
            break
    if arkeo_avail < amt_base:
        return jsonify({"error": f"insufficient ARKEO (have {arkeo_avail/1e8:.8f}, need {amt_float:.8f})"}), 400

    # Slippage: derive min out from quote (best-effort)
    quote, qerr = _osmosis_quote_arkeo_to_usdc(amt_float)
    if quote and quote.get("min_amount_out_base"):
        min_out = int(quote.get("min_amount_out_base"))
    else:
        min_out = 1  # fallback

    _append_hotwallet_log({"action": "convert_arkeo_to_usdc", "stage": "start", "amount": amt_float})

    swap_cmd = [
        "osmosisd",
        "tx",
        "gamm",
        "swap-exact-amount-in",
        f"{amt_base}{arkeo_denom}",
        str(min_out),
        "--broadcast-mode",
        "sync",
        "--swap-route-pool-ids",
        "2977",
        "--swap-route-denoms",
        usdc_denom,
        "--from",
        settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME,
        "--keyring-backend",
        "test",
        "--home",
        settings.get("OSMOSIS_HOME") or OSMOSIS_HOME,
        "--chain-id",
        "osmosis-1",
        "--node",
        OSMOSIS_RPC,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--gas-prices",
        "0.035uosmo",
        "-y",
    ]
    swap_code, swap_out = run_list(swap_cmd)
    swap_tx = _extract_txhash(swap_out)
    if swap_code != 0 or not swap_tx:
        _append_hotwallet_log({"action": "convert_arkeo_to_usdc", "stage": "swap_failed", "detail": swap_out})
        return jsonify({"error": "swap failed", "detail": swap_out, "swap_cmd": swap_cmd, "swap_exit": swap_code}), 500

    ok, tx_log = _wait_for_osmo_tx_success(swap_tx, attempts=10, sleep_s=3)
    if not ok:
        _append_hotwallet_log({"action": "convert_arkeo_to_usdc", "stage": "swap_not_included", "swap_tx": swap_tx, "raw_log": tx_log})
        return jsonify({"error": "swap failed on-chain or not included", "swap_tx": swap_tx, "swap_out": swap_out, "raw_log": tx_log}), 500

    # Refresh balances and report USDC gained
    try:
        balances_after = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances_after = balances
    usdc_before = usdc_avail
    usdc_after = usdc_before
    for b in balances_after:
        if b.get("denom") == usdc_denom:
            try:
                usdc_after = int(b.get("amount", "0"))
            except Exception:
                usdc_after = usdc_before
            break
    usdc_delta = usdc_after - usdc_before

    _append_hotwallet_log(
        {
            "action": "convert_arkeo_to_usdc",
            "stage": "submitted",
            "swap_tx": swap_tx,
            "usdc_denom": usdc_denom,
            "usdc_before": usdc_before,
            "usdc_after": usdc_after,
            "usdc_delta": usdc_delta,
        }
    )

    return jsonify(
        {
            "status": "submitted",
            "swap_tx": swap_tx,
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "swap_cmd": _mask_cmd_sensitive(swap_cmd),
            "usdc_before": usdc_before,
            "usdc_after": usdc_after,
            "usdc_delta": usdc_delta,
        }
    )


@app.post("/api/hotwallet/convert-usdc-to-osmo")
def hotwallet_convert_usdc_to_osmo():
    """
    Swap Osmosis USDC -> OSMO (to fund gas) via configured pool (default pool_id 678).
    """
    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    if amt_float > 2.0:
        return jsonify({"error": "amount too large for gas top-up (max 2 USDC)"}), 400
    amt_base = int(round(amt_float * 1_000_000))  # USDC 6 decimals

    if not OSMOSIS_RPC:
        return jsonify({"error": "OSMOSIS_RPC not configured"}), 400

    # Ensure wallet
    settings = _merge_subscriber_settings()
    settings, osmo_err = _ensure_osmo_wallet(settings)
    if osmo_err:
        return jsonify({"error": f"osmo wallet: {osmo_err}"}), 400
    osmo_addr = settings.get("OSMOSIS_ADDRESS")

    # Balances
    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception as e:
        return jsonify({"error": f"osmosis balances: {e}"}), 500

    # USDC denom discovery
    usdc_denom_override = settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""
    usdc_denom = usdc_denom_override
    usdc_avail = 0
    if usdc_denom:
        for b in balances:
            if b.get("denom") == usdc_denom:
                try:
                    usdc_avail = int(b.get("amount", "0"))
                except Exception:
                    usdc_avail = 0
                break
    if not usdc_denom:
        usdc_denom, usdc_avail = _pick_usdc_osmo_denom(balances)
    if not usdc_denom:
        return jsonify({"error": "USDC denom not found on Osmosis"}), 400
    if usdc_avail < amt_base:
        return jsonify({"error": f"insufficient USDC (have {usdc_avail/1e6:.6f}, need {amt_float:.6f})"}), 400

    # Choose best pool
    best_pool, best_meta = _pick_best_usdc_osmo_pool(usdc_denom)
    pool_id = best_pool or USDC_OSMO_POOL_ID

    # Slippage: derive min_out from quote if possible
    quote, qerr = _osmosis_quote_usdc_to_osmo(amt_float)
    min_out = 1
    if quote and quote.get("min_amount_out_base"):
        min_out = int(quote.get("min_amount_out_base"))

    _append_hotwallet_log({"action": "convert_usdc_to_osmo", "stage": "start", "amount": amt_float})

    swap_cmd = [
        "osmosisd",
        "tx",
        "gamm",
        "swap-exact-amount-in",
        f"{amt_base}{usdc_denom}",
        str(min_out),
        "--broadcast-mode",
        "sync",
        "--swap-route-pool-ids",
        str(pool_id),
        "--swap-route-denoms",
        "uosmo",
        "--from",
        settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME,
        "--keyring-backend",
        "test",
        "--home",
        settings.get("OSMOSIS_HOME") or OSMOSIS_HOME,
        "--chain-id",
        "osmosis-1",
        "--node",
        OSMOSIS_RPC,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--gas-prices",
        "0.035uosmo",
        "-y",
    ]
    swap_code, swap_out = run_list(swap_cmd)
    swap_tx = _extract_txhash(swap_out)
    if swap_code != 0 or not swap_tx:
        _append_hotwallet_log({"action": "convert_usdc_to_osmo", "stage": "swap_failed", "detail": swap_out})
        return jsonify({"error": "swap failed", "detail": swap_out, "swap_cmd": swap_cmd, "swap_exit": swap_code}), 500

    ok, tx_log = _wait_for_osmo_tx_success(swap_tx, attempts=10, sleep_s=3)
    if not ok:
        _append_hotwallet_log({"action": "convert_usdc_to_osmo", "stage": "swap_not_included", "swap_tx": swap_tx, "raw_log": tx_log})
        return jsonify({"error": "swap failed on-chain or not included", "swap_tx": swap_tx, "swap_out": swap_out, "raw_log": tx_log}), 500

    # Refresh balances and report OSMO gained
    try:
        balances_after = _osmosis_balances_raw(osmo_addr)
    except Exception:
        balances_after = balances
    osmo_before = 0
    osmo_after = 0
    for b in balances:
        if b.get("denom") == "uosmo":
            try:
                osmo_before = int(b.get("amount", "0"))
            except Exception:
                osmo_before = 0
            break
    for b in balances_after:
        if b.get("denom") == "uosmo":
            try:
                osmo_after = int(b.get("amount", "0"))
            except Exception:
                osmo_after = osmo_before
            break
    osmo_delta = osmo_after - osmo_before

    _append_hotwallet_log(
        {
            "action": "convert_usdc_to_osmo",
            "stage": "submitted",
            "swap_tx": swap_tx,
            "usdc_denom": usdc_denom,
            "osmo_before": osmo_before,
            "osmo_after": osmo_after,
            "osmo_delta": osmo_delta,
            "pool_id": pool_id,
            "pool_meta": best_meta or {},
        }
    )

    return jsonify(
        {
            "status": "submitted",
            "swap_tx": swap_tx,
            "usdc_denom": usdc_denom,
            "osmo_before": osmo_before,
            "osmo_after": osmo_after,
            "osmo_delta": osmo_delta,
            "swap_cmd": _mask_cmd_sensitive(swap_cmd),
        }
    )


@app.post("/api/hotwallet/arkeo-to-native")
def hotwallet_arkeo_to_native():
    """
    IBC transfer ARKEO (wrapped on Osmosis) to native ARKEO on Arkeo chain.
    """
    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    amt_base = int(round(amt_float * 100_000_000))  # ARKEO 8 decimals on Osmosis

    if not OSMOSIS_RPC:
        return jsonify({"error": "OSMOSIS_RPC not configured"}), 400
    if not OSMO_TO_ARKEO_CHANNEL:
        return jsonify({"error": "OSMO_TO_ARKEO_CHANNEL not configured"}), 400

    settings = _merge_subscriber_settings()
    settings, osmo_err = _ensure_osmo_wallet(settings)
    settings, arkeo_err = _ensure_arkeo_mnemonic(settings)
    if osmo_err:
        return jsonify({"error": f"osmo wallet: {osmo_err}"}), 400
    if arkeo_err:
        return jsonify({"error": f"arkeo wallet: {arkeo_err}"}), 400
    osmo_addr = settings.get("OSMOSIS_ADDRESS")
    arkeo_addr, addr_err = derive_address(KEY_NAME, KEYRING)
    if addr_err:
        return jsonify({"error": f"arkeo address: {addr_err}"}), 400

    try:
        balances = _osmosis_balances_raw(osmo_addr)
    except Exception as e:
        return jsonify({"error": f"osmosis balances: {e}"}), 500

    # Gas check
    osmo_gas = 0
    for b in balances:
        if b.get("denom") == "uosmo":
            try:
                osmo_gas = int(b.get("amount", "0"))
            except Exception:
                osmo_gas = 0
            break
    if osmo_gas < int(MIN_OSMO_GAS * 1_000_000):
        return jsonify({"error": f"insufficient OSMO for gas (need >= {MIN_OSMO_GAS} OSMO)"}), 400

    # ARKEO denom and balance
    arkeo_denom = _discover_arkeo_osmo_denom(balances)
    if not arkeo_denom:
        return jsonify({"error": "ARKEO denom on Osmosis not found"}), 400
    arkeo_avail = 0
    for b in balances:
        if b.get("denom") == arkeo_denom:
            try:
                arkeo_avail = int(b.get("amount", "0"))
            except Exception:
                arkeo_avail = 0
            break
    if arkeo_avail < amt_base:
        return jsonify({"error": f"insufficient ARKEO (have {arkeo_avail/1e8:.8f}, need {amt_float:.8f})"}), 400

    _append_hotwallet_log({"action": "arkeo_to_native", "stage": "start", "amount": amt_float})

    ibc_cmd = [
        "osmosisd",
        "tx",
        "ibc-transfer",
        "transfer",
        "transfer",
        OSMO_TO_ARKEO_CHANNEL,
        arkeo_addr,
        f"{amt_base}{arkeo_denom}",
        "--from",
        settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME,
        "--keyring-backend",
        "test",
        "--home",
        settings.get("OSMOSIS_HOME") or OSMOSIS_HOME,
        "--chain-id",
        "osmosis-1",
        "--node",
        OSMOSIS_RPC,
        "--gas",
        "500000",
        "--fees",
        "15000uosmo",
        "--broadcast-mode",
        "sync",
        "-y",
    ]
    ibc_code, ibc_out = run_list(ibc_cmd)
    ibc_tx = _extract_txhash(ibc_out)
    packet_info = None
    try:
        packet_info = _parse_send_packet(json.loads(ibc_out) if ibc_out else {})
    except Exception:
        packet_info = None
    # Fallback: query tx to pull packet info if not present
    if ibc_tx and not packet_info:
        try:
            tx_json_raw = run_list(
                [
                    "osmosisd",
                    "query",
                    "tx",
                    ibc_tx,
                    "--node",
                    OSMOSIS_RPC,
                    "-o",
                    "json",
                ]
            )[1]
            packet_info = _parse_send_packet(json.loads(tx_json_raw))
        except Exception:
            packet_info = None
    if ibc_code != 0 or not ibc_tx:
        _append_hotwallet_log({"action": "arkeo_to_native", "stage": "ibc_failed", "detail": ibc_out})
        return (
            jsonify(
                {
                    "error": "ibc transfer failed",
                    "detail": ibc_out,
                    "raw_log": ibc_out,
                    "ibc_cmd": ibc_cmd,
                    "ibc_exit": ibc_code,
                }
            ),
            500,
        )

    start_arkeo_bal, _ = _arkeo_balance(arkeo_addr)
    # Attempt inclusion check on Osmosis
    tx_found, tx_resp = _query_osmo_tx(ibc_tx, attempts=6, sleep_s=2.0)
    tx_code = None
    tx_raw_log = None
    if tx_resp:
        tx_code = tx_resp.get("code")
        tx_raw_log = tx_resp.get("raw_log")
    arrived, arkeo_final, arkeo_poll_errors = _wait_for_arkeo_balance_increase(
        arkeo_addr, amt_base, tolerance_bps=ARRIVAL_TOLERANCE_BPS, attempts=6, sleep_s=5, start_amt=start_arkeo_bal
    )

    _append_hotwallet_log(
        {
            "action": "arkeo_to_native",
            "stage": "submitted",
            "ibc_tx": ibc_tx,
            "osmo_tx": ibc_tx,
            "packet_sequence": packet_info.get("packet_sequence") if packet_info else None,
            "osmo_src_channel": packet_info.get("src_channel") if packet_info else None,
            "arkeo_dst_channel": packet_info.get("dst_channel") if packet_info else None,
            "packet_info_found": bool(packet_info),
            "arkeo_start": start_arkeo_bal,
            "arkeo_final": arkeo_final,
            "arkeo_expected": amt_base,
            "arrival_confirmed": arrived,
            "arkeo_poll_errors": arkeo_poll_errors,
            "osmo_included": tx_found,
            "osmo_tx_code": tx_code,
            "osmo_tx_raw_log": tx_raw_log,
        }
    )

    return jsonify(
        {
            "status": "submitted",
            "ibc_tx": ibc_tx,
            "osmo_tx": ibc_tx,
            "packet_sequence": packet_info.get("packet_sequence") if packet_info else None,
            "osmo_src_channel": packet_info.get("src_channel") if packet_info else None,
            "arkeo_dst_channel": packet_info.get("dst_channel") if packet_info else None,
            "packet_info_found": bool(packet_info),
            "arkeo_denom": arkeo_denom,
            "arkeo_start": start_arkeo_bal,
            "arkeo_final": arkeo_final,
            "arkeo_expected": amt_base,
            "arrival_confirmed": arrived,
            "arkeo_poll_errors": arkeo_poll_errors,
            "osmo_included": tx_found,
            "osmo_tx_code": tx_code,
            "osmo_tx_raw_log": tx_raw_log,
            "ibc_cmd": _mask_cmd_sensitive(ibc_cmd),
        }
    )


CAST_BIN = _pick_executable("cast", ["/usr/local/bin/cast", "/root/.foundry/bin/cast"])
OSMOSISD_BIN = _pick_executable("osmosisd", ["/usr/local/bin/osmosisd"])
_CAST_LOGGED = False
ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeo"))
KEY_NAME = os.getenv("KEY_NAME", "subscriber")
KEYRING = os.getenv("KEY_KEYRING_BACKEND", "test")
KEY_MNEMONIC = os.getenv("KEY_MNEMONIC", "")
ARKEOD_NODE = _strip_quotes(
    os.getenv("ARKEOD_NODE")
    or os.getenv("EXTERNAL_ARKEOD_NODE")
    or "tcp://127.0.0.1:26657"
)
ETH_RPC = _strip_quotes(os.getenv("ETH_RPC") or "")
ETH_USDC_CONTRACT = _strip_quotes(os.getenv("ETH_USDC_CONTRACT") or "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")  # default to mainnet USDC
ETH_USDC_DECIMALS = int(os.getenv("ETH_USDC_DECIMALS", "6"))
OSMOSIS_RPC = _strip_quotes(os.getenv("OSMOSIS_RPC") or "")
OSMOSIS_HOME = os.path.expanduser(os.getenv("OSMOSIS_HOME", "/app/config/osmosis"))
OSMOSIS_KEY_NAME = os.getenv("OSMOSIS_KEY_NAME", "osmo-subscriber")
# cache for Osmosis denom traces/metadata
OSMOSIS_DENOM_CACHE = os.path.join(CACHE_DIR or "/app/cache", "osmo_denom_cache.json")
DEFAULT_OSMOSIS_USDC_DENOMS = [
    # Axelar canonical USDC on Osmosis
    "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2",
    # Known wrapped USDC (channel-750) provided
    "ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4",
]
USDC_OSMO_POOL_ID = os.getenv("USDC_OSMO_POOL_ID") or "678"  # fallback pool for USDC<->OSMO swaps (override if needed)
_env_osmo_denoms = [d.strip() for d in (os.getenv("OSMOSIS_USDC_DENOMS") or "").split(",") if d.strip()]
OSMOSIS_USDC_DENOMS = _env_osmo_denoms if _env_osmo_denoms else DEFAULT_OSMOSIS_USDC_DENOMS.copy()
MIN_OSMO_GAS = _safe_float(os.getenv("MIN_OSMO_GAS") or 0.1, 0.1)
DEFAULT_SLIPPAGE_BPS = int(os.getenv("DEFAULT_SLIPPAGE_BPS") or "100")
OSMO_TO_ARKEO_CHANNEL = os.getenv("OSMO_TO_ARKEO_CHANNEL") or "channel-103074"
# Reverse direction (Arkeo -> Osmosis) based on chain-registry entry
ARKEO_TO_OSMO_CHANNEL = os.getenv("ARKEO_TO_OSMO_CHANNEL") or "channel-1"
ARRIVAL_TOLERANCE_BPS = int(os.getenv("ARRIVAL_TOLERANCE_BPS") or "100")  # allow slight shortfall when checking arrival
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
SUBSCRIBER_ENV_PATH = os.getenv("SUBSCRIBER_ENV_PATH", "/app/config/subscriber.env")
SUBSCRIBER_SETTINGS_PATH = os.getenv("SUBSCRIBER_SETTINGS_PATH") or os.path.join(
    CONFIG_DIR or "/app/config", "subscriber-settings.json"
)
ADMIN_PASSWORD_PATH = os.getenv("ADMIN_PASSWORD_PATH") or (
    os.path.join(CACHE_DIR or "/app/cache", "admin_password.txt")
)

# PAYG proxy defaults (can be overridden via env; per-listener overrides later)
PROXY_AUTO_CREATE = True
# Default to 0 so we compute deposit = duration * qpm * rate when unset.
PROXY_CREATE_DEPOSIT = os.getenv("PROXY_CREATE_DEPOSIT", "0")
PROXY_CREATE_DURATION = os.getenv("PROXY_CREATE_DURATION", "5000")
PROXY_CREATE_RATE = os.getenv("PROXY_CREATE_RATE", FEES_DEFAULT)
PROXY_CREATE_QPM = os.getenv("PROXY_CREATE_QPM", "10000")
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
PROXY_OPEN_COOLDOWN = int(os.getenv("PROXY_OPEN_COOLDOWN", "0"))  # seconds to cool down a provider after open failure
PROXY_CONTRACT_CACHE_TTL = int(os.getenv("PROXY_CONTRACT_CACHE_TTL", "45"))  # seconds; 0 disables TTL check
SIGNHERE_HOME = os.path.join(Path.home(), ".arkeo")
AXELAR_GAS_AMOUNT_ETH = _safe_float(os.getenv("AXELAR_GAS_AMOUNT_ETH") or 0.0, 0.0)
MIN_OSMO_BRIDGE_USDC = _safe_float(os.getenv("MIN_OSMO_BRIDGE_USDC") or 0.0, 0.0)
SQUID_FROM_CHAIN_ID = os.getenv("SQUID_FROM_CHAIN_ID") or "1"  # default to Ethereum mainnet
SQUID_TO_CHAIN_ID = os.getenv("SQUID_TO_CHAIN_ID") or "875"  # default to Osmosis (Squid chain id)
# Silence Foundry nightly warnings to keep logs clean
os.environ.setdefault("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1")


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
        "/api/logout",
        "/api/ping",
    }
    if path in exempt:
        return True
    return False


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
        # allow full CRUD for listener/admin operations
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        headers["Access-Control-Max-Age"] = "3600"
    return headers

def _is_auth_required() -> bool:
    return bool(_load_admin_password())


def _expand_tilde(val: str | None) -> str:
    if not val:
        return ""
    return os.path.expanduser(val)


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


def _default_subscriber_settings() -> dict:
    """Return defaults from env + sane fallbacks."""
    rest_api_env = os.getenv("ARKEO_REST_API") or os.getenv("EXTERNAL_ARKEO_REST_API") or os.getenv("ARKEO_REST_API_PORT") or ""
    defaults = {
        "SUBSCRIBER_NAME": os.getenv("SUBSCRIBER_NAME", "Arkeo Core Subscriber"),
        "KEY_NAME": os.getenv("KEY_NAME", KEY_NAME),
        "KEY_KEYRING_BACKEND": os.getenv("KEY_KEYRING_BACKEND", KEYRING),
        "KEY_MNEMONIC": os.getenv("KEY_MNEMONIC", KEY_MNEMONIC),
        "CHAIN_ID": _strip_quotes(os.getenv("CHAIN_ID") or os.getenv("ARKEOD_CHAIN_ID") or ""),
        "ARKEOD_HOME": _expand_tilde(os.getenv("ARKEOD_HOME") or ARKEOD_HOME),
        "ARKEOD_NODE": _strip_quotes(
            os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or ARKEOD_NODE
        ),
        "ARKEO_REST_API": rest_api_env,
        "ADMIN_PORT": os.getenv("ADMIN_PORT") or os.getenv("ENV_ADMIN_PORT") or "8079",
        "ADMIN_API_PORT": os.getenv("ADMIN_API_PORT") or str(API_PORT),
        "ALLOW_LOCALHOST_SENTINEL_URIS": os.getenv("ALLOW_LOCALHOST_SENTINEL_URIS") or "0",
        "ETH_RPC": _strip_quotes(os.getenv("ETH_RPC") or ""),
        "ETH_USDC_CONTRACT": _strip_quotes(os.getenv("ETH_USDC_CONTRACT") or "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        "ETH_USDC_DECIMALS": int(os.getenv("ETH_USDC_DECIMALS", "6")),
        "OSMOSIS_RPC": _strip_quotes(os.getenv("OSMOSIS_RPC") or ""),
        "OSMOSIS_USDC_DENOMS": OSMOSIS_USDC_DENOMS,
        "ETH_MNEMONIC": "",
        "ETH_ADDRESS": "",
        "OSMOSIS_MNEMONIC": "",
        "OSMOSIS_ADDRESS": "",
        "USDC_OSMO_DENOM": os.getenv("USDC_OSMO_DENOM", "ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4"),
        "ARKEO_OSMO_DENOM": os.getenv("ARKEO_OSMO_DENOM", "ibc/AD969E97A63B64B30A6E4D9F598341A403B849F5ACFEAA9F18DBD9255305EC65"),
        "MIN_OSMO_GAS": MIN_OSMO_GAS,
        "DEFAULT_SLIPPAGE_BPS": DEFAULT_SLIPPAGE_BPS,
        "OSMO_TO_ARKEO_CHANNEL": os.getenv("OSMO_TO_ARKEO_CHANNEL") or OSMO_TO_ARKEO_CHANNEL,
        "ARKEO_TO_OSMO_CHANNEL": os.getenv("ARKEO_TO_OSMO_CHANNEL") or ARKEO_TO_OSMO_CHANNEL,
        "ARRIVAL_TOLERANCE_BPS": ARRIVAL_TOLERANCE_BPS,
    }
    return defaults


def _load_subscriber_settings_file() -> dict | None:
    """Load persisted subscriber settings if present."""
    path = SUBSCRIBER_SETTINGS_PATH
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_subscriber_settings_file(settings: dict) -> None:
    """Persist subscriber settings JSON alongside cache."""
    path = SUBSCRIBER_SETTINGS_PATH
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except OSError:
        pass


def _merge_subscriber_settings(overrides: dict | None = None) -> dict:
    """Merge defaults, persisted file, and optional overrides."""
    merged = _default_subscriber_settings()
    saved = _load_subscriber_settings_file()
    if isinstance(saved, dict):
        merged.update(saved)
    if overrides and isinstance(overrides, dict):
        merged.update(overrides)
    # Normalize legacy/external keys
    if merged.get("EXTERNAL_ARKEOD_NODE") and not merged.get("ARKEOD_NODE"):
        merged["ARKEOD_NODE"] = merged["EXTERNAL_ARKEOD_NODE"]
    merged.pop("EXTERNAL_ARKEOD_NODE", None)
    if merged.get("EXTERNAL_ARKEO_REST_API") and not merged.get("ARKEO_REST_API_PORT") and not merged.get("ARKEO_REST_API"):
        merged["ARKEO_REST_API"] = merged["EXTERNAL_ARKEO_REST_API"]
    merged.pop("EXTERNAL_ARKEO_REST_API", None)
    if merged.get("ARKEO_REST_API_PORT") and not merged.get("ARKEO_REST_API"):
        merged["ARKEO_REST_API"] = merged["ARKEO_REST_API_PORT"]
    merged.pop("ARKEO_REST_API_PORT", None)
    merged["ARKEOD_HOME"] = _expand_tilde(merged.get("ARKEOD_HOME") or ARKEOD_HOME)
    if merged.get("ARKEOD_NODE"):
        merged["ARKEOD_NODE"] = _ensure_tcp_scheme(_strip_quotes(merged.get("ARKEOD_NODE") or ""))
    merged.pop("SENTINEL_NODE", None)
    merged.pop("SENTINEL_PORT", None)
    # Normalize Osmosis USDC denoms to list
    denoms = merged.get("OSMOSIS_USDC_DENOMS")
    if isinstance(denoms, str):
        merged["OSMOSIS_USDC_DENOMS"] = [d.strip() for d in denoms.split(",") if d.strip()]
    if not merged.get("OSMOSIS_USDC_DENOMS"):
        merged["OSMOSIS_USDC_DENOMS"] = DEFAULT_OSMOSIS_USDC_DENOMS.copy()
    return merged


def _apply_subscriber_settings(settings: dict) -> None:
    """Apply subscriber settings to globals and os.environ for runtime use."""
    global KEY_NAME, KEYRING, ARKEOD_HOME, ARKEOD_NODE, CHAIN_ID, NODE_ARGS, CHAIN_ARGS, KEY_MNEMONIC, ETH_RPC, ETH_USDC_CONTRACT, ETH_USDC_DECIMALS, OSMOSIS_RPC, OSMOSIS_USDC_DENOMS, MIN_OSMO_GAS, DEFAULT_SLIPPAGE_BPS, OSMO_TO_ARKEO_CHANNEL, ARKEO_TO_OSMO_CHANNEL
    if not isinstance(settings, dict):
        return
    KEY_NAME = settings.get("KEY_NAME", KEY_NAME)
    KEYRING = settings.get("KEY_KEYRING_BACKEND", KEYRING)
    KEY_MNEMONIC = settings.get("KEY_MNEMONIC", KEY_MNEMONIC)
    ARKEOD_HOME = _expand_tilde(settings.get("ARKEOD_HOME") or ARKEOD_HOME)
    node_val = settings.get("ARKEOD_NODE") or ARKEOD_NODE
    ARKEOD_NODE = _ensure_tcp_scheme(_strip_quotes(node_val))
    CHAIN_ID = _strip_quotes(settings.get("CHAIN_ID") or CHAIN_ID)
    NODE_ARGS = ["--node", ARKEOD_NODE] if ARKEOD_NODE else []
    CHAIN_ARGS = ["--chain-id", CHAIN_ID] if CHAIN_ID else []
    rest_api_val = settings.get("ARKEO_REST_API") or ""
    ETH_RPC = _strip_quotes(settings.get("ETH_RPC") or ETH_RPC or "")
    ETH_USDC_CONTRACT = _strip_quotes(settings.get("ETH_USDC_CONTRACT") or ETH_USDC_CONTRACT or "")
    try:
        ETH_USDC_DECIMALS = int(settings.get("ETH_USDC_DECIMALS") or ETH_USDC_DECIMALS or 6)
    except Exception:
        ETH_USDC_DECIMALS = 6
    try:
        denoms = settings.get("OSMOSIS_USDC_DENOMS") or []
        if isinstance(denoms, str):
            denoms = [d.strip() for d in denoms.split(",") if d.strip()]
        if not isinstance(denoms, list):
            denoms = []
        if not denoms:
            denoms = DEFAULT_OSMOSIS_USDC_DENOMS.copy()
        OSMOSIS_USDC_DENOMS = denoms
    except Exception:
        OSMOSIS_USDC_DENOMS = DEFAULT_OSMOSIS_USDC_DENOMS.copy()
    try:
        MIN_OSMO_GAS = _safe_float(settings.get("MIN_OSMO_GAS") if settings.get("MIN_OSMO_GAS") not in (None, "") else MIN_OSMO_GAS, MIN_OSMO_GAS)
    except Exception:
        MIN_OSMO_GAS = 0.1
    try:
        DEFAULT_SLIPPAGE_BPS = int(settings.get("DEFAULT_SLIPPAGE_BPS") if settings.get("DEFAULT_SLIPPAGE_BPS") not in (None, "") else DEFAULT_SLIPPAGE_BPS or 100)
    except Exception:
        DEFAULT_SLIPPAGE_BPS = 100
    try:
        ARRIVAL_TOLERANCE_BPS = int(settings.get("ARRIVAL_TOLERANCE_BPS") if settings.get("ARRIVAL_TOLERANCE_BPS") not in (None, "") else ARRIVAL_TOLERANCE_BPS or 100)
    except Exception:
        ARRIVAL_TOLERANCE_BPS = 100
    try:
        OSMO_TO_ARKEO_CHANNEL = settings.get("OSMO_TO_ARKEO_CHANNEL") or OSMO_TO_ARKEO_CHANNEL
    except Exception:
        OSMO_TO_ARKEO_CHANNEL = OSMO_TO_ARKEO_CHANNEL
    try:
        ARKEO_TO_OSMO_CHANNEL = settings.get("ARKEO_TO_OSMO_CHANNEL") or ARKEO_TO_OSMO_CHANNEL
    except Exception:
        ARKEO_TO_OSMO_CHANNEL = ARKEO_TO_OSMO_CHANNEL
    OSMOSIS_RPC = _strip_quotes(settings.get("OSMOSIS_RPC") or OSMOSIS_RPC or "")

    # Best-effort auto-discover Osmosis->Arkeo channel if missing
    if not OSMO_TO_ARKEO_CHANNEL:
        discovered = _discover_osmo_to_arkeo_channel()
        if discovered:
            OSMO_TO_ARKEO_CHANNEL = discovered
            settings["OSMO_TO_ARKEO_CHANNEL"] = discovered
            try:
                _write_subscriber_settings_file(settings)
            except Exception:
                pass

    env_overrides = {
        "SUBSCRIBER_NAME": settings.get("SUBSCRIBER_NAME", ""),
        "KEY_NAME": KEY_NAME,
        "KEY_KEYRING_BACKEND": KEYRING,
        "KEY_MNEMONIC": settings.get("KEY_MNEMONIC", ""),
        "CHAIN_ID": CHAIN_ID,
        "ARKEOD_HOME": ARKEOD_HOME,
        "ARKEOD_NODE": ARKEOD_NODE,
        "ARKEO_REST_API": rest_api_val,
        "ADMIN_PORT": settings.get("ADMIN_PORT", ""),
        "ADMIN_API_PORT": settings.get("ADMIN_API_PORT", ""),
        "ALLOW_LOCALHOST_SENTINEL_URIS": settings.get("ALLOW_LOCALHOST_SENTINEL_URIS", ""),
        "ETH_RPC": settings.get("ETH_RPC", ""),
        "ETH_USDC_CONTRACT": settings.get("ETH_USDC_CONTRACT", ""),
        "ETH_USDC_DECIMALS": settings.get("ETH_USDC_DECIMALS", ""),
        "OSMOSIS_RPC": settings.get("OSMOSIS_RPC", ""),
        "OSMOSIS_USDC_DENOMS": ",".join(OSMOSIS_USDC_DENOMS) if OSMOSIS_USDC_DENOMS else "",
        "ETH_MNEMONIC": settings.get("ETH_MNEMONIC", ""),
        "ETH_ADDRESS": settings.get("ETH_ADDRESS", ""),
        "OSMOSIS_MNEMONIC": settings.get("OSMOSIS_MNEMONIC", ""),
        "OSMOSIS_ADDRESS": settings.get("OSMOSIS_ADDRESS", ""),
        "USDC_OSMO_DENOM": settings.get("USDC_OSMO_DENOM", ""),
        "ARKEO_OSMO_DENOM": settings.get("ARKEO_OSMO_DENOM", ""),
        "MIN_OSMO_GAS": settings.get("MIN_OSMO_GAS", ""),
        "DEFAULT_SLIPPAGE_BPS": settings.get("DEFAULT_SLIPPAGE_BPS", ""),
        "OSMO_TO_ARKEO_CHANNEL": settings.get("OSMO_TO_ARKEO_CHANNEL", ""),
        "ARKEO_TO_OSMO_CHANNEL": settings.get("ARKEO_TO_OSMO_CHANNEL", ""),
        "ARRIVAL_TOLERANCE_BPS": settings.get("ARRIVAL_TOLERANCE_BPS", ""),
    }
    for k, v in env_overrides.items():
        if v is None:
            continue
        os.environ[k] = str(v)


def _mnemonic_file_path(settings: dict | None = None) -> str:
    cfg = settings or _merge_subscriber_settings()
    home = _expand_tilde(cfg.get("ARKEOD_HOME") or ARKEOD_HOME)
    key_name = cfg.get("KEY_NAME") or KEY_NAME
    return os.path.join(home, f"{key_name}_mnemonic.txt")


def _extract_mnemonic(text: str) -> str:
    """Best-effort extraction of a 12-24 word mnemonic from text, preferring the last match."""
    if not text:
        return ""
    best = ""
    # Scan lines in order; keep the last 12-24 word sequence
    for line in text.splitlines():
        words = [w for w in line.strip().split() if w.isalpha()]
        if 12 <= len(words) <= 24:
            best = " ".join(words)
    # Regex across the whole text, keep last match
    for m in re.finditer(r"([a-zA-Z]+(?: [a-zA-Z]+){11,23})", text):
        phrase = m.group(1).strip()
        wc = len([w for w in phrase.split() if w.isalpha()])
        if 12 <= wc <= 24:
            best = phrase
    return best.strip()


def _mask_mnemonic(mn: str) -> str:
    """Mask mnemonic for logs (keep first 2 and last word)."""
    words = mn.strip().split()
    if len(words) <= 3:
        return "***"
    return " ".join(words[:2] + ["..."] + words[-1:])


def _arkeo_key_exists(settings: dict) -> bool:
    """Return True if the Arkeo key already exists in the keyring."""
    key_name = settings.get("KEY_NAME") or KEY_NAME
    keyring = settings.get("KEY_KEYRING_BACKEND") or KEYRING
    home = _expand_tilde(settings.get("ARKEOD_HOME") or ARKEOD_HOME)
    cmd = ["arkeod", "--home", home, "--keyring-backend", keyring, "keys", "show", key_name]
    code, _out = run_list(cmd)
    return code == 0


def _ensure_arkeo_mnemonic(settings: dict) -> tuple[dict, bool]:
    """
    Ensure KEY_MNEMONIC is populated if possible.
    Returns (settings, changed).
    """
    changed = False
    key_name = settings.get("KEY_NAME") or KEY_NAME
    keyring = settings.get("KEY_KEYRING_BACKEND") or KEYRING
    home = _expand_tilde(settings.get("ARKEOD_HOME") or ARKEOD_HOME)
    if settings.get("KEY_MNEMONIC"):
        return settings, False

    if not _arkeo_key_exists(settings):
        code, out, mn = _create_hotwallet(key_name, keyring, home)
        if code == 0 and mn:
            settings["KEY_MNEMONIC"] = mn
            print(f"[boot] Arkeo wallet created and mnemonic captured (masked={_mask_mnemonic(mn)})")
            changed = True
        else:
            print(f"[boot] failed to create Arkeo wallet for mnemonic capture: exit={code} out={out}")
        return settings, changed

    # Key exists but no mnemonic available; cannot recover without user-provided mnemonic
    print("[boot] Arkeo key exists but KEY_MNEMONIC is empty; cannot recover mnemonic from keyring")
    return settings, False


def _read_hotwallet_mnemonic(settings: dict | None = None) -> tuple[str, str]:
    """Return mnemonic and source (settings/env/file/none)."""
    cfg = _merge_subscriber_settings(settings or {})
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
    """No-op: mnemonics are persisted only in subscriber-settings.json."""
    return


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


def _ensure_eth_wallet(settings: dict) -> tuple[dict, str | None]:
    """Ensure ETH mnemonic/address exist in settings; returns (settings, error)."""
    global _CAST_LOGGED
    if not isinstance(settings, dict):
        return settings, "invalid settings"
    if not CAST_BIN or not os.path.isfile(CAST_BIN):
        err = f"cast binary not found (looked for {CAST_BIN or 'cast'})"
        print(err)
        return settings, err
    if not _CAST_LOGGED:
        print(f"[eth] using cast binary at {CAST_BIN}")
        _CAST_LOGGED = True
    mnemonic = settings.get("ETH_MNEMONIC") or ""
    address = settings.get("ETH_ADDRESS") or ""

    def derive_addr(mn: str) -> tuple[str | None, str | None]:
        try:
            cmd = [
                CAST_BIN,
                "wallet",
                "address",
                "--mnemonic",
                mn,
            ]
            code, out = run_list(cmd)
            if code == 0 and out:
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                addr = None
                for line in lines:
                    m = re.search(r"0x[a-fA-F0-9]{40}", line)
                    if m:
                        addr = m.group(0)
                        break
                if not addr and lines:
                    addr = lines[-1]
                if addr:
                    print(f"[eth] derived address from mnemonic: {addr}")
                    return addr, None
            return None, f"addr derive exit={code}: {out}"
        except Exception as e:
            return None, str(e)

    # If mnemonic exists but no address, derive it
    if mnemonic and not address:
        print(f"[eth] mnemonic present, deriving address (masked={_mask_mnemonic(mnemonic)})")
        addr, derr = derive_addr(mnemonic)
        if addr:
            settings["ETH_ADDRESS"] = addr
            return settings, None
        if derr:
            err = f"failed to derive eth address: {derr}"
            print(err)
            # If we cannot derive and have no address, attempt regeneration
            mnemonic = ""
            settings["ETH_MNEMONIC"] = ""

    # If both present, done
    if mnemonic and address:
        print(f"[eth] mnemonic/address already present; skipping generation")
        return settings, None

    # Generate mnemonic if missing
    try:
        code, out = run_list([CAST_BIN, "wallet", "new-mnemonic", "--words", "24"])
        if code != 0 or not out:
            err = f"failed to generate eth mnemonic: {out}"
            print(err)
            return settings, err
        mnemonic_new = _extract_mnemonic(out.strip())
        if len(mnemonic_new.split()) < 12:
            err = f"unexpected mnemonic format: {out}"
            print(err)
            return settings, err
        print(f"[eth] generated mnemonic (masked={_mask_mnemonic(mnemonic_new)})")
        settings["ETH_MNEMONIC"] = mnemonic_new
        addr, derr = derive_addr(mnemonic_new)
        if addr:
            settings["ETH_ADDRESS"] = addr
            return settings, None
        err = f"failed to derive eth address after mnemonic gen: {derr}"
        print(err)
        return settings, err
    except Exception as e:
        err = f"failed to generate eth wallet: {e}"
        print(err)
        return settings, err


def _ensure_osmo_wallet(settings: dict) -> tuple[dict, str | None]:
    """Ensure Osmosis mnemonic/address exist in settings using osmosisd keyring-backend test."""
    if not isinstance(settings, dict):
        return settings, "invalid settings"
    if not OSMOSISD_BIN or not os.path.isfile(OSMOSISD_BIN):
        err = f"osmosisd binary not found (looked for {OSMOSISD_BIN or 'osmosisd'})"
        print(err)
        return settings, err
    mnemonic = settings.get("OSMOSIS_MNEMONIC") or ""
    address = settings.get("OSMOSIS_ADDRESS") or ""
    key_name = settings.get("OSMOSIS_KEY_NAME") or OSMOSIS_KEY_NAME
    home = settings.get("OSMOSIS_HOME") or OSMOSIS_HOME
    os.makedirs(home, exist_ok=True)

    def _derive_address_with_mnemonic(mn: str) -> tuple[str | None, str | None]:
        try:
            cmd = [
                OSMOSISD_BIN,
                "keys",
                "add",
                key_name,
                "--keyring-backend",
                "test",
                "--home",
                home,
                "--recover",
                "--output",
                "json",
            ]
            code, out = run_with_input(cmd, mn.strip() + "\n")
            if code != 0:
                return None, out
            data = json.loads(out)
            return data.get("address"), None
        except Exception as e:
            return None, str(e)

    # If mnemonic exists but no address, try to recover to derive address
    if mnemonic and not address:
        addr, err = _derive_address_with_mnemonic(mnemonic)
        if addr:
            settings["OSMOSIS_ADDRESS"] = addr
            return settings, None
        if err:
            err_msg = f"failed to derive osmosis address: {err}"
            print(err_msg)
            return settings, err_msg
    # If both present, done
    if mnemonic and address:
        return settings, None
    # Try to add new key to get mnemonic and address
    try:
        cmd = [
            OSMOSISD_BIN,
            "keys",
            "add",
            key_name,
            "--keyring-backend",
            "test",
            "--home",
            home,
            "--output",
            "json",
        ]
        code, out = run_list(cmd)
        if code != 0:
            # If key exists, try show
            if "exists" in (out or "").lower():
                code_show, out_show = run_list(
                    [OSMOSISD_BIN, "keys", "show", key_name, "--keyring-backend", "test", "--home", home, "--output", "json"]
                )
                if code_show == 0:
                    data_show = json.loads(out_show)
                    addr_show = data_show.get("address")
                    if addr_show:
                        settings["OSMOSIS_ADDRESS"] = addr_show
                        if not mnemonic:
                            settings["OSMOSIS_MNEMONIC"] = ""
                        return settings, None
            err = f"failed to create osmosis wallet: {out}"
            print(err)
            return settings, err
        data = json.loads(out)
        if data.get("mnemonic"):
            settings["OSMOSIS_MNEMONIC"] = data.get("mnemonic")
        if data.get("address"):
            settings["OSMOSIS_ADDRESS"] = data.get("address")
        return settings, None
    except Exception as e:
        err = f"failed to create osmosis wallet: {e}"
        print(err)
        return settings, err


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


# Apply persisted subscriber settings at import time (if present)
_apply_subscriber_settings(_merge_subscriber_settings())


def _bootstrap_wallets():
    """Ensure ETH/OSMO wallets are generated at startup if missing."""
    try:
        settings = _merge_subscriber_settings()
        changed = False
        # Ensure Arkeo mnemonic is captured when possible
        settings, arkeo_changed = _ensure_arkeo_mnemonic(settings)
        changed = changed or arkeo_changed
        before_eth_mn = settings.get("ETH_MNEMONIC")
        before_eth_addr = settings.get("ETH_ADDRESS")
        before_osmo_mn = settings.get("OSMOSIS_MNEMONIC")
        before_osmo_addr = settings.get("OSMOSIS_ADDRESS")
        # ETH
        settings, eth_err = _ensure_eth_wallet(settings)
        if not eth_err and settings.get("ETH_MNEMONIC") and settings.get("ETH_ADDRESS"):
            changed = True
            print("[boot] ETH wallet ensured (mnemonic+address present)")
        elif eth_err:
            print(f"[boot] ETH wallet init error: {eth_err}")
        # OSMO
        settings, osmo_err = _ensure_osmo_wallet(settings)
        if not osmo_err and settings.get("OSMOSIS_MNEMONIC") and settings.get("OSMOSIS_ADDRESS"):
            changed = True
            print("[boot] Osmosis wallet ensured (mnemonic+address present)")
        elif osmo_err:
            print(f"[boot] Osmosis wallet init error: {osmo_err}")
        # strip transient errors before persisting
        settings.pop("ETH_ERROR", None)
        settings.pop("OSMOSIS_ERROR", None)
        if (
            changed
            or settings.get("ETH_MNEMONIC") != before_eth_mn
            or settings.get("ETH_ADDRESS") != before_eth_addr
            or settings.get("OSMOSIS_MNEMONIC") != before_osmo_mn
            or settings.get("OSMOSIS_ADDRESS") != before_osmo_addr
        ):
            _write_subscriber_settings_file(settings)
    except Exception as e:
        print(f"[boot] wallet bootstrap failed: {e}")


_bootstrap_wallets()


@app.after_request
def add_cors(resp):
    headers = _cors_headers()
    for k, v in headers.items():
        resp.headers[k] = v
    return resp


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


def _eth_block_height_internal() -> tuple[str | None, str | None]:
    """Return (height_str, error_str) from the configured ETH_RPC endpoint."""
    if not ETH_RPC:
        return None, "ETH_RPC not configured"
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
        req = urllib.request.Request(
            ETH_RPC,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if "result" in data:
                hex_val = data["result"]
                try:
                    height_int = int(hex_val, 16)
                    return str(height_int), None
                except Exception:
                    return hex_val, None
            return None, "no result in response"
    except Exception as e:
        return None, str(e)


@app.get("/api/eth-block-height")
def eth_block_height():
    """Return the latest Ethereum block height from ETH_RPC."""
    height, err = _eth_block_height_internal()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"height": height})


def _eth_balance_internal() -> tuple[str | None, str | None]:
    """Return (balance_eth_str, error) using ETH_RPC and ETH_ADDRESS (auto-deriving if needed)."""
    if not ETH_RPC:
        return None, "ETH_RPC not configured"
    settings = _merge_subscriber_settings()
    settings, err = _ensure_eth_wallet(settings)
    if err:
        return None, err
    addr = settings.get("ETH_ADDRESS")
    if not addr:
        return None, "ETH_ADDRESS not available"
    try:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [addr, "latest"]}
        ).encode()
        req = urllib.request.Request(
            ETH_RPC,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            hex_val = (data or {}).get("result")
            if hex_val is None:
                return None, "no result in response"
            try:
                wei = int(hex_val, 16)
                eth_val = wei / 1e18
                return f"{eth_val:.6f} ETH", None
            except Exception:
                return hex_val, None
    except Exception as e:
        return None, str(e)


def _eth_token_balance_internal(
    contract: str | None, decimals: int = 6, symbol: str = "USDC"
) -> tuple[str | None, str | None]:
    """Return (balance_token_str, error) using eth_call balanceOf."""
    contract_addr = (contract or "").strip()
    if not contract_addr:
        return None, "token contract not configured"
    if not ETH_RPC:
        return None, "ETH_RPC not configured"
    settings = _merge_subscriber_settings()
    settings, err = _ensure_eth_wallet(settings)
    if err:
        return None, err
    addr = settings.get("ETH_ADDRESS")
    if not addr:
        return None, "ETH_ADDRESS not available"
    try:
        addr_clean = addr.lower().replace("0x", "")
        if len(addr_clean) != 40:
            return None, f"invalid address: {addr}"
        data_field = "0x70a08231" + ("0" * 24) + addr_clean
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_call",
                "params": [
                    {"to": contract_addr, "data": data_field},
                    "latest",
                ],
            }
        ).encode()
        req = urllib.request.Request(
            ETH_RPC,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            hex_val = (data or {}).get("result")
            if hex_val is None:
                return None, "no result in response"
            try:
                amt = int(hex_val, 16)
                div = float(10**decimals)
                val = amt / div
                return f"{val:.6f} {symbol}", None
            except Exception:
                return hex_val, None
    except Exception as e:
        return None, str(e)


@app.get("/api/eth-balance")
def eth_balance():
    """Return ETH balance for the derived ETH wallet."""
    bal, err = _eth_balance_internal()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"balance": bal})


@app.get("/api/eth-usdc-balance")
def eth_usdc_balance():
    """Return USDC balance for the derived ETH wallet."""
    bal, err = _eth_token_balance_internal(ETH_USDC_CONTRACT, ETH_USDC_DECIMALS, "USDC")
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"balance": bal})


def _osmosis_block_height_internal() -> tuple[str | None, str | None]:
    """Return (height_str, error_str) from the configured OSMOSIS_RPC endpoint."""
    if not OSMOSIS_RPC:
        return None, "OSMOSIS_RPC not configured"
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "status", "params": []}).encode()
        req = urllib.request.Request(
            OSMOSIS_RPC,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            sync_info = data.get("result", {}).get("sync_info") or data.get("SyncInfo") or {}
            height = sync_info.get("latest_block_height") or sync_info.get("latest_block")
            if height is None:
                return None, "no height in response"
            return str(height), None
    except Exception as e:
        return None, str(e)


@app.get("/api/osmosis-block-height")
def osmosis_block_height():
    """Return the latest Osmosis block height from OSMOSIS_RPC."""
    height, err = _osmosis_block_height_internal()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"height": height})


def _osmosis_balance_internal() -> tuple[str | None, str | None]:
    """Return (balance_str, error) for the Osmosis wallet."""
    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return None, err
    addr = settings.get("OSMOSIS_ADDRESS")
    if not addr:
        return None, "OSMOSIS_ADDRESS not available"
    resolved, err = _resolve_osmo_denoms(addr)
    if err:
        return None, err
    assets = resolved.get("assets") or []
    if not assets:
        return {
            "osmo": "0.000000 OSMO",
            "usdc": "0.000000 USDC",
            "arkeo": "0.000000 ARKEO",
            "assets": [],
        }, None

    total_osmo = 0
    total_usdc = 0
    total_arkeo = 0
    other_parts: list[str] = []
    arkeo_denom = resolved.get("arkeo_denom") or settings.get("ARKEO_OSMO_DENOM") or os.getenv("ARKEO_OSMO_DENOM") or ""
    usdc_denom = resolved.get("usdc_denom") or settings.get("USDC_OSMO_DENOM") or os.getenv("USDC_OSMO_DENOM") or ""

    for a in assets:
        denom = a.get("denom") or ""
        base = (a.get("base_denom") or denom or "").lower()
        amt = int(a.get("amount") or 0)
        if denom == "uosmo" or base == "uosmo":
            total_osmo += amt
            continue
        if "usdc" in base:
            total_usdc += amt
            continue
        if "arkeo" in base:
            total_arkeo += amt
            continue
        # track extras for debugging display
        other_parts.append(f"{amt} {denom}")

    osmo_str = f"{total_osmo/1e6:.6f} OSMO"
    usdc_str = f"{total_usdc/1e6:.6f} USDC"
    # Wrapped ARKEO on Osmosis uses 8 decimals
    arkeo_str = f"{total_arkeo/1e8:.8f} ARKEO"
    extras = ", ".join(other_parts) if other_parts else ""
    combined_parts = [p for p in [osmo_str, usdc_str, arkeo_str if arkeo_denom else "", extras] if p]
    combined = ", ".join(combined_parts)

    # Persist discovered denoms when found
    if usdc_denom or arkeo_denom:
        try:
            _write_bridge_denoms(usdc_denom, arkeo_denom)
        except Exception:
            pass

    return (
        {
            "osmo": osmo_str,
            "usdc": usdc_str,
            "arkeo": arkeo_str,
            "arkeo_denom": arkeo_denom,
            "usdc_denom": usdc_denom,
            "full": combined,
            "assets": assets,
        },
        None,
    )


@app.get("/api/osmosis-balance")
def osmosis_balance():
    """Return Osmosis balance for the derived Osmosis wallet."""
    bal, err = _osmosis_balance_internal()
    if err:
        return jsonify({"error": err}), 500
    if isinstance(bal, dict):
        return jsonify(bal)
    return jsonify({"balance": bal})


@app.get("/api/osmosis-assets")
def osmosis_assets():
    """Return resolved Osmosis assets (denom traces + metadata) for the hot wallet."""
    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return jsonify({"error": err}), 500
    addr = settings.get("OSMOSIS_ADDRESS")
    if not addr:
        return jsonify({"error": "OSMOSIS_ADDRESS not available"}), 500
    assets, err = _resolve_osmo_assets(addr)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"address": addr, "assets": assets or []})


@app.get("/api/osmosis-price")
def osmosis_price():
    """Return spot estimate for ARKEO/USDC from pool 2977."""
    price, err = _osmosis_price_estimate()
    if err:
        return jsonify({"error": err}), 500
    return jsonify(price or {})


@app.post("/api/osmosis-quote-usdc-to-arkeo")
def osmosis_quote_usdc_to_arkeo():
    """Return swap quote for USDC -> ARKEO using pool 2977."""
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    amt = data.get("amount") or data.get("usdc") or data.get("amt")
    try:
        amt_f = float(amt)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    quote, err = _osmosis_quote_usdc_to_arkeo(amt_f)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(quote or {})

@app.post("/api/osmosis-quote-usdc-to-osmo")
def osmosis_quote_usdc_to_osmo():
    """Return swap quote for USDC -> OSMO using pool 678."""
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    amt = data.get("amount") or data.get("usdc") or data.get("amt")
    try:
        amt_f = float(amt)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    quote, err = _osmosis_quote_usdc_to_osmo(amt_f)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(quote or {})

@app.post("/api/osmosis-quote-arkeo-to-usdc")
def osmosis_quote_arkeo_to_usdc():
    """Return swap quote for ARKEO -> USDC using pool 2977."""
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    amt = data.get("amount") or data.get("arkeo") or data.get("amt")
    try:
        amt_f = float(amt)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    quote, err = _osmosis_quote_arkeo_to_usdc(amt_f)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(quote or {})


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
    rest_api_val = os.getenv("ARKEO_REST_API") or os.getenv("EXTERNAL_ARKEO_REST_API") or ""

    base = provider_pubkeys_response(user, keyring_backend)
    address, addr_err = derive_address(user, keyring_backend)
    base.update(
        {
            "fees": fees,
            "bond": bond,
            "sentinel_uri": SENTINEL_URI_DEFAULT,
            "metadata_nonce": METADATA_NONCE_DEFAULT,
            "arkeod_node": ARKEOD_NODE,
            "arkeo_rest_api": rest_api_val,
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
    resp = provider_info().get_json()
    return jsonify(resp)


@app.get("/api/wallets")
def wallets_info():
    """Return wallet addresses for arkeo/eth/osmosis (no mnemonics)."""
    settings = _merge_subscriber_settings()
    _apply_subscriber_settings(settings)
    # derive arkeo address
    address = ""
    try:
        raw_pk, bech32_pk, pub_err = derive_pubkeys(
            settings.get("KEY_NAME") or KEY_NAME, settings.get("KEY_KEYRING_BACKEND") or KEYRING
        )
        address = bech32_pk or ""
    except Exception:
        address = ""
    # ensure eth/osmo addresses (won't regenerate mnemonics here)
    eth_addr = settings.get("ETH_ADDRESS") or ""
    osmo_addr = settings.get("OSMOSIS_ADDRESS") or ""
    return jsonify(
        {
            "arkeo_address": address,
            "eth_address": eth_addr,
            "osmosis_address": osmo_addr,
        }
    )


@app.get("/api/subscriber-settings")
def subscriber_settings_get():
    """Return subscriber settings (replacement for subscriber.env) plus mnemonic if available."""
    settings = _merge_subscriber_settings()
    _apply_subscriber_settings(settings)
    mnemonic, mnemonic_source = _read_hotwallet_mnemonic(settings)
    generated = False
    if mnemonic:
        settings["KEY_MNEMONIC"] = mnemonic
    else:
        code, out, gen_mnemonic = _create_hotwallet(
            settings.get("KEY_NAME") or KEY_NAME,
            settings.get("KEY_KEYRING_BACKEND") or KEYRING,
            _expand_tilde(settings.get("ARKEOD_HOME") or ARKEOD_HOME),
        )
        if code != 0 or not gen_mnemonic:
            return jsonify({"error": "failed to create hotwallet", "detail": out}), 500
        settings["KEY_MNEMONIC"] = gen_mnemonic
        _write_hotwallet_mnemonic(settings, gen_mnemonic)
        _apply_subscriber_settings(settings)
        _write_subscriber_settings_file(settings)
        mnemonic = gen_mnemonic
        mnemonic_source = "generated"
        generated = True
    # Ensure a baseline settings file exists before any further enrichment
    _write_subscriber_settings_file(settings)
    # Ensure ETH/OSMOSIS mnemonics/addresses exist; generate if missing
    settings, eth_err = _ensure_eth_wallet(settings)
    settings, osmo_err = _ensure_osmo_wallet(settings)
    settings.pop("ETH_ERROR", None)
    settings.pop("OSMOSIS_ERROR", None)
    _write_subscriber_settings_file(settings)
    _apply_subscriber_settings(settings)
    raw_pk, bech32_pk, pub_err = derive_pubkeys(
        settings.get("KEY_NAME") or KEY_NAME, settings.get("KEY_KEYRING_BACKEND") or KEYRING
    )
    _write_subscriber_settings_file(settings)
    return jsonify(
        {
            "settings": settings,
            "subscriber_settings_path": SUBSCRIBER_SETTINGS_PATH,
            "mnemonic_source": mnemonic_source,
            "mnemonic_found": bool(mnemonic),
            "mnemonic_generated": generated,
            "pubkey": {"raw": raw_pk, "bech32": bech32_pk, "error": pub_err},
            "eth_rpc": ETH_RPC,
            "osmosis_rpc": OSMOSIS_RPC,
            "eth_error": eth_err,
            "osmosis_error": osmo_err,
        }
    )

@app.get("/api/subscriber-settings/exists")
def subscriber_settings_exists():
    """Return whether subscriber-settings.json exists (without creating it)."""
    exists = bool(SUBSCRIBER_SETTINGS_PATH and os.path.isfile(SUBSCRIBER_SETTINGS_PATH))
    return jsonify({"exists": exists})


@app.post("/api/subscriber-settings")
def subscriber_settings_save():
    """Persist subscriber settings and optionally rotate hotwallet mnemonic."""
    payload = request.get_json(force=True, silent=True) or {}
    incoming = payload.get("settings") if isinstance(payload, dict) else None
    data = incoming if isinstance(incoming, dict) else payload
    if not isinstance(data, dict):
        return jsonify({"error": "invalid payload"}), 400

    merged = _merge_subscriber_settings(data)
    new_mnemonic = (data.get("KEY_MNEMONIC") or data.get("mnemonic") or "").strip()
    current_mnemonic, mnemonic_source = _read_hotwallet_mnemonic(merged)
    rotate = bool(new_mnemonic)
    delete_result: tuple[int, str] | None = None
    import_result: tuple[int, str] | None = None

    if rotate:
        delete_result = _delete_hotwallet(
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            _expand_tilde(merged.get("ARKEOD_HOME") or ARKEOD_HOME),
        )
        delete_code, delete_out = delete_result
        if delete_code not in (0, 1) and "not found" not in delete_out.lower():
            return jsonify({"error": "failed to delete existing hotwallet", "detail": delete_out}), 500

        import_result = _import_hotwallet_from_mnemonic(
            new_mnemonic,
            merged.get("KEY_NAME") or KEY_NAME,
            merged.get("KEY_KEYRING_BACKEND") or KEYRING,
            _expand_tilde(merged.get("ARKEOD_HOME") or ARKEOD_HOME),
        )
        import_code, import_out = import_result
        if import_code != 0:
            return jsonify({"error": "failed to import hotwallet from mnemonic", "detail": import_out}), 500
        merged["KEY_MNEMONIC"] = new_mnemonic
    else:
        merged["KEY_MNEMONIC"] = current_mnemonic

    _apply_subscriber_settings(merged)
    if merged.get("KEY_MNEMONIC"):
        _write_hotwallet_mnemonic(merged, merged["KEY_MNEMONIC"])
    # Ensure ETH/OSMO wallets (generate if blank) and persist
    merged, eth_err = _ensure_eth_wallet(merged)
    merged, osmo_err = _ensure_osmo_wallet(merged)
    merged.pop("ETH_ERROR", None)
    merged.pop("OSMOSIS_ERROR", None)
    _write_subscriber_settings_file(merged)

    raw_pk, bech32_pk, pub_err = derive_pubkeys(
        merged.get("KEY_NAME") or KEY_NAME, merged.get("KEY_KEYRING_BACKEND") or KEYRING
    )
    return jsonify(
        {
            "settings": merged,
            "subscriber_settings_path": SUBSCRIBER_SETTINGS_PATH,
            "mnemonic_source": "rotated" if rotate else mnemonic_source,
            "mnemonic_rotated": rotate,
            "delete_result": delete_result,
            "import_result": import_result,
            "pubkey": {"raw": raw_pk, "bech32": bech32_pk, "error": pub_err},
            "eth_error": eth_err,
            "osmosis_error": osmo_err,
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
    # If a password is set, require valid session to change it
    if _is_auth_required() and not _validate_session(request.cookies.get(ADMIN_SESSION_NAME)):
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
    recovered: dict | None = None
    try:
        with open(LISTENERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("listeners"), list):
                return data
    except (OSError, json.JSONDecodeError) as e:
        # If the file exists but is malformed, back it up instead of overwriting silently
        try:
            if os.path.isfile(LISTENERS_FILE):
                # Capture a small preview of the broken payload to help debugging
                try:
                    with open(LISTENERS_FILE, "r", encoding="utf-8", errors="replace") as rf:
                        raw_preview = rf.read(2048)
                except Exception:
                    raw_preview = ""
                ts = int(time.time())
                backup = f"{LISTENERS_FILE}.bad.{ts}"
                os.rename(LISTENERS_FILE, backup)
                # Try to salvage from the backup copy so we don't wipe existing listeners
                try:
                    with open(backup, "r", encoding="utf-8") as bf:
                        data = json.load(bf)
                        if isinstance(data, dict) and isinstance(data.get("listeners"), list):
                            recovered = data
                            _write_listeners(recovered)
                            return recovered
                except Exception:
                    recovered = None
                try:
                    print(
                        f"[listeners] malformed listeners.json, backed up to {backup}; "
                        f"error={e}; preview={raw_preview!r}"
                    )
                except Exception:
                    pass
        except Exception:
            pass
    if recovered is not None:
        return recovered
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
    tmp_path = f"{path}.tmp.{os.getpid()}.{int(time.time() * 1000)}"
    lock_path = f"{path}.lock"
    lock_fh = None
    # Acquire simple file lock to avoid concurrent writers corrupting JSON
    try:
        import fcntl  # POSIX-only; acceptable in this environment

        lock_fh = open(lock_path, "w")
        deadline = time.time() + 3.0  # 3s timeout
        while True:
            try:
                fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    try:
                        print(f"[listeners] write lock timeout for {path}")
                    except Exception:
                        pass
                    if lock_fh:
                        lock_fh.close()
                    return
                time.sleep(0.05)
    except Exception as e:
        try:
            print(f"[listeners] lock acquire failed: {e}")
        except Exception:
            pass
        if lock_fh:
            try:
                lock_fh.close()
            except Exception:
                pass
        # proceed without lock to avoid total failure, but still attempt write
        lock_fh = None
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=True, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        try:
            print(f"[listeners] wrote {path} (tmp={tmp_path})")
        except Exception:
            pass
    except OSError as e:
        try:
            print(f"[listeners] write failed: {e}")
        except Exception:
            pass
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
    finally:
        if lock_fh:
            try:
                import fcntl as _fcntl  # already imported; guard if missing

                _fcntl.flock(lock_fh, _fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_fh.close()
            except Exception:
                pass


def _normalize_top_services(entries) -> list[dict]:
    """Normalize top_services entries to the current on-disk shape."""
    normalized: list[dict] = []
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict):
            continue
        pk = item.get("provider_pubkey") or item.get("pubkey")
        svc = item.get("service_id") if item.get("service_id") is not None else item.get("service")
        if not pk:
            continue
        entry: dict = {
            "provider_pubkey": str(pk),
        }
        # keep service id for dedup/lookup, but avoid padding with empty string
        if svc not in (None, ""):
            entry["service_id"] = str(svc)
        # Persist only dynamic/runtime fields; static metadata is hydrated from caches.
        for key in (
            "status",
            "status_updated_at",
            "rt_avg_ms",
            "rt_count",
            "rt_last_ms",
            "rt_updated_at",
        ):
            if key in item:
                entry[key] = item.get(key)
        normalized.append(entry)
    return normalized


def _provider_moniker_from_meta(p: dict | None) -> str | None:
    if not isinstance(p, dict):
        return None
    meta = p.get("metadata") or {}
    moniker = (
        (meta.get("config") or {}).get("moniker")
        or meta.get("moniker")
        or (p.get("provider") or {}).get("moniker")
        or p.get("provider_moniker")
    )
    return moniker or None


def _build_active_maps():
    """Return (active_map, provider_meta_map, svc_lookup) for enrichment."""
    active_map = {}
    provider_meta_map = {}
    try:
        data = _load_cached("active_services")
        entries = data.get("active_services") if isinstance(data, dict) else []
        if isinstance(entries, list):
            for e in entries:
                if not isinstance(e, dict):
                    continue
                pk = e.get("provider_pubkey")
                sid_val = e.get("service_id") or e.get("service") or e.get("id")
                if pk is None or sid_val is None:
                    continue
                active_map[(str(pk), str(sid_val))] = e
    except Exception:
        pass
    try:
        ap = _load_cached("active_providers")
        prov_list = ap.get("providers") if isinstance(ap, dict) else []
        if isinstance(prov_list, list):
            for p in prov_list:
                if not isinstance(p, dict):
                    continue
                pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
                if pk:
                    provider_meta_map[pk] = p
    except Exception:
        pass
    svc_lookup = _load_active_service_types_lookup()
    return active_map, provider_meta_map, svc_lookup


def _enrich_top_services_for_response(top: list, svc_id: str, active_map: dict, provider_meta_map: dict) -> list:
    """Enrich top_services entries with cache data for responses (not persisted)."""
    enriched: list[dict] = []
    sid_str = str(svc_id or "")
    for ts in top if isinstance(top, list) else []:
        if not isinstance(ts, dict):
            continue
        pk = ts.get("provider_pubkey")
        entry = dict(ts)
        key = (str(pk), sid_str)
        active = active_map.get(key) or {}
        raw = active.get("raw") if isinstance(active, dict) else {}
        if not entry.get("metadata_uri"):
            entry["metadata_uri"] = active.get("metadata_uri") or (raw.get("metadata_uri") if isinstance(raw, dict) else None)
        if not entry.get("sentinel_url"):
            mu = entry.get("metadata_uri")
            if _is_external(mu):
                entry["sentinel_url"] = _sentinel_from_metadata_uri(mu)
        if not entry.get("provider_moniker"):
            entry["provider_moniker"] = _provider_moniker_from_meta(provider_meta_map.get(pk)) or _active_provider_moniker(pk) or pk
        if "pay_as_you_go_rate" not in entry or entry.get("pay_as_you_go_rate") is None:
            if isinstance(raw, dict):
                entry["pay_as_you_go_rate"] = _extract_paygo_rate(raw)
        if entry.get("queries_per_minute") is None and isinstance(raw, dict):
            entry["queries_per_minute"] = raw.get("queries_per_minute")
        if entry.get("min_contract_duration") is None and isinstance(raw, dict):
            entry["min_contract_duration"] = raw.get("min_contract_duration")
        if entry.get("max_contract_duration") is None and isinstance(raw, dict):
            entry["max_contract_duration"] = raw.get("max_contract_duration")
        if entry.get("settlement_duration") is None and isinstance(raw, dict):
            entry["settlement_duration"] = raw.get("settlement_duration")
        enriched.append(entry)
    return enriched


def _enrich_listener_for_response(listener: dict) -> dict:
    """Return a copy of listener enriched with cache data for API responses."""
    if not isinstance(listener, dict):
        return {}
    l = dict(listener)
    active_map, provider_meta_map, svc_lookup = _build_active_maps()
    sid = l.get("service_id") or l.get("service")
    top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
    l["top_services"] = _enrich_top_services_for_response(top, sid, active_map, provider_meta_map)
    # for response only: set provider_pubkey to primary top entry for compatibility with UI/runtime
    if l["top_services"]:
        primary = l["top_services"][0]
        if isinstance(primary, dict):
            l["provider_pubkey"] = primary.get("provider_pubkey")
    svc_meta = svc_lookup.get(str(sid) or "", {})
    if svc_meta:
        l.setdefault("service_name", svc_meta.get("service_name", ""))
        l.setdefault("service_description", svc_meta.get("service_description", ""))
    # hydrate primary provider moniker/sentinel for UI convenience
    if not l.get("provider_moniker") and l.get("provider_pubkey"):
        l["provider_moniker"] = _provider_moniker_from_meta(provider_meta_map.get(l.get("provider_pubkey"))) or _active_provider_moniker(l.get("provider_pubkey"))
    if not l.get("sentinel_url") and l.get("top_services"):
        primary = l["top_services"][0]
        if isinstance(primary, dict):
            sent = primary.get("sentinel_url")
            if not sent:
                mu = primary.get("metadata_uri")
                if _is_external(mu):
                    sent = _sentinel_from_metadata_uri(mu)
            if sent:
                l["sentinel_url"] = sent
    if not l.get("health_method"):
        l["health_method"] = "POST"
    if l.get("health_payload") is None:
        l["health_payload"] = ""
    if l.get("health_header") is None:
        l["health_header"] = ""
    return l
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
    sentinel_url = _normalize_sentinel_url(sentinel_url or SENTINEL_URI_DEFAULT)
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
    floor = _load_port_floor()
    for p in range(floor, LISTENER_PORT_END + 1):
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


@app.post("/api/listener-port-start")
def set_listener_port_start():
    """Set the minimum port for listeners (must be within allowed range)."""
    payload = request.get_json(silent=True) or {}
    try:
        start_port = int(payload.get("start_port"))
    except Exception:
        return jsonify({"error": "invalid_start_port"}), 400
    if start_port < LISTENER_PORT_START or start_port > LISTENER_PORT_END:
        return jsonify({"error": f"start_port must be between {LISTENER_PORT_START} and {LISTENER_PORT_END}"}), 400
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    listeners = listeners if isinstance(listeners, list) else []
    for l in listeners:
        try:
            pval = int(l.get("port"))
            if pval < start_port:
                return jsonify({"error": "start_port_below_existing", "detail": f"listener port {pval} is below requested start_port"}), 400
        except Exception:
            continue
    _save_port_floor(start_port)
    used = _collect_used_ports(listeners)
    return jsonify({
        "port_floor": start_port,
        "port_range": [start_port, LISTENER_PORT_END],
        "next_port": _next_available_port(used),
    })


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


def _normalize_sentinel_url(url: str | None) -> str | None:
    """Return a sentinel base URL without metadata.json suffix."""
    if not url:
        return None
    url = url.strip()
    if url.endswith("metadata.json") or url.rstrip("/").endswith("metadata.json"):
        return _sentinel_from_metadata_uri(url)
    return url


def _active_provider_moniker(provider_pubkey: str | None) -> str | None:
    """Lookup provider moniker from active_providers cache."""
    if not provider_pubkey:
        return None
    try:
        data = _load_cached("active_providers")
    except Exception:
        return None
    prov_list = data.get("providers") if isinstance(data, dict) else []
    if not isinstance(prov_list, list):
        return None
    for p in prov_list:
        if not isinstance(p, dict):
            continue
        pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
        if str(pk) != str(provider_pubkey):
            continue
        meta = p.get("metadata") or {}
        try:
            cfg = meta.get("config") or {}
            mon = cfg.get("moniker") or meta.get("moniker")
            if mon:
                return mon
        except Exception:
            pass
    return None


def _active_service_lookup(provider_pubkey: str | None, service_id: str | int | None) -> dict:
    """Lookup active_services entry by provider/service from cache."""
    if not provider_pubkey or service_id is None:
        return {}
    try:
        data = _load_cached("active_services")
    except Exception:
        return {}
    entries = data.get("active_services") if isinstance(data, dict) else []
    if not isinstance(entries, list):
        return {}
    sid_str = str(service_id)
    for e in entries:
        if not isinstance(e, dict):
            continue
        pk = e.get("provider_pubkey")
        sid_val = e.get("service_id") or e.get("service") or e.get("id")
        if str(pk) == str(provider_pubkey) and str(sid_val) == sid_str:
            return e
    return {}


def _extract_paygo_rate(raw: dict) -> dict | None:
    """Return a single pay-as-you-go rate dict if available."""
    if not isinstance(raw, dict):
        return None
    rates = raw.get("pay_as_you_go_rate") or raw.get("pay_as_you_go_rates")
    if isinstance(rates, list) and rates:
        item = rates[0]
        return item if isinstance(item, dict) else None
    if isinstance(rates, dict):
        return rates
    return None


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
    if not top:
        return []
    svc_id_for_lookup = cfg.get("service_id") or cfg.get("service")
    # cache lookups for active services/providers
    active_lookup = {}
    try:
        data = _load_cached("active_services")
        entries = data.get("active_services") if isinstance(data, dict) else []
        if isinstance(entries, list):
            for e in entries:
                if not isinstance(e, dict):
                    continue
                pk = e.get("provider_pubkey")
                sid_val = e.get("service_id") or e.get("service") or e.get("id")
                if not pk or sid_val is None:
                    continue
                active_lookup[(str(pk), str(sid_val))] = e
    except Exception:
        pass
    prov_meta_cache = {}
    try:
        ap = _load_cached("active_providers")
        prov_list = ap.get("providers") if isinstance(ap, dict) else []
        if isinstance(prov_list, list):
            for p in prov_list:
                if not isinstance(p, dict):
                    continue
                    # skip bad rows
                pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
                if pk:
                    prov_meta_cache[pk] = p
    except Exception:
        pass
    if isinstance(top, list):
        for ts in top:
            if not isinstance(ts, dict):
                continue
            ts_status = str(ts.get("status") or "").lower()
            if ts_status == "down":
                continue
            pk = ts.get("provider_pubkey")
            if not pk:
                continue
            svc_for_ts = ts.get("service_id") or ts.get("service") or svc_id_for_lookup
            active = active_lookup.get((str(pk), str(svc_for_ts))) or _active_service_lookup(pk, svc_for_ts)
            active_raw = active.get("raw") if isinstance(active, dict) else {}
            mu = (active.get("metadata_uri") if isinstance(active, dict) else None) or active_raw.get("metadata_uri")
            sentinel_url = _normalize_sentinel_url(ts.get("sentinel_url")) if ts.get("sentinel_url") else None
            if not sentinel_url and _is_external(mu):
                sentinel_url = _sentinel_from_metadata_uri(mu)
            if not sentinel_url:
                # fallback: try parent cfg sentinel
                sentinel_url = _normalize_sentinel_url(cfg.get("provider_sentinel_api"))
            if not sentinel_url:
                continue  # skip candidates without a usable sentinel URL
            settle = (
                (active.get("settlement_duration") if isinstance(active, dict) else None)
                or (active_raw.get("settlement_duration") if isinstance(active_raw, dict) else None)
                or _lookup_settlement_duration(pk, svc_for_ts)
            )
            rate = _extract_paygo_rate(active_raw) if isinstance(active_raw, dict) else None
            qpm = active_raw.get("queries_per_minute") if isinstance(active_raw, dict) else None
            min_dur = active_raw.get("min_contract_duration") if isinstance(active_raw, dict) else None
            max_dur = active_raw.get("max_contract_duration") if isinstance(active_raw, dict) else None
            moniker = _active_provider_moniker(pk)
            if not moniker and pk in prov_meta_cache:
                meta = prov_meta_cache[pk].get("metadata") or {}
                moniker = (meta.get("config") or {}).get("moniker") or meta.get("moniker")
            candidates.append(
                {
                    "provider_pubkey": pk,
                    "provider_moniker": moniker,
                    "sentinel_url": sentinel_url,
                    "settlement_duration": settle,
                    "pay_as_you_go_rate": rate,
                    "queries_per_minute": qpm,
                    "min_contract_duration": min_dur,
                    "max_contract_duration": max_dur,
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
    # Prefer top_services ordering first
    top = listener.get("top_services") or []
    for ts in top if isinstance(top, list) else []:
        if not isinstance(ts, dict):
            continue
        ts_status = str(ts.get("status") or "").lower()
        if ts_status == "down":
            continue
        pk = ts.get("provider_pubkey") or listener.get("provider_pubkey")
        sent = ts.get("sentinel_url")
        mon = ts.get("provider_moniker") or listener.get("provider_moniker")
        meta_uri = ts.get("metadata_uri")
        if not sent and _is_external(meta_uri):
            sent = _sentinel_from_metadata_uri(meta_uri)
        sent = _normalize_sentinel_url(sent)
        if pk and sent:
            return pk, sent, mon
    # Fall back to stored values
    pk = listener.get("provider_pubkey")
    sent = _normalize_sentinel_url(listener.get("sentinel_url"))
    mon = listener.get("provider_moniker")
    if pk and sent:
        return pk, sent, mon
    # Try active_services cache for sentinel/moniker
    try:
        svc_id = listener.get("service_id") or listener.get("service")
        active = _active_service_lookup(pk, svc_id)
        if active:
            mu = active.get("metadata_uri") or (active.get("raw") or {}).get("metadata_uri")
            if _is_external(mu):
                sent = _sentinel_from_metadata_uri(mu)
            if not mon:
                mon = _active_provider_moniker(pk)
            if pk and sent:
                return pk, sent, mon
    except Exception:
        pass
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


def _nonce_cache_key(contract_id: str, client_pub: str) -> str:
    return f"{contract_id}:{client_pub}"


def _next_nonce_cached(contract_id: str, client_pub: str) -> int | None:
    key = _nonce_cache_key(contract_id, client_pub)
    with _NONCE_LOCK:
        if key not in _NONCE_CACHE:
            return None
        _NONCE_CACHE[key] += 1
        return _NONCE_CACHE[key]


def _seed_nonce_cache(contract_id: str, client_pub: str, highest_nonce: int) -> int:
    key = _nonce_cache_key(contract_id, client_pub)
    with _NONCE_LOCK:
        _NONCE_CACHE[key] = highest_nonce
        return _NONCE_CACHE[key]


def _peek_nonce_cache(contract_id: str, client_pub: str) -> int | None:
    key = _nonce_cache_key(contract_id, client_pub)
    with _NONCE_LOCK:
        return _NONCE_CACHE.get(key)


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


def _forward_to_sentinel(
    sentinel: str,
    service_path: str,
    body: bytes | None,
    arkauth: str,
    timeout: int = PROXY_TIMEOUT_SECS,
    as_header: bool = False,
    method: str = "POST",
    query_string: str | None = None,
) -> tuple[int, bytes, dict, str, dict]:
    """Forward the request to the sentinel, supporting POST and GET."""
    method = (method or "POST").upper()
    url = f"{sentinel.rstrip('/')}/{service_path.lstrip('/')}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    final_headers = dict(headers)
    qs = query_string or ""
    if qs and qs.startswith("?"):
        qs = qs[1:]
    if as_header:
        final_headers["arkauth"] = arkauth
    else:
        # Append arkauth to existing query, preserving any user-supplied params
        qs_parts = []
        if qs:
            qs_parts.append(qs)
        qs_parts.append(f"arkauth={urllib.parse.quote(arkauth, safe='')}")
        url = f"{url}?{'&'.join(qs_parts)}" if qs_parts else url
    # For GET we must not send a body or urllib will coerce to POST.
    data_bytes = body if method != "GET" else None
    req = urllib.request.Request(url, data=data_bytes, headers=final_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.getheaders()), url, final_headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers), url, final_headers
    except Exception as e:
        return (
            502,
            json.dumps({"error": "proxy_upstream_error", "detail": str(e)}).encode(),
            {"Content-Type": "application/json"},
            url,
            final_headers,
        )


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
        try:
            origin = self.headers.get("Origin")
        except Exception:
            origin = None
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
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
        # Special status endpoint for health of the listener itself (use /arkeostatus to avoid intercepting upstream /status)
        if self.path.strip("/").split("?")[0] == "arkeostatus":
            cfg = self.server.cfg
            node = cfg.get("node_rpc") or ARKEOD_NODE
            service_id = cfg.get("service_id")
            service_name = cfg.get("service_name")
            client_key = cfg.get("client_key") or KEY_NAME
            client_pub_local = getattr(self.server, "client_pubkey", "") or ""
            if not client_pub_local:
                raw, bech, err = derive_pubkeys(client_key, KEYRING)
                if not err:
                    client_pub_local = bech
                    self.server.client_pubkey = bech
            payload = {
                "client_pub_local": client_pub_local,
                "active_contract": getattr(self.server, "active_contract", None),
                "last_code": getattr(self.server, "last_code", None),
                "last_nonce": getattr(self.server, "last_nonce", None),
                "provider_pubkey": cfg.get("provider_pubkey"),
                "service_id": service_id,
                "service_name": service_name,
                "sentinel": cfg.get("provider_sentinel_api"),
                "height": None,
                "active_contract_provider_moniker": None,
            }
            try:
                payload["height"] = _get_current_height(node)
            except Exception:
                payload["height"] = None

            # If we don't already have an active_contract cached, try to select one
            if not payload.get("active_contract"):
                try:
                    cur_h = _get_current_height(node)
                    # ensure contract cache map
                    if not hasattr(self.server, "contract_cache"):
                        self.server.contract_cache = {}
                    contract_cache = self.server.contract_cache

                    candidates = _candidate_providers(cfg)
                    provider_filter = None
                    sentinel = None
                    if candidates:
                        provider_filter = candidates[0].get("provider_pubkey") or cfg.get("provider_pubkey")
                        sentinel = candidates[0].get("sentinel_url") or cfg.get("provider_sentinel_api")
                    if not provider_filter:
                        provider_filter = cfg.get("provider_pubkey")
                    active = None
                    cache_entry = contract_cache.get(provider_filter) if provider_filter else None
                    if cache_entry:
                        ttl_ok = PROXY_CONTRACT_CACHE_TTL <= 0 or (time.time() - cache_entry.get("cached_at", 0) < PROXY_CONTRACT_CACHE_TTL)
                        if ttl_ok:
                            active = cache_entry.get("contract")
                    if not active:
                        contracts = _fetch_contracts(node, timeout=PROXY_CONTRACT_TIMEOUT, active_only=True, client_filter=client_pub_local)
                        active = _select_active_contract(contracts or [], client_pub_local, _safe_int(service_id, 0), cur_h, provider_filter=provider_filter)
                        if active and provider_filter:
                            try:
                                contract_cache[provider_filter] = {"contract": active, "cached_at": time.time()}
                            except Exception:
                                pass
                    if active:
                        payload["active_contract"] = active
                        try:
                            pm = _active_provider_moniker(active.get("provider"))
                            if pm:
                                payload["active_contract_provider_moniker"] = pm
                                active = dict(active)
                                active["provider_moniker"] = pm
                                payload["active_contract"] = active
                        except Exception:
                            pass
                        payload["active_contract_detail"] = "Active contract found for the selected provider service."
                        if provider_filter:
                            payload["provider_pubkey"] = provider_filter
                        try:
                            self.server.active_contract = active
                            if hasattr(self.server, "active_contracts") and provider_filter:
                                self.server.active_contracts[provider_filter] = active
                        except Exception:
                            pass
                        # try to pick last nonce if cached
                        try:
                            if hasattr(self.server, "last_nonce_cache"):
                                last_nc = self.server.last_nonce_cache
                                if isinstance(last_nc, dict):
                                    payload["last_nonce"] = last_nc.get(str(active.get("id")))
                        except Exception:
                            pass
                    else:
                        payload["active_contract_detail"] = "No active contract found for the selected provider service."
                except Exception as e:
                    payload["active_contract_detail"] = f"Failed to load contract: {e}"

            # If we already had an active_contract cached, still try to enrich with moniker
            if payload.get("active_contract") and not payload.get("active_contract_provider_moniker"):
                try:
                    pm = _active_provider_moniker(payload["active_contract"].get("provider"))
                    if pm:
                        payload["active_contract_provider_moniker"] = pm
                        ac = dict(payload["active_contract"])
                        ac["provider_moniker"] = pm
                        payload["active_contract"] = ac
                except Exception:
                    pass

            return self._send_json(200, payload)
        # Forward GET requests through the same payg flow (needed for REST-style services/tests)
        try:
            return self._do_post_inner(method="GET")
        except Exception as e:
            tb = traceback.format_exc()
            self._log("error", f"unhandled proxy exception (GET): {e}\n{tb}")
            return self._send_json(502, {"error": "proxy_exception", "detail": str(e)})

    def do_POST(self):
        try:
            return self._do_post_inner()
        except Exception as e:
            tb = traceback.format_exc()
            try:
                last = getattr(self.server, "last_candidate", {}) if hasattr(self.server, "last_candidate") else {}
                last_nonce = getattr(self.server, "last_nonce", None)
                last_nonce_source = getattr(self.server, "last_nonce_source", None)
            except Exception:
                last, last_nonce, last_nonce_source = {}, None, None
            self._log("error", f"unhandled proxy exception: {e}\n{tb}")
            payload = {
                "error": "proxy_exception",
                "detail": str(e),
                "sentinel": last.get("sentinel"),
                "provider": last.get("provider"),
                "service_id": last.get("service_id"),
                "service_name": last.get("service_name"),
                "last_nonce": last_nonce,
                "last_nonce_source": last_nonce_source,
            }
            return self._send_json(502, payload)

    def _do_post_inner(self, method: str = "POST"):
        cfg = self.server.cfg
        node = cfg.get("node_rpc") or ARKEOD_NODE
        sentinel = cfg.get("provider_sentinel_api") or SENTINEL_URI_DEFAULT
        service = cfg.get("service_name") or cfg.get("service_slug") or cfg.get("service_id") or ""
        svc_id = _safe_int(cfg.get("service_id"), 0)
        client_key = cfg.get("client_key") or KEY_NAME
        method = (method or "POST").upper()
        parsed_path = urllib.parse.urlparse(self.path or "/")
        incoming_path = parsed_path.path or "/"
        service_path = service
        orig_query = parsed_path.query or ""
        if method == "GET":
            # Preserve path after the service name for REST-style GETs
            path_no_slash = incoming_path[1:] if incoming_path.startswith("/") else incoming_path
            if service and path_no_slash.startswith(service):
                remainder = path_no_slash[len(service):]
                remainder = remainder[1:] if remainder.startswith("/") else remainder
            else:
                remainder = path_no_slash
            if remainder:
                service_path = f"{service}/{remainder}" if service else remainder
        try:
            length = _safe_int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        if method == "GET":
            body = b""
        else:
            body = self.rfile.read(length) if length > 0 else b"{}"
        response_time_sec = 0
        t_total_start = time.time()
        self._log("info", f"req start service={service} svc_id={svc_id} bytes={len(body)} method={method}")

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
        nonce_ms = 0
        overhead_ms = 0
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
            if method != "GET":
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
                if active:
                    try:
                        self._log("info", f"using active contract id={active.get('id')} height={active.get('height')} provider={active.get('provider')}")
                    except Exception:
                        pass

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

            # Optimistic nonce: use cached counter; on nonce failure, sync from sentinel once and retry
            # Seed nonce cache from persisted value if available
            try:
                persisted_nonce = _read_persisted_nonce(cfg.get("listener_id"), cid)
                if persisted_nonce is not None:
                    _seed_nonce_cache(cid, contract_client, persisted_nonce)
            except Exception:
                pass

            nonce_start = time.time()
            nonce_source = "cache"
            nonce_cache_prev = _peek_nonce_cache(cid, contract_client)
            nonce = _next_nonce_cached(cid, contract_client)
            if nonce is None:
                nonce_source = "sentinel"
                nonce = _claims_highest_nonce(sentinel, cid, contract_client) + 1
                _seed_nonce_cache(cid, contract_client, nonce)
            nonce_ms = int((time.time() - nonce_start) * 1000)
            try:
                self.server.last_nonce = nonce
                self.server.last_nonce_source = nonce_source
                self.server.last_nonce_cache = _peek_nonce_cache(cid, contract_client)
                self.server.last_candidate = {
                    "provider": provider_filter,
                    "sentinel": sentinel,
                    "service_id": svc_id,
                    "service_name": service,
                }
            except Exception:
                pass

            forward_start_time = None

            def _sign_and_forward(nonce_val: int):
                nonlocal forward_ms, forward_start_time
                sign_start = time.time()
                sig_hex_local, sig_err_local = _sign_message(
                    client_key, cid, nonce_val, cfg.get("sign_template", PROXY_SIGN_TEMPLATE)
                )
                sign_ms_local = int((time.time() - sign_start) * 1000)
                if not sig_hex_local:
                    return None, None, sig_err_local, sign_ms_local
                arkauth4 = f"{cid}:{contract_client}:{nonce_val}:{sig_hex_local}"
                self._log("info", f"forwarding 4-part to sentinel={sentinel} svc={service} cid={cid} nonce={nonce_val} provider={provider_filter}")
                forward_start_time = time.time()
                code_local, resp_body_local, resp_hdrs_local, fwd_url_local, fwd_headers_local = _forward_to_sentinel(
                    sentinel,
                    service_path,
                    body,
                    arkauth4,
                    timeout=_safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS),
                    as_header=bool(cfg.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER)),
                    method=method,
                    query_string=orig_query,
                )
                try:
                    body_preview = body.decode(errors="ignore")[:200] if isinstance(body, (bytes, bytearray)) else str(body)[:200]
                    self._log(
                        "info",
                        f"sentinel request url={fwd_url_local} headers={json.dumps(fwd_headers_local)} body_preview={body_preview}",
                    )
                except Exception:
                    pass
                if code_local == 401:
                    self._log("warning", "401 on 4-part arkauth -> retrying 3-part")
                    arkauth3 = f"{cid}:{nonce_val}:{sig_hex_local}"
                    code_local, resp_body_local, resp_hdrs_local, fwd_url_local, fwd_headers_local = _forward_to_sentinel(
                        sentinel,
                        service_path,
                        body,
                        arkauth3,
                        timeout=_safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS),
                        as_header=bool(cfg.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER)),
                        method=method,
                        query_string=orig_query,
                    )
                    try:
                        body_preview = body.decode(errors="ignore")[:200] if isinstance(body, (bytes, bytearray)) else str(body)[:200]
                        self._log(
                            "info",
                            f"sentinel request (3-part) url={fwd_url_local} headers={json.dumps(fwd_headers_local)} body_preview={body_preview}",
                        )
                    except Exception:
                        pass
                forward_ms = int((time.time() - forward_start_time) * 1000)
                try:
                    self.server.last_upstream = {
                        "code": code_local,
                        "body": resp_body_local.decode(errors="ignore") if isinstance(resp_body_local, (bytes, bytearray)) else str(resp_body_local),
                        "url": fwd_url_local,
                        "headers": fwd_headers_local,
                        "method": method,
                    }
                except Exception:
                    pass
                return code_local, resp_body_local, sig_hex_local, sign_ms_local

            code, resp_body, sig_hex, sign_ms = _sign_and_forward(nonce)

            # On nonce/auth failure, sync from sentinel and retry once
            def _is_nonce_error(code_val, body_val):
                if code_val in (401, 403):
                    return True
                if isinstance(body_val, (bytes, bytearray)) and b"nonce" in body_val:
                    return True
                if isinstance(body_val, str) and "nonce" in body_val.lower():
                    return True
                return False

            if _is_nonce_error(code, resp_body):
                try:
                    highest = _claims_highest_nonce(sentinel, cid, contract_client)
                    _seed_nonce_cache(cid, contract_client, highest + 1)
                    nonce = highest + 1
                    nonce_source = "retry"
                    code, resp_body, sig_hex, sign_ms = _sign_and_forward(nonce)
                except Exception as e:
                    sig_hex = None
                    sig_err = str(e)
                    sign_ms = sign_ms or 0

            if not sig_hex:
                self._log("error", f"sign_failed: {sig_err} timing_ms fetch={fetch_ms} select_ms={select_ms} nonce_ms={nonce_ms} sign_ms={sign_ms}")
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
            # persist last response info for UI/debug regardless of success
            self.server.last_code = code
            self.server.last_nonce = nonce
            self.server.last_nonce_source = nonce_source
            try:
                self.server.last_nonce_cache = _peek_nonce_cache(cid, contract_client)
                _persist_listener_nonce(cfg.get("listener_id"), cid, nonce)
            except Exception:
                self.server.last_nonce_cache = None
            success = code is not None and 200 <= int(code) < 300

            if success:
                # response time for the actual forward; fall back to total if missing
                base_start = forward_start_time or t_total_start
                response_time_sec = time.time() - base_start
                total_time_sec = time.time() - t_total_start
                # Prefer total time for metrics if available
                if total_time_sec > response_time_sec:
                    response_time_sec = total_time_sec
                if forward_ms == 0 and forward_start_time:
                    forward_ms = int((time.time() - forward_start_time) * 1000)
                # Everything outside the measured buckets
                measured = fetch_ms + select_ms + nonce_ms + sign_ms + forward_ms
                overhead_ms = max(0, int(total_time_sec * 1000) - measured)

                self._log(
                    "info",
                    (
                        "timings total_ms=%d fetch_ms=%d select_ms=%d nonce_ms=%d sign_ms=%d "
                        "forward_ms=%d overhead_ms=%d auto_create=%s"
                    )
                    % (
                        int(total_time_sec * 1000),
                        fetch_ms,
                        select_ms,
                        nonce_ms,
                        sign_ms,
                        forward_ms,
                        overhead_ms,
                        auto_created_this_request,
                    ),
                )
            else:
                # Do not record timings on failure; mark the provider down
                response_time_sec = 0
                if forward_ms == 0 and forward_start_time:
                    forward_ms = int((time.time() - forward_start_time) * 1000)
                try:
                    body_preview = ""
                    if isinstance(resp_body, (bytes, bytearray)):
                        body_preview = resp_body.decode(errors="ignore")
                    else:
                        body_preview = str(resp_body)
                    if len(body_preview) > 400:
                        body_preview = body_preview[:400] + "...[truncated]"
                except Exception:
                    body_preview = ""
                self._log("warning", f"forward failed code={code} provider={provider_filter} sentinel={sentinel}; not recording timings body='{body_preview}'")
                try:
                    _set_top_service_status(cfg.get("listener_id"), provider_filter, "Down")
                except Exception:
                    pass

            meta_full = _build_arkeo_meta_clean(active, nonce, svc_id, service, provider_filter, contract_client, sentinel, response_time_sec)
            # success → clear cooldown for this provider
            if provider_filter in cooldowns:
                try:
                    del cooldowns[provider_filter]
                except Exception:
                    pass
            if success:
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
                if success:
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

                try:
                    prev = getattr(self.server, "last_upstream", {}) if hasattr(self.server, "last_upstream") else {}
                    merged_last = {"code": code, "body": body_text}
                    if isinstance(prev, dict):
                        for k in ("url", "headers", "method"):
                            if k in prev:
                                merged_last[k] = prev[k]
                    self.server.last_upstream = merged_last
                except Exception:
                    pass

                if decorate:
                    try:
                        upstream = json.loads(body_text)
                    except Exception:
                        upstream = body_text
                    if isinstance(upstream, dict):
                        merged = dict(upstream)
                        merged["arkeo"] = meta_full
                        return self._send_json(code, merged)
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

            # non-success upstream: return the upstream response (no failover)
            last_err = f"upstream_status_{code}"
            last_meta = _build_arkeo_meta_clean(active, nonce, svc_id, service, provider_filter, contract_client, sentinel, 0)
            try:
                prev = getattr(self.server, "last_upstream", {}) if hasattr(self.server, "last_upstream") else {}
                merged_last = {
                    "code": code,
                    "body": resp_body.decode(errors="ignore") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body),
                }
                if isinstance(prev, dict):
                    for k in ("url", "headers", "method"):
                        if k in prev:
                            merged_last[k] = prev[k]
                self.server.last_upstream = merged_last
            except Exception:
                pass
            self._log("warning", f"upstream non-2xx code={code} provider={provider_filter} sentinel={sentinel}; returning error (no failover)")
            # return the upstream payload/code directly
            if decorate:
                try:
                    upstream = json.loads(resp_body.decode(errors="ignore") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body))
                except Exception:
                    upstream = resp_body.decode(errors="ignore") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body)
                meta_full = _build_arkeo_meta_clean(active, nonce, svc_id, service, provider_filter, contract_client, sentinel, 0)
                if isinstance(upstream, dict):
                    merged = dict(upstream)
                    merged["arkeo"] = meta_full
                    return self._send_json(code, merged)
                return self._send_json(code, {"arkeo": meta_full, "response": upstream})
            # raw pass-through
            if isinstance(resp_body, (bytes, bytearray)):
                out_bytes = resp_body
            else:
                out_bytes = str(resp_body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_bytes)))
            self.send_header("Connection", "close")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-Arkeo-Contract-Id", _safe_str(cid))
            self.send_header("X-Arkeo-Nonce", _safe_str(nonce))
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
        try:
            prev = getattr(self.server, "last_upstream", {}) if hasattr(self.server, "last_upstream") else {}
            merged_last = {"code": 503, "body": err}
            if isinstance(prev, dict):
                for k in ("url", "headers", "method"):
                    if k in prev:
                        merged_last[k] = prev[k]
            self.server.last_upstream = merged_last
        except Exception:
            pass
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


def _test_listener_port(
    port: int,
    payload: bytes | None,
    headers: dict,
    timeout: float = 12.0,
    method: str = "POST",
    path: str = "/",
) -> tuple[bool, str | None, str | None, dict]:
    """Attempt an HTTP request against the listener; return headers too."""
    method = (method or "POST").upper()
    path = path or "/"
    if not str(path).startswith("/"):
        path = f"/{path}"
    url = f"http://127.0.0.1:{port}{path}"
    data_bytes = None if method == "GET" else payload
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return True, body, None, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = None
        return False, body, f"HTTP {e.code}: {e.reason}", dict(e.headers) if e.headers else {}
    except Exception as e:
        return False, None, str(e), {}


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


def _providers_for_service(service_id: str) -> list[dict]:
    """Return all active providers for a service_id with sentinel + moniker hints."""
    sid = str(service_id) if service_id is not None else ""
    if not sid:
        return []
    providers: list[dict] = []
    raw = _top_active_services_by_payg(sid, limit=1000)
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        item = dict(entry)
        item["service_id"] = sid
        mu = item.get("metadata_uri") or (item.get("raw") or {}).get("metadata_uri")
        if mu and _is_external(mu) and not item.get("sentinel_url"):
            sent = _sentinel_from_metadata_uri(mu)
            if sent:
                item["sentinel_url"] = sent
        if not item.get("provider_moniker"):
            item["provider_moniker"] = _active_provider_moniker(item.get("provider_pubkey") or "")
        providers.append(item)
    return providers


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
        results = cache_fetch_once(record_status=True)
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
        "metadata": 0,
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

    metadata_cache = _safe_load("metadata")
    meta_obj = metadata_cache.get("metadata") if isinstance(metadata_cache, dict) else {}
    if isinstance(meta_obj, dict):
        counts["metadata"] = len(meta_obj)

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
    health_method_raw = (payload.get("health_method") or payload.get("healthMethod") or "POST").strip().upper()
    health_method = "GET" if health_method_raw == "GET" else "POST"
    health_payload = (payload.get("health_payload") or payload.get("healthPayload") or "").strip()
    health_header = (payload.get("health_header") or payload.get("healthHeader") or "").strip()
    port_val = payload.get("port")
    port: int | None = None
    if port_val not in (None, ""):
        try:
            port = int(port_val)
        except (TypeError, ValueError):
            return None, "port must be an integer"
        floor = _load_port_floor()
        if port < floor or port > LISTENER_PORT_END:
            return None, f"port must be between {floor} and {LISTENER_PORT_END}"
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
        "health_method": health_method,
        "health_payload": health_payload,
        "health_header": health_header,
    }, None


@app.get("/api/listeners")
def get_listeners():
    """Return current listeners registry."""
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    listeners = listeners if isinstance(listeners, list) else []
    used_ports = _collect_used_ports(listeners)
    next_port = _next_available_port(used_ports)
    floor = _load_port_floor()
    return jsonify({
        "listeners": [_enrich_listener_for_response(l) for l in listeners],
        "port_range": [floor, LISTENER_PORT_END],
        "next_port": next_port,
        "port_floor": floor,
    })


@app.post("/api/listeners")
def create_listener():
    payload = request.get_json(silent=True) or {}
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
    used_ports = _collect_used_ports(listeners)
    floor = _load_port_floor()
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
    best = _normalize_top_services(_top_active_services_by_payg(clean.get("service_id") or "", limit=5))
    # primary provider comes from top_services ordering
    raw_entry = {
        "id": payload.get("id") or str(int(time.time() * 1000)),
        "target": "",
        "status": clean["status"],
        "port": port,
        "service_id": clean.get("service_id") or "",
        "top_services": best,
        "whitelist_ips": clean.get("whitelist_ips") or "",
        "health_method": clean.get("health_method") or "POST",
        "health_payload": clean.get("health_payload") or "",
        "health_header": clean.get("health_header") or "",
        "created_at": now,
        "updated_at": now,
    }
    ok, err = _ensure_listener_runtime(raw_entry, previous_port=None, previous_status=None, previous_entry=None)
    if not ok:
        return jsonify({"error": err or "failed to start listener"}), 500
    listeners.append(raw_entry)
    listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = listeners
    data["fetched_at"] = now
    _write_listeners(data)
    return jsonify({"listener": _enrich_listener_for_response(raw_entry), "next_port": _next_available_port(used_ports | {port})})


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
    best = _top_active_services_by_payg(clean.get("service_id") or "", limit=5)
    updated = None
    old_snapshot = None
    provider_pk = (clean.get("provider_pubkey") or "").strip() or None
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
        # top services ordering: use custom if provided, else keep existing unless service changed or empty
        existing_top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
        if custom_top is not None:
            new_top = custom_top  # honor explicit (even empty) input
        else:
            new_top = existing_top
            if str(l.get("service_id")) != str(clean.get("service_id") or "") or not new_top:
                new_top = best
        l["top_services"] = _normalize_top_services(new_top)
        # derive provider/sentinel from top services primary (new order wins)
        if l["top_services"]:
            primary = l["top_services"][0]
            if isinstance(primary, dict):
                provider_pk = primary.get("provider_pubkey") or provider_pk
        # do not persist provider_pubkey; runtime derives from top_services
        if "provider_pubkey" in l:
            l.pop("provider_pubkey", None)
        l["whitelist_ips"] = clean.get("whitelist_ips") if clean.get("whitelist_ips") is not None else l.get("whitelist_ips", "")
        l["health_method"] = clean.get("health_method") or l.get("health_method") or "POST"
        l["health_payload"] = clean.get("health_payload") if clean.get("health_payload") is not None else l.get("health_payload", "")
        l["health_header"] = clean.get("health_header") if clean.get("health_header") is not None else l.get("health_header", "")
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
    return jsonify({"listener": _enrich_listener_for_response(updated), "next_port": _next_available_port(used_ports)})


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
    best = _normalize_top_services(_top_active_services_by_payg(svc_id, limit=3))
    found["top_services"] = best
    found["updated_at"] = _timestamp()
    listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = listeners
    _write_listeners(data)
    return jsonify({"listener": _enrich_listener_for_response(found)})


@app.get("/api/services/<service_id>/providers")
def providers_for_service(service_id: str):
    """Return active providers for a given service id (from cache)."""
    try:
        providers = _providers_for_service(service_id)
    except Exception as e:
        return jsonify({"error": "failed_to_load_providers", "detail": str(e)}), 500
    return jsonify({"providers": providers, "count": len(providers)})


@app.get("/api/listeners/<listener_id>/test")
def test_listener(listener_id: str):
    """Test connectivity to a listener port (eth_blockNumber JSON-RPC)."""
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            listeners = []
        target = next((l for l in listeners if isinstance(l, dict) and str(l.get("id")) == str(listener_id)), None)
        if not target:
            return jsonify({"error": "listener not found"}), 404
        try:
            port = int(target.get("port"))
        except Exception:
            return jsonify({"error": "invalid port"}), 400

        # Build health check strictly from listener config
        hm = (target.get("health_method") or "POST").upper()
        hp = target.get("health_payload") or ""
        hh = target.get("health_header") or ""
        headers = {}
        if hh:
            headers["Content-Type"] = hh
        payload_bytes = b""
        label = ""
        path = "/"
        if hm == "GET":
            # If payload is a full URL, use it directly; otherwise prefix with best-guess service name for sentinel routing.
            if hp.startswith("http://") or hp.startswith("https://"):
                path = hp.strip()
            else:
                svc_prefix = (
                    target.get("service_name")
                    or _service_slug_for_id(target.get("service_id"))
                    or target.get("service_description")
                    or target.get("service")
                    or target.get("service_id")
                    or ""
                ).strip("/")
                base_path = hp.strip().lstrip("/")
                if svc_prefix:
                    path = f"/{svc_prefix}/{base_path}" if base_path else f"/{svc_prefix}"
                else:
                    path = f"/{base_path}" if base_path else "/"
            label = f"GET {path}"
        else:
            payload_bytes = hp.encode() if hp else b""
            label = "custom health payload" if hp else "empty payload"
            if not hh:
                headers["Content-Type"] = "application/json"
            path = "/"  # POSTs go to root; payload determines behavior
        req_path = path if path else "/"
        if not req_path.startswith("http://") and not req_path.startswith("https://"):
            if not str(req_path).startswith("/"):
                req_path = f"/{req_path}"
            req_url = f"http://127.0.0.1:{port}{req_path}"
        else:
            req_url = req_path
        ok, resp, err, resp_headers = _test_listener_port(port, payload_bytes if hm != "GET" else None, headers, method=hm, path=req_path)
        headers_cli = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
        if hm == "GET":
            cmd = f"curl -X GET http://127.0.0.1:{port}{path} {headers_cli}".strip()
        else:
            cmd = (
                "curl -X POST http://127.0.0.1:"
                f"{port}{path} {headers_cli} "
                f"--data '{payload_bytes.decode()}'"
            ).strip()

        provider_pk, sentinel_url, provider_moniker = _resolve_listener_target(target)
        sentinel_norm = _normalize_sentinel_url(sentinel_url or SENTINEL_URI_DEFAULT)
        sentinel_target = None
        try:
            if sentinel_norm:
                svc_path = str(target.get("service_name") or target.get("service_id") or "").strip()
                sentinel_target = f"{sentinel_norm.rstrip('/')}/{svc_path}" if svc_path else sentinel_norm
        except Exception:
            sentinel_target = sentinel_norm

        # Use the same candidate logic the runtime uses to surface the actual upstream info
        runtime_cfg = {
            "top_services": target.get("top_services") or [],
            "service_id": target.get("service_id"),
            "service": target.get("service"),
            "provider_pubkey": target.get("provider_pubkey"),
            "provider_sentinel_api": target.get("sentinel_url"),
        }
        candidates = _candidate_providers(runtime_cfg) or []
        primary = candidates[0] if candidates else {}
        cand_sentinel = _normalize_sentinel_url(primary.get("sentinel_url"))
        cand_provider = primary.get("provider_pubkey")

        payload = {
            "ok": ok,
            "port": port,
            "command": cmd,
            "service_id": target.get("service_id"),
            "service_name": target.get("service_name"),
        "provider_pubkey": provider_pk,
        "provider_moniker": provider_moniker,
        "sentinel_url": sentinel_norm,
        "sentinel_target": sentinel_target,
            "response_headers": resp_headers or {},
            "candidate_sentinel": cand_sentinel,
            "candidate_provider": cand_provider,
            "health_method": hm,
            "health_header": hh,
            "health_payload": hp,
            "request_url": req_url,
            "request_method": hm,
            "request_headers": headers,
            "request_body": hp if hm != "GET" else "",
        }
        # show the upstream target we expect the sentinel to hit (best-effort)
        health_url_example = None
        if cand_sentinel:
            if hm == "GET":
                if hp.startswith("http://") or hp.startswith("https://"):
                    health_url_example = hp
                else:
                    health_url_example = f"{cand_sentinel.rstrip('/')}/{hp.lstrip('/')}" if hp else cand_sentinel
            else:
                health_url_example = cand_sentinel
        if health_url_example:
            payload["health_url_example"] = health_url_example

        # Expose last proxy status if available
        srv_entry = _LISTENER_SERVERS.get(port)
        srv = srv_entry.get("server") if isinstance(srv_entry, dict) else None
        if srv:
            payload["last_code"] = getattr(srv, "last_code", None)
            payload["last_nonce"] = getattr(srv, "last_nonce", None)
            payload["last_nonce_source"] = getattr(srv, "last_nonce_source", None)
            payload["last_nonce_cache"] = getattr(srv, "last_nonce_cache", None)
            last_up = getattr(srv, "last_upstream", None)
            if isinstance(last_up, dict):
                payload["last_upstream_code"] = last_up.get("code")
                payload["last_upstream_body"] = last_up.get("body")
                payload["last_upstream_url"] = last_up.get("url")
                payload["last_upstream_headers"] = last_up.get("headers")
            last_cand = getattr(srv, "last_candidate", None)
            if isinstance(last_cand, dict):
                payload["last_candidate_provider"] = last_cand.get("provider")
                payload["last_candidate_sentinel"] = last_cand.get("sentinel")
                payload["last_candidate_service_id"] = last_cand.get("service_id")
                payload["last_candidate_service_name"] = last_cand.get("service_name")
            active_contract = getattr(srv, "active_contract", None)
            if isinstance(active_contract, dict):
                payload["active_contract_id"] = active_contract.get("id")
                payload["active_contract_height"] = active_contract.get("height")
                payload["active_contract_provider"] = active_contract.get("provider")
                payload["active_contract_service"] = active_contract.get("service")
                try:
                    client_pub = active_contract.get("client")
                    cid = active_contract.get("id")
                    if cid and client_pub:
                        payload["nonce_cached"] = _peek_nonce_cache(str(cid), str(client_pub))
                        payload["nonce_cache_key"] = _nonce_cache_key(str(cid), str(client_pub))
                except Exception:
                    pass
        if isinstance(resp_headers, dict):
            payload["arkeo_nonce"] = resp_headers.get("X-Arkeo-Nonce") or resp_headers.get("x-arkeo-nonce")
            payload["arkeo_contract_id"] = resp_headers.get("X-Arkeo-Contract-Id") or resp_headers.get("x-arkeo-contract-id")
            payload["arkeo_cost"] = resp_headers.get("X-Arkeo-Cost") or resp_headers.get("x-arkeo-cost")

        if label:
            payload["test"] = label
        if resp:
            payload["response"] = resp
        if err:
            payload["error"] = err

        # Always return 200; payload.ok/error indicate result to keep UI polling simple
        return jsonify(payload), 200
    except Exception as e:
        return jsonify({"error": "listener_test_failed", "detail": str(e)}), 500


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
        "ARKEO_REST_API",
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
    # Keep ARKEO_REST_API in sync with PROVIDER_HUB_URI if provided
    if payload.get("provider_hub_uri"):
        _set_env("PROVIDER_HUB_URI", payload.get("provider_hub_uri"))
        _set_env("ARKEO_REST_API", payload.get("provider_hub_uri"))

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
