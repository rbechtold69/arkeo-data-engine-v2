#!/usr/bin/env python3
import base64
import binascii
import json
import os
import queue
import shutil
from pathlib import Path
import secrets
import re
import shlex
import socket
import socketserver
import subprocess
import threading
from contextlib import contextmanager
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
ARKEO_STATUS_FILE = os.path.join(CACHE_DIR, "arkeo_status.json")
ARKEO_STATUS_TTL = float(os.getenv("ARKEO_STATUS_TTL", "30.0"))
LOG_DIR = os.path.join(CACHE_DIR, "logs")
NONCE_STORE_DIR = os.path.join(CACHE_DIR, "nonce_store")
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
_LISTENERS_RW_LOCK = threading.RLock()
TX_LOCK = threading.Lock()
_PORT_FLOOR = None
HOTWALLET_LOG = os.path.join(CACHE_DIR, "logs", "hotwallet-tx.log")
AXELAR_CONFIG_CACHE = os.path.join(CONFIG_DIR, "axelar", "eth-mainnet.json")


@contextmanager
def tx_lock(timeout_s: float = 30.0):
    if not TX_LOCK.acquire(timeout=timeout_s):
        raise TimeoutError("tx lock busy")
    try:
        yield
    finally:
        TX_LOCK.release()


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

# Single-lane executor primitives (serialize nonce/sign/forward per listener)
class WorkItem:
    def __init__(
        self,
        method,
        path,
        query,
        headers,
        body,
        client_ip,
        deadline: float | None = None,
        raw_path: str | None = None,
        raw_query: str | None = None,
    ):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.client_ip = client_ip
        self.response = queue.Queue(maxsize=1)
        self.cancelled = False
        self.created_at = time.time()
        self.deadline = deadline
        self.raw_path = raw_path
        self.raw_query = raw_query


class NonceStore:
    def __init__(self, path: str):
        self.path = path
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.lock = threading.Lock()
        self.nonce = self._load()

    def _load(self) -> int:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return int(data.get("nonce", 0))
        except Exception:
            return 0

    def _save(self, val: int) -> None:
        tmp = f"{self.path}.tmp"
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"nonce": val}, f)
            os.replace(tmp, self.path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    def next(self) -> int:
        with self.lock:
            self.nonce += 1
            self._save(self.nonce)
            return self.nonce

    def set(self, val: int) -> None:
        with self.lock:
            try:
                self.nonce = int(val)
            except Exception:
                return
            self._save(self.nonce)


class SingleLaneExecutor:
    def __init__(self, cfg: dict, maxsize: int = 16):
        self.q = queue.Queue(maxsize=maxsize)
        self.cfg = cfg
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def submit(self, work: WorkItem) -> bool:
        try:
            self.q.put_nowait(work)
            return True
        except queue.Full:
            return False

    def _worker(self):
        while True:
            work: WorkItem = self.q.get()
            if work.cancelled:
                continue
            try:
                if work.deadline and time.time() > work.deadline:
                    resp = {
                        "status": 503,
                        "body": json.dumps({"error": "queue_timeout"}),
                        "headers": {"Content-Type": "application/json"},
                    }
                else:
                    resp = _handle_forward_lane(work, self.cfg)
                try:
                    work.response.put_nowait(resp)
                except Exception:
                    pass
            except Exception as e:
                try:
                    work.response.put_nowait(
                        {"status": 502, "body": json.dumps({"error": "worker_exception", "detail": str(e)})}
                    )
                except Exception:
                    pass


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
    """ETH hot wallet bridge is disabled; external signing is required."""
    return jsonify({"error": ETH_WALLET_DISABLED_MSG}), 400


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
    def _via_osmosisd() -> list[dict]:
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

    def _via_rest_fallback() -> list[dict]:
        # use public rest fallback to avoid payg/proxy issues
        url = f"https://rest.cosmos.directory/osmosis/cosmos/bank/v1beta1/balances/{addr}"
        code, out = run_list(["curl", "-s", url])
        if code != 0:
            raise RuntimeError(f"osmosis balances rest exit={code}: {out}")
        data = json.loads(out)
        return data.get("balances") or data.get("result") or []

    try:
        return _via_osmosisd()
    except Exception as e:
        # fallback to public REST if local/proxied osmosisd fails
        try:
            return _via_rest_fallback()
        except Exception:
            raise e


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

    # Resolve denoms using pool state (no wallet required)
    pool_state, pool_err = _pool_2977_state()
    if pool_err or not pool_state:
        return None, pool_err or "pool unavailable"
    usdc_denom = pool_state.get("usdc_denom") or os.getenv("USDC_OSMO_DENOM") or ""
    arkeo_denom = pool_state.get("arkeo_denom") or ""
    if not arkeo_denom:
        arkeo_denom = os.getenv("ARKEO_OSMO_DENOM") or ""
    if not arkeo_denom or not usdc_denom:
        return None, "ARKEO/USDC denoms on Osmosis not found"

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

    pool_state, pool_err = _pool_2977_state()
    if pool_err or not pool_state:
        return None, pool_err or "pool unavailable"
    usdc_denom = pool_state.get("usdc_denom") or os.getenv("USDC_OSMO_DENOM") or ""
    arkeo_denom = pool_state.get("arkeo_denom") or os.getenv("ARKEO_OSMO_DENOM") or ""
    if not arkeo_denom or not usdc_denom:
        return None, "ARKEO/USDC denoms on Osmosis not found"

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
        # Some CLIs prepend "gas estimate: xxx" before the JSON; try the last JSON-like line.
        raw = out.strip()
        try_json = raw
        if "\n" in raw:
            try_json = raw.splitlines()[-1]
        data = json.loads(try_json)
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
    # Fallback regex search
    m = re.search(r"txhash[:\"\\s]*([0-9A-Fa-f]{64})", out)
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

    def scan_events(events: list[dict]) -> dict | None:
        for ev in events or []:
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

    for log in logs:
        found = scan_events(log.get("events") or [])
        if found:
            return found

    # Some responses use top-level events instead of logs
    top_events = data.get("events") or data.get("tx_response", {}).get("events") or []
    return scan_events(top_events)


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
    Swap Osmosis USDC -> wrapped ARKEO via pool 2977 and keep it on Osmosis.
    Requires OSMO gas and USDC on Osmosis. No IBC transfer is performed here.
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

    # Ensure wallets
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

    # Track pre-swap ARKEO balance for delta reporting
    arkeo_before = 0
    for b in balances:
        if b.get("denom") == arkeo_denom:
            try:
                arkeo_before = int(b.get("amount", "0"))
            except Exception:
                arkeo_before = 0
            break

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
        "0.05uosmo",
        "--broadcast-mode",
        "sync",
        "-o",
        "json",
        "-y",
    ]
    swap_code, swap_out = run_list(swap_cmd)
    swap_tx = _extract_txhash(swap_out)
    if not swap_tx:
        # best-effort regex fallback
        m = re.search(r"txhash[:\"\\s]*([0-9A-Fa-f]{64})", swap_out or "")
        if m:
            swap_tx = m.group(1)
    if not swap_tx:
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
                "swap_exit": swap_code,
            }
        ), 500
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

    arkeo_after = arkeo_avail
    arkeo_delta = arkeo_after - arkeo_before

    # Persist discovered denoms
    _write_bridge_denoms(usdc_denom, arkeo_denom)

    _append_hotwallet_log(
        {
            "action": "convert_usdc_to_arkeo",
            "stage": "swap_complete",
            "swap_tx": swap_tx,
            "arkeo_denom": arkeo_denom,
            "usdc_denom": usdc_denom,
            "arkeo_before": arkeo_before,
            "arkeo_after": arkeo_after,
            "arkeo_delta": arkeo_delta,
        }
    )

    return jsonify(
        {
            "status": "swap_complete",
            "swap_tx": swap_tx,
            "usdc_denom": usdc_denom,
            "arkeo_denom": arkeo_denom,
            "swap_cmd": _mask_cmd_sensitive(swap_cmd),
            "arkeo_before": arkeo_before,
            "arkeo_after": arkeo_after,
            "arkeo_delta": arkeo_delta,
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
        "0.05uosmo",
        "--broadcast-mode",
        "sync",
        "-o",
        "json",
        "-y",
    ]
    swap_code, swap_out = run_list(swap_cmd)
    swap_tx = _extract_txhash(swap_out)
    if not swap_tx:
        m = re.search(r"txhash[:\"\\s]*([0-9A-Fa-f]{64})", swap_out or "")
        if m:
            swap_tx = m.group(1)
    if not swap_tx:
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



@app.post("/api/hotwallet/arkeo-to-osmosis")
def hotwallet_arkeo_to_osmosis():
    """
    IBC transfer native ARKEO (Arkeo chain) to wrapped ARKEO on Osmosis.
    """
    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    try:
        amt_float = float(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400
    if amt_float <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    # Treat ARKEO as 8-decimal for this flow to match wrapped ARKEO on Osmosis.
    amt_base = int(round(amt_float * 100_000_000))

    if not ARKEO_TO_OSMO_CHANNEL:
        return jsonify({"error": "ARKEO_TO_OSMO_CHANNEL not configured"}), 400

    settings = _merge_subscriber_settings()
    # Osmosis hot wallet not required; rely on provided Osmosis address (e.g., Keplr) or stored address.
    settings, arkeo_err = _ensure_arkeo_mnemonic(settings)
    if arkeo_err:
        return jsonify({"error": f"arkeo wallet: {arkeo_err}"}), 400
    osmo_addr = payload.get("osmosis_address") or settings.get("OSMOSIS_ADDRESS")
    if not osmo_addr:
        return jsonify({"error": "osmosis address required (connect Keplr or set OSMOSIS_ADDRESS)"}), 400
    arkeo_addr, addr_err = derive_address(KEY_NAME, KEYRING)
    if addr_err:
        return jsonify({"error": f"arkeo address: {addr_err}"}), 400

    # Arkeo balance check
    arkeo_bal, bal_err = _arkeo_balance(arkeo_addr)
    if bal_err:
        return jsonify({"error": f"arkeo balance: {bal_err}"}), 500
    if arkeo_bal < amt_base:
        return jsonify({"error": f"insufficient ARKEO (have {arkeo_bal/1e6:.6f}, need {amt_float:.6f})"}), 400

    # Osmosis ARKEO denom
    try:
        denoms_res, denom_err = _resolve_osmo_denoms(osmo_addr)
    except Exception as e:
        return jsonify({"error": f"osmosis denoms: {e}"}), 500
    if denom_err:
        return jsonify({"error": denom_err}), 500
    arkeo_denom = denoms_res.get("arkeo_denom")
    if not arkeo_denom:
        return jsonify({"error": "ARKEO denom on Osmosis not found"}), 400

    # Snapshot Osmosis wrapped ARKEO balance
    osmo_balances = _osmosis_balances_raw(osmo_addr)
    osmo_start = 0
    for b in osmo_balances:
        if b.get("denom") == arkeo_denom:
            try:
                osmo_start = int(b.get("amount", "0"))
            except Exception:
                osmo_start = 0
            break

    _append_hotwallet_log({"action": "arkeo_to_osmosis", "stage": "start", "amount": amt_float})

    ibc_cmd = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "--keyring-backend",
        KEYRING,
        "tx",
        "ibc-transfer",
        "transfer",
        "transfer",
        ARKEO_TO_OSMO_CHANNEL,
        osmo_addr,
        f"{amt_base}uarkeo",
        "--from",
        KEY_NAME,
        "--chain-id",
        CHAIN_ID,
        "--node",
        ARKEOD_NODE,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--gas-prices",
        "0.025uarkeo",
        "--broadcast-mode",
        "sync",
        "-y",
        "-o",
        "json",
    ]
    retry_sequence = None
    retry_attempted = False
    retry_sequences_tried: list[str] = []

    try:
        with tx_lock(timeout_s=45.0):
            ibc_code, ibc_out = run_list(ibc_cmd)
            ibc_tx = _extract_txhash(ibc_out)
            tx_code = None
            tx_raw_log = None
            packet_info = None
            try:
                packet_info = _parse_send_packet(json.loads(ibc_out) if ibc_out else {})
            except Exception:
                packet_info = None

            # Retry on account-sequence mismatch by waiting for the expected sequence to land.
            if (ibc_code != 0 or not ibc_tx) and "account sequence mismatch" in str(ibc_out).lower():
                for attempt in range(4):
                    exp = None
                    m_exp = re.search(r"expected\s+(\d+)", str(ibc_out))
                    if m_exp:
                        exp = m_exp.group(1)
                    if exp:
                        retry_attempted = True
                        retry_sequence = str(exp)
                        retry_sequences_tried.append(retry_sequence)
                        _append_hotwallet_log(
                            {
                                "action": "arkeo_to_osmosis",
                                "stage": "ibc_retry_sequence",
                                "sequence": retry_sequence,
                                "attempt": attempt + 1,
                            }
                        )
                        # Wait for chain sequence to catch up to expected.
                        try:
                            target = int(exp)
                        except Exception:
                            target = None
                        if target is not None:
                            deadline = time.time() + 12
                            while time.time() < deadline:
                                try:
                                    seq_cmd = ["arkeod", "--home", ARKEOD_HOME, "query", "auth", "account", arkeo_addr, "-o", "json"]
                                    if ARKEOD_NODE:
                                        seq_cmd.extend(["--node", ARKEOD_NODE])
                                    seq_code, seq_out = run_list(seq_cmd)
                                    if seq_code == 0:
                                        acct = json.loads(seq_out)
                                        if isinstance(acct, dict):
                                            account_info = acct.get("account") or acct.get("result") or {}
                                            seq_val = None
                                            if isinstance(account_info, dict):
                                                val = account_info.get("value") or account_info
                                                if isinstance(val, dict):
                                                    seq_val = val.get("sequence")
                                                elif account_info.get("base_account"):
                                                    base = account_info.get("base_account") or {}
                                                    if isinstance(base, dict):
                                                        seq_val = base.get("sequence")
                                            if seq_val is not None and int(seq_val) >= target:
                                                break
                                except Exception:
                                    pass
                                time.sleep(1.0)
                    # Retry the original cmd (let CLI pick the sequence after chain advances)
                    ibc_code, ibc_out = run_list(ibc_cmd)
                    ibc_tx = _extract_txhash(ibc_out)
                    try:
                        packet_info = _parse_send_packet(json.loads(ibc_out) if ibc_out else {})
                    except Exception:
                        packet_info = None
                    if ibc_code == 0 and ibc_tx:
                        break
                    if "account sequence mismatch" not in str(ibc_out).lower():
                        break
                    time.sleep(0.8)
    except TimeoutError:
        return jsonify({"error": "tx lock busy, try again shortly"}), 409
    # Fallback: query Arkeo tx to pull packet info and tx code
    if ibc_tx and not packet_info:
        try:
            tx_json_raw = run_list(
                [
                    "arkeod",
                    "--home",
                    ARKEOD_HOME,
                    "query",
                    "tx",
                    ibc_tx,
                    "--node",
                    ARKEOD_NODE,
                    "-o",
                    "json",
                ]
            )[1]
            tx_raw_log = tx_json_raw
            parsed = json.loads(tx_json_raw)
            tx_code = (parsed.get("tx_response") or {}).get("code")
            packet_info = _parse_send_packet(parsed)
        except Exception:
            packet_info = None

    if ibc_code != 0 or not ibc_tx:
        _append_hotwallet_log({"action": "arkeo_to_osmosis", "stage": "ibc_failed", "detail": ibc_out})
        return (
            jsonify(
                {
                    "error": "ibc transfer failed",
                    "detail": ibc_out,
                    "raw_log": ibc_out,
                    "ibc_cmd": ibc_cmd,
                    "ibc_exit": ibc_code,
                    "retry_attempted": retry_attempted,
                    "retry_sequence": retry_sequence,
                    "retry_sequences": retry_sequences_tried if retry_attempted else None,
                }
            ),
            500,
        )

    # Wait briefly for Osmosis arrival
    _append_hotwallet_log(
        {
            "action": "arkeo_to_osmosis",
            "stage": "submitted",
            "ibc_tx": ibc_tx,
            "osmo_start": osmo_start,
            "arkeo_sent": amt_base,
            "arkeo_addr": arkeo_addr,
            "osmo_addr": osmo_addr,
            "packet_sequence": packet_info.get("packet_sequence") if packet_info else None,
            "osmo_src_channel": packet_info.get("src_channel") if packet_info else None,
            "arkeo_dst_channel": packet_info.get("dst_channel") if packet_info else None,
            "packet_info_found": bool(packet_info),
            "tx_code": tx_code,
            "tx_raw_log": tx_raw_log,
            "retry_attempted": retry_attempted,
            "retry_sequence": retry_sequence,
            "retry_sequences": retry_sequences_tried if retry_attempted else None,
        }
    )

    arrived, osmo_final = _wait_for_osmo_balance_increase(osmo_addr, arkeo_denom, amt_base, attempts=30, sleep_s=6)
    _append_hotwallet_log(
        {
            "action": "arkeo_to_osmosis",
            "stage": "arrival" if arrived else "pending",
            "ibc_tx": ibc_tx,
            "osmo_start": osmo_start,
            "osmo_final": osmo_final,
            "arkeo_sent": amt_base,
            "arrived": arrived,
            "packet_sequence": packet_info.get("packet_sequence") if packet_info else None,
            "osmo_src_channel": packet_info.get("src_channel") if packet_info else None,
            "arkeo_dst_channel": packet_info.get("dst_channel") if packet_info else None,
            "packet_info_found": bool(packet_info),
            "tx_code": tx_code,
            "tx_raw_log": tx_raw_log,
        }
    )

    return jsonify(
        {
            "status": "submitted",
            "ibc_tx": ibc_tx,
            "osmo_start": osmo_start,
            "osmo_final": osmo_final,
            "arkeo_denom": arkeo_denom,
            "arrival_confirmed": arrived,
            "packet_sequence": packet_info.get("packet_sequence") if packet_info else None,
            "osmo_src_channel": packet_info.get("src_channel") if packet_info else None,
            "arkeo_dst_channel": packet_info.get("dst_channel") if packet_info else None,
            "packet_info_found": bool(packet_info),
            "tx_code": tx_code,
            "tx_raw_log": tx_raw_log,
            "ibc_cmd": _mask_cmd_sensitive(ibc_cmd),
            "retry_attempted": retry_attempted,
            "retry_sequence": retry_sequence,
            "retry_sequences": retry_sequences_tried if retry_attempted else None,
        }
    )


OSMOSISD_BIN = _pick_executable("osmosisd", ["/usr/local/bin/osmosisd"])
ETH_WALLET_DISABLED_MSG = "Ethereum hot wallet disabled; use external wallet/signing"
OSMO_WALLET_DISABLED_MSG = "Osmosis hot wallet disabled; use external wallet/signing"
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
# ETH flows disabled; keep defaults empty
ETH_RPC = ""
ETH_USDC_CONTRACT = ""
ETH_USDC_DECIMALS = int(os.getenv("ETH_USDC_DECIMALS", "6"))
OSMOSIS_RPC = _strip_quotes(os.getenv("OSMOSIS_RPC") or "")
OSMOSIS_HOME = os.path.expanduser(os.getenv("OSMOSIS_HOME", "/app/config/osmosis"))
OSMOSIS_KEY_NAME = os.getenv("OSMOSIS_KEY_NAME", "osmo-subscriber")
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "*")
# cache for Osmosis denom traces/metadata
OSMOSIS_DENOM_CACHE = os.path.join(CACHE_DIR or "/app/cache", "osmo_denom_cache.json")
DEFAULT_OSMOSIS_USDC_DENOMS = [
    # Axelar canonical USDC on Osmosis
    "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2",
    # Known wrapped USDC (channel-750) provided
    "ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4",
]
_env_osmo_denoms = [d.strip() for d in (os.getenv("OSMOSIS_USDC_DENOMS") or "").split(",") if d.strip()]
OSMOSIS_USDC_DENOMS = _env_osmo_denoms if _env_osmo_denoms else DEFAULT_OSMOSIS_USDC_DENOMS.copy()
MIN_OSMO_GAS = _safe_float(os.getenv("MIN_OSMO_GAS") or 0.1, 0.1)
DEFAULT_SLIPPAGE_BPS = int(os.getenv("DEFAULT_SLIPPAGE_BPS") or "100")
# IBC channels (hardcoded from chain-registry)
OSMO_TO_ARKEO_CHANNEL = "channel-103074"  # Osmosis -> Arkeo
ARKEO_TO_OSMO_CHANNEL = "channel-1"      # Arkeo -> Osmosis
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
PROXY_CREATE_FEES = os.getenv("PROXY_CREATE_FEES", "300uarkeo")
PROXY_CREATE_TIMEOUT = int(os.getenv("PROXY_CREATE_TIMEOUT", "30"))
PROXY_CREATE_BACKOFF = int(os.getenv("PROXY_CREATE_BACKOFF", "2"))
PROXY_MAX_DEPOSIT = os.getenv("PROXY_MAX_DEPOSIT", "50000000")
PROXY_SIGN_TEMPLATE = os.getenv("PROXY_SIGN_TEMPLATE", "{contract_id}:{nonce}:")
PROXY_ARKAUTH_FORMAT = os.getenv("PROXY_ARKAUTH_FORMAT", "4part")
PROXY_TIMEOUT_SECS = int(os.getenv("PROXY_TIMEOUT_SECS", "15"))
PROXY_BYPASS_TIMEOUT = _safe_float(os.getenv("PROXY_BYPASS_TIMEOUT") or "3.0", 3.0)
PROXY_BYPASS_COOLDOWN = _safe_float(os.getenv("PROXY_BYPASS_COOLDOWN") or "60.0", 60.0)
PROXY_PROVIDER_COOLDOWN = _safe_float(os.getenv("PROXY_PROVIDER_COOLDOWN") or "60.0", 60.0)
PROXY_HEIGHT_SKEW = int(os.getenv("PROXY_HEIGHT_SKEW", "6"))
PROXY_WHITELIST_IPS = os.getenv("PROXY_WHITELIST_IPS", "0.0.0.0")
PROXY_TRUST_FORWARDED = str(os.getenv("PROXY_TRUST_FORWARDED", "true")).lower() in ("1", "true", "yes", "on")
PROXY_DECORATE_RESPONSE = str(os.getenv("PROXY_DECORATE_RESPONSE", "true")).lower() in ("1", "true", "yes", "on")
PROXY_ARKAUTH_AS_HEADER = str(os.getenv("PROXY_ARKAUTH_AS_HEADER", "false")).lower() in ("1", "true", "yes", "on")
PROXY_CONTRACT_TIMEOUT = int(os.getenv("PROXY_CONTRACT_TIMEOUT", "10"))
PROXY_CONTRACT_LIMIT = int(os.getenv("PROXY_CONTRACT_LIMIT", "5000"))
# Poll/test helper timeout (UI “Poll” and “Test” buttons). Default aligns with lane worst-case
# (timeout_secs + create_timeout) so first-time contract opens can complete.
PROXY_TEST_TIMEOUT = float(os.getenv("PROXY_TEST_TIMEOUT", "45.0"))
PROXY_OPEN_COOLDOWN = int(os.getenv("PROXY_OPEN_COOLDOWN", "0"))  # seconds to cool down a provider after open failure
PROXY_CONTRACT_CACHE_TTL = 0  # TTL disabled; cached contract reused until invalid
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
    except FileNotFoundError as e:
        return 127, str(e)
    except Exception as e:
        return 1, str(e)


def run_list(cmd: list[str]) -> tuple[int, str]:
    """Run a command without a shell and return (exit_code, output)."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return 0, out.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode("utf-8")
    except FileNotFoundError as e:
        return 127, str(e)
    except Exception as e:
        return 1, str(e)


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


def _ensure_http_rpc(url: str | None) -> str:
    """Return an HTTP(S) RPC URL suitable for browser use; converts tcp:// to http://."""
    if not url:
        return ""
    s = _strip_quotes(str(url).strip())
    lower = s.lower()
    if lower.startswith("tcp://"):
        return "http://" + s[len("tcp://") :]
    return s


def _default_subscriber_settings() -> dict:
    """Return defaults from env + sane fallbacks."""
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
        "ADMIN_PORT": os.getenv("ADMIN_PORT") or os.getenv("ENV_ADMIN_PORT") or "8079",
        "ADMIN_API_PORT": os.getenv("ADMIN_API_PORT") or str(API_PORT),
        "OSMOSIS_RPC": _strip_quotes(os.getenv("OSMOSIS_RPC") or ""),
        "OSMOSIS_USDC_DENOMS": OSMOSIS_USDC_DENOMS,
        "ETH_ADDRESS": "",
        "USDC_OSMO_DENOM": os.getenv("USDC_OSMO_DENOM", "ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4"),
        "ARKEO_OSMO_DENOM": os.getenv("ARKEO_OSMO_DENOM", "ibc/AD969E97A63B64B30A6E4D9F598341A403B849F5ACFEAA9F18DBD9255305EC65"),
        "MIN_OSMO_GAS": MIN_OSMO_GAS,
        "DEFAULT_SLIPPAGE_BPS": DEFAULT_SLIPPAGE_BPS,
        "ARRIVAL_TOLERANCE_BPS": ARRIVAL_TOLERANCE_BPS,
        "WALLET_SYNC_INTERVAL": os.getenv("WALLET_SYNC_INTERVAL", "15"),
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
    # Strip disabled mnemonic fields before persisting
    sanitized = dict(settings) if isinstance(settings, dict) else {}
    sanitized.pop("ETH_MNEMONIC", None)
    sanitized.pop("OSMOSIS_MNEMONIC", None)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sanitized, f, indent=2)
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
    merged.pop("EXTERNAL_ARKEO_REST_API", None)
    merged.pop("ARKEO_REST_API_PORT", None)
    merged["ARKEOD_HOME"] = _expand_tilde(merged.get("ARKEOD_HOME") or ARKEOD_HOME)
    if merged.get("ARKEOD_NODE"):
        merged["ARKEOD_NODE"] = _ensure_tcp_scheme(_strip_quotes(merged.get("ARKEOD_NODE") or ""))
    merged.pop("SENTINEL_NODE", None)
    merged.pop("SENTINEL_PORT", None)
    # Always use hardcoded IBC channels
    merged.pop("OSMO_TO_ARKEO_CHANNEL", None)
    merged.pop("ARKEO_TO_OSMO_CHANNEL", None)
    # Normalize Osmosis USDC denoms to list
    denoms = merged.get("OSMOSIS_USDC_DENOMS")
    if isinstance(denoms, str):
        merged["OSMOSIS_USDC_DENOMS"] = [d.strip() for d in denoms.split(",") if d.strip()]
    if not merged.get("OSMOSIS_USDC_DENOMS"):
        merged["OSMOSIS_USDC_DENOMS"] = DEFAULT_OSMOSIS_USDC_DENOMS.copy()
    # Drop ETH mnemonic (external signing expected)
    merged.pop("ETH_MNEMONIC", None)
    # Drop Osmosis hot wallet fields (external signing expected)
    merged.pop("OSMOSIS_MNEMONIC", None)
    merged.pop("OSMOSIS_ADDRESS", None)
    merged.pop("OSMOSIS_KEY_NAME", None)
    merged.pop("OSMOSIS_HOME", None)
    return merged


def _apply_subscriber_settings(settings: dict) -> None:
    """Apply subscriber settings to globals and os.environ for runtime use."""
    global KEY_NAME, KEYRING, ARKEOD_HOME, ARKEOD_NODE, CHAIN_ID, NODE_ARGS, CHAIN_ARGS, KEY_MNEMONIC, ETH_RPC, ETH_USDC_CONTRACT, ETH_USDC_DECIMALS, OSMOSIS_RPC, OSMOSIS_USDC_DENOMS, MIN_OSMO_GAS, DEFAULT_SLIPPAGE_BPS, OSMO_TO_ARKEO_CHANNEL, ARKEO_TO_OSMO_CHANNEL, CORS_ALLOWED_ORIGINS
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
    # MIN_OSMO_GAS, DEFAULT_SLIPPAGE_BPS, ARRIVAL_TOLERANCE_BPS, and channel defaults are hardcoded; do not override from settings
    OSMOSIS_RPC = _strip_quotes(settings.get("OSMOSIS_RPC") or OSMOSIS_RPC or "")
    # Always keep hardcoded channel values
    OSMO_TO_ARKEO_CHANNEL = "channel-103074"
    ARKEO_TO_OSMO_CHANNEL = "channel-1"
    try:
        cors_val = settings.get("CORS_ALLOWED_ORIGINS", CORS_ALLOWED_ORIGINS)
        CORS_ALLOWED_ORIGINS = cors_val if cors_val is not None else CORS_ALLOWED_ORIGINS
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
        "ADMIN_PORT": settings.get("ADMIN_PORT", ""),
        "ADMIN_API_PORT": settings.get("ADMIN_API_PORT", ""),
        "ETH_RPC": settings.get("ETH_RPC", ""),
        "ETH_USDC_CONTRACT": settings.get("ETH_USDC_CONTRACT", ""),
        "ETH_USDC_DECIMALS": settings.get("ETH_USDC_DECIMALS", ""),
        "OSMOSIS_RPC": settings.get("OSMOSIS_RPC", ""),
        "OSMOSIS_USDC_DENOMS": ",".join(OSMOSIS_USDC_DENOMS) if OSMOSIS_USDC_DENOMS else "",
        "ETH_ADDRESS": settings.get("ETH_ADDRESS", ""),
        "USDC_OSMO_DENOM": settings.get("USDC_OSMO_DENOM", ""),
        "ARKEO_OSMO_DENOM": settings.get("ARKEO_OSMO_DENOM", ""),
        "MIN_OSMO_GAS": MIN_OSMO_GAS,
        "DEFAULT_SLIPPAGE_BPS": DEFAULT_SLIPPAGE_BPS,
        "ARRIVAL_TOLERANCE_BPS": ARRIVAL_TOLERANCE_BPS,
        "CORS_ALLOWED_ORIGINS": CORS_ALLOWED_ORIGINS,
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
    """Ethereum hot wallet management disabled; external signing expected."""
    if not isinstance(settings, dict):
        return settings, "invalid settings"
    return settings, ETH_WALLET_DISABLED_MSG


def _ensure_osmo_wallet(settings: dict) -> tuple[dict, str | None]:
    """Osmosis hot wallet management disabled; external signing expected."""
    if not isinstance(settings, dict):
        return settings, "invalid settings"
    return settings, OSMO_WALLET_DISABLED_MSG


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
        before_eth_addr = settings.get("ETH_ADDRESS")
        # ETH
        settings, eth_err = _ensure_eth_wallet(settings)
        if eth_err:
            print(f"[boot] ETH wallet init note: {eth_err}")
        # strip transient errors before persisting
        settings.pop("ETH_ERROR", None)
        if (
            changed
            or settings.get("ETH_ADDRESS") != before_eth_addr
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
    cached = _read_arkeo_status_cache(ARKEO_STATUS_TTL)
    if cached and cached.get("ok") and cached.get("height") is not None:
        return jsonify(
            {
                "height": str(cached.get("height")),
                "status": cached.get("status") or {},
                "synced_at": cached.get("synced_at"),
                "synced_at_unix": cached.get("synced_at_unix"),
                "cached": True,
            }
        )
    height = _get_current_height(ARKEOD_NODE)
    cached = _read_arkeo_status_cache(ARKEO_STATUS_TTL)
    if cached and cached.get("ok") and cached.get("height") is not None:
        return jsonify(
            {
                "height": str(cached.get("height")),
                "status": cached.get("status") or {},
                "synced_at": cached.get("synced_at"),
                "synced_at_unix": cached.get("synced_at_unix"),
                "cached": True,
            }
        )
    detail = cached.get("error") if isinstance(cached, dict) else None
    return jsonify({"error": "failed to fetch status", "detail": detail}), 500


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
        return jsonify({"error": err}), 200
    return jsonify({"height": height})


def _osmosis_address_from_request() -> tuple[str | None, str | None]:
    """
    Return (address, error) for Osmosis balance queries.
    Priority: explicit request arg -> persisted hot wallet (if enabled).
    """
    req_addr = _strip_quotes(request.args.get("address") or request.args.get("addr") or "")
    if req_addr:
        return req_addr, None
    settings = _merge_subscriber_settings()
    settings, err = _ensure_osmo_wallet(settings)
    if err:
        return None, err
    addr = settings.get("OSMOSIS_ADDRESS")
    if not addr:
        return None, "OSMOSIS_ADDRESS not available"
    return addr, None


def _osmosis_balance_internal(addr: str | None) -> tuple[str | dict | None, str | None]:
    """Return (balance, error) for the provided Osmosis address."""
    if not addr:
        return None, "address required"
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
    """
    Return Osmosis balance for a provided address (preferred) or the derived hot wallet.
    Use /api/osmosis/balances?address=... for an explicit address to avoid hot wallet dependency.
    """
    addr, addr_err = _osmosis_address_from_request()
    bal, err = _osmosis_balance_internal(addr)
    if addr_err and not bal:
        return jsonify({"error": addr_err}), 200
    if err:
        return jsonify({"error": err}), 200
    if isinstance(bal, dict):
        return jsonify(bal)
    return jsonify({"balance": bal})


@app.get("/api/osmosis/balances")
def osmosis_balances():
    """Return Osmosis balances for an explicit address; Keplr-backed flow uses this."""
    addr = _strip_quotes(request.args.get("address") or request.args.get("addr") or "")
    if not addr:
        return jsonify({"error": "address query param required"}), 400
    bal, err = _osmosis_balance_internal(addr)
    if err:
        return jsonify({"error": err, "address": addr}), 200
    if isinstance(bal, dict):
        bal["address"] = addr
        return jsonify(bal)
    return jsonify({"balance": bal, "address": addr})


@app.get("/api/osmosis-assets")
def osmosis_assets():
    """Return resolved Osmosis assets (denom traces + metadata) for the provided address."""
    addr, addr_err = _osmosis_address_from_request()
    if addr_err and not addr:
        return jsonify({"error": addr_err}), 200
    assets, err = _resolve_osmo_assets(addr)
    if err:
        return jsonify({"error": err}), 200
    return jsonify({"address": addr, "assets": assets or []})


@app.get("/api/osmosis-price")
def osmosis_price():
    """Return spot estimate for ARKEO/USDC from pool 2977."""
    price, err = _osmosis_price_estimate()
    if err:
        return jsonify({"error": err}), 500
    return jsonify(price or {})


@app.get("/api/osmosis-rpc")
def osmosis_rpc_get():
    """Return HTTP(S) Osmosis RPC endpoint (tcp converted to http)."""
    rpc = _ensure_http_rpc(OSMOSIS_RPC)
    return jsonify({"rpc": rpc})

@app.get("/api/osmosis-arkeo-config")
def osmosis_arkeo_config():
    """Return basic config for Osmosis->Arkeo IBC (denom/channel/rpc)."""
    try:
        try:
            arkeo_addr, addr_err = derive_address(KEY_NAME, KEYRING)
        except Exception:
            arkeo_addr, addr_err = "", "addr_error"
        arkeo_denom = globals().get("ARKEO_OSMO_DENOM") or "ibc/AD969E97A63B64B30A6E4D9F598341A403B849F5ACFEAA9F18DBD9255305EC65"
        channel = globals().get("OSMO_TO_ARKEO_CHANNEL") or "channel-103074"
        payload = {
            "arkeo_denom": arkeo_denom,
            "source_channel": channel,
            "source_port": "transfer",
            "osmosis_rpc": _ensure_http_rpc(OSMOSIS_RPC),
            "osmosis_chain_id": "osmosis-1",
            "arkeo_address": arkeo_addr,
            "arkeo_address_error": addr_err,
        }
        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    rest_api_val = ""

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
    # ETH/OSMOSIS hot wallets disabled (external signing expected)
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
            "osmosis_error": OSMO_WALLET_DISABLED_MSG,
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


def _update_listeners_atomic(mutator) -> dict:
    """
    Atomically read-modify-write listeners.json under an in-process lock.

    mutator(data) should return True if it modified the payload (so we should write),
    otherwise False.
    """
    with _LISTENERS_RW_LOCK:
        data = _ensure_listeners_file()
        changed = False
        try:
            changed = bool(mutator(data))
        except Exception:
            changed = False
        if changed:
            try:
                data["fetched_at"] = _timestamp()
            except Exception:
                pass
            _write_listeners(data)
        return data


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
        # Persist dynamic/runtime fields; static metadata is hydrated from caches.
        for key in (
            "status",
            "status_updated_at",
            # Response-time metrics (computed by proxy lane)
            "rt_avg_ms",
            "rt_count",
            "rt_last_ms",
            "rt_updated_at",
            # Polling warm-up: skip the first metric sample after reset-metrics.
            "rt_ignore_next",
            # Contract/config status (set by proxy path and surfaced in UI)
            "last_contract_id",
            "last_cors_origins",
            "cors_configured",
        ):
            if key in item:
                entry[key] = item.get(key)
        normalized.append(entry)
    return normalized


def _merge_top_services_persisted_fields(existing: list, incoming: list) -> list[dict]:
    """Merge persisted per-provider fields from existing top_services into incoming top_services."""
    existing_by_pk: dict[str, dict] = {}
    for e in existing if isinstance(existing, list) else []:
        if not isinstance(e, dict):
            continue
        pk = e.get("provider_pubkey") or e.get("pubkey")
        if pk:
            existing_by_pk[str(pk)] = e

    merged: list[dict] = []
    for item in incoming if isinstance(incoming, list) else []:
        if not isinstance(item, dict):
            continue
        out = dict(item)
        pk = out.get("provider_pubkey") or out.get("pubkey")
        src = existing_by_pk.get(str(pk)) if pk is not None else None
        if isinstance(src, dict):
            for key in (
                "status",
                "status_updated_at",
                "rt_avg_ms",
                "rt_count",
                "rt_last_ms",
                "rt_updated_at",
                "rt_ignore_next",
                "last_contract_id",
                "last_cors_origins",
                "cors_configured",
            ):
                if key not in out and key in src:
                    out[key] = src.get(key)
        merged.append(out)
    return merged


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


def _provider_location_from_meta(p: dict | None) -> str | None:
    if not isinstance(p, dict):
        return None
    meta = p.get("metadata") or {}
    location = (
        (meta.get("config") or {}).get("location")
        or meta.get("location")
        or (p.get("provider") or {}).get("location")
        or p.get("location")
    )
    return location or None


def _normalize_location_value(value: str | None) -> str:
    if not value:
        return ""
    val = str(value).strip()
    val = val.replace("–", "-").replace("—", "-")
    val = re.sub(r"\s*-\s*", " - ", val)
    return val.lower()


def _location_family(value: str | None) -> str:
    norm = _normalize_location_value(value)
    if " - " in norm:
        return norm.split(" - ", 1)[0].strip()
    return norm


def _location_match_score(preferred: str | None, candidate: str | None) -> int:
    if not preferred:
        return 0
    pref = _normalize_location_value(preferred)
    cand = _normalize_location_value(candidate)
    if not cand:
        return 1
    if " - " in pref:
        return 0 if cand == pref else 1
    return 0 if _location_family(cand) == pref else 1


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
        if not entry.get("provider_location"):
            entry["provider_location"] = _provider_location_from_meta(provider_meta_map.get(pk)) or entry.get("provider_location")
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
    bypass_pw = l.get("bypass_password") or ""
    l["bypass_password_set"] = bool(bypass_pw)
    if "bypass_password" in l:
        l.pop("bypass_password", None)
    try:
        port_val = l.get("port")
        port = int(port_val) if port_val is not None else None
    except Exception:
        port = None
    if port is not None:
        try:
            entry = _LISTENER_SERVERS.get(port)
            srv = entry.get("server") if isinstance(entry, dict) else None
        except Exception:
            srv = None
        if srv is not None:
            bypass_last_ms = getattr(srv, "bypass_last_ms", None)
            bypass_last_code = getattr(srv, "bypass_last_code", None)
            bypass_last_at = getattr(srv, "bypass_last_at", None)
            if bypass_last_ms is None:
                last_timings = getattr(srv, "last_timings", None)
                if isinstance(last_timings, dict) and last_timings.get("bypass"):
                    bypass_last_ms = last_timings.get("total_ms")
            if bypass_last_ms is not None:
                l["bypass_last_ms"] = bypass_last_ms
            if bypass_last_code is not None:
                l["bypass_last_code"] = bypass_last_code
            if bypass_last_at is not None:
                l["bypass_last_at"] = bypass_last_at
            try:
                cooldown_until = getattr(srv, "bypass_cooldown_until", None)
                if cooldown_until:
                    l["bypass_cooldown_until"] = cooldown_until
            except Exception:
                pass
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


def _safe_bool(val, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off", ""):
        return False
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


def _parse_cors_origins(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(o).strip() for o in raw if str(o).strip()]
    return [o.strip() for o in str(raw).split(",") if o.strip()]


def _resolve_proxy_cors_origin(origin: str | None, cfg: dict | None) -> str | None:
    origins = _parse_cors_origins(cfg.get("cors_allowed_origins") if isinstance(cfg, dict) else None)
    if not origins:
        return None
    if "*" in origins:
        return "*"
    if not origin:
        return None
    return origin if origin in origins else None


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

    cors_override = listener.get("cors_allowed_origins") if "cors_allowed_origins" in listener else None
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
        "bypass_uri": listener.get("bypass_uri") or "",
        "bypass_username": listener.get("bypass_username") or "",
        "bypass_password": listener.get("bypass_password") or "",
        "bypass_timeout_sec": listener.get("bypass_timeout_sec", PROXY_BYPASS_TIMEOUT),
        "bypass_cooldown_sec": listener.get("bypass_cooldown_sec", PROXY_BYPASS_COOLDOWN),
        "top_services": listener.get("top_services") or [],
        "cors_allowed_origins": cors_override if cors_override is not None else CORS_ALLOWED_ORIGINS,
        "last_contracts": {
            str(entry.get("provider_pubkey")): {
                "contract_id": entry.get("last_contract_id"),
                "cors_origins": entry.get("last_cors_origins"),
                "cors_configured": entry.get("cors_configured", False),
            }
            for entry in (listener.get("top_services") or [])
            if isinstance(entry, dict) and entry.get("provider_pubkey")
        },
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
    srv.cors_configured = cfg.get("last_contracts") or {}
    # Warmup flag for response-time metrics (first successful request after (re)start is ignored).
    srv.metrics_warm = False
    # In-memory caches used by the lane worker
    srv.contract_cache = {}
    srv.nonce_stores = {}
    srv.cooldowns = {}
    # Single-lane executor: serialize nonce/sign/forward per listener
    srv.lane_exec = SingleLaneExecutor(cfg, maxsize=16)
    timeout_secs = _safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS)
    create_timeout = _safe_int(cfg.get("create_timeout_sec", PROXY_CREATE_TIMEOUT), PROXY_CREATE_TIMEOUT)
    # Worst-case: a request may need to open a contract then forward upstream.
    srv.lane_timeout = max(timeout_secs, timeout_secs + create_timeout)
    # Limit simultaneous handler threads waiting on the lane to avoid unbounded growth
    srv.lane_sem = threading.BoundedSemaphore(32)

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
            "bypass_uri",
            "bypass_username",
            "bypass_password",
            "bypass_timeout_sec",
            "bypass_cooldown_sec",
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
        # Always return the full allowed range so the UI can move the floor back down.
        "port_range": [LISTENER_PORT_START, LISTENER_PORT_END],
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
    """Return service name/description from cached service registries."""
    sid = str(service_id or "").strip()
    if not sid:
        return {}

    # 1) active_service_types (derived from active_services)
    try:
        lookup = _load_active_service_types_lookup()
        st = lookup.get(sid) if isinstance(lookup, dict) else None
        if isinstance(st, dict):
            name = (st.get("name") or "").strip()
            desc = (st.get("description") or "").strip()
            if name or desc:
                return {"service_id": sid, "service_name": name, "service_description": desc}
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
                name = (item.get("name") or item.get("service") or "").strip()
                desc = (item.get("description") or "").strip()
                if name or desc:
                    return {"service_id": sid, "service_name": name, "service_description": desc}
    except Exception:
        pass

    # 3) best-effort name-only lookup
    try:
        name = _service_slug_for_id(sid)
        if name:
            return {"service_id": sid, "service_name": name, "service_description": ""}
    except Exception:
        pass
    return {}


def _auto_start_listeners() -> None:
    """Auto-start listeners marked active in listeners.json on process boot."""
    try:
        data = _ensure_listeners_file()
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return
        for entry in listeners:
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("status") or "").lower()
            if status != "active":
                continue
            ok, err = _ensure_listener_runtime(entry, previous_port=None, previous_status=None, previous_entry=None)
            if not ok and err:
                print(f"[listener] autostart failed port={entry.get('port')} err={err}", flush=True)
    except Exception as e:
        try:
            print(f"[listener] autostart exception: {e}", flush=True)
        except Exception:
            pass


def _active_service_type_lookup(service_id) -> dict:
    """Return service name/description from active_service_types cache file."""
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

    def _mut(data: dict) -> bool:
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            ts = l.get("top_services")
            if not isinstance(ts, list):
                return False
            for entry in ts:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("provider_pubkey")) != str(provider_pubkey):
                    continue
                if entry.get("status") == status:
                    return False
                entry["status"] = status
                entry["status_updated_at"] = _timestamp()
                l["updated_at"] = _timestamp()
                return True
            return False
        return False

    try:
        _update_listeners_atomic(_mut)
    except Exception:
        pass


def _update_top_service_metrics(
    listener_id: str | None,
    provider_pubkey: str | None,
    response_time_sec: float | None,
    include_in_avg: bool = True,
):
    """
    Update response-time fields for a provider entry in listeners.json.

    - Always stores the last observed timing (rt_last_ms).
    - Updates avg/count only when include_in_avg=True and warmup is not active.
    """
    if not listener_id or not provider_pubkey or response_time_sec is None:
        return
    rt_ms = int(response_time_sec * 1000)

    def _mut(data: dict) -> bool:
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            ts = l.get("top_services")
            if not isinstance(ts, list):
                return False
            for entry in ts:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("provider_pubkey")) != str(provider_pubkey):
                    continue
                # Always store the last observed timing (even if we don't include it in avg/count).
                entry["rt_last_ms"] = rt_ms
                entry["rt_updated_at"] = _timestamp()
                l["updated_at"] = _timestamp()

                # When polling, we reset metrics and mark the next sample as a warm-up (per provider).
                # Consume the flag here so it survives UI reorders and avoids double-counting.
                try:
                    ign = entry.get("rt_ignore_next")
                    if ign is not None and str(ign).strip().lower() not in ("0", "false", "no", "off", ""):
                        entry.pop("rt_ignore_next", None)
                        return True
                except Exception:
                    entry.pop("rt_ignore_next", None)
                    return True

                # Do not update avg/count for samples that are excluded (e.g., config failed).
                if not include_in_avg:
                    return True
                cnt = _safe_int(entry.get("rt_count"), 0)
                avg = float(entry.get("rt_avg_ms") or 0)
                new_cnt = cnt + 1
                new_avg = ((avg * cnt) + rt_ms) / new_cnt if new_cnt else rt_ms
                entry["rt_avg_ms"] = new_avg
                entry["rt_count"] = new_cnt
                return True
            return False
        return False

    try:
        _update_listeners_atomic(_mut)
    except Exception:
        pass


def _update_top_service_contract(
    listener_id: str | None,
    provider_pubkey: str | None,
    contract_id: str | int | None,
    origins: str | list | None = None,
    cors_configured: bool | None = None,
):
    """Persist last contract id/origins per provider entry in listeners.json (best effort)."""
    if not listener_id or provider_pubkey is None or contract_id is None:
        return
    cid = str(contract_id)

    def _mut(data: dict) -> bool:
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            ts = l.get("top_services")
            if not isinstance(ts, list):
                return False
            for entry in ts:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("provider_pubkey")) != str(provider_pubkey):
                    continue
                entry["last_contract_id"] = cid
                if origins is not None:
                    entry["last_cors_origins"] = origins
                if cors_configured is not None:
                    entry["cors_configured"] = bool(cors_configured)
                l["updated_at"] = _timestamp()
                return True
            return False
        return False

    try:
        _update_listeners_atomic(_mut)
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
    include_down = True
    # If we have at least one healthy entry, skip "Down"/misconfigured providers from the live candidate set.
    # This keeps a failed provider in the UI list but avoids routing to it during normal operation.
    if isinstance(top, list):
        try:
            include_down = not any(
                str(ts.get("status") or "").lower() in ("up", "ok") and ts.get("cors_configured") is not False
                for ts in top
                if isinstance(ts, dict)
            )
        except Exception:
            include_down = True
        for ts in top:
            if not isinstance(ts, dict):
                continue
            if not include_down:
                ts_status = str(ts.get("status") or "").lower()
                if ts_status == "down" or ts.get("cors_configured") is False:
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


def _read_arkeo_status_cache(max_age_sec: float | None = None) -> dict | None:
    try:
        with open(ARKEO_STATUS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        if max_age_sec is not None:
            ts = float(data.get("synced_at_unix") or 0)
            if ts <= 0:
                return None
            if (time.time() - ts) > float(max_age_sec):
                return None
        return data
    except Exception:
        return None


def _write_arkeo_status(ok: bool, node: str, height: int | None = None, error: str | None = None, status: dict | None = None) -> None:
    payload = {
        "ok": ok,
        "height": height,
        "node": node,
        "synced_at": _timestamp(),
        "synced_at_unix": time.time(),
    }
    if error:
        payload["error"] = error
    if status is not None:
        payload["status"] = status
    tmp_path = f"{ARKEO_STATUS_FILE}.tmp"
    try:
        Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
        os.replace(tmp_path, ARKEO_STATUS_FILE)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _get_current_height(node: str) -> int:
    cached = _read_arkeo_status_cache(ARKEO_STATUS_TTL)
    if cached is not None:
        if cached.get("ok") and cached.get("height") is not None:
            return _safe_int(cached.get("height"))
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if node:
        cmd.extend(["--node", node])
    cmd.append("status")
    code, out = run_list(cmd)
    if code != 0:
        _write_arkeo_status(False, node, None, f"status exit={code}")
        return 0
    try:
        data = json.loads(out)
        sync_info = data.get("sync_info") or data.get("SyncInfo") or {}
        height = _safe_int(sync_info.get("latest_block_height") or sync_info.get("latest_block"))
        _write_arkeo_status(True, node, height, None, data)
        return height
    except Exception:
        _write_arkeo_status(False, node, None, "invalid status json")
        return 0


def _get_height_with_source(node: str) -> tuple[int, bool]:
    cached = _read_arkeo_status_cache(ARKEO_STATUS_TTL)
    if cached is not None and cached.get("ok") and cached.get("height") is not None:
        return _safe_int(cached.get("height")), True
    return _get_current_height(node), False


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


def _select_active_contract(
    contracts: list,
    client_pub: str,
    svc_id: int,
    cur_height: int,
    provider_filter: str | None = None,
    height_skew: int = 0,
):
    """Pick newest usable contract for this client/service (optionally provider)."""
    try:
        effective_height = cur_height + int(height_skew or 0)
    except Exception:
        effective_height = cur_height
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
        if (_safe_int(c.get("height")) + _safe_int(c.get("duration"))) <= effective_height:
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


def _nonce_store_path(listener_id: str | None, contract_id: str | None) -> str:
    lid = str(listener_id or "listener")
    cid = str(contract_id or "contract")
    return os.path.join(NONCE_STORE_DIR, f"nonce_store_{lid}_{cid}.json")


def _handle_forward_lane(work: WorkItem, cfg: dict) -> dict:
    """Single-lane worker: select/auto-create contract, allocate nonce, sign, forward, return response."""
    t_start = time.time()
    method = (work.method or "POST").upper()
    service_path = work.path or ""
    query_string = work.query or ""
    body = work.body or b""
    raw_path = getattr(work, "raw_path", None) or "/"
    raw_query = getattr(work, "raw_query", None)
    if raw_query is None:
        raw_query = query_string
    client_ip = work.client_ip or ""
    queue_wait_ms = 0
    try:
        if getattr(work, "created_at", None):
            queue_wait_ms = int((t_start - float(work.created_at)) * 1000)
            if queue_wait_ms < 0:
                queue_wait_ms = 0
    except Exception:
        queue_wait_ms = 0

    listener_id = cfg.get("listener_id")
    node = cfg.get("node_rpc") or ARKEOD_NODE
    service = cfg.get("service_name") or cfg.get("service_slug") or cfg.get("service_id") or ""
    svc_id = _safe_int(cfg.get("service_id"), 0)
    client_key = cfg.get("client_key") or KEY_NAME
    sign_template = cfg.get("sign_template", PROXY_SIGN_TEMPLATE)

    server_ref = cfg.get("_server_ref", None)
    logger = getattr(server_ref, "logger", None) if server_ref is not None else None

    def _log(level: str, msg: str) -> None:
        if not logger:
            return
        fn = getattr(logger, level, None)
        if callable(fn):
            try:
                fn(msg)
            except Exception:
                pass

    def _req_header(name: str) -> str | None:
        try:
            req_headers = getattr(work, "headers", None)
            if not isinstance(req_headers, dict):
                return None
            val = req_headers.get(name)
            if val is None:
                name_l = str(name).lower()
                for hk, hv in req_headers.items():
                    if str(hk).lower() == name_l:
                        val = hv
                        break
            if val is None:
                return None
            return str(val)
        except Exception:
            return None

    # Parity: enforce whitelist again inside the lane.
    wl = _parse_whitelist(cfg.get("whitelist_ips") or PROXY_WHITELIST_IPS)
    allow_all = any(ip == "0.0.0.0" for ip in wl)
    if not allow_all and client_ip and client_ip not in wl:
        return {
            "status": 403,
            "body": json.dumps({"error": "ip not whitelisted", "ip": client_ip}),
            "headers": {"Content-Type": "application/json"},
        }

    bypass_uri = (cfg.get("bypass_uri") or "").strip()
    bypass_skip_reason = None
    try:
        if _req_header("X-Arkeo-Force-Provider"):
            bypass_skip_reason = "force_provider"
        bypass_hdr = _req_header("X-Arkeo-Bypass")
        if bypass_hdr and str(bypass_hdr).strip().lower() in ("0", "false", "no", "off", "disable", "disabled"):
            bypass_skip_reason = "header_disabled"
    except Exception:
        bypass_skip_reason = None

    if bypass_uri and bypass_skip_reason:
        _log("info", f"bypass skipped ({bypass_skip_reason})")
    elif bypass_uri:
        bypass_timeout = _safe_float(cfg.get("bypass_timeout_sec"), PROXY_BYPASS_TIMEOUT)
        if bypass_timeout <= 0:
            bypass_timeout = PROXY_BYPASS_TIMEOUT
        bypass_cooldown = _safe_float(cfg.get("bypass_cooldown_sec"), PROXY_BYPASS_COOLDOWN)
        if bypass_cooldown < 0:
            bypass_cooldown = 0.0
        bypass_username = cfg.get("bypass_username") or ""
        bypass_password = cfg.get("bypass_password") or ""
        try:
            now = time.time()
            cooldown_until = 0.0
            if server_ref is not None:
                cooldown_until = float(getattr(server_ref, "bypass_cooldown_until", 0.0) or 0.0)
            if cooldown_until and now < cooldown_until:
                _log("warning", f"bypass cooldown active; skipping for {cooldown_until - now:.0f}s")
                raise BypassError("cooldown_active")
            bypass_log_url = _redact_url_userinfo(bypass_uri)
            _log("info", f"bypass attempt url={bypass_log_url} timeout={bypass_timeout:.1f}s")
            code, resp_body, resp_hdrs, fwd_url, _fwd_headers = _forward_to_bypass(
                bypass_uri,
                raw_path,
                raw_query,
                body,
                method=method,
                timeout=bypass_timeout,
                headers=getattr(work, "headers", None),
                username=bypass_username,
                password=bypass_password,
            )
            if not isinstance(resp_hdrs, dict):
                resp_hdrs = {"Content-Type": "application/json"}
            resp_hdrs.setdefault("Content-Type", "application/json")
            try:
                hop_headers = {
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                    "proxy-connection",
                    "te",
                    "trailers",
                    "transfer-encoding",
                    "upgrade",
                    "content-length",
                }
                for hk in list(resp_hdrs.keys()):
                    if str(hk).lower() in hop_headers:
                        resp_hdrs.pop(hk, None)
                resp_hdrs["X-Arkeo-Bypass-Used"] = "1"
            except Exception:
                pass
            total_ms = int((time.time() - t_start) * 1000)
            other_ms = total_ms - queue_wait_ms
            if other_ms < 0:
                other_ms = 0
            try:
                if server_ref is not None:
                    timings_payload = {
                        "total_ms": total_ms,
                        "queue_wait_ms": queue_wait_ms,
                        "height_ms": 0,
                        "contract_fetch_ms": 0,
                        "contract_select_ms": 0,
                        "cors_ms": 0,
                        "cors_ok": None,
                        "nonce_store_ms": 0,
                        "nonce_prep_ms": 0,
                        "nonce_persist_ms": 0,
                        "sign_ms": 0,
                        "sentinel_forward_ms": other_ms,
                        "other_ms": 0,
                        "auto_create": False,
                        "bypass": True,
                    }
                    try:
                        want_timings = False
                        val = _req_header("X-Arkeo-Return-Timings")
                        if val is not None and str(val).strip().lower() not in ("", "0", "false", "no", "off", "null"):
                            want_timings = True
                        if want_timings:
                            resp_hdrs["X-Arkeo-Timings"] = json.dumps(timings_payload, separators=(",", ":"))
                    except Exception:
                        pass
                    server_ref.last_code = code
                    server_ref.last_timings = timings_payload
                    server_ref.bypass_last_ms = total_ms
                    server_ref.bypass_last_code = code
                    server_ref.bypass_last_at = time.time()
                    safe_headers = dict(_fwd_headers) if isinstance(_fwd_headers, dict) else {}
                    sensitive_headers = {
                        "authorization",
                        "cookie",
                        "set-cookie",
                        "x-api-key",
                        "x-api-token",
                        "x-auth-token",
                    }
                    for hk in list(safe_headers.keys()):
                        if str(hk).lower() in sensitive_headers:
                            safe_headers.pop(hk, None)
                    server_ref.last_upstream = {
                        "code": code,
                        "body": resp_body.decode(errors="ignore") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body),
                        "url": _redact_url_userinfo(fwd_url),
                        "headers": safe_headers,
                        "method": method,
                    }
            except Exception:
                pass
            try:
                _log("info", f"bypass timings total_ms={total_ms} queue_wait_ms={queue_wait_ms}")
            except Exception:
                pass
            _log("info", f"bypass ok code={code} url={_redact_url_userinfo(fwd_url)}")
            return {"status": code or 502, "body": resp_body or b"", "headers": resp_hdrs}
        except BypassError as e:
            _log("warning", f"bypass failed ({e}); falling back to arkeo")
            if server_ref is not None and bypass_cooldown > 0 and str(e) != "cooldown_active":
                server_ref.bypass_cooldown_until = time.time() + bypass_cooldown

    # Ensure client pubkey is available for contract selection/creation.
    client_pub = getattr(server_ref, "client_pubkey", "") if server_ref is not None else ""
    if not client_pub:
        raw, bech, err = derive_pubkeys(client_key, KEYRING)
        if not err and bech:
            client_pub = bech
            if server_ref is not None:
                server_ref.client_pubkey = bech
    if not client_pub:
        return {
            "status": 500,
            "body": json.dumps({"error": "client_pubkey_unavailable"}),
            "headers": {"Content-Type": "application/json"},
        }

    # Init caches on the server object for reuse across requests.
    if server_ref is not None:
        if not hasattr(server_ref, "contract_cache"):
            server_ref.contract_cache = {}
        if not hasattr(server_ref, "nonce_stores"):
            server_ref.nonce_stores = {}
        if not hasattr(server_ref, "cooldowns"):
            server_ref.cooldowns = {}
        if not hasattr(server_ref, "cors_configured"):
            server_ref.cors_configured = cfg.get("last_contracts") or {}

    # Candidate providers (ordered failover).
    forced_provider = None
    try:
        fp = _req_header("X-Arkeo-Force-Provider")
        if fp:
            fp = str(fp).strip()
            if fp:
                forced_provider = fp
    except Exception:
        forced_provider = None

    candidate_cfg = cfg
    if forced_provider:
        try:
            top_all = cfg.get("top_services") if isinstance(cfg.get("top_services"), list) else []
            forced_top = [
                ts
                for ts in top_all
                if isinstance(ts, dict) and str(ts.get("provider_pubkey") or "") == str(forced_provider)
            ]
            candidate_cfg = dict(cfg)
            candidate_cfg["provider_pubkey"] = forced_provider
            candidate_cfg["top_services"] = forced_top
            # Hint the sentinel URL for fallback if present on the top_services row
            try:
                if forced_top and forced_top[0].get("sentinel_url"):
                    candidate_cfg["provider_sentinel_api"] = forced_top[0].get("sentinel_url")
            except Exception:
                pass
            _log("info", f"force_provider enabled provider={forced_provider}")
        except Exception:
            candidate_cfg = cfg

    candidates = _candidate_providers(candidate_cfg)
    if forced_provider:
        candidates = [c for c in candidates if isinstance(c, dict) and str(c.get("provider_pubkey") or "") == str(forced_provider)]
    if not candidates:
        if forced_provider:
            return {
                "status": 503,
                "body": json.dumps({"error": "forced_provider_not_found", "provider_pubkey": forced_provider}),
                "headers": {"Content-Type": "application/json"},
            }
        return {"status": 503, "body": json.dumps({"error": "no_providers"}), "headers": {"Content-Type": "application/json"}}
    try:
        ordered = ", ".join(
            f"{c.get('provider_pubkey')}@{c.get('sentinel_url')}" for c in candidates if isinstance(c, dict)
        )
        _log("info", f"provider candidates (ordered): {ordered}")
    except Exception:
        pass

    height_start = time.time()
    cur_height, height_from_cache = _get_height_with_source(node)
    height_ms = int((time.time() - height_start) * 1000)

    try:
        height_skew = int(PROXY_HEIGHT_SKEW or 0) if height_from_cache else 0
    except Exception:
        height_skew = 0
    try:
        effective_height = cur_height + height_skew
    except Exception:
        effective_height = cur_height

    def _contract_is_usable(c: dict | None, provider_filter: str) -> bool:
        if not isinstance(c, dict):
            return False
        if str(c.get("client")) != str(client_pub):
            return False
        if str(c.get("provider")) != str(provider_filter):
            return False
        if _safe_int(c.get("service")) != svc_id:
            return False
        if _safe_int(c.get("settlement_height")) != 0:
            return False
        if _safe_int(c.get("deposit")) <= 0:
            return False
        if (_safe_int(c.get("height")) + _safe_int(c.get("duration"))) <= effective_height:
            return False
        return True

    last_err = None
    for idx, cand in enumerate(candidates, start=1):
        cand_start = time.time()
        provider_filter = cand.get("provider_pubkey")
        sentinel = _normalize_sentinel_url(
            cand.get("sentinel_url")
            or candidate_cfg.get("provider_sentinel_api")
            or cfg.get("provider_sentinel_api")
            or SENTINEL_URI_DEFAULT
        )
        if not provider_filter or not sentinel:
            continue

        _log("info", f"candidate {idx}/{len(candidates)} provider={provider_filter} sentinel={sentinel}")

        # Skip providers on cooldown.
        try:
            cd = getattr(server_ref, "cooldowns", {}).get(provider_filter) if server_ref is not None else None
            if cd and time.time() < cd and not forced_provider:
                continue
        except Exception:
            pass

        # ---- Contract selection (cache → chain → auto-create)
        contract_fetch_ms = 0
        contract_select_start = time.time()
        active = None

        # Cache hit (fast path).
        try:
            cache_entry = getattr(server_ref, "contract_cache", {}).get(provider_filter) if server_ref is not None else None
            if isinstance(cache_entry, dict) and _contract_is_usable(cache_entry.get("contract"), provider_filter):
                active = cache_entry.get("contract")
                _log("info", f"contract_cache_hit provider={provider_filter} contract_id={active.get('id')}")
        except Exception:
            pass

        # Chain select (slow path).
        if not active:
            t_fetch = time.time()
            contracts = _fetch_contracts(node, timeout=PROXY_CONTRACT_TIMEOUT, active_only=True, client_filter=client_pub)
            contract_fetch_ms = int((time.time() - t_fetch) * 1000)
            _log("info", f"contracts fetched count={len(contracts) if isinstance(contracts, list) else 0}")
            active = _select_active_contract(
                contracts or [],
                client_pub,
                svc_id,
                cur_height,
                provider_filter=provider_filter,
                height_skew=height_skew,
            )
            if active:
                _log(
                    "info",
                    f"contract_chain_select provider={provider_filter} contract_id={active.get('id')} height={active.get('height')}",
                )
                try:
                    if server_ref is not None:
                        server_ref.contract_cache[provider_filter] = {"contract": active, "cached_at": time.time()}
                except Exception:
                    pass

        auto_created = False
        # Auto-create if needed.
        if not active and _safe_bool(cfg.get("auto_create", PROXY_AUTO_CREATE), bool(PROXY_AUTO_CREATE)):
            auto_created = True
            _log("info", f"no active contract -> attempting auto-create (provider={provider_filter})")
            cfg_create = dict(cfg)
            cfg_create["create_provider_pubkey"] = provider_filter
            cfg_create["create_delegate"] = client_pub
            cfg_create["provider_pubkey"] = provider_filter
            cfg_create["provider_sentinel_api"] = sentinel
            # Align settlement duration with provider if known.
            try:
                if cand.get("settlement_duration"):
                    cfg_create["create_settlement"] = cand.get("settlement_duration")
            except Exception:
                pass
            # Align pay-as-you-go rate if advertised.
            try:
                rate_info = cand.get("pay_as_you_go_rate")
                if isinstance(rate_info, dict) and rate_info.get("amount"):
                    amt = str(rate_info.get("amount"))
                    denom = str(rate_info.get("denom") or "")
                    cfg_create["create_rate"] = f"{amt}{denom}"
            except Exception:
                pass
            # Align QPM if advertised.
            try:
                if cand.get("queries_per_minute") is not None:
                    cfg_create["create_qpm"] = cand.get("queries_per_minute")
            except Exception:
                pass
            start_height = cur_height or _get_current_height(node)
            try:
                _log(
                    "info",
                    "open-contract attempt "
                    f"deposit={_safe_int(cfg_create.get('create_deposit', PROXY_CREATE_DEPOSIT), PROXY_CREATE_DEPOSIT)} "
                    f"rate={cfg_create.get('create_rate', PROXY_CREATE_RATE)} "
                    f"dur={_safe_int(cfg_create.get('create_duration', PROXY_CREATE_DURATION), PROXY_CREATE_DURATION)} "
                    f"qpm={_safe_int(cfg_create.get('create_qpm', PROXY_CREATE_QPM), PROXY_CREATE_QPM)} "
                    f"settlement={_safe_int(cfg_create.get('create_settlement', PROXY_CREATE_SETTLEMENT), PROXY_CREATE_SETTLEMENT)} "
                    f"provider={provider_filter}"
                )
            except Exception:
                pass
            txhash, out, _dep, ok = _create_contract_now(cfg_create, client_pub, log_cb=_log)
            if out:
                _log("info", f"open-contract response: {out.strip()}")
            if txhash:
                _log("info", f"open-contract txhash={txhash}")
            if not ok:
                _log("info", "open-contract failed; skipping contract wait")
                last_err = "open_contract_failed"
                try:
                    _set_top_service_status(listener_id, provider_filter, "Down")
                except Exception:
                    pass
                try:
                    _update_top_service_metrics(listener_id, provider_filter, (time.time() - cand_start), include_in_avg=False)
                except Exception:
                    pass
                try:
                    if server_ref is not None and PROXY_OPEN_COOLDOWN:
                        server_ref.cooldowns[provider_filter] = time.time() + PROXY_OPEN_COOLDOWN
                except Exception:
                    pass
                continue
            wait_sec = _safe_int(cfg_create.get("create_timeout_sec", PROXY_CREATE_TIMEOUT), PROXY_CREATE_TIMEOUT)
            active = _wait_for_new_contract(cfg_create, client_pub, svc_id, start_height, wait_sec)
            if active:
                _log(
                    "info",
                    f"auto-created contract id={active.get('id')} height={active.get('height')} provider={provider_filter}",
                )
                try:
                    if server_ref is not None:
                        server_ref.contract_cache[provider_filter] = {"contract": active, "cached_at": time.time()}
                except Exception:
                    pass
                # New contract: reset CORS configured flag for this provider.
                try:
                    desired = cfg.get("cors_allowed_origins")
                    if server_ref is not None and isinstance(server_ref.cors_configured, dict):
                        server_ref.cors_configured[provider_filter] = {
                            "contract_id": str(active.get("id")),
                            "cors_origins": desired,
                            "cors_configured": False,
                        }
                    _update_top_service_contract(listener_id, provider_filter, active.get("id"), desired, cors_configured=False)
                except Exception:
                    pass

        if not active:
            last_err = "no_active_contract"
            try:
                _set_top_service_status(listener_id, provider_filter, "Down")
            except Exception:
                pass
            try:
                # Record how long we spent attempting this provider (even though it failed), so the UI can show a timing.
                _update_top_service_metrics(listener_id, provider_filter, (time.time() - cand_start), include_in_avg=False)
            except Exception:
                pass
            try:
                if server_ref is not None and PROXY_OPEN_COOLDOWN:
                    server_ref.cooldowns[provider_filter] = time.time() + PROXY_OPEN_COOLDOWN
            except Exception:
                pass
            continue

        contract_select_ms = int((time.time() - contract_select_start) * 1000) - int(contract_fetch_ms)
        if contract_select_ms < 0:
            contract_select_ms = 0

        cid = str(active.get("id"))
        contract_client = str(active.get("client") or client_pub)

        # Persist last contract id for this provider for status/debug.
        try:
            _update_top_service_contract(listener_id, provider_filter, cid, cfg.get("cors_allowed_origins"))
        except Exception:
            pass

        # ---- Configure proxy CORS (listener-local)
        cors_ok: bool | None = None
        cors_ms = 0
        desired_origins = cfg.get("cors_allowed_origins")
        if desired_origins is not None:
            cors_start = time.time()
            try:
                has_origins = bool(_parse_cors_origins(desired_origins))
                cors_ok = True if has_origins else False
                if server_ref is not None and isinstance(server_ref.cors_configured, dict):
                    server_ref.cors_configured[provider_filter] = {
                        "contract_id": cid,
                        "cors_origins": desired_origins,
                        "cors_configured": bool(cors_ok),
                    }
                _update_top_service_contract(
                    listener_id,
                    provider_filter,
                    cid,
                    desired_origins,
                    cors_configured=bool(cors_ok),
                )
            except Exception:
                pass
            finally:
                try:
                    cors_ms = int((time.time() - cors_start) * 1000)
                except Exception:
                    cors_ms = 0

        # ---- Per-contract nonce store
        nonce_store_ms = 0
        nonce_persist_ms = 0
        nonce_store = None
        nonce_store_start = time.time()
        try:
            stores = getattr(server_ref, "nonce_stores", None) if server_ref is not None else None
            if not isinstance(stores, dict):
                stores = {}
                if server_ref is not None:
                    server_ref.nonce_stores = stores
            nonce_store = stores.get(cid) if isinstance(stores, dict) else None
            if nonce_store is None:
                nonce_store = NonceStore(_nonce_store_path(listener_id, cid))
                persisted = _read_persisted_nonce(listener_id, cid) or 0
                highest = 0
                try:
                    highest = _claims_highest_nonce(sentinel, cid, contract_client)
                except Exception:
                    highest = 0
                seed = max(persisted, highest, nonce_store.nonce)
                if seed and seed != nonce_store.nonce:
                    nonce_store.set(seed)
                if isinstance(stores, dict):
                    stores[cid] = nonce_store
        except Exception:
            # Fallback to a throwaway store (still persisted on disk).
            nonce_store = NonceStore(_nonce_store_path(listener_id, cid))
        finally:
            try:
                nonce_store_ms = int((time.time() - nonce_store_start) * 1000)
            except Exception:
                nonce_store_ms = 0

        # ---- Nonce, sign, forward
        nonce_prep_start = time.time()
        nonce = nonce_store.next()
        nonce_prep_ms = int((time.time() - nonce_prep_start) * 1000)
        persist_start = time.time()
        try:
            _persist_listener_nonce(listener_id, cid, nonce)
        except Exception:
            pass
        finally:
            try:
                nonce_persist_ms += int((time.time() - persist_start) * 1000)
            except Exception:
                pass

        sign_start = time.time()
        sig_hex, sig_err = _sign_message(client_key, cid, nonce, sign_template)
        sign_ms = int((time.time() - sign_start) * 1000)
        if not sig_hex:
            last_err = sig_err or "sign_error"
            try:
                _update_top_service_metrics(listener_id, provider_filter, (time.time() - cand_start), include_in_avg=False)
            except Exception:
                pass
            continue

        timeout_secs = _safe_int(cfg.get("timeout_secs", PROXY_TIMEOUT_SECS), PROXY_TIMEOUT_SECS)
        as_header = _safe_bool(cfg.get("arkauth_as_header", PROXY_ARKAUTH_AS_HEADER), bool(PROXY_ARKAUTH_AS_HEADER))

        arkauth4 = f"{cid}:{contract_client}:{nonce}:{sig_hex}"
        _log("info", f"forwarding 4-part to sentinel={sentinel} svc={service} cid={cid} nonce={nonce} provider={provider_filter}")
        fwd_start = time.time()
        code, resp_body, resp_hdrs, fwd_url, fwd_headers = _forward_to_sentinel(
            sentinel,
            service_path,
            body,
            arkauth4,
            timeout=timeout_secs,
            as_header=as_header,
            method=method,
            query_string=query_string,
        )
        if code == 401:
            arkauth3 = f"{cid}:{nonce}:{sig_hex}"
            code, resp_body, resp_hdrs, fwd_url, fwd_headers = _forward_to_sentinel(
                sentinel,
                service_path,
                body,
                arkauth3,
                timeout=timeout_secs,
                as_header=as_header,
                method=method,
                query_string=query_string,
            )
        sentinel_forward_ms = int((time.time() - fwd_start) * 1000)

        def _is_nonce_error(code_val, body_val) -> bool:
            if int(code_val or 0) in (401, 403):
                return True
            try:
                if isinstance(body_val, (bytes, bytearray)) and b"nonce" in body_val.lower():
                    return True
            except Exception:
                pass
            try:
                if isinstance(body_val, str) and "nonce" in body_val.lower():
                    return True
            except Exception:
                pass
            return False

        # Sync nonce from sentinel on nonce-related errors, retry once.
        if _is_nonce_error(code, resp_body):
            try:
                highest = _claims_highest_nonce(sentinel, cid, contract_client)
                if highest >= 0:
                    nonce_store.set(highest)
            except Exception:
                pass
            nonce = nonce_store.next()
            persist_start = time.time()
            try:
                _persist_listener_nonce(listener_id, cid, nonce)
            except Exception:
                pass
            finally:
                try:
                    nonce_persist_ms += int((time.time() - persist_start) * 1000)
                except Exception:
                    pass
            sign_start = time.time()
            sig_hex, sig_err = _sign_message(client_key, cid, nonce, sign_template)
            sign_ms += int((time.time() - sign_start) * 1000)
            if not sig_hex:
                last_err = sig_err or "sign_error"
                try:
                    _update_top_service_metrics(listener_id, provider_filter, (time.time() - cand_start), include_in_avg=False)
                except Exception:
                    pass
                continue
            arkauth_retry = f"{cid}:{contract_client}:{nonce}:{sig_hex}"
            fwd_start = time.time()
            code, resp_body, resp_hdrs, fwd_url, fwd_headers = _forward_to_sentinel(
                sentinel,
                service_path,
                body,
                arkauth_retry,
                timeout=timeout_secs,
                as_header=as_header,
                method=method,
                query_string=query_string,
            )
            if code == 401:
                arkauth3_retry = f"{cid}:{nonce}:{sig_hex}"
                code, resp_body, resp_hdrs, fwd_url, fwd_headers = _forward_to_sentinel(
                    sentinel,
                    service_path,
                    body,
                    arkauth3_retry,
                    timeout=timeout_secs,
                    as_header=as_header,
                    method=method,
                    query_string=query_string,
                )
            sentinel_forward_ms = int((time.time() - fwd_start) * 1000)

        try:
            if _is_proxy_upstream_error(code, resp_body) and server_ref is not None and PROXY_PROVIDER_COOLDOWN > 0:
                server_ref.cooldowns[provider_filter] = time.time() + float(PROXY_PROVIDER_COOLDOWN)
        except Exception:
            pass

        total_ms = int((time.time() - t_start) * 1000)
        tracked_ms = (
            height_ms
            + contract_fetch_ms
            + contract_select_ms
            + cors_ms
            + nonce_store_ms
            + nonce_prep_ms
            + nonce_persist_ms
            + sign_ms
            + sentinel_forward_ms
        )
        other_ms = total_ms - tracked_ms
        if other_ms < 0:
            other_ms = 0

        timings_payload = {
            "total_ms": total_ms,
            "queue_wait_ms": queue_wait_ms,
            "height_ms": height_ms,
            "contract_fetch_ms": contract_fetch_ms,
            "contract_select_ms": contract_select_ms,
            "cors_ms": cors_ms,
            "cors_ok": cors_ok,
            "nonce_store_ms": nonce_store_ms,
            "nonce_prep_ms": nonce_prep_ms,
            "nonce_persist_ms": nonce_persist_ms,
            "sign_ms": sign_ms,
            "sentinel_forward_ms": sentinel_forward_ms,
            "other_ms": other_ms,
            "auto_create": bool(auto_created),
        }

        hdrs = {"Content-Type": resp_hdrs.get("Content-Type", "application/json")}
        # Decorate response headers with Arkeo metadata.
        try:
            hdrs["X-Arkeo-Contract-Id"] = cid
            hdrs["X-Arkeo-Nonce"] = str(nonce)
            hdrs["X-Arkeo-Provider"] = provider_filter or ""
            hdrs["X-Arkeo-Service-Id"] = str(svc_id)
            if cfg.get("decorate_response"):
                hdrs["X-Arkeo-Client"] = contract_client
                hdrs["X-Arkeo-Sentinel"] = sentinel
        except Exception:
            pass
        # Opt-in: include per-request timings in the response headers (used by /api/listeners/<id>/test to avoid races).
        try:
            want_timings = False
            req_headers = getattr(work, "headers", None)
            if isinstance(req_headers, dict):
                val = req_headers.get("X-Arkeo-Return-Timings")
                if val is None:
                    for hk, hv in req_headers.items():
                        if str(hk).lower() == "x-arkeo-return-timings":
                            val = hv
                            break
                if val is not None and str(val).strip().lower() not in ("", "0", "false", "no", "off", "null"):
                    want_timings = True
            if want_timings:
                hdrs["X-Arkeo-Timings"] = json.dumps(timings_payload, separators=(",", ":"))
        except Exception:
            pass

        # Cache active contract and last request info for status/debug.
        try:
            if server_ref is not None:
                server_ref.active_contract = active
                server_ref.last_nonce = nonce
                server_ref.last_code = code
                server_ref.last_candidate = {
                    "provider": provider_filter,
                    "sentinel": sentinel,
                    "service_id": svc_id,
                    "service_name": service,
                }
                server_ref.last_upstream = {
                    "code": code,
                    "body": resp_body.decode(errors="ignore") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body),
                    "url": fwd_url,
                    "headers": fwd_headers,
                    "method": method,
                }
                server_ref.last_timings = timings_payload
        except Exception:
            pass

        # Update listeners.json status/metrics.
        try:
            status_to_set = "Up" if int(code or 0) < 400 else "Down"
            if cors_ok is False:
                status_to_set = "Down"
            _set_top_service_status(listener_id, provider_filter, status_to_set)
        except Exception:
            pass
        try:
            # Record response-time fields for successful requests.
            # Always record last timing; update avg/count only when config succeeded.
            # Poll warm-up skipping is handled per provider via rt_ignore_next (set by /reset-metrics).
            if not auto_created:
                _update_top_service_metrics(
                    listener_id,
                    provider_filter,
                    (total_ms / 1000.0),
                    include_in_avg=(int(code or 0) < 400 and cors_ok is not False),
                )
        except Exception:
            pass

        _log(
            "info",
            "timings "
            f"total_ms={total_ms} queue_wait_ms={queue_wait_ms} height_ms={height_ms} "
            f"contract_fetch_ms={contract_fetch_ms} contract_select_ms={contract_select_ms} cors_ms={cors_ms} "
            f"nonce_store_ms={nonce_store_ms} nonce_prep_ms={nonce_prep_ms} nonce_persist_ms={nonce_persist_ms} "
            f"sign_ms={sign_ms} sentinel_forward_ms={sentinel_forward_ms} other_ms={other_ms} "
            f"auto_create={auto_created} provider={provider_filter} sentinel={sentinel} contract_id={cid}",
        )
        _log("info", f"proxy done code={code} cid={cid} nonce={nonce} provider={provider_filter}")

        return {"status": code or 502, "body": resp_body or b"", "headers": hdrs}

    return {"status": 503, "body": json.dumps({"error": last_err or "no_active_contract"}), "headers": {"Content-Type": "application/json"}}


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

def _parse_cors_origins(val) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        items = [str(v).strip() for v in val if str(v).strip()]
    else:
        items = [s.strip() for s in str(val).split(",") if s.strip()]
    if not items:
        return []
    if any(o == "*" for o in items):
        return ["*"]
    return items


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


def _fetch_contract_config(
    contract_id: int | str,
    sentinel_url: str | None,
    client_key: str,
    sign_template: str = PROXY_SIGN_TEMPLATE,
    timeout: int = 10,
) -> tuple[bool, dict | None, str | None]:
    """Fetch manage/contract/{id} from sentinel with signed arkauth."""
    try:
        cid = str(int(contract_id))
    except Exception:
        return False, None, "invalid contract id"
    base = _normalize_sentinel_url(sentinel_url) or ""
    base = base.rstrip("/")
    if not base:
        return False, None, "invalid sentinel url"
    nonce = int(time.time())
    sig, err = _sign_message(client_key, cid, nonce, sign_template)
    if err or not sig:
        return False, None, err or "sign failed"
    qs = urllib.parse.urlencode({"arkcontract": f"{cid}:{nonce}:{sig}"})
    url = f"{base}/manage/contract/{cid}?{qs}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status or 200
            if not (200 <= status < 300):
                return False, None, f"status {status}"
            try:
                data = json.loads(body.decode() if isinstance(body, (bytes, bytearray)) else str(body))
            except Exception:
                data = {"raw": body.decode(errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body)}
            return True, data, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="ignore")
        except Exception:
            body = ""
        return False, None, f"http_error {e.code}: {body[:200]}"
    except Exception as e:
        return False, None, str(e)


class BypassError(Exception):
    pass


def _forward_to_bypass(
    bypass_base: str,
    request_path: str,
    query_string: str | None,
    body: bytes | None,
    method: str = "POST",
    timeout: float = PROXY_BYPASS_TIMEOUT,
    headers: dict | None = None,
    username: str | None = None,
    password: str | None = None,
) -> tuple[int, bytes, dict, str, dict]:
    """Forward the request to a bypass target without Arkeo auth."""
    method = (method or "POST").upper()
    base = (bypass_base or "").strip().rstrip("/")
    if not base:
        raise BypassError("missing bypass url")
    path = request_path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base}{path}"
    qs = query_string or ""
    if qs and qs.startswith("?"):
        qs = qs[1:]
    if qs:
        url = f"{url}?{qs}"

    final_headers: dict[str, str] = {}
    skip_headers = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
    if isinstance(headers, dict):
        for hk, hv in headers.items():
            if hv is None:
                continue
            name = str(hk)
            lname = name.lower()
            if lname in skip_headers:
                continue
            final_headers[name] = str(hv)
    lower_names = {k.lower(): k for k in final_headers.keys()}
    if "accept" not in lower_names:
        final_headers["Accept"] = "application/json"
    if "content-type" not in lower_names:
        final_headers["Content-Type"] = "application/json"
    if username or password:
        for hk in list(final_headers.keys()):
            if hk.lower() == "authorization":
                final_headers.pop(hk, None)
        token = base64.b64encode(f"{username or ''}:{password or ''}".encode("utf-8")).decode("ascii")
        final_headers["Authorization"] = f"Basic {token}"

    data_bytes = body if method != "GET" else None
    req = urllib.request.Request(url, data=data_bytes, headers=final_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.getheaders()), url, final_headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers), url, final_headers
    except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
        raise BypassError(str(e))
    except Exception as e:
        raise BypassError(str(e))


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


def _redact_url_userinfo(url: str) -> str:
    """Remove userinfo and query strings from URLs before logging."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.scheme or not parsed.netloc:
            return url
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except Exception:
        return url
    return url


def _is_proxy_upstream_error(code: int | None, resp_body: bytes | str | None) -> bool:
    """Return True if the response matches our proxy_upstream_error wrapper."""
    try:
        if int(code or 0) != 502:
            return False
    except Exception:
        return False
    if resp_body is None:
        return False
    try:
        payload = resp_body
        if isinstance(resp_body, (bytes, bytearray)):
            payload = resp_body.decode("utf-8", errors="ignore")
        if isinstance(payload, str):
            payload = json.loads(payload)
        if isinstance(payload, dict) and payload.get("error") == "proxy_upstream_error":
            return True
    except Exception:
        return False
    return False


_TXHASH_RE = re.compile(r'(?i)\btxhash\b[:\s"]+([0-9A-Fa-f]{64})')


def _parse_tx_json(raw: str) -> dict | None:
    """Extract the tx JSON object from CLI output that may include warnings."""
    if not raw:
        return None
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except Exception:
                continue
    try:
        start = raw.find("{")
        if start != -1:
            return json.loads(raw[start:])
    except Exception:
        return None
    return None


def _create_contract_now(cfg: dict, client_pub: str, log_cb=None) -> tuple[str | None, str, int, bool]:
    def _query_account_seq(node_rpc: str) -> tuple[str | None, str | None]:
        client_key = cfg.get("client_key") or KEY_NAME
        keyring_backend = cfg.get("keyring_backend") or KEYRING
        addr, addr_err = derive_address(client_key, keyring_backend)
        if addr_err or not addr:
            return None, None
        acct_cmd = ["arkeod", "--home", ARKEOD_HOME, "query", "auth", "account", addr, "-o", "json"]
        if node_rpc:
            acct_cmd.extend(["--node", node_rpc])
        code, acct_out = run_list(acct_cmd)
        if code != 0:
            return None, None
        try:
            acct = json.loads(acct_out)
        except Exception:
            return None, None
        if not isinstance(acct, dict):
            return None, None
        account_info = acct.get("account") or acct.get("result") or {}
        if isinstance(account_info, dict) and account_info.get("base_account"):
            account_info = account_info.get("base_account") or {}
        if isinstance(account_info, dict):
            val = account_info.get("value") or account_info
        else:
            val = account_info
        if not isinstance(val, dict):
            return None, None
        seq_val = val.get("sequence")
        acc_num = val.get("account_number")
        return str(seq_val) if seq_val is not None else None, str(acc_num) if acc_num is not None else None
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
    node_rpc = cfg.get("node_rpc") or ARKEOD_NODE
    cmd_base = [
        "arkeod",
        "tx",
        "arkeo",
        "open-contract",
        "--home",
        ARKEOD_HOME,
        str(cfg.get("create_provider_pubkey", "")),
        str(cfg.get("service_name", "")),
        str(client_pub),
        str(_safe_int(cfg.get("create_type", "1"))),
        str(dep),
        str(_safe_int(cfg.get("create_duration", PROXY_CREATE_DURATION))),
        str(cfg.get("create_rate", PROXY_CREATE_RATE)),
        str(_safe_int(cfg.get("create_qpm", PROXY_CREATE_QPM))),
        str(_safe_int(cfg.get("create_settlement", PROXY_CREATE_SETTLEMENT))),
        str(_safe_int(cfg.get("create_authz", "0"))),
        str(cfg.get("create_delegate", "")),
        "--from",
        str(cfg.get("client_key", "")),
        "--fees",
        str(cfg.get("create_fees", PROXY_CREATE_FEES)),
        "--keyring-backend",
        str(cfg.get("keyring_backend", "test")),
        "--node",
        str(node_rpc),
        "--chain-id",
        str(cfg.get("chain_id")),
        "--yes",
        "--output",
        "json",
    ]
    cmd = [*cmd_base, "--gas", "auto", "--gas-adjustment", "1.2"]
    if callable(log_cb):
        try:
            log_cb("info", f"open-contract cmd={shlex.join(cmd)}")
        except Exception:
            pass
    try:
        with tx_lock(timeout_s=45.0):
            code, out = run_list(cmd)
    except TimeoutError:
        return None, "tx lock busy", dep, False
    if code != 0 and "account sequence mismatch" in str(out).lower():
        seq_val = None
        got_val = None
        m_exp = re.search(r"expected\s+(\d+)", str(out))
        m_got = re.search(r"got\s+(\d+)", str(out))
        if m_exp:
            seq_val = m_exp.group(1)
        if m_got:
            got_val = m_got.group(1)
        if seq_val is None and got_val is not None:
            try:
                seq_val = str(int(got_val) + 1)
            except Exception:
                seq_val = got_val
        acct_seq, _acct_num = _query_account_seq(node_rpc)
        if seq_val is None and acct_seq is not None:
            seq_val = acct_seq
        wait_max = _safe_int(cfg.get("create_timeout_sec", PROXY_CREATE_TIMEOUT), PROXY_CREATE_TIMEOUT)
        wait_max = min(wait_max, 10)
        if callable(log_cb):
            try:
                log_cb("info", f"open-contract retry wait target_seq={seq_val} timeout={wait_max}s")
            except Exception:
                pass
        if seq_val is not None:
            try:
                target_seq = int(seq_val)
            except Exception:
                target_seq = None
            deadline = time.time() + wait_max
            while target_seq is not None and time.time() < deadline:
                cur_seq, _cur_acc = _query_account_seq(node_rpc)
                try:
                    if cur_seq is not None and int(cur_seq) >= target_seq:
                        break
                except Exception:
                    pass
                time.sleep(0.5)
        else:
            time.sleep(min(0.5, wait_max))
        retry_cmd = list(cmd)
        if callable(log_cb):
            try:
                log_cb("info", f"open-contract retry cmd={shlex.join(retry_cmd)}")
            except Exception:
                pass
        try:
            with tx_lock(timeout_s=45.0):
                code, out = run_list(retry_cmd)
        except TimeoutError:
            return None, "tx lock busy", dep, False
    if code != 0:
        return None, out, dep, False
    j = _parse_tx_json(out)
    if isinstance(j, dict):
        code_val = j.get("code")
        if code_val not in (None, "", 0, "0"):
            return None, out, dep, False
        txh = j.get("txhash") or j.get("TxHash") or ""
        if isinstance(txh, list):
            txh = txh[0] if txh else ""
        if txh:
            return txh, out, dep, True
    m = _TXHASH_RE.search(out)
    if m:
        return m.group(1), out, dep, True
    return None, out, dep, True


def _wait_for_new_contract(cfg: dict, client_pub: str, svc_id: int, start_height: int, wait_sec: int) -> dict | None:
    deadline = time.time() + wait_sec
    node = cfg.get("node_rpc") or ARKEOD_NODE
    provider_filter = cfg.get("create_provider_pubkey") or cfg.get("provider_pubkey")
    while time.time() < deadline:
        contracts = _fetch_contracts(node, active_only=True, client_filter=client_pub)
        cur_h, height_from_cache = _get_height_with_source(node)
        try:
            height_skew = int(PROXY_HEIGHT_SKEW or 0) if height_from_cache else 0
        except Exception:
            height_skew = 0
        c = _select_active_contract(
            contracts,
            client_pub,
            svc_id,
            cur_h,
            provider_filter=provider_filter,
            height_skew=height_skew,
        )
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

    def do_OPTIONS(self):
        """Handle CORS preflight for proxy endpoints."""
        try:
            origin = self.headers.get("Origin")
        except Exception:
            origin = None
        allowed_origin = _resolve_proxy_cors_origin(origin, self.server.cfg)
        allow_headers = self.headers.get("Access-Control-Request-Headers", "*")
        self.send_response(204)
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            if allowed_origin != "*":
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", allow_headers)
            self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()
        self.close_connection = True

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
        allowed_origin = _resolve_proxy_cors_origin(origin, self.server.cfg)
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            if allowed_origin != "*":
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
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
        cfg = self.server.cfg
        # Pass server ref into cfg for lane helper access to active contract
        cfg["_server_ref"] = self.server
        if self.path.strip("/").split("?")[0] == "arkeostatus":
            node = cfg.get("node_rpc") or ARKEOD_NODE
            sentinel = cfg.get("provider_sentinel_api") or SENTINEL_URI_DEFAULT
            service_id = cfg.get("service_id")
            service_name = cfg.get("service_name")
            client_key = cfg.get("client_key") or KEY_NAME
            client_pub_local = getattr(self.server, "client_pubkey", "") or ""
            if not client_pub_local:
                raw, bech, err = derive_pubkeys(client_key, KEYRING)
                if not err:
                    client_pub_local = bech
                    self.server.client_pubkey = bech
            try:
                req_origin = self.headers.get("Origin")
            except Exception:
                req_origin = None
            allow_origin = _resolve_proxy_cors_origin(req_origin, cfg)
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
                "cors_request_origin": req_origin,
                "cors_allow_origin": allow_origin,
            }
            try:
                height_val, _from_cache = _get_height_with_source(node)
                payload["height"] = height_val
            except Exception:
                payload["height"] = None

            # If we don't already have an active_contract cached, try to select one
            if not payload.get("active_contract"):
                try:
                    cur_h, height_from_cache = _get_height_with_source(node)
                    try:
                        height_skew = int(PROXY_HEIGHT_SKEW or 0) if height_from_cache else 0
                    except Exception:
                        height_skew = 0
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
                        active = cache_entry.get("contract")
                    if not active:
                        contracts = _fetch_contracts(node, timeout=PROXY_CONTRACT_TIMEOUT, active_only=True, client_filter=client_pub_local)
                        active = _select_active_contract(
                            contracts or [],
                            client_pub_local,
                            _safe_int(service_id, 0),
                            cur_h,
                            provider_filter=provider_filter,
                            height_skew=height_skew,
                        )
                    if active and provider_filter:
                        try:
                            contract_cache[provider_filter] = {"contract": active, "cached_at": time.time()}
                        except Exception:
                            pass
                except Exception as e:
                    payload["active_contract_detail"] = f"Failed to load contract: {e}"
                    active = None
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
                    try:
                        _update_top_service_contract(cfg.get("listener_id"), provider_filter or active.get("provider"), active.get("id"), None)
                    except Exception:
                        pass
                    payload["active_contract_detail"] = "Active contract found for the selected provider service."
                    try:
                        cid = active.get("id")
                        if cid and client_pub_local:
                            payload["contract_claims_url"] = f"{sentinel}/claims?contract_id={cid}&client={client_pub_local}"
                        if cid:
                            payload["contract_manage_url_hint"] = f"{sentinel}/manage/contract/{cid}"
                        if cid and sentinel:
                            ok_cfg, cfg_data, cfg_err = _fetch_contract_config(
                                cid,
                                sentinel,
                                client_key,
                                cfg.get("sign_template", PROXY_SIGN_TEMPLATE),
                            )
                            if ok_cfg and cfg_data is not None:
                                payload["contract_config"] = cfg_data
                            elif cfg_err:
                                payload["contract_config_error"] = cfg_err
                    except Exception:
                        pass
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
    sem = getattr(self.server, "lane_sem", None)
    if sem is not None:
        got = sem.acquire(blocking=False)
        if not got:
            return self._send_json(503, {"error": "listener busy"})
    try:
        return self._do_post_inner_core(method=method)
    finally:
        if sem is not None:
            try:
                sem.release()
            except Exception:
                pass

def _do_post_inner_core(self, method: str = "POST"):
    """Parse request, enforce whitelist, enqueue to lane, return upstream response."""
    cfg = self.server.cfg
    # Make the server available to the lane worker for caching/state.
    cfg["_server_ref"] = self.server
    method = (method or "POST").upper()
    try:
        body_len = int(self.headers.get("Content-Length", "0"))
    except Exception:
        body_len = 0

    parsed_path = urllib.parse.urlparse(self.path or "/")
    incoming_path = parsed_path.path or "/"
    service = cfg.get("service_name") or cfg.get("service_slug") or cfg.get("service_id") or ""
    svc_id = _safe_int(cfg.get("service_id"), 0)
    service_path = service
    orig_query = parsed_path.query or ""

    path_no_slash = incoming_path[1:] if incoming_path.startswith("/") else incoming_path
    if service and path_no_slash.startswith(service):
        remainder = path_no_slash[len(service):]
        remainder = remainder[1:] if remainder.startswith("/") else remainder
    else:
        remainder = path_no_slash
    if remainder:
        service_path = f"{service}/{remainder}" if service else remainder

    try:
        body = self.rfile.read(body_len) if body_len > 0 else b""
    except Exception:
        body = b""

    try:
        self._log("info", f"req start service={service} svc_id={svc_id} bytes={len(body)} method={method}")
    except Exception:
        pass

    trust_forwarded = _safe_bool(cfg.get("trust_forwarded", PROXY_TRUST_FORWARDED), bool(PROXY_TRUST_FORWARDED))
    client_ip = self._client_ip(trust_forwarded)
    wl = _parse_whitelist(cfg.get("whitelist_ips") or PROXY_WHITELIST_IPS)
    allow_all = any(ip == "0.0.0.0" for ip in wl)
    if not allow_all:
        if client_ip not in wl:
            try:
                self._log("warning", f"whitelist block ip={client_ip} wl={wl}")
            except Exception:
                pass
            return self._send_json(403, {"error": "ip not whitelisted", "ip": client_ip})

    lane = getattr(self.server, "lane_exec", None)
    lane_timeout = getattr(self.server, "lane_timeout", PROXY_TIMEOUT_SECS)
    if not lane:
        return self._send_json(500, {"error": "lane_not_initialized"})

    work = WorkItem(
        method=method,
        path=service_path,
        query=orig_query,
        headers=dict(self.headers),
        body=body,
        client_ip=client_ip,
        deadline=time.time() + float(lane_timeout),
        raw_path=incoming_path,
        raw_query=orig_query,
    )
    if not lane.submit(work):
        try:
            qsz = None
            try:
                qsz = lane.q.qsize()
            except Exception:
                qsz = None
            if qsz is not None:
                self._log("warning", f"lane queue full qsize={qsz}")
            else:
                self._log("warning", "lane queue full")
        except Exception:
            pass
        return self._send_json(503, {"error": "listener busy"})
    try:
        qsz_after = None
        try:
            qsz_after = lane.q.qsize()
        except Exception:
            qsz_after = None
        if qsz_after is not None:
            self._log("info", f"lane enqueue ok qsize={qsz_after}")
    except Exception:
        pass

    try:
        resp = work.response.get(timeout=lane_timeout)
    except Exception:
        work.cancelled = True
        try:
            qsz = None
            try:
                qsz = lane.q.qsize()
            except Exception:
                qsz = None
            if qsz is not None:
                self._log("warning", f"lane timeout waiting for worker response qsize={qsz}")
            else:
                self._log("warning", "lane timeout waiting for worker response")
        except Exception:
            pass
        return self._send_json(503, {"error": "timeout"})

    status = resp.get("status", 502)
    body_bytes = resp.get("body", b"")
    hdrs = resp.get("headers", {})
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode()
    try:
        self.send_response(status)
        origin = self.headers.get("Origin")
        allowed_origin = _resolve_proxy_cors_origin(origin, self.server.cfg)
        if allowed_origin:
            hdrs["Access-Control-Allow-Origin"] = allowed_origin
            if allowed_origin != "*":
                hdrs.setdefault("Access-Control-Allow-Credentials", "true")
                hdrs.setdefault("Vary", "Origin")
            else:
                hdrs.pop("Access-Control-Allow-Credentials", None)
                hdrs.pop("Vary", None)
        else:
            hdrs.pop("Access-Control-Allow-Origin", None)
            hdrs.pop("Access-Control-Allow-Credentials", None)
        for hk, hv in hdrs.items():
            self.send_header(hk, hv)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body_bytes:
            self.wfile.write(body_bytes)
        self.close_connection = True
    except Exception as e:
        try:
            self._log("error", f"failed to send lane response: {e}")
        except Exception:
            pass
    return

# Bind the lane-aware handlers to the handler class
PaygProxyHandler._do_post_inner = _do_post_inner
PaygProxyHandler._do_post_inner_core = _do_post_inner_core


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
    timeout: float = None,
    method: str = "POST",
    path: str = "/",
) -> tuple[bool, str | None, str | None, dict, int | None]:
    """Attempt an HTTP request against the listener; return headers too."""
    method = (method or "POST").upper()
    path = path or "/"
    if not str(path).startswith("/"):
        path = f"/{path}"
    url = f"http://127.0.0.1:{port}{path}"
    data_bytes = None if method == "GET" else payload
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or PROXY_TEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return True, body, None, dict(resp.headers), int(getattr(resp, "status", 0) or 0)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = None
        return (
            False,
            body,
            f"HTTP {e.code}: {e.reason}",
            dict(e.headers) if e.headers else {},
            int(getattr(e, "code", 0) or 0),
        )
    except Exception as e:
        return False, None, str(e), {}, None


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


def _top_active_services_by_payg(service_id: str, limit: int = 3, preferred_location: str | None = None) -> list[dict]:
    """Return up to `limit` active services for the given service_id, sorted by location then pay-as-you-go rate."""
    if not service_id:
        return []
    # build provider lookup for moniker/status
    provider_lookup: dict[str, str] = {}
    provider_location_lookup: dict[str, str] = {}
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
                loc = _provider_location_from_meta(p)
                if loc:
                    provider_location_lookup[pk] = loc
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
        provider_pk = e.get("provider_pubkey") or ""
        moniker = provider_lookup.get(provider_pk) or "(Inactive)"
        provider_location = provider_location_lookup.get(provider_pk) or ""
        candidates.append(
            {
                "provider_pubkey": provider_pk,
                "provider_moniker": moniker,
                "metadata_uri": e.get("metadata_uri"),
                "pay_as_you_go_rate": {"amount": amt, "denom": denom},
                "queries_per_minute": qpm,
                "min_contract_duration": min_dur,
                "max_contract_duration": max_dur,
                "settlement_duration": settle,
                "provider_location": provider_location,
                "raw": e,
            }
        )
    # sort: first by missing rate (push down), then by amount asc
    def _sort_key(item: dict):
        rate = item.get("pay_as_you_go_rate") or {}
        amt = rate.get("amount")
        # push None to bottom by treating None as very large
        amt_key = amt if isinstance(amt, int) else (1 << 62)
        loc_score = _location_match_score(preferred_location, item.get("provider_location"))
        return (loc_score, amt_key, item.get("provider_pubkey") or "")

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
    location = None
    if "location" in payload:
        location = (payload.get("location") or "").strip()
    whitelist_ips = (payload.get("whitelist_ips") or "").strip()
    cors_allowed_origins = None
    if "cors_allowed_origins" in payload or "corsAllowedOrigins" in payload:
        cors_allowed_origins = (
            payload.get("cors_allowed_origins") or payload.get("corsAllowedOrigins") or ""
        ).strip()
    health_method_raw = (payload.get("health_method") or payload.get("healthMethod") or "POST").strip().upper()
    health_method = "GET" if health_method_raw == "GET" else "POST"
    health_payload = (payload.get("health_payload") or payload.get("healthPayload") or "").strip()
    health_header = (payload.get("health_header") or payload.get("healthHeader") or "").strip()
    bypass_uri = None
    if "bypass_uri" in payload or "bypassUri" in payload:
        bypass_uri = (payload.get("bypass_uri") or payload.get("bypassUri") or "").strip()
        if bypass_uri and not bypass_uri.lower().startswith(("http://", "https://")):
            return None, "bypass_uri must start with http:// or https://"
    bypass_username = None
    if "bypass_username" in payload or "bypassUsername" in payload:
        bypass_username = (payload.get("bypass_username") or payload.get("bypassUsername") or "").strip()
    bypass_password = None
    if "bypass_password" in payload or "bypassPassword" in payload:
        bypass_password = (payload.get("bypass_password") or payload.get("bypassPassword") or "").strip()
    bypass_timeout_sec = None
    if "bypass_timeout_sec" in payload or "bypassTimeoutSec" in payload:
        raw_timeout = payload.get("bypass_timeout_sec") or payload.get("bypassTimeoutSec") or ""
        raw_timeout = str(raw_timeout).strip()
        if raw_timeout:
            try:
                bypass_timeout_sec = float(raw_timeout)
            except Exception:
                return None, "bypass_timeout_sec must be a number"
        else:
            bypass_timeout_sec = ""
    bypass_cooldown_sec = None
    if "bypass_cooldown_sec" in payload or "bypassCooldownSec" in payload:
        raw_cooldown = payload.get("bypass_cooldown_sec") or payload.get("bypassCooldownSec") or ""
        raw_cooldown = str(raw_cooldown).strip()
        if raw_cooldown:
            try:
                bypass_cooldown_sec = float(raw_cooldown)
            except Exception:
                return None, "bypass_cooldown_sec must be a number"
        else:
            bypass_cooldown_sec = ""
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
        "location": location,
        "whitelist_ips": whitelist_ips,
        "cors_allowed_origins": cors_allowed_origins,
        "bypass_uri": bypass_uri,
        "bypass_username": bypass_username,
        "bypass_password": bypass_password,
        "bypass_timeout_sec": bypass_timeout_sec,
        "bypass_cooldown_sec": bypass_cooldown_sec,
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
        # Full allowed range (UI shows all options); floor indicates current minimum.
        "port_range": [LISTENER_PORT_START, LISTENER_PORT_END],
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
    best = _normalize_top_services(
        _top_active_services_by_payg(
            clean.get("service_id") or "",
            limit=5,
            preferred_location=clean.get("location") or None,
        )
    )
    # primary provider comes from top_services ordering
    raw_entry = {
        "id": payload.get("id") or str(int(time.time() * 1000)),
        "target": "",
        "status": clean["status"],
        "port": port,
        "service_id": clean.get("service_id") or "",
        "location": clean.get("location") or "",
        "top_services": best,
        "whitelist_ips": clean.get("whitelist_ips") or "",
        "cors_allowed_origins": clean.get("cors_allowed_origins") if clean.get("cors_allowed_origins") is not None else CORS_ALLOWED_ORIGINS,
        "bypass_uri": clean.get("bypass_uri") or "",
        "bypass_username": clean.get("bypass_username") or "",
        "bypass_password": clean.get("bypass_password") or "",
        "bypass_timeout_sec": clean.get("bypass_timeout_sec") if clean.get("bypass_timeout_sec") is not None else "",
        "bypass_cooldown_sec": clean.get("bypass_cooldown_sec") if clean.get("bypass_cooldown_sec") is not None else "",
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
    payload_top_services = payload.get("top_services") if isinstance(payload, dict) else None
    custom_top = payload_top_services if isinstance(payload_top_services, list) else None
    data = _ensure_listeners_file()
    listeners = data.get("listeners") if isinstance(data, dict) else []
    if not isinstance(listeners, list):
        listeners = []
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
    existing_location = None
    for l in listeners:
        if not isinstance(l, dict):
            continue
        if str(l.get("id")) == str(listener_id):
            existing_location = l.get("location")
            break
    preferred_location = clean.get("location") if clean.get("location") is not None else existing_location
    best = _top_active_services_by_payg(
        clean.get("service_id") or "",
        limit=5,
        preferred_location=preferred_location or None,
    )
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
        if clean.get("location") is not None:
            l["location"] = clean.get("location") or ""
        # top services ordering: use custom if provided, else keep existing unless service changed or empty
        existing_top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
        if custom_top is not None:
            # Honor explicit (even empty) input, but preserve persisted per-provider fields.
            new_top = _merge_top_services_persisted_fields(existing_top, custom_top)
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
        if clean.get("cors_allowed_origins") is not None:
            l["cors_allowed_origins"] = clean.get("cors_allowed_origins")
        if clean.get("bypass_uri") is not None:
            l["bypass_uri"] = clean.get("bypass_uri")
        if clean.get("bypass_username") is not None:
            l["bypass_username"] = clean.get("bypass_username")
        if clean.get("bypass_password") is not None:
            l["bypass_password"] = clean.get("bypass_password")
        if clean.get("bypass_timeout_sec") is not None:
            l["bypass_timeout_sec"] = clean.get("bypass_timeout_sec")
        if clean.get("bypass_cooldown_sec") is not None:
            l["bypass_cooldown_sec"] = clean.get("bypass_cooldown_sec")
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
    # Persist under lock so lane updates (contract/config/metrics) are not lost
    # due to concurrent read-modify-write writers.
    with _LISTENERS_RW_LOCK:
        fresh = _ensure_listeners_file()
        fresh_listeners = fresh.get("listeners") if isinstance(fresh, dict) else []
        if not isinstance(fresh_listeners, list):
            fresh_listeners = []
        persisted = None
        for l in fresh_listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            if clean["port"] is not None:
                l["port"] = clean["port"]
            l["target"] = ""
            l["status"] = clean["status"]
            l["service_id"] = clean.get("service_id") or ""
            # Preserve persisted per-provider fields when custom top_services is provided.
            existing_top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
            if custom_top is not None:
                new_top = _merge_top_services_persisted_fields(existing_top, custom_top)
            else:
                new_top = existing_top
                if str(l.get("service_id")) != str(clean.get("service_id") or "") or not new_top:
                    new_top = best
            l["top_services"] = _normalize_top_services(new_top)
            if clean.get("location") is not None:
                l["location"] = clean.get("location") or ""
            l["whitelist_ips"] = clean.get("whitelist_ips") if clean.get("whitelist_ips") is not None else l.get("whitelist_ips", "")
            if clean.get("cors_allowed_origins") is not None:
                l["cors_allowed_origins"] = clean.get("cors_allowed_origins")
            if clean.get("bypass_uri") is not None:
                l["bypass_uri"] = clean.get("bypass_uri")
            if clean.get("bypass_username") is not None:
                l["bypass_username"] = clean.get("bypass_username")
            if clean.get("bypass_password") is not None:
                l["bypass_password"] = clean.get("bypass_password")
            if clean.get("bypass_timeout_sec") is not None:
                l["bypass_timeout_sec"] = clean.get("bypass_timeout_sec")
            if clean.get("bypass_cooldown_sec") is not None:
                l["bypass_cooldown_sec"] = clean.get("bypass_cooldown_sec")
            l["health_method"] = clean.get("health_method") or l.get("health_method") or "POST"
            l["health_payload"] = clean.get("health_payload") if clean.get("health_payload") is not None else l.get("health_payload", "")
            l["health_header"] = clean.get("health_header") if clean.get("health_header") is not None else l.get("health_header", "")
            l["updated_at"] = _timestamp()
            persisted = l
            break
        if persisted is None:
            return jsonify({"error": "listener not found"}), 404
        fresh_listeners.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
        fresh["listeners"] = fresh_listeners
        _write_listeners(fresh)
        used_ports = _collect_used_ports(fresh_listeners)
        return jsonify({"listener": _enrich_listener_for_response(persisted), "next_port": _next_available_port(used_ports)})


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
        # Clean up per-listener nonce stores for this listener.
        try:
            cache_path = Path(NONCE_STORE_DIR)
            for f in cache_path.glob(f"nonce_store_{listener_id}_*.json"):
                try:
                    f.unlink()
                except Exception:
                    pass
        except Exception:
            pass
    new_list.sort(key=lambda x: x.get("port") if isinstance(x, dict) else 0)
    data["listeners"] = new_list
    data["fetched_at"] = _timestamp()
    _write_listeners(data)
    used_ports = _collect_used_ports(new_list)
    return jsonify({"status": "ok", "next_port": _next_available_port(used_ports)})


@app.post("/api/listeners/<listener_id>/reset-metrics")
def reset_listener_metrics(listener_id: str):
    """Clear response-time metrics for a listener's top services (used before polling)."""
    updated: dict | None = None

    def _mut(data: dict) -> bool:
        nonlocal updated
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            top = l.get("top_services") if isinstance(l.get("top_services"), list) else []
            for ts in top:
                if not isinstance(ts, dict):
                    continue
                ts.pop("rt_avg_ms", None)
                ts.pop("rt_count", None)
                ts.pop("rt_last_ms", None)
                ts.pop("rt_updated_at", None)
                # Per-provider warm-up: ignore the first sample after reset.
                ts["rt_ignore_next"] = True
            l["top_services"] = top
            l["updated_at"] = _timestamp()
            updated = l
            return True
        return False

    try:
        _update_listeners_atomic(_mut)
    except Exception as e:
        return jsonify({"error": "reset_failed", "detail": str(e)}), 500

    if not updated:
        return jsonify({"error": "listener not found"}), 404
    # Also reset in-memory warmup so the next request doesn't skew metrics.
    try:
        port_val = updated.get("port")
        port = int(port_val) if port_val is not None else None
        if port is not None:
            with _LISTENER_LOCK:
                entry = _LISTENER_SERVERS.get(port)
            srv = entry.get("server") if isinstance(entry, dict) else None
            if srv is not None:
                setattr(srv, "metrics_warm", False)
    except Exception:
        pass
    return jsonify({"listener": _enrich_listener_for_response(updated)})


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
    updated: dict | None = None

    def _mut(data: dict) -> bool:
        nonlocal updated
        listeners = data.get("listeners") if isinstance(data, dict) else []
        if not isinstance(listeners, list):
            return False
        for l in listeners:
            if not isinstance(l, dict):
                continue
            if str(l.get("id")) != str(listener_id):
                continue
            svc_id = l.get("service_id") or ""
            preferred_location = l.get("location") or None
            best = _normalize_top_services(
                _top_active_services_by_payg(svc_id, limit=3, preferred_location=preferred_location)
            )
            l["top_services"] = best
            l["updated_at"] = _timestamp()
            updated = l
            return True
        return False

    try:
        _update_listeners_atomic(_mut)
    except Exception as e:
        return jsonify({"error": "refresh_failed", "detail": str(e)}), 500

    if not updated:
        return jsonify({"error": "listener not found"}), 404
    return jsonify({"listener": _enrich_listener_for_response(updated)})


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
        forced_provider = request.args.get("provider_pubkey") or request.args.get("provider")
        if forced_provider:
            forced_provider = str(forced_provider).strip()
            if forced_provider:
                headers["X-Arkeo-Force-Provider"] = forced_provider
        # Polling uses the first run as a warm-up (contract fetch / config) and should not skew response-time stats.
        warmup = request.args.get("warmup")
        if warmup and str(warmup).strip().lower() not in ("0", "false", "no", "off", "null"):
            headers["X-Arkeo-Ignore-Metrics"] = "1"
        # Always request per-request timings in headers so the test endpoint is race-free (no reliance on global srv.last_timings).
        headers["X-Arkeo-Return-Timings"] = "1"
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
        ok, resp, err, resp_headers, resp_code = _test_listener_port(
            port,
            payload_bytes if hm != "GET" else None,
            headers,
            method=hm,
            path=req_path,
        )
        used_provider = None
        used_contract_id = None
        used_nonce = None
        bypass_used = False
        if isinstance(resp_headers, dict):
            def _hdr(name: str) -> str | None:
                v = resp_headers.get(name)
                if v is None:
                    name_l = name.lower()
                    for hk, hv in resp_headers.items():
                        if str(hk).lower() == name_l:
                            v = hv
                            break
                if v is None:
                    return None
                return str(v)
            used_provider = _hdr("X-Arkeo-Provider")
            used_contract_id = _hdr("X-Arkeo-Contract-Id")
            used_nonce = _hdr("X-Arkeo-Nonce")
            bypass_hdr = _hdr("X-Arkeo-Bypass-Used")
            if bypass_hdr is not None and str(bypass_hdr).strip().lower() not in ("", "0", "false", "no", "off", "null"):
                bypass_used = True
        timings_from_header = None
        if isinstance(resp_headers, dict):
            th = resp_headers.get("X-Arkeo-Timings") or resp_headers.get("x-arkeo-timings")
            if th:
                try:
                    timings_from_header = json.loads(th)
                except Exception:
                    timings_from_header = None
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
        if forced_provider:
            runtime_cfg["provider_pubkey"] = forced_provider
            try:
                runtime_cfg["top_services"] = [
                    ts
                    for ts in (runtime_cfg.get("top_services") or [])
                    if isinstance(ts, dict) and str(ts.get("provider_pubkey") or "") == str(forced_provider)
                ]
            except Exception:
                pass
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
            "forced_provider_pubkey": forced_provider,
            "used_provider_pubkey": used_provider,
            "used_contract_id": used_contract_id,
            "used_nonce": used_nonce,
            "bypass_used": bypass_used,
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
        if resp_code is not None:
            payload["last_upstream_code"] = resp_code
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
            last_timings = getattr(srv, "last_timings", None)
            if isinstance(last_timings, dict):
                payload["last_timings"] = last_timings
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
                # Expose configured CORS origins for visibility (configuration is handled by the proxy lane).
                try:
                    cfg_local = getattr(srv, "cfg", {}) or {}
                    cors_origins = cfg_local.get("cors_allowed_origins") or CORS_ALLOWED_ORIGINS
                    payload["cors_allowed_origins"] = cors_origins
                except Exception:
                    pass
        # Override last_timings with per-request timings when present to avoid races with other in-flight requests.
        if isinstance(timings_from_header, dict):
            payload["last_timings"] = timings_from_header
        # Override last_upstream_code with the actual HTTP status for this test request (race-free).
        if resp_code is not None:
            payload["last_upstream_code"] = resp_code
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
    # Keep PROVIDER_HUB_URI in sync if provided
    if payload.get("provider_hub_uri"):
        _set_env("PROVIDER_HUB_URI", payload.get("provider_hub_uri"))

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


@app.post("/api/subscriber-totals")
def subscriber_totals():
    """Summarize contract spending for this subscriber using cached provider-contracts."""
    body = request.get_json(silent=True) or {}
    service_filter = (body.get("service") or "").strip()
    from_h = str(body.get("from_height") or body.get("from") or 0)
    to_h = str(body.get("to_height") or body.get("to") or 999_999_999)
    from_h_int = _safe_int(from_h, 0)
    to_h_int = _safe_int(to_h, 999_999_999)

    def empty_summary(subscriber_pubkey: str = "", err: str | None = None, detail=None):
        return jsonify(
            {
                "subscriber_pubkey": subscriber_pubkey or None,
                "service_filter": service_filter or None,
                "from_height": from_h,
                "to_height": to_h,
                "tokens_paid_total_uarkeo": 0,
                "tokens_paid_finalized_uarkeo": 0,
                "payg_requests_total": 0,
                "active_contracts": 0,
                "settled_contracts": 0,
                "remaining_uarkeo": 0,
                "contracts": [],
                "service_totals": [],
                "error": err,
                "detail": detail,
            }
        ), 200

    raw_pubkey, bech32_pubkey, pub_err = derive_pubkeys(KEY_NAME, KEYRING)
    subscriber_pubkey = bech32_pubkey or raw_pubkey
    if not subscriber_pubkey:
        return empty_summary("", "failed to derive subscriber pubkey", pub_err)
    subscriber_pubkey_alts = {subscriber_pubkey.strip()}
    if raw_pubkey:
        subscriber_pubkey_alts.add(raw_pubkey.strip())

    contracts_raw = _load_cached("provider-contracts")
    contracts = []
    if isinstance(contracts_raw, dict):
        data = contracts_raw.get("data")
        if isinstance(data, dict):
            for key in ("contracts", "contract", "result"):
                val = data.get(key)
                if isinstance(val, list):
                    contracts = val
                    break
        elif isinstance(data, list):
            contracts = data
    if not isinstance(contracts, list):
        contracts = []

    filtered = []
    for c in contracts:
        if not isinstance(c, dict):
            continue
        client_val = c.get("client") or c.get("subscriber") or c.get("subscriber_pubkey") or ""
        client_val = str(client_val).strip().strip('"')
        if not client_val or client_val not in subscriber_pubkey_alts:
            continue
        service_val = c.get("service") or c.get("service_id") or c.get("serviceID") or c.get("name") or ""
        service_val = str(service_val).strip()
        if service_filter and service_val != service_filter:
            continue
        contract_id = c.get("contract_id") or c.get("id") or c.get("contractID") or c.get("contractId") or ""
        contract_type = (c.get("type") or c.get("authorization") or "").upper()
        settlement_height = _safe_int(
            c.get("settlement_height")
            or c.get("settlementHeight")
            or c.get("settlementheight")
            or 0,
            0,
        )
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
                continue

        settlement_duration = _safe_int(
            c.get("settlement_duration") or c.get("settlementDuration") or c.get("settlementduration") or 0,
            0,
        )
        paid = _safe_int(c.get("paid"), 0)
        deposit = _safe_int(c.get("deposit"), 0)
        nonce = _safe_int(c.get("nonce"), 0)
        if nonce == 0:
            continue
        rate_amount = 0
        rate_val = c.get("rate") or c.get("rates") or c.get("pay_as_you_go_rate") or c.get("pay_as_you_go_rates")
        if isinstance(rate_val, list) and rate_val:
            try:
                rate_amount = _safe_int((rate_val[0] or {}).get("amount"), 0)
            except Exception:
                rate_amount = 0
        elif isinstance(rate_val, dict):
            rate_amount = _safe_int(rate_val.get("amount"), 0)
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
        return empty_summary(subscriber_pubkey)

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
            "subscriber_pubkey": subscriber_pubkey,
            "service_filter": service_filter or None,
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
        }
    )


_bootstrap_thread = threading.Thread(target=_bootstrap_listeners_from_cache, daemon=True)
_bootstrap_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT)
