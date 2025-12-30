#!/usr/bin/env python3
import json
import os
import subprocess
from collections import deque
from datetime import datetime, timezone
import math
from flask import Flask, jsonify, request

from cache_fetcher import (
    ensure_cache_dir as cache_ensure_cache_dir,
    fetch_once as cache_fetch_once,
    STATUS_FILE as CACHE_STATUS_FILE,
)

app = Flask(__name__)

CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeo"))
ARKEOD_NODE = os.getenv("ARKEOD_NODE") or "tcp://127.0.0.1:26657"
NODE_ARGS = ["--node", ARKEOD_NODE] if ARKEOD_NODE else []
API_PORT = int(os.getenv("ADMIN_API_PORT") or os.getenv("ENV_ADMIN_API_PORT") or "9996")
LOG_FILES = {
    "init": "/var/log/dashboard-init.log",
    "cache": "/var/log/dashboard-cache.log",
    "api": "/var/log/dashboard-api.log",
    "web": "/var/log/dashboard-web.log",
    "supervisor": "/var/log/supervisor/supervisord.log",
    "dashboard_info": "/var/log/dashboard-info.log",
}

ARKEO_DECIMALS = 8
ARKEO_DIVISOR = 10**ARKEO_DECIMALS

DASHBOARD_INFO_FILE = os.getenv("DASHBOARD_INFO_FILE", "/app/cache/dashboard_info.json")
try:
    BLOCK_TIME_SECONDS = float(os.getenv("BLOCK_TIME_SECONDS", "5.79954919"))
except ValueError:
    BLOCK_TIME_SECONDS = 5.79954919


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


def _format_arkeo_amount(uarkeo) -> str:
    try:
        amount = int(uarkeo or 0)
    except (TypeError, ValueError):
        amount = 0
    sign = "-" if amount < 0 else ""
    amount = abs(amount)
    whole = amount // ARKEO_DIVISOR
    frac = amount % ARKEO_DIVISOR
    return f"{sign}{whole}.{frac:0{ARKEO_DECIMALS}d}"


def _load_cached(name: str) -> dict:
    path = os.path.join(CACHE_DIR, f"{name}.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _tail_file(path: str, max_lines: int = 400) -> tuple[list[str], bool]:
    """Return up to max_lines from the end of a file and whether it was truncated."""
    if not os.path.isfile(path):
        return [], False
    lines: deque[str] = deque(maxlen=max_lines)
    truncated = False
    try:
        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                count += 1
                lines.append(line.rstrip("\n"))
        truncated = count > max_lines
    except Exception:
        return [], False
    return list(lines), truncated


def _latest_block_height() -> tuple[int | None, str | None]:
    cmd = ["arkeod", "--home", ARKEOD_HOME, "status", "--output", "json"]
    if NODE_ARGS:
        cmd[1:1] = NODE_ARGS
    code, out = run_list(cmd)
    if code != 0:
        return None, f"arkeod status failed: {out}"
    try:
        payload = json.loads(out)
        sync_info = payload.get("SyncInfo") or payload.get("sync_info") or {}
        height_raw = sync_info.get("latest_block_height") or sync_info.get("latestBlockHeight")
        if height_raw is None:
            return None, "missing latest_block_height"
        try:
            return int(height_raw), None
        except (TypeError, ValueError):
            return None, f"invalid height: {height_raw}"
    except json.JSONDecodeError as e:
        return None, f"parse error: {e}"


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


@app.get("/api/ping")
def ping():
    return jsonify({"status": "ok", "ts": _timestamp()})


@app.get("/api/version")
def version():
    return jsonify({"app": "dashboard-core", "version": "dev"})


@app.get("/api/block-height")
def block_height():
    height, err = _latest_block_height()
    return jsonify({"height": height, "node": ARKEOD_NODE, "error": err})


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

    def provider_is_active(prov: dict) -> bool:
        """Treat truthy/online status values as active (active_providers are already pre-filtered)."""
        if not isinstance(prov, dict):
            return False
        status_val = prov.get("status")
        if status_val is None:
            return True
        if isinstance(status_val, bool):
            return bool(status_val)
        status_str = str(status_val).strip().lower()
        return status_str in ("1", "online", "true", "on", "up", "running")

    providers_list = [p for p in providers_list if provider_is_active(p)]
    contracts_list = contracts_raw.get("data", {}).get("contracts") or contracts_raw.get("data", {}).get("contract") or []
    if not isinstance(contracts_list, list):
        contracts_list = []
    services_list = []
    if isinstance(services_raw.get("data"), list):
        services_list = services_raw.get("data") or []
    elif isinstance(services_raw.get("data"), dict):
        data = services_raw["data"]
        services_list = data.get("services") or data.get("service") or data.get("result") or []
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
            return True
        if isinstance(status_val, bool):
            return bool(status_val)
        status_str = str(status_val).strip().lower()
        return status_str in ("1", "active", "online", "true", "on", "up", "running")

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
            amt, denom = _min_payg_rate(s if isinstance(s, dict) else {})
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
                    "pay_as_you_go_rate": {"amount": amt, "denom": denom},
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
                    "paid": c.get("paid"),
                    "height": c.get("height") or c.get("start_height") or c.get("created_height"),
                    "duration": c.get("duration"),
                    "rate": c.get("rate"),
                    "deposit": c.get("deposit"),
                    "type": c.get("type"),
                    "settlement_height": c.get("settlement_height"),
                    "settlement_duration": c.get("settlement_duration"),
                    "raw": c,
                }
            )
        combined.append(
            {
                "pubkey": pubkey,
                "provider": p.get("provider") or p,
                "provider_moniker": p.get("provider_moniker") or p.get("providerMoniker"),
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
        validators_cache = _load_cached("validators")
        if validators_cache:
            results["validators"] = {"data": validators_cache, "exit_code": 0}
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
    validators_cache = _safe_load("validators")

    counts = {
        "active_providers": 0,
        "active_services": 0,
        "contracts": 0,
        "supported_chains": 0,
        "subscribers": 0,
        "validators_bonded": 0,
        "validators_active": 0,
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
        total_paid, total_tx = _contracts_all_time_totals(contracts_list)
        counts["total_paid_uarkeo"] = total_paid
        counts["total_paid_arkeo"] = _format_arkeo_amount(total_paid)
        counts["total_transactions"] = total_tx
    else:
        counts["total_paid_uarkeo"] = 0
        counts["total_paid_arkeo"] = _format_arkeo_amount(0)
        counts["total_transactions"] = 0

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

    validators_list = []
    v_data = validators_cache.get("validators") or validators_cache.get("data") or {}
    if isinstance(v_data, list):
        validators_list = v_data
    elif isinstance(v_data, dict):
        validators_list = v_data.get("validators") or v_data.get("result") or []
    if isinstance(validators_list, list):
        counts["validators_bonded"] = len(validators_list)
        active = [v for v in validators_list if isinstance(v, dict) and not v.get("jailed")]
        counts["validators_active"] = len(active)

    return jsonify(counts)


@app.get("/api/logs")
def logs():
    """Return recent logs for debugging."""
    out: dict[str, dict] = {}
    for name, path in LOG_FILES.items():
        lines, truncated = _tail_file(path)
        out[name] = {
            "path": path,
            "lines": lines,
            "truncated": truncated,
            "line_count": len(lines),
        }
    return jsonify(out)


@app.get("/api/dashboard-info")
def dashboard_info():
    """Return the latest dashboard_info.json contents."""
    payload = {}
    try:
        if os.path.isfile(DASHBOARD_INFO_FILE):
            with open(DASHBOARD_INFO_FILE, "r", encoding="utf-8") as f:
                payload = json.load(f)
    except Exception:
        payload = {}
    return jsonify(payload)


@app.get("/api/active-services")
def active_services():
    """Return the cached active_services.json contents."""
    payload = {}
    try:
        payload = _load_cached("active_services") or {}
    except Exception:
        payload = {}
    return jsonify(payload)


@app.get("/api/active-service-types")
def active_service_types():
    """Return the cached active_service_types.json contents."""
    payload = {}
    try:
        payload = _load_cached("active_service_types") or {}
    except Exception:
        payload = {}
    return jsonify(payload)


def _blocks_for_range(range_name: str) -> int | None:
    """Return number of blocks for a named window (daily/weekly/monthly) based on BLOCK_TIME_SECONDS."""
    secs_map = {
        "daily": 86400,
        "weekly": 604800,
        "monthly": 2592000,
    }
    secs = secs_map.get(range_name)
    if not secs:
        return None
    bt = BLOCK_TIME_SECONDS if isinstance(BLOCK_TIME_SECONDS, (int, float)) else 5.79954919
    if bt <= 0:
        return None
    return max(1, int(math.ceil(secs / bt)))


def _parse_contract_height(contract: dict) -> int | None:
    for key in ("height", "start_height", "created_height", "settlement_height"):
        if key in contract:
            try:
                return int(contract.get(key))
            except (TypeError, ValueError):
                continue
    return None


def _contracts_all_time_totals(contracts_list: list) -> tuple[int, int]:
    total_paid = 0
    total_tx = 0
    for c in contracts_list:
        if not isinstance(c, dict):
            continue
        try:
            if int(c.get("nonce") or 0) == 0:
                continue
        except (TypeError, ValueError):
            pass
        try:
            total_paid += int(c.get("paid") or 0)
        except (TypeError, ValueError):
            pass
        try:
            total_tx += int(c.get("nonce") or 1)
        except (TypeError, ValueError):
            total_tx += 1
    return total_paid, total_tx


def _contract_provider_pubkey(contract: dict) -> str | None:
    for key in ("provider", "provider_pubkey", "provider_pub_key", "providerPubKey"):
        if key in contract:
            val = contract.get(key)
            if val:
                return str(val)
    return None


@app.get("/api/contracts-range")
def contracts_range():
    """Return contracts filtered by a time window (daily/weekly/monthly/all_time)."""
    range_param = (request.args.get("range") or "daily").lower()
    if range_param not in ("daily", "weekly", "monthly", "all_time"):
        range_param = "daily"
    provider_filter = request.args.get("provider") or request.args.get("pubkey") or request.args.get("provider_pubkey")
    provider_filter = str(provider_filter) if provider_filter else None
    block_window = _blocks_for_range(range_param) if range_param != "all_time" else None
    contracts_raw = _load_cached("provider-contracts")
    contracts_list = contracts_raw.get("data", {}).get("contracts") or contracts_raw.get("data", {}).get("contract") or []
    if not isinstance(contracts_list, list):
        contracts_list = []
    latest_height, height_err = _latest_block_height()
    cutoff = None
    if latest_height is not None and block_window:
        cutoff = latest_height - block_window
    filtered = []
    for c in contracts_list:
        if not isinstance(c, dict):
            continue
        if provider_filter:
            pk = _contract_provider_pubkey(c)
            if not pk or str(pk) != provider_filter:
                continue
        if cutoff is not None:
            h = _parse_contract_height(c)
            if h is not None and h < cutoff:
                continue
        # Ignore unused contracts (nonce == 0)
        try:
            if int(c.get("nonce") or 0) == 0:
                continue
        except (TypeError, ValueError):
            pass
        filtered.append(c)
    total_paid = 0
    total_tx = 0
    for c in filtered:
        try:
            total_paid += int(c.get("paid") or 0)
        except (TypeError, ValueError):
            pass
        try:
            total_tx += int(c.get("nonce") or 1)
        except (TypeError, ValueError):
            total_tx += 1
    return jsonify(
        {
            "range": range_param,
            "block_time_seconds": BLOCK_TIME_SECONDS,
            "block_window": block_window,
            "latest_height": latest_height,
            "height_error": height_err,
            "cutoff_height": cutoff,
            "count": len(filtered),
            "provider_filter": provider_filter,
            "total_paid_uarkeo": total_paid,
            "total_paid_arkeo": _format_arkeo_amount(total_paid),
            "total_transactions": total_tx,
            "contracts": filtered,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT)
