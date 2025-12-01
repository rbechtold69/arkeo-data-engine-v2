#!/usr/bin/env python3
"""Periodic Arkeo cache fetcher for subscriber-core.

Fetches providers, contracts, and services from arkeod every CACHE_FETCH_INTERVAL
seconds and writes JSON to CACHE_DIR for use by the UI or other helpers.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib import request, error
from urllib.parse import urlparse

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeod"))
ARKEOD_NODE = (
    os.getenv("ARKEOD_NODE")
    or os.getenv("EXTERNAL_ARKEOD_NODE")
    or "tcp://provider1.innovationtheory.com:26657"
)
ARKEO_REST_API = (
    os.getenv("ARKEO_REST_API_PORT")
    or os.getenv("EXTERNAL_ARKEO_REST_API")
    or "http://provider1.innovationtheory.com:1317"
)
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
CACHE_FETCH_INTERVAL = int(os.getenv("CACHE_FETCH_INTERVAL", "300"))  # seconds
STATUS_FILE = os.path.join(CACHE_DIR, "_sync_status.json")


def run_list(cmd: List[str]) -> Tuple[int, str]:
    """Run a command without a shell and return (exit_code, output)."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return 0, out.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode("utf-8")


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_cache_dir() -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError:
        pass


def _write_status(payload: Dict[str, Any]) -> None:
    """Write sync status atomically."""
    path = STATUS_FILE
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


def mark_sync_start(started_at: str | None = None) -> None:
    ensure_cache_dir()
    payload = {
        "in_progress": True,
        "started_at": started_at or timestamp(),
    }
    _write_status(payload)


def mark_sync_end(ok: bool = True, error: str | None = None) -> None:
    ensure_cache_dir()
    finished = timestamp()
    payload = {
        "in_progress": False,
        "finished_at": finished,
    }
    if ok:
        payload["last_success"] = finished
    if error:
        payload["last_error"] = error
    _write_status(payload)


def build_commands() -> Dict[str, List[str]]:
    base = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        base.extend(["--node", ARKEOD_NODE])
    return {
        "provider-services": [*base, "query", "arkeo", "list-providers", "-o", "json"],
        "provider-contracts": [*base, "query", "arkeo", "list-contracts", "-o", "json"],
        # services/types are fetched via REST API (no pagination)
        "service-types": [],
    }


def normalize_result(name: str, code: int, out: str, cmd: List[str]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "fetched_at": timestamp(),
        "exit_code": code,
        "cmd": cmd,
    }
    if code == 0:
        try:
            payload["data"] = json.loads(out)
        except json.JSONDecodeError:
            payload["data"] = out
    else:
        payload["error"] = out
    return payload


def fetch_services_rest() -> Dict[str, Any]:
    """Fetch services via REST endpoint without pagination."""
    url = f"{ARKEO_REST_API.rstrip('/')}/arkeo/services"
    try:
        with request.urlopen(url, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except error.URLError as e:
        return {
            "fetched_at": timestamp(),
            "exit_code": 1,
            "cmd": [url],
            "error": str(e),
        }
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        data = body
    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": [url],
        "data": data,
    }


def fetch_metadata_uri(url: str, timeout: float = 5.0) -> Tuple[Any, str | None, int]:
    """Fetch metadata from a URI; return (parsed_or_raw, error_string_or_None, status_flag)."""
    try:
        with request.urlopen(url, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e), 0
    try:
        return json.loads(body), None, 1
    except json.JSONDecodeError:
        return body, None, 1


def _is_external(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        parsed = urlparse(uri)
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


def build_providers_metadata(provider_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build active_providers.json by listing providers/services, then fetch external metadata_uri (short timeout)."""
    providers_list: List[Dict[str, Any]] = []
    data = provider_payload.get("data")
    if isinstance(data, dict):
        providers_list = data.get("providers") or data.get("provider") or []
    if not isinstance(providers_list, list):
        providers_list = []

    enriched: List[Dict[str, Any]] = []
    seen: Dict[str, Dict[str, Any]] = {}
    url_cache: Dict[str, Tuple[Any, str | None, int]] = {}
    # Track service counts per pubkey
    service_counts: Dict[str, int] = {}

    def iter_services(p: Dict[str, Any]) -> List[Dict[str, Any]]:
        if isinstance(p.get("services"), list):
            return p["services"]
        if isinstance(p.get("service"), list):
            return p["service"]
        return [p]

    # First pass: assemble providers with services and pick latest external metadata_uri (no fetch yet)
    for p in providers_list:
        if not isinstance(p, dict):
            continue
        pubkey = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        services_enriched = []
        meta_uri_val = None
        # Consider provider-level metadata_uri as well
        provider_level_mu = p.get("metadata_uri") or p.get("metadataUri")
        if _is_external(provider_level_mu):
            meta_uri_val = provider_level_mu
        for s in iter_services(p):
            if not isinstance(s, dict):
                continue
            mu = s.get("metadata_uri") or s.get("metadataUri")
            services_enriched.append(
                {
                    "id": s.get("service_id") or s.get("id") or s.get("service"),
                    "name": s.get("service") or s.get("name"),
                    "metadata_uri": mu,
                    "raw": s,
                }
            )
            if _is_external(mu):
                meta_uri_val = mu  # keep the latest external metadata_uri seen
        if pubkey:
            if pubkey in seen:
                seen_entry = seen[pubkey]
                if meta_uri_val:
                    seen_entry["metadata_uri"] = meta_uri_val
                continue
            entry = {
                "pubkey": pubkey,
                "provider": p,
                "metadata_uri": meta_uri_val,
                "metadata": None,
                "metadata_error": None,
                "status": 0,
            }
            seen[pubkey] = entry
            enriched.append(entry)
        else:
            enriched.append({"pubkey": pubkey, "provider": p, "status": 0})
        # count ONLINE services for this pubkey
        svc_count = 0
        for svc in services_enriched:
            status_val = svc["raw"].get("status") if isinstance(svc.get("raw"), dict) else None
            status_str = str(status_val).strip().lower() if status_val is not None else ""
            if status_str == "online" or status_val in (1, True, "1"):
                svc_count += 1
        service_counts[pubkey] = service_counts.get(pubkey, 0) + svc_count

    # Second pass: fetch metadata_uri for entries that have a valid external URI
    for entry in enriched:
        mu = entry.get("metadata_uri")
        provider_status_raw = ""
        prov_obj = entry.get("provider")
        if isinstance(prov_obj, dict):
            provider_status_raw = str(prov_obj.get("status") or "").lower()

        if _is_external(mu):
            if mu in url_cache:
                meta_data_val, meta_err_val, status_val = url_cache[mu]
            else:
                meta_data_val, meta_err_val, status_val = fetch_metadata_uri(mu)
                url_cache[mu] = (meta_data_val, meta_err_val, status_val)
            entry["metadata"] = meta_data_val if status_val == 1 else None
            entry["metadata_error"] = meta_err_val if status_val != 1 else None
            entry["status"] = status_val
        else:
            # No external metadata_uri; cannot mark active
            entry["metadata"] = None
            entry["metadata_error"] = "metadata_uri missing or local" if mu else "metadata_uri not set"
            entry["status"] = 0
        # attach count of online services for this pubkey (if computed)
        pk = entry.get("pubkey")
        if pk and pk in service_counts:
            entry["online_service_count"] = service_counts.get(pk, 0)

    # Keep only active entries (status == 1) with at least one ONLINE service
    active_only = [
        e
        for e in enriched
        if (e.get("status") == 1 or e.get("status") == "1")
        and (e.get("online_service_count") or 0) > 0
    ]
    return {
        "fetched_at": timestamp(),
        "source": "provider-services",
        "providers": active_only,
    }


def build_active_services(provider_services_payload: Dict[str, Any], active_providers_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build active_services.json by selecting ONLINE services from provider-services (basic filter) and filtering to active providers."""
    active_prov_lookup = set()
    providers_list = active_providers_payload.get("providers") if isinstance(active_providers_payload, dict) else []
    if isinstance(providers_list, list):
        for p in providers_list:
            if not isinstance(p, dict):
                continue
            status = p.get("status")
            if status == 1 or status == "1":
                pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
                if pk:
                    active_prov_lookup.add(pk)
    data = provider_services_payload.get("data") if isinstance(provider_services_payload, dict) else {}
    prov_entries = []
    if isinstance(data, dict):
        prov_entries = data.get("providers") or data.get("provider") or []
    if not isinstance(prov_entries, list):
        prov_entries = []

    active_services: list[dict[str, Any]] = []

    for entry in prov_entries:
        if not isinstance(entry, dict):
            continue
        pk = entry.get("pub_key") or entry.get("pubkey") or entry.get("pubKey")
        if not pk or (active_prov_lookup and pk not in active_prov_lookup):
            continue
        status_val = entry.get("status")
        status_str = str(status_val).strip().lower() if status_val is not None else ""
        if status_str != "online" and status_val not in (1, True, "1"):
            continue
        mu = entry.get("metadata_uri") or entry.get("metadataUri")
        if not mu or not _is_external(mu):
            continue
        active_services.append(
            {
                "provider_pubkey": pk,
                "service_id": entry.get("service_id") or entry.get("id") or entry.get("service"),
                "service": entry.get("service") or entry.get("name"),
                "metadata_uri": mu,
                "raw": entry,
            }
        )

    return {
        "fetched_at": timestamp(),
        "source": "provider-services",
        "active_services": active_services,
    }


def build_subscribers_from_contracts(contracts_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Derive subscribers.json from provider-contracts cache (unique subscriber addresses)."""
    contracts_list = []
    data = contracts_payload.get("data") if isinstance(contracts_payload, dict) else {}
    if isinstance(data, dict):
        contracts_list = data.get("contracts") or data.get("contract") or []
    if not isinstance(contracts_list, list):
        contracts_list = []

    subs: dict[str, dict[str, Any]] = {}
    for c in contracts_list:
        if not isinstance(c, dict):
            continue
        addr = c.get("client")
        if not addr:
            continue
        entry = subs.setdefault(addr, {"subscriber": addr, "contracts": 0, "services": set()})
        entry["contracts"] += 1
        svc = c.get("service") or c.get("service_id") or c.get("serviceID")
        if svc is not None:
            entry["services"].add(str(svc))

    subscribers: list[dict[str, Any]] = []
    for s in subs.values():
        subscribers.append(
            {
                "subscriber": s["subscriber"],
                "contracts": s["contracts"],
                "services": sorted(s["services"]),
            }
        )

    return {
        "fetched_at": timestamp(),
        "source": "provider-contracts",
        "subscribers": subscribers,
    }


def write_cache(name: str, payload: Dict[str, Any]) -> None:
    path = os.path.join(CACHE_DIR, f"{name}.json")
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
        os.replace(tmp_path, path)
        print(f"[cache] wrote {name} -> {path} (exit={payload.get('exit_code')})", flush=True)
    except OSError as e:
        print(f"[cache] failed to write {name}: {e}", flush=True)
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def fetch_once(commands: Dict[str, List[str]], record_status: bool = False) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    start_ts = timestamp()
    if record_status:
        mark_sync_start(start_ts)
    ok = True
    error_msg = None
    try:
        for name, cmd in commands.items():
            if name == "service-types":
                payload = fetch_services_rest()
            else:
                code, out = run_list(cmd)
                payload = normalize_result(name, code, out, cmd)
                if code != 0:
                    ok = False
                    error_msg = f"{name} exit={code}"
            write_cache(name, payload)
            results[name] = payload
        # Derive active_providers.json from provider-services (fetch external metadata_uri with timeout)
        providers_payload = None
        if "provider-services" in results and results["provider-services"].get("exit_code") == 0:
            providers_payload = build_providers_metadata(results["provider-services"])
            write_cache("active_providers", providers_payload)
        # Derive active_services.json only after providers_payload exists
        if providers_payload is not None:
            active_services_payload = build_active_services(results["provider-services"], providers_payload)
            write_cache("active_services", active_services_payload)
            results["active_services"] = active_services_payload
            results["active_providers"] = providers_payload
        # Derive subscribers.json from provider-contracts if available
        if "provider-contracts" in results and results["provider-contracts"].get("exit_code") == 0:
            subscribers_payload = build_subscribers_from_contracts(results["provider-contracts"])
            write_cache("subscribers", subscribers_payload)
            results["subscribers"] = subscribers_payload
    except Exception as e:
        ok = False
        error_msg = str(e)
        raise
    finally:
        if record_status:
            mark_sync_end(ok=ok, error=error_msg)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Arkeo cache fetcher")
    parser.add_argument("--once", action="store_true", help="Run a single fetch cycle then exit")
    args = parser.parse_args()

    ensure_cache_dir()
    commands = build_commands()
    interval = max(60, CACHE_FETCH_INTERVAL)  # enforce a sane floor
    print(
        f"[cache] starting fetch loop every {interval}s; cache dir={CACHE_DIR}; node={ARKEOD_NODE}; rest_api={ARKEO_REST_API}",
        flush=True,
    )
    if args.once:
        fetch_once(commands, record_status=True)
        return
    while True:
        fetch_once(commands, record_status=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
