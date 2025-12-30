#!/usr/bin/env python3
"""Periodic Arkeo cache fetcher for dashboard-core.

Fetches providers, contracts, validators, and services from arkeod every CACHE_FETCH_INTERVAL
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
from urllib import request
from urllib.parse import urlparse

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeo"))
# These are dynamically refreshed from subscriber-settings.json before each fetch cycle (if present)
ARKEOD_NODE = os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or "tcp://127.0.0.1:26657"
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
CONFIG_DIR = os.getenv("CONFIG_DIR", "/app/config")
STATUS_FILE = os.path.join(CACHE_DIR, "_sync_status.json")
SUBSCRIBER_SETTINGS_PATH = os.path.join(CONFIG_DIR, "subscriber-settings.json")
LEGACY_SUBSCRIBER_SETTINGS_PATH = os.path.join(CACHE_DIR, "subscriber-settings.json")
METADATA_CACHE_PATH = os.path.join(CACHE_DIR, "metadata.json")
# Static service type metadata (to merge chain fields) now lives under /app/admin
SERVICE_TYPE_RESOURCES_PATH = os.getenv("SERVICE_TYPE_RESOURCES_PATH", "/app/admin/service-type_resources.json")


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


def _parse_service_types_text(raw: str) -> Dict[str, Any] | None:
    """Parse text output from `arkeod query arkeo all-services` into {"services": [...]}."""
    if not raw or not isinstance(raw, str):
        return None
    services: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("- "):
            continue
        # Expected pattern: "- name : id (Description)"
        try:
            body = line[2:].strip()
            if " :" not in body:
                continue
            name_part, rest = body.split(" :", 1)
            name = name_part.strip()
            rest = rest.strip()
            # id then optional description in parentheses
            service_id_str = rest.split(" ", 1)[0].strip()
            try:
                service_id = int(service_id_str)
            except ValueError:
                # sometimes format could be "id (desc)"
                if "(" in service_id_str:
                    service_id_str = service_id_str.split("(")[0].strip()
                try:
                    service_id = int(service_id_str)
                except Exception:
                    continue
            desc = ""
            if "(" in rest and rest.endswith(")"):
                desc = rest[rest.find("(") + 1 : -1].strip()
            services.append(
                {
                    "service_id": service_id,
                    "name": name,
                    "description": desc,
                }
            )
        except Exception:
            continue
    if not services:
        return None
    return {"services": services}


def _extract_pagination(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        pag = data.get("pagination")
        if isinstance(pag, dict):
            return pag
        inner = data.get("data")
        if isinstance(inner, dict):
            pag = inner.get("pagination")
            if isinstance(pag, dict):
                return pag
    return {}


def _extract_contracts_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [c for c in data if isinstance(c, dict)]
    if isinstance(data, dict):
        inner = data.get("data") if "data" in data else None
        if inner is not None:
            return _extract_contracts_list(inner)
        contracts = data.get("contracts") or data.get("contract") or data.get("result") or []
        if isinstance(contracts, list):
            return [c for c in contracts if isinstance(c, dict)]
    return []


def _extract_providers_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data") if "data" in data else None
        if inner is not None:
            return _extract_providers_list(inner)
        prov = data.get("providers") or data.get("provider") or data.get("result") or []
        if isinstance(prov, list):
            return prov
    return []


def _extract_service_types_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data") if "data" in data else None
        if inner is not None:
            return _extract_service_types_list(inner)
        svc = data.get("services") or data.get("service") or data.get("result") or []
        if isinstance(svc, list):
            return svc
    return []


def _service_types_cmd() -> list[str]:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "all-services", "-o", "json"])
    return cmd


def _contracts_list_cmd(page_key: str | None = None, limit: int | None = None) -> list[str]:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-contracts", "-o", "json"])
    if limit:
        cmd.extend(["--limit", str(limit)])
    cmd.append("--count-total")
    if page_key:
        cmd.extend(["--page-key", str(page_key)])
    return cmd


def _providers_list_cmd(page_key: str | None = None, limit: int | None = None) -> list[str]:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-providers", "-o", "json"])
    if limit:
        cmd.extend(["--limit", str(limit)])
    cmd.append("--count-total")
    if page_key:
        cmd.extend(["--page-key", str(page_key)])
    return cmd


def fetch_contracts_paginated() -> Dict[str, Any]:
    """Fetch all contracts across pages, honoring pagination next_key when present."""
    page_key = None
    pages = 0
    seen_keys: set[str] = set()
    contracts: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("CONTRACTS_PAGE_LIMIT", 0)
    per_page_limit = _page_limit("CONTRACTS_PAGE_SIZE")
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _contracts_list_cmd(page_key=page_key, limit=per_page_limit or None)
        code, out = run_list(cmd)
        if code != 0:
            return {
                "fetched_at": timestamp(),
                "exit_code": code,
                "cmd": cmd,
                "error": out,
            }
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": "invalid JSON from list-contracts",
            }
        page_contracts = _extract_contracts_list(data)
        if page_contracts:
            contracts.extend(page_contracts)
            raw_seen += len(page_contracts)
        pages += 1
        last_pagination = _extract_pagination(data)

        if total_cap and raw_seen >= total_cap:
            break

        next_key = None
        if isinstance(last_pagination, dict):
            next_key = last_pagination.get("next_key") or last_pagination.get("nextKey")
        if not next_key:
            break
        next_key = str(next_key)
        if next_key in seen_keys:
            break
        seen_keys.add(next_key)
        page_key = next_key

    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _contracts_list_cmd(limit=per_page_limit or None),
        "data": {"contracts": contracts, "pagination": last_pagination},
        "pages": pages,
    }


def fetch_provider_services_paginated() -> Dict[str, Any]:
    """Fetch all providers across pages, honoring pagination next_key when present."""
    page_key = None
    pages = 0
    seen_keys: set[str] = set()
    providers: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("PROVIDER_SERVICES_PAGE_LIMIT", 0)
    per_page_limit = _page_limit("PROVIDER_SERVICES_PAGE_SIZE")
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _providers_list_cmd(page_key=page_key, limit=per_page_limit or None)
        code, out = run_list(cmd)
        if code != 0:
            return {
                "fetched_at": timestamp(),
                "exit_code": code,
                "cmd": cmd,
                "error": out,
            }
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": "invalid JSON from list-providers",
            }
        page_providers = _extract_providers_list(data)
        if page_providers:
            providers.extend(page_providers)
            raw_seen += len(page_providers)
        pages += 1
        last_pagination = _extract_pagination(data)

        if total_cap and raw_seen >= total_cap:
            break

        next_key = None
        if isinstance(last_pagination, dict):
            next_key = last_pagination.get("next_key") or last_pagination.get("nextKey")
        if not next_key:
            break
        next_key = str(next_key)
        if next_key in seen_keys:
            break
        seen_keys.add(next_key)
        page_key = next_key

    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _providers_list_cmd(limit=per_page_limit or None),
        "data": {"providers": providers, "pagination": last_pagination},
        "pages": pages,
    }


def fetch_service_types_paginated() -> Dict[str, Any]:
    """Fetch service types (single-page for current CLI)."""
    pages = 0
    services: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("SERVICE_TYPES_PAGE_LIMIT", 0)
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _service_types_cmd()
        code, out = run_list(cmd)
        if code != 0:
            return {
                "fetched_at": timestamp(),
                "exit_code": code,
                "cmd": cmd,
                "error": out,
            }
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            parsed = _parse_service_types_text(out)
            if parsed:
                return {
                    "fetched_at": timestamp(),
                    "exit_code": 0,
                    "cmd": cmd,
                    "data": parsed,
                    "parsed_from": "arkeod all-services",
                }
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": "invalid JSON from all-services",
            }
        if isinstance(data, str):
            parsed = _parse_service_types_text(data)
            if parsed:
                return {
                    "fetched_at": timestamp(),
                    "exit_code": 0,
                    "cmd": cmd,
                    "data": parsed,
                    "parsed_from": "arkeod all-services",
                }
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": "invalid JSON from all-services",
            }

        page_services = _extract_service_types_list(data)
        if page_services:
            services.extend(page_services)
            raw_seen += len(page_services)
        pages += 1
        last_pagination = _extract_pagination(data)

        if total_cap and raw_seen >= total_cap:
            break
        break

    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _service_types_cmd(),
        "data": {"services": services, "pagination": last_pagination},
        "pages": pages,
    }


def build_commands() -> Dict[str, List[str]]:
    base = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        base.extend(["--node", ARKEOD_NODE])
    return {
        "provider-services": [
            *base,
            "query",
            "arkeo",
            "list-providers",
            "--limit",
            str(PAGE_LIMIT),
            "--count-total",
            "-o",
            "json",
        ],
        "provider-contracts": [
            *base,
            "query",
            "arkeo",
            "list-contracts",
            "--limit",
            str(PAGE_LIMIT),
            "--count-total",
            "-o",
            "json",
        ],
        "validators": [*base, "query", "staking", "validators", "--page-limit", "1000", "--page-count-total", "--status", "BOND_STATUS_BONDED", "-o", "json"],
        "service-types": [
            *base,
            "query",
            "arkeo",
            "all-services",
            "-o",
            "json",
        ],
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


def merge_service_types_with_resources(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Merge service-types payload with static resources to add chain when available."""
    try:
        with open(SERVICE_TYPE_RESOURCES_PATH, "r", encoding="utf-8") as f:
            static_data = json.load(f)
    except Exception:
        return payload
    services_static = []
    data_static = static_data.get("data") if isinstance(static_data, dict) else {}
    if isinstance(data_static, list):
        services_static = data_static
    elif isinstance(data_static, dict):
        services_static = data_static.get("services") or data_static.get("service") or data_static.get("result") or []
    if not isinstance(services_static, list):
        return payload
    id_lookup: Dict[str, str] = {}
    name_lookup: Dict[str, str] = {}
    for s in services_static:
        if not isinstance(s, dict):
            continue
        chain_val = s.get("chain")
        if not chain_val:
            continue
        sid = s.get("service_id") or s.get("id")
        if sid is not None:
            id_lookup[str(sid)] = chain_val
        name_val = s.get("name") or s.get("service")
        if name_val:
            name_lookup[str(name_val).lower()] = chain_val
    data_live = payload.get("data")
    live_list: list[Any] = []
    if isinstance(data_live, list):
        live_list = data_live
    elif isinstance(data_live, dict):
        live_list = data_live.get("services") or data_live.get("service") or data_live.get("result") or []
    if not isinstance(live_list, list):
        return payload
    changed = False
    for svc in live_list:
        if not isinstance(svc, dict):
            continue
        if svc.get("chain"):
            continue
        sid = svc.get("service_id") or svc.get("id")
        sname = svc.get("name") or svc.get("service")
        chain_val = None
        if sid is not None and str(sid) in id_lookup:
            chain_val = id_lookup[str(sid)]
        elif sname and str(sname).lower() in name_lookup:
            chain_val = name_lookup[str(sname).lower()]
        if chain_val is not None:
            svc["chain"] = chain_val
            changed = True
    if not changed:
        return payload
    if isinstance(data_live, list):
        payload["data"] = live_list
    elif isinstance(data_live, dict):
        if isinstance(data_live.get("services"), list):
            data_live["services"] = live_list
        elif isinstance(data_live.get("service"), list):
            data_live["service"] = live_list
        elif isinstance(data_live.get("result"), list):
            data_live["result"] = live_list
        payload["data"] = data_live
    return payload


def _is_external(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        parsed = urlparse(uri)
        host = (parsed.hostname or "").lower()
        if not parsed.scheme or not host:
            return False
        # Localhost/loopback is never allowed for metadata URIs.
        if host == "localhost" or host.startswith("127."):
            return False
        return True
    except Exception:
        return False


def _status_is_online(status_val: Any) -> bool:
    """Return True when a status field represents ONLINE (tolerant parsing)."""
    if status_val is None:
        # If status is missing, treat it as unknown (not explicitly offline).
        return True
    if status_val in (1, True, "1"):
        return True
    status_str = str(status_val).strip().lower()
    return status_str == "online"


def _refresh_runtime_settings() -> None:
    """Reload ARKEOD_NODE from env or subscriber-settings.json (config/cache)."""
    global ARKEOD_NODE
    settings = {}
    for path in (SUBSCRIBER_SETTINGS_PATH, LEGACY_SUBSCRIBER_SETTINGS_PATH):
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    settings = json.load(f) or {}
                break
        except Exception:
            settings = {}
    node_val = settings.get("ARKEOD_NODE") or os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or ARKEOD_NODE
    if node_val:
        ARKEOD_NODE = str(node_val).strip()


def _provider_entries_from_payload(payload: Any) -> list[dict[str, Any]]:
    """
    Extract a provider list from a provider-services payload.

    Accepts payload shapes:
      - {"data": {"providers": [...]}} or {"data": {"provider": [...]} }
      - {"data": [...]} (list-style)
      - {"providers": [...]} / {"provider": [...]}
      - [...] (list-style, already)
    """
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("providers", "provider"):
        if isinstance(payload.get(key), list):
            return [p for p in payload[key] if isinstance(p, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [p for p in data if isinstance(p, dict)]
    if isinstance(data, dict):
        for key in ("providers", "provider"):
            if isinstance(data.get(key), list):
                return [p for p in data[key] if isinstance(p, dict)]
    return []


def _iter_provider_service_records(provider_entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Return service records for a provider entry, handling both nested and flat structures."""
    if isinstance(provider_entry.get("services"), list):
        return [s for s in provider_entry["services"] if isinstance(s, dict)]
    if isinstance(provider_entry.get("service"), list):
        return [s for s in provider_entry["service"] if isinstance(s, dict)]
    return [provider_entry]


def _service_records_from_provider_services_payload(payload: Any) -> list[dict[str, Any]]:
    """
    Flatten provider-services payload into a list of service-ish records.

    For nested provider entries, this copies provider-level fields (pub_key/status/metadata_uri/bond)
    onto each service record when missing.
    """
    records: list[dict[str, Any]] = []
    for p in _provider_entries_from_payload(payload):
        pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        p_status = p.get("status")
        p_mu = p.get("metadata_uri") or p.get("metadataUri")
        p_bond = p.get("bond")
        for s in _iter_provider_service_records(p):
            if s is p:
                records.append(p)
                continue
            rec = dict(s)
            if pk and not (rec.get("pub_key") or rec.get("pubkey") or rec.get("pubKey")):
                rec["pub_key"] = pk
            if rec.get("status") is None and p_status is not None:
                rec["status"] = p_status
            if not (rec.get("metadata_uri") or rec.get("metadataUri")) and p_mu:
                rec["metadata_uri"] = p_mu
            if rec.get("bond") is None and p_bond is not None:
                rec["bond"] = p_bond
            records.append(rec)
    return records


def _active_services_list_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Extract an active_services list from payloads that might be dict-or-list wrapped."""
    if isinstance(payload, list):
        return [s for s in payload if isinstance(s, dict)]
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("active_services"), list):
        return [s for s in payload["active_services"] if isinstance(s, dict)]
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("active_services"), list):
        return [s for s in data["active_services"] if isinstance(s, dict)]
    return []


def _metadata_entry_data(entry: Any) -> dict[str, Any] | None:
    """Return the JSON metadata dict from a metadata cache entry, if present."""
    if not isinstance(entry, dict):
        return None
    if "data" in entry:
        return entry.get("data") if isinstance(entry.get("data"), dict) else None
    # Back-compat: if the entry is a raw metadata dict (not a wrapper), accept it.
    if any(k in entry for k in ("metadata_uri", "fetched_at", "status", "error")):
        return None
    return entry


def _metadata_cache_map_from_payload(payload: Any) -> dict[str, dict[str, Any]]:
    """Normalize metadata cache payloads into metadata_uri -> {"metadata_uri","fetched_at","data"}."""
    if payload is None:
        return {}
    items: Any = payload
    if isinstance(payload, dict) and isinstance(payload.get("metadata"), dict):
        items = payload.get("metadata")
    if isinstance(items, dict):
        out: dict[str, dict[str, Any]] = {}
        for mu, entry in items.items():
            if not mu:
                continue
            meta = _metadata_entry_data(entry)
            if not isinstance(meta, dict):
                continue
            fetched_at = entry.get("fetched_at") if isinstance(entry, dict) else None
            out[str(mu)] = {"metadata_uri": str(mu), "fetched_at": fetched_at, "data": meta}
        return out
    if isinstance(items, list):
        out: dict[str, dict[str, Any]] = {}
        for entry in items:
            if not isinstance(entry, dict):
                continue
            mu = entry.get("metadata_uri") or entry.get("metadataUri") or entry.get("uri") or entry.get("url")
            if not mu:
                continue
            meta = _metadata_entry_data(entry)
            if meta is None:
                meta = {
                    k: v
                    for k, v in entry.items()
                    if k not in ("metadata_uri", "metadataUri", "uri", "url", "fetched_at", "status", "error")
                }
            if not isinstance(meta, dict) or not meta:
                continue
            out[str(mu)] = {"metadata_uri": str(mu), "fetched_at": entry.get("fetched_at"), "data": meta}
        return out
    return {}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _page_limit(override_env: str) -> int | None:
    per_resource = _env_int(override_env, 0)
    if per_resource and per_resource > 0:
        return per_resource
    if PAGE_LIMIT and PAGE_LIMIT > 0:
        return PAGE_LIMIT
    return None


# Resolve env-derived knobs after helpers are defined
CACHE_FETCH_INTERVAL = _env_int("CACHE_FETCH_INTERVAL", 300)
METADATA_TTL_SECONDS = _env_int("METADATA_TTL_SECONDS", 3600)
SERVICE_TYPES_TTL_SECONDS = _env_int("SERVICE_TYPES_TTL_SECONDS", 3600)
MIN_SERVICE_BOND = _env_int("MIN_SERVICE_BOND", 100_000_000)
PAGE_LIMIT = _env_int("PAGE_LIMIT", 1000)


def _load_metadata_cache() -> dict[str, dict[str, Any]]:
    """
    Load metadata.json as a mapping of metadata_uri -> {"metadata_uri","fetched_at","data"}.

    Only successful (JSON object) metadata entries are returned.
    """
    try:
        with open(METADATA_CACHE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}

    items: Any = raw
    if isinstance(raw, dict):
        items = raw.get("metadata") or raw

    cleaned: dict[str, dict[str, Any]] = {}

    if isinstance(items, dict):
        for mu, entry in items.items():
            if not mu or not isinstance(mu, str):
                continue
            meta = _metadata_entry_data(entry)
            if not isinstance(meta, dict):
                continue
            fetched_at = entry.get("fetched_at") if isinstance(entry, dict) else None
            cleaned[mu] = {"metadata_uri": mu, "fetched_at": fetched_at, "data": meta}
        return cleaned

    if isinstance(items, list):
        for entry in items:
            if not isinstance(entry, dict):
                continue
            mu = entry.get("metadata_uri") or entry.get("metadataUri") or entry.get("uri") or entry.get("url")
            if not mu or not isinstance(mu, str):
                continue
            meta = _metadata_entry_data(entry)
            if meta is None:
                # List-style entries might inline the metadata without a "data" wrapper.
                meta = {k: v for k, v in entry.items() if k not in ("metadata_uri", "metadataUri", "uri", "url", "fetched_at")}
            if not isinstance(meta, dict) or not meta:
                continue
            cleaned[mu] = {"metadata_uri": mu, "fetched_at": entry.get("fetched_at"), "data": meta}
    return cleaned


def _metadata_entry_ok(entry: Any) -> bool:
    """Return True if a metadata cache entry contains usable JSON metadata."""
    return isinstance(_metadata_entry_data(entry), dict)


def _load_cache_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _cache_is_fresh(path: str, ttl_sec: int) -> tuple[bool, Dict[str, Any]]:
    payload = _load_cache_file(path)
    if not payload:
        return False, {}
    exit_code = payload.get("exit_code")
    if exit_code not in (0, "0", None):
        return False, {}
    fetched = payload.get("fetched_at")
    if not fetched:
        return False, {}
    try:
        ts = datetime.fromisoformat(str(fetched)).timestamp()
    except Exception:
        return False, {}
    if (time.time() - ts) < ttl_sec:
        return True, payload
    return False, {}


def _save_metadata_cache(cache: dict[str, dict[str, Any]]) -> None:
    ensure_cache_dir()
    payload = {"metadata": cache}
    tmp_path = f"{METADATA_CACHE_PATH}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
        os.replace(tmp_path, METADATA_CACHE_PATH)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _update_metadata_cache_from_providers(provider_services_payload: Any) -> dict[str, dict[str, Any]]:
    """
    Fetch metadata for ONLINE provider/services only.

    - Failed fetches are dropped (no status:0 entries are written).
    - metadata.json contains only successful JSON object entries.
    """
    # Load raw metadata.json so we can clean old status:0/error entries on disk.
    raw: Any = {}
    try:
        with open(METADATA_CACHE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        raw = {}
    items: Any = raw.get("metadata") if isinstance(raw, dict) else raw
    if isinstance(raw, dict) and "metadata" not in raw:
        items = raw

    cache_map: dict[str, dict[str, Any]] = {}
    changed = False

    def _add_existing(mu: str, entry: Any) -> None:
        nonlocal changed, cache_map
        if not _is_external(mu):
            changed = True
            return
        meta = _metadata_entry_data(entry)
        if not isinstance(meta, dict):
            changed = True
            return
        fetched_at = entry.get("fetched_at") if isinstance(entry, dict) else None
        # Normalize away legacy status/error fields so metadata.json only contains successful entries.
        if isinstance(entry, dict) and ("status" in entry or "error" in entry):
            changed = True
        cache_map[mu] = {"metadata_uri": mu, "fetched_at": fetched_at, "data": meta}

    if isinstance(items, dict):
        for mu, entry in items.items():
            if not mu or not isinstance(mu, str):
                changed = True
                continue
            _add_existing(mu, entry)
    elif isinstance(items, list):
        # List-style metadata payloads are normalized to our dict-of-uris format.
        changed = True
        for entry in items:
            if not isinstance(entry, dict):
                continue
            mu = entry.get("metadata_uri") or entry.get("metadataUri") or entry.get("uri") or entry.get("url")
            if not mu or not isinstance(mu, str):
                continue
            _add_existing(mu, entry)

    # Collect metadata URIs from ONLINE services/providers only.
    uris: set[str] = set()
    for rec in _service_records_from_provider_services_payload(provider_services_payload):
        if not isinstance(rec, dict):
            continue
        if not _status_is_online(rec.get("status")):
            continue
        mu = rec.get("metadata_uri") or rec.get("metadataUri")
        if mu and _is_external(mu):
            uris.add(str(mu))

    now = time.time()

    def _is_stale(entry: dict[str, Any]) -> bool:
        fetched = entry.get("fetched_at")
        if not fetched:
            return True
        try:
            ts = datetime.fromisoformat(str(fetched)).timestamp()
        except Exception:
            return True
        return (now - ts) > METADATA_TTL_SECONDS

    for mu in uris:
        entry = cache_map.get(mu)
        if isinstance(entry, dict) and not _is_stale(entry):
            continue

        data_val, _err_val, status_val = fetch_metadata_uri(mu)
        if status_val == 1 and isinstance(data_val, dict):
            cache_map[mu] = {"metadata_uri": mu, "fetched_at": timestamp(), "data": data_val}
            changed = True
        else:
            # Drop failures: keep any previous successful entry, but never write a failed placeholder.
            continue

    if changed:
        _save_metadata_cache(cache_map)
    return cache_map


def _parse_int_value(val: Any) -> int | None:
    """Return an integer from various representations (raw int, numeric string, or coin string)."""
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        try:
            return int(val)
        except (TypeError, ValueError):
            return None
    if isinstance(val, str):
        digits = ""
        for ch in val:
            if ch.isdigit():
                digits += ch
            elif digits:
                break
        if digits:
            try:
                return int(digits)
            except (TypeError, ValueError):
                return None
    return None


def _bond_amount_uarkeo(entry: Dict[str, Any]) -> int:
    """Extract a bond amount in uarkeo (best-effort)."""
    bond = entry.get("bond")
    if isinstance(bond, dict):
        denom = bond.get("denom") or bond.get("Denom")
        amount_val = bond.get("amount") or bond.get("Amount")
        if denom and str(denom).lower() != "uarkeo":
            return 0
        amt = _parse_int_value(amount_val)
        return amt if isinstance(amt, int) else 0
    amt = _parse_int_value(bond)
    return amt if isinstance(amt, int) else 0


def _min_payg_rate(raw: Dict[str, Any]) -> tuple[int | None, str | None]:
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
        amt_int = _parse_int_value(amt)
        if amt_int is None:
            continue
        if best_amt is None or amt_int < best_amt:
            best_amt = amt_int
            best_denom = denom
    return best_amt, best_denom


def build_active_services(
    provider_services_payload: Any,
    metadata_cache: Any | None = None,
) -> Dict[str, Any]:
    """Build active_services.json: pick ONLINE services with usable metadata.json and a minimum bond."""
    meta_cache = _metadata_cache_map_from_payload(metadata_cache)
    prov_entries = _service_records_from_provider_services_payload(provider_services_payload)

    active_services: list[dict[str, Any]] = []

    for entry in prov_entries:
        if not isinstance(entry, dict):
            continue
        pk = entry.get("pub_key") or entry.get("pubkey") or entry.get("pubKey")
        if not pk:
            continue
        if not _status_is_online(entry.get("status")):
            continue
        bond_amt = _bond_amount_uarkeo(entry)
        if bond_amt < MIN_SERVICE_BOND:
            continue
        payg_amt, payg_denom = _min_payg_rate(entry)
        if payg_amt is None or payg_amt <= 0:
            continue
        mu = entry.get("metadata_uri") or entry.get("metadataUri")
        if not mu or not _is_external(mu):
            continue
        meta_entry = meta_cache.get(str(mu))
        if not _metadata_entry_ok(meta_entry):
            continue
        active_services.append(
            {
                "provider_pubkey": str(pk),
                "service_id": entry.get("service_id") or entry.get("id") or entry.get("service"),
                "service": entry.get("service") or entry.get("name"),
                "metadata_uri": str(mu),
                "pay_as_you_go_rate": {"amount": payg_amt, "denom": payg_denom},
                "raw": entry,
            }
        )

    return {
        "fetched_at": timestamp(),
        "source": "provider-services",
        "active_services": active_services,
    }


def build_active_providers_from_active_services(
    active_services_payload: Any,
    provider_services_payload: Any,
    metadata_cache: Any | None = None,
) -> Dict[str, Any]:
    """
    Build active_providers.json by rolling up from active_services.json.

    Status/bond/metadata checks are enforced when building active_services; providers are
    included here when they have at least one active service AND a cached external metadata entry.
    """
    active_services = _active_services_list_from_payload(active_services_payload)
    meta_cache = _metadata_cache_map_from_payload(metadata_cache)

    provider_lookup: dict[str, dict[str, Any]] = {}
    for p in _provider_entries_from_payload(provider_services_payload):
        pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        if pk and str(pk) not in provider_lookup:
            provider_lookup[str(pk)] = p

    agg: dict[str, dict[str, Any]] = {}
    for svc in active_services:
        if not isinstance(svc, dict):
            continue
        pk = svc.get("provider_pubkey") or svc.get("pubkey") or svc.get("pub_key") or svc.get("pubKey")
        if not pk:
            continue
        pk_s = str(pk)
        entry = agg.setdefault(pk_s, {"pubkey": pk_s, "count": 0, "metadata_uris": []})
        entry["count"] += 1
        mu = svc.get("metadata_uri")
        if mu and mu not in entry["metadata_uris"]:
            entry["metadata_uris"].append(str(mu))

    providers: list[dict[str, Any]] = []
    for pk, info in agg.items():
        candidates: list[str] = info.get("metadata_uris") or []
        chosen_mu = None
        for mu in candidates:
            if not _is_external(mu):
                continue
            if _metadata_entry_ok(meta_cache.get(mu)):
                chosen_mu = mu
                break
        if not chosen_mu:
            # Require a cached external metadata entry to attach moniker/metadata.
            continue

        meta_entry = meta_cache.get(chosen_mu) or {}
        meta_val = _metadata_entry_data(meta_entry) or {}

        moniker_val = None
        if isinstance(meta_val, dict):
            cfg = meta_val.get("config") if isinstance(meta_val.get("config"), dict) else {}
            moniker_val = cfg.get("moniker") or meta_val.get("moniker")

        providers.append(
            {
                "pubkey": pk,
                "provider": provider_lookup.get(pk) or {},
                "metadata_uri": chosen_mu,
                "metadata": meta_val if isinstance(meta_val, dict) else {},
                "metadata_error": None,
                "status": 1,
                "provider_moniker": moniker_val or pk,
                "online_service_count": int(info.get("count") or 0),
            }
        )

    return {
        "fetched_at": timestamp(),
        "source": "active_services",
        "providers": providers,
        "debug_counts": {"active_services": len(active_services), "providers_kept": len(providers)},
    }


def build_active_service_types(active_services_payload: Any, service_types_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Derive active_service_types.json with unique service ids and counts, enriched with service type metadata."""
    active_services = _active_services_list_from_payload(active_services_payload)

    service_types_list: List[Dict[str, Any]] = []
    st_data = service_types_payload.get("data") if isinstance(service_types_payload, dict) else {}
    if isinstance(st_data, list):
        service_types_list = st_data
    elif isinstance(st_data, dict):
        service_types_list = (
            st_data.get("services")
            or st_data.get("service")
            or st_data.get("result")
            or st_data.get("data")
            or st_data.get("entries")
            or []
        )
    if not isinstance(service_types_list, list):
        service_types_list = []

    st_lookup: Dict[str, Dict[str, Any]] = {}
    for st in service_types_list:
        if not isinstance(st, dict):
            continue
        sid = st.get("service_id") or st.get("id") or st.get("serviceID") or st.get("service")
        if sid is None:
            continue
        st_lookup[str(sid)] = st

    counts: Dict[str, int] = {}
    for svc in active_services:
        if not isinstance(svc, dict):
            continue
        sid = svc.get("service_id") or svc.get("id") or svc.get("service")
        if sid is None:
            continue
        key = str(sid)
        counts[key] = counts.get(key, 0) + 1

    entries = []
    for sid, cnt in counts.items():
        entries.append(
            {
                "service_id": sid,
                "count": cnt,
                "service_type": st_lookup.get(sid),
            }
        )

    def _sort_key(entry: Dict[str, Any]):
        st = entry.get("service_type") or {}
        desc = st.get("description") or st.get("desc") or ""
        name = st.get("name") or st.get("service") or ""
        return (str(desc).lower(), str(name).lower(), str(entry.get("service_id")))

    entries.sort(key=_sort_key)

    return {
        "fetched_at": timestamp(),
        "source": "active_services",
        "active_service_types": entries,
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


def fetch_once(commands: Dict[str, List[str]] | None = None, record_status: bool = False) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    _refresh_runtime_settings()
    commands = build_commands()
    start_ts = timestamp()
    print(f"[cache] sync started at {start_ts} node={ARKEOD_NODE}", flush=True)
    if record_status:
        mark_sync_start(start_ts)
    ok = True
    error_msg = None
    try:
        metadata_cache: dict[str, dict[str, Any]] | None = None
        for name, cmd in commands.items():
            if name == "service-types":
                cache_path = os.path.join(CACHE_DIR, "service-types.json")
                fresh, cached = _cache_is_fresh(cache_path, SERVICE_TYPES_TTL_SECONDS)
                if fresh:
                    payload = cached
                    if payload.get("exit_code") == 0:
                        if isinstance(payload.get("data"), str):
                            parsed = _parse_service_types_text(payload.get("data"))
                            if parsed:
                                payload["data"] = parsed
                        payload = merge_service_types_with_resources(payload)
                    results[name] = payload
                    continue
                payload = fetch_service_types_paginated()
            elif name == "provider-services":
                payload = fetch_provider_services_paginated()
            elif name == "provider-contracts":
                payload = fetch_contracts_paginated()
            else:
                code, out = run_list(cmd)
                payload = normalize_result(name, code, out, cmd)

            if payload.get("exit_code") != 0:
                ok = False
                error_msg = f"{name} exit={payload.get('exit_code')}"

            if name == "service-types" and payload.get("exit_code") == 0:
                # If the output was plaintext, parse into structured services list
                if isinstance(payload.get("data"), str):
                    parsed = _parse_service_types_text(payload.get("data"))
                    if parsed:
                        payload["data"] = parsed
                payload = merge_service_types_with_resources(payload)
            if name == "provider-services" and payload.get("exit_code") == 0:
                metadata_cache = _update_metadata_cache_from_providers(payload)
            write_cache(name, payload)
            results[name] = payload

        if metadata_cache is None:
            try:
                metadata_cache = _load_metadata_cache()
            except Exception:
                metadata_cache = {}
        if metadata_cache is not None:
            results["metadata"] = {"metadata": metadata_cache, "exit_code": 0}

        active_services_payload = None
        if "provider-services" in results and results["provider-services"].get("exit_code") == 0:
            active_services_payload = build_active_services(results["provider-services"], metadata_cache or {})
            write_cache("active_services", active_services_payload)
            results["active_services"] = active_services_payload

        active_providers_payload = None
        if active_services_payload is not None and "provider-services" in results:
            active_providers_payload = build_active_providers_from_active_services(
                active_services_payload, results["provider-services"], metadata_cache or {}
            )
            write_cache("active_providers", active_providers_payload)
            results["active_providers"] = active_providers_payload

        if active_services_payload is not None and "service-types" in results and results["service-types"].get("exit_code") == 0:
            ast_payload = build_active_service_types(active_services_payload, results["service-types"])
            write_cache("active_service_types", ast_payload)
            results["active_service_types"] = ast_payload

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
        end_ts = timestamp()
        status = "success" if ok else f"failed ({error_msg})"
        print(f"[cache] sync completed at {end_ts} [{status}]", flush=True)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Arkeo cache fetcher")
    parser.add_argument("--once", action="store_true", help="Run a single fetch cycle then exit")
    args = parser.parse_args()

    ensure_cache_dir()
    interval_raw = CACHE_FETCH_INTERVAL
    if interval_raw <= 0:
        print(
            f"[cache] background fetch loop disabled (CACHE_FETCH_INTERVAL={CACHE_FETCH_INTERVAL}); cache dir={CACHE_DIR}; node={ARKEOD_NODE}",
            flush=True,
        )
        while True:
            time.sleep(86400)

    interval = max(60, interval_raw) if interval_raw > 0 else 60
    print(
        f"[cache] starting fetch loop every {interval}s; cache dir={CACHE_DIR}; node={ARKEOD_NODE}",
        flush=True,
    )
    if args.once:
        fetch_once(record_status=True)
        return
    while True:
        fetch_once(record_status=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
