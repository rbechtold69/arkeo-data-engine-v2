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

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeo"))
# These are dynamically refreshed from subscriber-settings.json before each fetch cycle
ARKEOD_NODE = os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or "tcp://provider1.innovationtheory.com:26657"
CACHE_DIR = os.getenv("CACHE_DIR", "/app/cache")
CONFIG_DIR = os.getenv("CONFIG_DIR", "/app/config")
CACHE_FETCH_INTERVAL = 0  # populated below via env
STATUS_FILE = os.path.join(CACHE_DIR, "_sync_status.json")
SUBSCRIBER_SETTINGS_PATH = os.path.join(CONFIG_DIR, "subscriber-settings.json")
METADATA_CACHE_PATH = os.path.join(CACHE_DIR, "metadata.json")
METADATA_TTL_SECONDS = int(os.getenv("METADATA_TTL_SECONDS", "3600"))  # 1 hour default
MIN_SERVICE_BOND = int(os.getenv("MIN_SERVICE_BOND", "100000000"))  # 100_000_000 default
SERVICE_TYPES_TTL_SECONDS = int(os.getenv("SERVICE_TYPES_TTL_SECONDS", "3600"))  # 1 hour default
_CONTRACTS_PAGE_MODE = None
_PROVIDERS_PAGE_MODE = None
_SERVICE_TYPES_PAGE_MODE = None
_SERVICE_TYPES_LIMIT_SUPPORTED = None


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
        "status": [*base, "status"],
        "provider-services": [*base, "query", "arkeo", "list-providers", "-o", "json"],
        "provider-contracts": [*base, "query", "arkeo", "list-contracts", "-o", "json"],
        # service-types are fetched via CLI (supports pagination)
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


def _extract_contracts_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data") if "data" in data else None
        if inner is not None:
            return _extract_contracts_list(inner)
        items = data.get("contracts") or data.get("contract") or data.get("result") or []
        if isinstance(items, list):
            return items
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


def _parse_services_text(text: str) -> list[dict[str, Any]]:
    """Parse textual arkeod all-services output into a structured list."""
    services: list[dict[str, Any]] = []
    if not text or not isinstance(text, str):
        return services
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("- "):
            continue
        # Expected pattern: "- name : id (Description)"
        try:
            # remove leading "- "
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
    return services


def _service_types_cmd(page_key: str | None = None, page: int | None = None, limit: int | None = None) -> list[str]:
    cmd = [
        "arkeod",
        "--home",
        ARKEOD_HOME,
        "--node",
        ARKEOD_NODE,
        "query",
        "arkeo",
        "all-services",
        "-o",
        "json",
    ]
    if limit:
        cmd.extend(["--limit", str(limit)])
    if page_key:
        cmd.extend(["--page-key", str(page_key)])
    elif page:
        cmd.extend(["--page", str(page)])
    return cmd


def fetch_services_rest() -> Dict[str, Any]:
    """Fetch services via RPC, following pagination if available."""
    global _SERVICE_TYPES_PAGE_MODE
    global _SERVICE_TYPES_LIMIT_SUPPORTED
    rest_err = None
    forced_mode = _env_page_mode("SERVICE_TYPES_PAGE_MODE")
    page_mode = forced_mode or _SERVICE_TYPES_PAGE_MODE or "page-key"
    page_key = None
    page = 1
    pages = 0
    seen_keys: set[str] = set()
    services: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("SERVICE_TYPES_PAGE_LIMIT", 0)
    per_page_limit = _page_limit("SERVICE_TYPES_PAGE_SIZE")
    if _SERVICE_TYPES_LIMIT_SUPPORTED is False:
        per_page_limit = None
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _service_types_cmd(
            page_key=page_key if page_mode == "page-key" else None,
            page=page if page_mode == "page" else None,
            limit=per_page_limit or None,
        )
        try:
            code, out = run_list(cmd)
        except Exception as e:
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": ["arkeod query arkeo all-services"],
                "error": f"rest_err={rest_err}; rpc_exec_err={e}",
            }
        if code != 0:
            if "unknown flag" in out and "--limit" in out:
                _SERVICE_TYPES_LIMIT_SUPPORTED = False
                per_page_limit = None
                page_key = None
                page = 1
                pages = 0
                seen_keys.clear()
                services = []
                raw_seen = 0
                last_pagination = {}
                continue
            if page_mode == "page-key" and "unknown flag" in out and "page-key" in out:
                page_mode = "page"
                if not forced_mode:
                    _SERVICE_TYPES_PAGE_MODE = "page"
                page_key = None
                page = 1
                pages = 0
                seen_keys.clear()
                services = []
                raw_seen = 0
                last_pagination = {}
                continue
            if page_mode == "page" and "unknown flag" in out and "--page" in out:
                page_mode = "none"
                if not forced_mode:
                    _SERVICE_TYPES_PAGE_MODE = "none"
                page_key = None
                page = 1
                pages = 0
                seen_keys.clear()
                services = []
                raw_seen = 0
                last_pagination = {}
                continue
            return {
                "fetched_at": timestamp(),
                "exit_code": code,
                "cmd": cmd,
                "error": f"rpc_err={out}",
            }
        try:
            data_val: Any = json.loads(out)
        except json.JSONDecodeError:
            parsed = _parse_services_text(out)
            if parsed:
                return {
                    "fetched_at": timestamp(),
                    "exit_code": 0,
                    "cmd": cmd,
                    "data": {"services": parsed},
                    "parsed_from": "arkeod all-services",
                }
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": f"rest_err={rest_err}; rpc_parse_failed",
            }
        if isinstance(data_val, str):
            parsed = _parse_services_text(data_val)
            if parsed:
                return {
                    "fetched_at": timestamp(),
                    "exit_code": 0,
                    "cmd": cmd,
                    "data": {"services": parsed},
                    "parsed_from": "arkeod all-services",
                }
            return {
                "fetched_at": timestamp(),
                "exit_code": 1,
                "cmd": cmd,
                "error": f"rest_err={rest_err}; rpc_parse_failed",
            }

        page_services = _extract_service_types_list(data_val)
        if page_services:
            services.extend(page_services)
            raw_seen += len(page_services)
        pages += 1
        last_pagination = _extract_pagination(data_val)

        if total_cap and raw_seen >= total_cap:
            break
        if page_mode == "none":
            break
        if page_mode == "page-key":
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
        else:
            if not page_services:
                break
            page += 1

    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _service_types_cmd(limit=per_page_limit or None),
        "data": {"services": services, "pagination": last_pagination},
        "pages": pages,
    }


def _contracts_list_cmd(page_key: str | None = None, page: int | None = None, limit: int | None = None) -> list[str]:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-contracts", "-o", "json"])
    if limit:
        cmd.extend(["--limit", str(limit)])
    if page_key:
        cmd.extend(["--page-key", str(page_key)])
    elif page:
        cmd.extend(["--page", str(page)])
    return cmd


def fetch_contracts_paginated() -> Dict[str, Any]:
    """Fetch all contracts across pages, honoring pagination next_key when present."""
    global _CONTRACTS_PAGE_MODE
    forced_mode = _env_page_mode("CONTRACTS_PAGE_MODE")
    page_mode = forced_mode or _CONTRACTS_PAGE_MODE or "page-key"
    page_key = None
    page = 1
    pages = 0
    seen_keys: set[str] = set()
    contracts: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("CONTRACTS_PAGE_LIMIT", 0)
    per_page_limit = _page_limit("CONTRACTS_PAGE_SIZE")
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _contracts_list_cmd(
            page_key=page_key if page_mode == "page-key" else None,
            page=page if page_mode == "page" else None,
            limit=per_page_limit or None,
        )
        code, out = run_list(cmd)
        if code != 0:
            if page_mode == "page-key" and "unknown flag" in out and "page-key" in out:
                page_mode = "page"
                if not forced_mode:
                    _CONTRACTS_PAGE_MODE = "page"
                page_key = None
                page = 1
                pages = 0
                seen_keys.clear()
                contracts = []
                raw_seen = 0
                last_pagination = {}
                continue
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
        if isinstance(page_contracts, list):
            contracts.extend(page_contracts)
            raw_seen += len(page_contracts)
        pages += 1
        last_pagination = _extract_pagination(data)

        if total_cap and raw_seen >= total_cap:
            break

        if page_mode == "page-key":
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
        else:
            if not page_contracts:
                break
            page += 1

    payload = {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _contracts_list_cmd(limit=per_page_limit or None),
        "data": {"contracts": contracts, "pagination": last_pagination},
        "pages": pages,
    }
    return payload


def _providers_list_cmd(page_key: str | None = None, page: int | None = None, limit: int | None = None) -> list[str]:
    cmd = ["arkeod", "--home", ARKEOD_HOME]
    if ARKEOD_NODE:
        cmd.extend(["--node", ARKEOD_NODE])
    cmd.extend(["query", "arkeo", "list-providers", "-o", "json"])
    if limit:
        cmd.extend(["--limit", str(limit)])
    if page_key:
        cmd.extend(["--page-key", str(page_key)])
    elif page:
        cmd.extend(["--page", str(page)])
    return cmd


def fetch_provider_services_paginated() -> Dict[str, Any]:
    """Fetch all providers across pages, honoring pagination next_key when present."""
    global _PROVIDERS_PAGE_MODE
    forced_mode = _env_page_mode("PROVIDER_SERVICES_PAGE_MODE")
    page_mode = forced_mode or _PROVIDERS_PAGE_MODE or "page-key"
    page_key = None
    page = 1
    pages = 0
    seen_keys: set[str] = set()
    providers: list[dict[str, Any]] = []
    raw_seen = 0
    total_cap = _env_int("PROVIDER_SERVICES_PAGE_LIMIT", 0)
    per_page_limit = _page_limit("PROVIDER_SERVICES_PAGE_SIZE")
    last_pagination: Dict[str, Any] = {}

    while True:
        cmd = _providers_list_cmd(
            page_key=page_key if page_mode == "page-key" else None,
            page=page if page_mode == "page" else None,
            limit=per_page_limit or None,
        )
        code, out = run_list(cmd)
        if code != 0:
            if page_mode == "page-key" and "unknown flag" in out and "page-key" in out:
                page_mode = "page"
                if not forced_mode:
                    _PROVIDERS_PAGE_MODE = "page"
                page_key = None
                page = 1
                pages = 0
                seen_keys.clear()
                providers = []
                raw_seen = 0
                last_pagination = {}
                continue
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

        if page_mode == "page-key":
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
        else:
            if not page_providers:
                break
            page += 1

    return {
        "fetched_at": timestamp(),
        "exit_code": 0,
        "cmd": _providers_list_cmd(limit=per_page_limit or None),
        "data": {"providers": providers, "pagination": last_pagination},
        "pages": pages,
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
        if host == "localhost" or host.startswith("127."):
            return False
        return True
    except Exception:
        return False


def _is_localhost_uri(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        parsed = urlparse(uri)
        host = (parsed.hostname or "").lower()
        return host == "localhost" or host.startswith("127.")
    except Exception:
        return False


def _refresh_runtime_settings() -> None:
    """Reload ARKEOD_NODE from subscriber-settings.json if present."""
    global ARKEOD_NODE
    settings = {}
    try:
        with open(SUBSCRIBER_SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f) or {}
    except Exception:
        settings = {}
    node_val = settings.get("ARKEOD_NODE") or os.getenv("ARKEOD_NODE") or os.getenv("EXTERNAL_ARKEOD_NODE") or ARKEOD_NODE
    if node_val:
        ARKEOD_NODE = str(node_val).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _env_str(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    val = str(raw).strip()
    return val if val else None


def _env_page_mode(name: str) -> str | None:
    raw = _env_str(name)
    if not raw:
        return None
    norm = raw.strip().lower().replace("_", "-")
    if norm in ("page", "offset"):
        return "page"
    if norm in ("page-key", "pagekey", "key", "cursor"):
        return "page-key"
    return None


def _page_limit(override_env: str) -> int | None:
    per_resource = _env_int(override_env, 0)
    if per_resource and per_resource > 0:
        return per_resource
    global_limit = _env_int("PAGE_LIMIT", 1000)
    if global_limit and global_limit > 0:
        return global_limit
    return None


# Resolve fetch interval after helpers are defined
CACHE_FETCH_INTERVAL = _env_int("CACHE_FETCH_INTERVAL", 300)


def _load_metadata_cache() -> dict[str, dict[str, Any]]:
    try:
        with open(METADATA_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            items = data.get("metadata") or data
            if isinstance(items, dict):
                return items
    except Exception:
        pass
    return {}


def _load_cache_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_is_fresh(path: str, ttl_sec: int) -> tuple[bool, Dict[str, Any]]:
    payload = _load_cache_file(path)
    try:
        fetched = payload.get("fetched_at")
    except Exception:
        fetched = None
    if not fetched:
        return False, {}
    try:
        ts = datetime.fromisoformat(fetched).timestamp()
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


def _update_metadata_cache_from_providers(provider_services_payload: Dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Fetch metadata for unique metadata_uri entries, keeping cache and refreshing stale/failed entries.
    """
    cache_map = _load_metadata_cache()
    changed = False
    data = provider_services_payload.get("data") if isinstance(provider_services_payload, dict) else {}
    prov_entries = []
    if isinstance(data, dict):
        prov_entries = data.get("providers") or data.get("provider") or []
    elif isinstance(data, list):
        prov_entries = data
    if not isinstance(prov_entries, list):
        prov_entries = []

    uris = set()

    def _collect_mu(entry: dict[str, Any] | None):
        if not entry or not isinstance(entry, dict):
            return
        mu = entry.get("metadata_uri") or entry.get("metadataUri")
        status_val = entry.get("status")
        status_str = str(status_val).strip().lower() if status_val is not None else ""
        if status_str not in {"online", "1", "true"} and status_val not in (1, True):
            return  # skip offline/unknown services/providers
        if mu and _is_external(mu):
            uris.add(mu)

    for p in prov_entries:
        if not isinstance(p, dict):
            continue
        _collect_mu(p)
        if isinstance(p.get("services"), list):
            for s in p["services"]:
                _collect_mu(s if isinstance(s, dict) else None)
        if isinstance(p.get("service"), list):
            for s in p["service"]:
                _collect_mu(s if isinstance(s, dict) else None)

    now = time.time()

    def _is_stale(entry: dict[str, Any]) -> bool:
        fetched = entry.get("fetched_at")
        try:
            ts = datetime.fromisoformat(fetched).timestamp() if fetched else 0
        except Exception:
            ts = 0
        status_val = entry.get("status")
        if status_val != 1 and status_val != "1":
            return True
        return (now - ts) > METADATA_TTL_SECONDS

    for mu in uris:
        entry = cache_map.get(mu)
        if entry and not _is_stale(entry):
            continue
        data_val, err_val, status_val = fetch_metadata_uri(mu)
        if status_val == 1:
            cache_map[mu] = {
                "metadata_uri": mu,
                "fetched_at": timestamp(),
                "data": data_val,
                "error": None,
                "status": status_val,
            }
            changed = True
        else:
            # Drop failed/invalid entries from cache so only valid metadata is persisted
            if mu in cache_map:
                cache_map.pop(mu, None)
                changed = True
    if changed:
        _save_metadata_cache(cache_map)
    return cache_map


def build_providers_metadata(provider_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build active_providers.json by listing providers/services, then fetch external metadata_uri (short timeout)."""
    t_start = time.time()
    providers_list: List[Dict[str, Any]] = []
    data = provider_payload.get("data")
    if isinstance(data, dict):
        providers_list = data.get("providers") or data.get("provider") or []
    elif isinstance(data, list):
        providers_list = data
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
            # Try to set provider_moniker from metadata if available
            if not entry.get("provider_moniker") and isinstance(meta_data_val, dict):
                cfg = meta_data_val.get("config") if isinstance(meta_data_val.get("config"), dict) else {}
                moniker_val = cfg.get("moniker") or meta_data_val.get("moniker")
                if moniker_val:
                    entry["provider_moniker"] = moniker_val
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
    active_only = []
    for e in enriched:
        if (e.get("status") == 1 or e.get("status") == "1") and (e.get("online_service_count") or 0) > 0:
            if e.get("pubkey") and not e.get("provider_moniker"):
                # Fallback: use pubkey as moniker if none found
                e["provider_moniker"] = e["pubkey"]
            active_only.append(e)
    out = {
        "fetched_at": timestamp(),
        "source": "provider-services",
        "providers": active_only,
    }
    out["_duration_sec"] = round(time.time() - t_start, 3)
    return out


def build_active_services(provider_services_payload: Dict[str, Any], metadata_cache: dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Build active_services.json directly from provider-services by selecting ONLINE providers/services with cached metadata.
    """
    t_start = time.time()
    data = provider_services_payload.get("data") if isinstance(provider_services_payload, dict) else {}
    prov_entries = []
    if isinstance(data, dict):
        prov_entries = data.get("providers") or data.get("provider") or []
    elif isinstance(data, list):
        prov_entries = data
    if not isinstance(prov_entries, list):
        prov_entries = []

    active_services: list[dict[str, Any]] = []
    meta_cache = metadata_cache or {}

    for entry in prov_entries:
        if not isinstance(entry, dict):
            continue
        pk = entry.get("pub_key") or entry.get("pubkey") or entry.get("pubKey")
        if not pk:
            continue
        status_val = entry.get("status")
        status_str = str(status_val).strip().lower() if status_val is not None else ""
        if status_str not in {"online", "1"} and status_val not in (1, True):
            continue
        mu = entry.get("metadata_uri") or entry.get("metadataUri")
        if not mu or not _is_external(mu):
            continue
        meta_entry = meta_cache.get(mu) if meta_cache else None
        meta_ok = bool(meta_entry and (meta_entry.get("status") == 1 or meta_entry.get("status") == "1"))
        if not meta_ok:
            continue
        # bond threshold
        bond_val = entry.get("bond") or entry.get("service_bond") or entry.get("bond_amount")
        try:
            bond_int = int(bond_val)
        except Exception:
            bond_int = 0
        if bond_int < MIN_SERVICE_BOND:
            continue

        # Services list may be nested; if absent, still emit the provider-level service if present
        services_field = []
        if isinstance(entry.get("services"), list):
            services_field = entry["services"]
        elif isinstance(entry.get("service"), list):
            services_field = entry["service"]
        if services_field:
            for svc in services_field:
                if not isinstance(svc, dict):
                    continue
                svc_status = svc.get("status")
                svc_status_str = str(svc_status).strip().lower() if svc_status is not None else ""
                if svc_status_str not in {"online", "1"} and svc_status not in (1, True):
                    continue
                active_services.append(
                    {
                        "provider_pubkey": pk,
                        "service_id": svc.get("service_id") or svc.get("id") or svc.get("service"),
                        "service": svc.get("service") or svc.get("name"),
                        "metadata_uri": mu,
                        "metadata": meta_entry.get("data") if isinstance(meta_entry, dict) else None,
                        "raw": svc,
                    }
                )
        else:
            active_services.append(
                {
                    "provider_pubkey": pk,
                    "service_id": entry.get("service_id") or entry.get("id") or entry.get("service"),
                    "service": entry.get("service") or entry.get("name"),
                    "metadata_uri": mu,
                    "metadata": meta_entry.get("data") if isinstance(meta_entry, dict) else None,
                    "raw": entry,
                }
            )

    out = {
        "fetched_at": timestamp(),
        "source": "provider-services",
        "active_services": active_services,
    }
    out["_duration_sec"] = round(time.time() - t_start, 3)
    return out


def build_active_providers_from_active_services(active_services_payload: Dict[str, Any], provider_services_payload: Dict[str, Any], metadata_cache: dict[str, dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Build active_providers.json: one entry per provider pubkey with online services and cached metadata."""
    t_start = time.time()
    active_services = active_services_payload.get("active_services") if isinstance(active_services_payload, dict) else []
    if not isinstance(active_services, list):
        active_services = []
    meta_cache = metadata_cache or {}

    # Providers that actually have active services.
    active_provider_pks = set()
    for svc in active_services:
        if isinstance(svc, dict) and svc.get("provider_pubkey"):
            active_provider_pks.add(str(svc.get("provider_pubkey")))

    data = provider_services_payload.get("data") if isinstance(provider_services_payload, dict) else {}
    prov_entries = []
    if isinstance(data, dict):
        prov_entries = data.get("providers") or data.get("provider") or []
    elif isinstance(data, list):
        prov_entries = data
    if not isinstance(prov_entries, list):
        prov_entries = []

    providers: list[dict[str, Any]] = []
    seen_pubkeys: set[str] = set()
    providers_seen = 0

    for p in prov_entries:
        if not isinstance(p, dict):
            continue
        providers_seen += 1
        pk = p.get("pub_key") or p.get("pubkey") or p.get("pubKey")
        if not pk or pk not in active_provider_pks or pk in seen_pubkeys:
            continue

        mu = p.get("metadata_uri") or p.get("metadataUri")
        if not mu or not _is_external(mu):
            continue

        meta_entry = meta_cache.get(mu)
        meta_ok = bool(meta_entry)
        if not meta_ok:
            continue

        entry = dict(p)
        entry["provider_pubkey"] = pk
        entry["metadata_uri_active"] = True
        entry["metadata"] = meta_entry.get("data")
        # Prefer moniker from metadata when available.
        meta_val = entry["metadata"]
        if isinstance(meta_val, dict):
            cfg = meta_val.get("config") if isinstance(meta_val.get("config"), dict) else {}
            moniker_val = cfg.get("moniker") or meta_val.get("moniker")
            if moniker_val:
                entry["provider_moniker"] = moniker_val
        if not entry.get("provider_moniker"):
            entry["provider_moniker"] = pk

        providers.append(entry)
        seen_pubkeys.add(pk)

    out = {
        "fetched_at": timestamp(),
        "source": "active_services",
        "providers": providers,
        "debug_counts": {
            "active_services": len(active_services),
            "providers_seen": providers_seen,
            "providers_kept": len(providers),
        },
    }
    out["_duration_sec"] = round(time.time() - t_start, 3)
    return out

def build_active_service_types(active_services_payload: Dict[str, Any], service_types_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Derive active_service_types.json with unique service ids and counts, enriched with service type metadata."""
    t_start = time.time()
    active_services = []
    if isinstance(active_services_payload, dict):
        active_services = active_services_payload.get("active_services") or []
    if not isinstance(active_services, list):
        active_services = []

    service_types_list: List[Dict[str, Any]] = []
    st_data = service_types_payload.get("data") if isinstance(service_types_payload, dict) else {}
    if isinstance(st_data, list):
        service_types_list = st_data
    elif isinstance(st_data, dict):
        service_types_list = st_data.get("services") or st_data.get("service") or st_data.get("result") or []
    if not isinstance(service_types_list, list):
        service_types_list = []

    # Build lookup by service_id string
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

    # Sort by description (most readable), fallback to name or service_id
    def _sort_key(entry: Dict[str, Any]):
        st = entry.get("service_type") or {}
        desc = st.get("description") or st.get("desc") or ""
        name = st.get("name") or st.get("service") or ""
        return (str(desc).lower(), str(name).lower(), str(entry.get("service_id")))

    entries.sort(key=_sort_key)

    out = {
        "fetched_at": timestamp(),
        "source": "active_services",
        "active_service_types": entries,
    }
    out["_duration_sec"] = round(time.time() - t_start, 3)
    return out


def build_subscribers_from_contracts(contracts_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Derive subscribers.json from provider-contracts cache (unique subscriber addresses)."""
    t_start = time.time()
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

    out = {
        "fetched_at": timestamp(),
        "source": "provider-contracts",
        "subscribers": subscribers,
    }
    out["_duration_sec"] = round(time.time() - t_start, 3)
    return out


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


def _load_listeners() -> Dict[str, Any]:
    path = os.path.join(CACHE_DIR, "listeners.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _write_listeners(payload: Dict[str, Any]) -> None:
    path = os.path.join(CACHE_DIR, "listeners.json")
    tmp_path = f"{path}.tmp.{os.getpid()}.{int(time.time() * 1000)}"
    lock_path = f"{path}.lock"
    lock_fh = None
    try:
        import fcntl  # POSIX

        lock_fh = open(lock_path, "w")
        deadline = time.time() + 3.0
        while True:
            try:
                fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    print(f"[cache] listeners lock timeout for {path}", flush=True)
                    if lock_fh:
                        lock_fh.close()
                    return
                time.sleep(0.05)
    except Exception as e:
        print(f"[cache] listeners lock failed: {e}", flush=True)
        if lock_fh:
            try:
                lock_fh.close()
            except Exception:
                pass
        lock_fh = None
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        try:
            print(f"[cache] wrote listeners.json (tmp={tmp_path})", flush=True)
        except Exception:
            pass
    except OSError as e:
        print(f"[cache] failed to write listeners.json: {e}", flush=True)
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
    finally:
        if lock_fh:
            try:
                import fcntl as _fcntl

                _fcntl.flock(lock_fh, _fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_fh.close()
            except Exception:
                pass


def _sync_listeners_from_active(active_services_payload: Dict[str, Any], active_providers_payload: Dict[str, Any], provider_services_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Update listeners.json top_services entries to reflect latest active service data."""
    listeners_data = _load_listeners()
    listeners = listeners_data.get("listeners") if isinstance(listeners_data, dict) else None
    if not isinstance(listeners, list) or not listeners:
        return {}

    # Build provider moniker lookup from active_providers metadata
    prov_meta: Dict[str, str] = {}
    prov_list = active_providers_payload.get("providers") if isinstance(active_providers_payload, dict) else []
    if isinstance(prov_list, list):
        for p in prov_list:
            if not isinstance(p, dict):
                continue
            pk = p.get("pubkey") or p.get("pub_key") or p.get("pubKey")
            meta = p.get("metadata") or {}
            moniker = ""
            try:
                cfg = meta.get("config") or {}
                moniker = cfg.get("moniker") or ""
            except Exception:
                moniker = ""
            if pk and moniker:
                prov_meta[str(pk)] = moniker

    # Build service lookup by (provider_pubkey, service_id) from active_services only (authoritative active set)
    svc_lookup: Dict[tuple[str, str], Dict[str, Any]] = {}
    svc_list = active_services_payload.get("active_services") if isinstance(active_services_payload, dict) else []
    if isinstance(svc_list, list):
        for s in svc_list:
            if not isinstance(s, dict):
                continue
            pk = s.get("provider_pubkey")
            sid = s.get("service_id") or s.get("service")
            if pk is None or sid is None:
                continue
            key = (str(pk), str(sid))
            raw = s.get("raw") or {}
            svc_lookup[key] = {
                "provider_pubkey": str(pk),
                "status": raw.get("status") if isinstance(raw, dict) else None,
            }

    changed_any = False
    listeners_updated = 0
    services_updated = 0
    services_dropped = 0
    now = timestamp()

    for listener in listeners:
        if not isinstance(listener, dict):
            continue
        top = listener.get("top_services") or []
        if not isinstance(top, list):
            continue
        listener_changed = False
        new_top = []
        seen = set()
        for ts in top:
            if not isinstance(ts, dict):
                continue
            pk = ts.get("provider_pubkey") or ts.get("pubkey")
            sid = ts.get("service_id") or ts.get("service") or listener.get("service_id") or listener.get("service")
            if pk is None or sid is None:
                new_top.append(ts)
                continue
            key = (str(pk), str(sid))
            if key in seen:
                listener_changed = True
                continue  # dedupe duplicates
            seen.add(key)
            svc = svc_lookup.get(key)
            if svc:
                merged = {
                    "provider_pubkey": str(pk),
                }
                # refresh fields from active data (avoid clobbering runtime status updates)
                for k in ("status",):
                    if svc.get(k) is not None and not ts.get("status_updated_at"):
                        merged[k] = svc.get(k)
                # preserve metrics/status timestamps if present
                for k in ("rt_avg_ms", "rt_count", "rt_last_ms", "rt_updated_at", "status_updated_at"):
                    if ts.get(k) is not None:
                        merged[k] = ts.get(k)
                mon = prov_meta.get(str(pk))
                if mon:
                    merged["provider_moniker"] = mon
                new_top.append(merged)
                listener_changed = True
            else:
                # No longer active -> drop it
                listener_changed = True
        listener["top_services"] = new_top
        if listener_changed:
            listener["updated_at"] = now
            changed_any = True
            listeners_updated += 1
            services_updated += len(new_top)
            services_dropped += len(top) - len(new_top)

    if changed_any:
        listeners_data["listeners"] = listeners
        listeners_data["fetched_at"] = now
        _write_listeners(listeners_data)
    return {
        "listeners": len(listeners) if isinstance(listeners, list) else 0,
        "listeners_updated": listeners_updated,
        "services_updated": services_updated,
        "services_dropped": services_dropped,
    }


def fetch_once(commands: Dict[str, List[str]] | None = None, record_status: bool = False) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    _refresh_runtime_settings()
    loop_start = time.time()
    print(f"[cache] fetch_once start node={ARKEOD_NODE}", flush=True)
    commands = build_commands()
    start_ts = timestamp()
    if record_status:
        mark_sync_start(start_ts)
    ok = True
    error_msg = None
    fatal_errors = []
    try:
        metadata_cache: dict[str, dict[str, Any]] | None = None
        stage_times: Dict[str, float] = {}
        for name, cmd in commands.items():
            t0 = time.time()
            if name == "service-types":
                cache_path = os.path.join(CACHE_DIR, "service-types.json")
                fresh, cached = _cache_is_fresh(cache_path, SERVICE_TYPES_TTL_SECONDS)
                if fresh:
                    payload = cached
                    stage_times[name] = time.time() - t0
                    results[name] = payload
                    continue
                payload = fetch_services_rest()
            elif name == "provider-services":
                payload = fetch_provider_services_paginated()
                if payload.get("exit_code") != 0:
                    ok = False
                    fatal_errors.append(f"{name} exit={payload.get('exit_code')}")
            elif name == "provider-contracts":
                payload = fetch_contracts_paginated()
                if payload.get("exit_code") != 0:
                    ok = False
                    fatal_errors.append(f"{name} exit={payload.get('exit_code')}")
            else:
                code, out = run_list(cmd)
                payload = normalize_result(name, code, out, cmd)
                if code != 0:
                    ok = False
                    fatal_errors.append(f"{name} exit={code}")
            if name == "status":
                status_payload: Dict[str, Any] = {
                    "ok": payload.get("exit_code") == 0,
                    "height": None,
                    "node": ARKEOD_NODE,
                    "synced_at": timestamp(),
                    "synced_at_unix": time.time(),
                }
                if payload.get("exit_code") == 0:
                    try:
                        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
                        status_payload["status"] = data
                        sync_info = data.get("sync_info") or data.get("SyncInfo") or {}
                        height = sync_info.get("latest_block_height") or sync_info.get("latest_block")
                        if height is not None:
                            status_payload["height"] = int(height)
                        else:
                            status_payload["ok"] = False
                            status_payload["error"] = "no height in status"
                    except Exception as e:
                        status_payload["ok"] = False
                        status_payload["error"] = f"status parse error: {e}"
                else:
                    status_payload["error"] = payload.get("error") or "status failed"
                write_cache("arkeo_status", status_payload)
            # If provider-services succeeded, update metadata cache and annotate payload
            if name == "provider-services" and payload.get("exit_code") == 0:
                metadata_cache = _update_metadata_cache_from_providers(payload)
                # mark metadata_uri_active flags
                try:
                    active_uris = set(metadata_cache.keys()) if metadata_cache else set()
                    data_block = payload.get("data")
                    if isinstance(data_block, dict):
                        prov_entries = data_block.get("providers") or data_block.get("provider") or []
                    elif isinstance(data_block, list):
                        prov_entries = data_block
                    else:
                        prov_entries = []
                    if isinstance(prov_entries, list):
                        for p in prov_entries:
                            if not isinstance(p, dict):
                                continue
                            mu = p.get("metadata_uri") or p.get("metadataUri")
                            if mu and mu in active_uris:
                                p["metadata_uri_active"] = True
                            services_field = []
                            if isinstance(p.get("services"), list):
                                services_field = p["services"]
                            elif isinstance(p.get("service"), list):
                                services_field = p["service"]
                            for s in services_field:
                                if not isinstance(s, dict):
                                    continue
                                mu_svc = s.get("metadata_uri") or s.get("metadataUri")
                                if mu_svc and mu_svc in active_uris:
                                    s["metadata_uri_active"] = True
                except Exception:
                    pass
            if name != "status":
                write_cache(name, payload)
            results[name] = payload
            stage_times[name] = time.time() - t0
        # expose metadata cache in results for UI visibility
        if metadata_cache is None:
            try:
                metadata_cache = _load_metadata_cache()
            except Exception:
                metadata_cache = {}
        if metadata_cache is not None:
            results["metadata"] = {"metadata": metadata_cache, "exit_code": 0}
        # Derive active_services.json first, directly from provider-services + metadata cache
        active_services_payload = None
        active_providers_payload = None
        if "provider-services" in results and results["provider-services"].get("exit_code") == 0:
            t0 = time.time()
            active_services_payload = build_active_services(results["provider-services"], metadata_cache or {})
            write_cache("active_services", active_services_payload)
            results["active_services"] = active_services_payload
            stage_times["active_services_build"] = time.time() - t0
            # Derive active_providers.json from active_services
            t1 = time.time()
            active_providers_payload = build_active_providers_from_active_services(active_services_payload, results["provider-services"], metadata_cache or {})
            write_cache("active_providers", active_providers_payload)
            results["active_providers"] = active_providers_payload
            stage_times["active_providers_build"] = time.time() - t1
            # Derive active_service_types.json if service-types cache exists
            if "service-types" in results and results["service-types"].get("exit_code") == 0:
                t2 = time.time()
                ast_payload = build_active_service_types(active_services_payload, results["service-types"])
                write_cache("active_service_types", ast_payload)
                results["active_service_types"] = ast_payload
                stage_times["active_service_types_build"] = time.time() - t2
        else:
            print("[cache] skip active_services/active_providers_build (provider-services failed)", flush=True)
        # Derive subscribers.json from provider-contracts if available
        if "provider-contracts" in results and results["provider-contracts"].get("exit_code") == 0:
            t0 = time.time()
            subscribers_payload = build_subscribers_from_contracts(results["provider-contracts"])
            write_cache("subscribers", subscribers_payload)
            results["subscribers"] = subscribers_payload
            stage_times["subscribers_build"] = time.time() - t0
        else:
            print("[cache] skip subscribers_build (provider-contracts failed)", flush=True)
    except Exception as e:
        ok = False
        error_msg = str(e)
        raise
    finally:
        if record_status:
            final_err = error_msg or ("; ".join(fatal_errors) if fatal_errors else None)
            mark_sync_end(ok=ok, error=final_err)
        # emit timings
        try:
            total = time.time() - loop_start
            stage_parts = " ".join([f"{k}={stage_times[k]:.2f}s" for k in stage_times])
            print(f"[cache] fetch_once done total={total:.2f}s {stage_parts}", flush=True)
        except Exception:
            pass
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Arkeo cache fetcher")
    parser.add_argument("--once", action="store_true", help="Run a single fetch cycle then exit")
    args = parser.parse_args()

    ensure_cache_dir()
    _refresh_runtime_settings()
    interval_raw = CACHE_FETCH_INTERVAL
    if interval_raw <= 0:
        print(
            f"[cache] background fetch loop disabled (CACHE_FETCH_INTERVAL={CACHE_FETCH_INTERVAL}); cache dir={CACHE_DIR}; node={ARKEOD_NODE}",
            flush=True,
        )
        # sleep forever so supervisor keeps the process alive without looping
        while True:
            time.sleep(86400)

    interval = max(60, interval_raw) if interval_raw>0 else 60
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
