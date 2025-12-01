#!/usr/bin/env python3
import json
import os
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

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

ARKEOD_HOME = os.path.expanduser(os.getenv("ARKEOD_HOME", "/root/.arkeod"))
KEY_NAME = os.getenv("KEY_NAME", "provider")
KEYRING = os.getenv("KEY_KEYRING_BACKEND", "test")
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
API_PORT = int(os.getenv("ADMIN_API_PORT", "9999"))
SENTINEL_CONFIG_PATH = os.getenv("SENTINEL_CONFIG_PATH", "/app/config/sentinel.yaml")
SENTINEL_ENV_PATH = os.getenv("SENTINEL_ENV_PATH", "/app/config/sentinel.env")
PROVIDER_ENV_PATH = os.getenv("PROVIDER_ENV_PATH", "/app/provider.env")
ENV_EXPORT_KEYS = [
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


def _probe_url(base: str, path_override: str | None = None, timeout: float = 4.0) -> dict:
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
        req = urllib.request.Request(target, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            return {
                "ok": 200 <= (status or 0) < 400,
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
    os.path.dirname(SENTINEL_ENV_PATH) or ".",
    "sentinel-export.json",
)
PROVIDER_EXPORT_PATH = os.getenv("PROVIDER_EXPORT_PATH") or os.path.join(
    os.path.dirname(PROVIDER_ENV_PATH) or ".",
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


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
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
    rest_base = _normalize_base(os.getenv("ARKEO_REST_API_PORT") or os.getenv("PROVIDER_HUB_URI"))
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
    bundle = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sentinel_env_path": SENTINEL_ENV_PATH,
        "sentinel_config_path": SENTINEL_CONFIG_PATH,
        "export_path": PROVIDER_EXPORT_PATH,
        "sentinel_config": parsed_cfg,
        "sentinel_config_raw": raw_cfg,
        "env_file": env_file,
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
    rest_base = _normalize_base(os.getenv("ARKEO_REST_API_PORT") or os.getenv("PROVIDER_HUB_URI"))
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


@app.get("/api/endpoint-checks")
def endpoint_checks():
    """Probe key endpoints from inside the container and report reachability."""
    env_file = _load_env_file(SENTINEL_ENV_PATH)
    provider_env = _load_env_file(PROVIDER_ENV_PATH)

    def pick(key: str) -> str:
        return provider_env.get(key) or env_file.get(key) or os.getenv(key, "")

    sentinel_port = pick("SENTINEL_PORT") or "3636"
    sentinel_node = pick("SENTINEL_NODE")
    sentinel_external = _normalize_base(sentinel_node, sentinel_port)
    sentinel_internal = _normalize_base("127.0.0.1", sentinel_port)

    arkeod_node = pick("EXTERNAL_ARKEOD_NODE") or pick("ARKEOD_NODE")
    arkeod_base = _normalize_base(arkeod_node)

    rest_api = pick("ARKEO_REST_API_PORT") or pick("PROVIDER_HUB_URI")
    rest_base = _normalize_base(rest_api)

    admin_api_port = pick("ADMIN_API_PORT") or "9999"
    admin_port = pick("ADMIN_PORT") or "8080"
    admin_api_base = _normalize_base("127.0.0.1", admin_api_port)
    admin_ui_base = _normalize_base("127.0.0.1", admin_port)

    endpoints = {
        "arkeod_status": _probe_url(arkeod_base, "/status"),
        "arkeorpc": _probe_url(rest_base, "/cosmos/base/tendermint/v1beta1/node_info"),
        "sentinel_external": _probe_url(sentinel_external, "/metadata.json"),
        "sentinel_internal": _probe_url(sentinel_internal, "/metadata.json"),
        "admin_api": _probe_url(admin_api_base, "/api/version"),
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT)
