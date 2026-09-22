"""Operator-configured, read-only provider checks. A configured gate fails closed."""
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import threading
import time
import urllib.parse
import urllib.request


class HealthError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_limited(response, limit, timeout):
    deadline = time.monotonic() + timeout
    parts, size = [], 0
    while True:
        if time.monotonic() >= deadline:
            raise HealthError('response_deadline_exceeded')
        chunk = response.read1(min(8192, limit + 1 - size))
        if not chunk:
            return b''.join(parts)
        parts.append(chunk)
        size += len(chunk)
        if size > limit:
            raise HealthError('response_too_large')


def pointer(document, path):
    if not isinstance(path, str) or not path.startswith('/'):
        raise HealthError('invalid_field_path')
    try:
        for key in path[1:].split('/'):
            key = key.replace('~1', '/').replace('~0', '~')
            document = document[int(key)] if isinstance(document, list) else document[key]
        return document
    except (KeyError, IndexError, TypeError, ValueError):
        raise HealthError('missing_health_field') from None


def validate_check(document, check, now):
    if not isinstance(document, dict):
        raise HealthError('invalid_health_response')
    network, fresh = False, False
    if 'network_path' in check:
        expected = check.get('expected_network')
        if not isinstance(expected, str) or not expected or pointer(document, check['network_path']) != expected:
            raise HealthError('wrong_network')
        network = True
    if 'timestamp_path' in check:
        value = pointer(document, check['timestamp_path'])
        try:
            unit = check.get('timestamp_unit', 'rfc3339')
            if unit == 'rfc3339':
                parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    raise ValueError('timezone required')
                timestamp = parsed.timestamp()
            elif unit in ('seconds', 'milliseconds', 'nanoseconds'):
                timestamp = float(value) / {'seconds': 1, 'milliseconds': 1e3, 'nanoseconds': 1e9}[unit]
            else:
                raise ValueError('unknown timestamp unit')
            max_age = float(check.get('max_age_seconds', 60))
            if not 1 <= max_age <= 600 or not -10 <= now - timestamp <= max_age:
                raise ValueError('stale timestamp')
        except (TypeError, ValueError, OverflowError):
            raise HealthError('stale_or_invalid_timestamp') from None
        fresh = True
    if 'height_path' in check:
        value = pointer(document, check['height_path'])
        if isinstance(value, bool) or not str(value).isdigit() or int(value) < max(1, int(check.get('min_height', 1))):
            raise HealthError('invalid_height')
    required = check.get('equals', {})
    if not isinstance(required, dict):
        raise HealthError('invalid_health_policy')
    for field, expected in required.items():
        actual = pointer(document, field)
        if type(actual) is not type(expected) or actual != expected:
            raise HealthError('provider_not_ready')
    return network, fresh


class HealthGate:
    def __init__(self, fetch=None, clock=time.time):
        self.fetch = fetch or self._fetch
        self.clock = clock
        self.cache = {}
        self.lock = threading.Lock()

    @staticmethod
    def _fetch(check, timeout):
        url = urllib.parse.urlsplit(check['url'])
        loopback = url.hostname == 'localhost'
        try:
            loopback = loopback or ipaddress.ip_address(url.hostname or '').is_loopback
        except ValueError:
            pass
        if url.scheme != 'https' and not (url.scheme == 'http' and loopback):
            raise HealthError('health_url_requires_tls')
        if not url.hostname or url.username or url.password or url.fragment:
            raise HealthError('invalid_health_url')
        req = urllib.request.Request(check['url'], headers=check.get('headers', {}), method='GET')
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout) as response:
            if response.status != 200:
                raise HealthError('health_http_failure')
            return json.loads(read_limited(response, 65536, timeout))

    def check(self, listener, provider, upstream, deadline=None):
        path = os.environ.get('ARKEO_PROVIDER_HEALTH_FILE')
        required = os.environ.get('ARKEO_INSTITUTIONAL_MODE', '').lower() == 'true'
        if not path:
            if required:
                raise HealthError('health_policy_required')
            return
        try:
            with Path(path).open('rb') as source:
                raw = source.read(262145)
            if len(raw) > 262144:
                raise HealthError('health_policy_too_large')
            policy = json.loads(raw)['listeners'][str(listener)][str(provider)]
            if policy['upstream'].rstrip('/') != upstream.rstrip('/'):
                raise HealthError('health_endpoint_mismatch')
            checks = policy['checks']
            if not isinstance(checks, list) or not 1 <= len(checks) <= 3:
                raise HealthError('invalid_health_policy')
            network, fresh = False, False
            for check in checks:
                remaining = 2.0 if deadline is None else min(2.0, deadline - self.clock())
                if remaining <= 0:
                    raise HealthError('health_deadline_exceeded')
                key = json.dumps(check, sort_keys=True)
                with self.lock:
                    cached = self.cache.get(key)
                if cached and self.clock() - cached[0] < 2:
                    document = cached[1]
                else:
                    document = self.fetch(check, remaining)
                    with self.lock:
                        if len(self.cache) >= 256:
                            self.cache.clear()
                        self.cache[key] = (self.clock(), document)
                has_network, has_fresh = validate_check(document, check, self.clock())
                network, fresh = network or has_network, fresh or has_fresh
            if not network or not fresh:
                raise HealthError('network_and_freshness_checks_required')
        except HealthError:
            raise
        except Exception:
            # Never expose health URLs, API keys or response bodies to callers/logs.
            raise HealthError('provider_health_unavailable') from None


HEALTH_GATE = HealthGate()
