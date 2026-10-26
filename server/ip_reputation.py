"""Provider-neutral IP reputation checks for SafeGuard.

SafeGuard's public result schema is independent of any one vendor.
BlackIPS is an optional adapter behind this interface, not the result model.
"""
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROVIDER_BLACKIPS = 'blackips'
MAX_IPS_PER_URL = 4
BLACKIPS_TIMEOUT_SECONDS = 2.5
STATUS_PROBE_IP = '1.1.1.1'
STATUSES = ('listed', 'not_listed', 'unavailable', 'unsupported')
MISS_LIMITATION = 'An IP reputation miss is not proof that a site is safe.'
REACHABLE_STATUSES = ('listed', 'not_listed')


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def reputation_result(provider, ip, status, listed, source='', details=None, checked_at=None):
    if status not in STATUSES:
        raise ValueError('Unknown IP reputation status')
    return {
        'provider': provider,
        'ip': ip,
        'status': status,
        'listed': listed,
        'source': source or '',
        'checked_at': checked_at or utc_now(),
        'details': details or {},
    }


def parse_ip(value):
    text = str(value or '').strip()
    if not text:
        raise ValueError('Enter a valid IPv4 or IPv6 address.')
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ValueError('Enter a valid IPv4 or IPv6 address.') from None


def is_public_global_ip(value):
    """True only for globally routable addresses. Invalid input raises ValueError."""
    addr = value if isinstance(value, ipaddress._BaseAddress) else parse_ip(value)
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    ):
        return False
    return True


def require_public_global_ip(value):
    addr = parse_ip(value)
    if not is_public_global_ip(addr):
        raise ValueError('Only public IP addresses can be checked.')
    return addr


def _canonical_ip(raw):
    text = str(raw).split('%', 1)[0]
    return ipaddress.ip_address(text)


def resolve_public_ips(hostname, port=80, limit=MAX_IPS_PER_URL):
    """Resolve a hostname and return de-duplicated public IPs (IPv4 and IPv6)."""
    host = (hostname or '').strip().lower().rstrip('.')
    if not host:
        return []
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    found = []
    seen = set()
    for info in infos:
        try:
            addr = _canonical_ip(info[4][0])
        except ValueError:
            continue
        if not is_public_global_ip(addr):
            continue
        key = addr.compressed
        if key in seen:
            continue
        seen.add(key)
        found.append(key)
        if len(found) >= limit:
            break
    return found


class IpReputationProvider:
    """Adapter contract for BlackIPS, other TI feeds, or later Zetaris-backed IP intel."""
    name = 'unknown'

    def check(self, ip):
        raise NotImplementedError


class BlackIpsProvider(IpReputationProvider):
    name = PROVIDER_BLACKIPS

    def __init__(self, base_url=None):
        self.base_url = (base_url or '').strip().rstrip('/')

    def check(self, ip):
        try:
            addr = parse_ip(ip)
        except ValueError:
            return reputation_result(self.name, str(ip or ''), 'unsupported', None,
                                     details={'reason': 'invalid_ip'})
        display = addr.compressed
        if not is_public_global_ip(addr):
            return reputation_result(self.name, display, 'unsupported', None,
                                     details={'reason': 'not_public'})
        if not self.base_url:
            return reputation_result(self.name, display, 'unavailable', None,
                                     details={'reason': 'not_configured'})
        try:
            payload = self._query(display)
            return normalize_blackips_payload(payload, display)
        except Exception as ex:
            return reputation_result(self.name, display, 'unavailable', None,
                                     details={'reason': 'provider_error', 'error_type': type(ex).__name__})

    def _query(self, ip):
        endpoint = urllib.parse.urlsplit(self.base_url)
        if (endpoint.scheme not in ('http', 'https') or not endpoint.hostname
                or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment):
            raise ValueError('Invalid BlackIPS endpoint')
        url = f'{self.base_url}/check?{urllib.parse.urlencode({"ip": ip})}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'SafeGuardAI-ResearchPrototype/0.2'},
        )
        try:
            response = urllib.request.urlopen(req, timeout=BLACKIPS_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            if error.code not in (400, 422, 503):
                raise
            response = error
        with response as resp:
            raw = resp.read(8193)
        if len(raw) > 8192:
            raise ValueError('BlackIPS response exceeded size limit')
        payload = json.loads(raw.decode('utf-8', errors='replace'))
        if not isinstance(payload, dict):
            raise ValueError('BlackIPS response was not an object')
        return payload


def normalize_blackips_payload(payload, ip, checked_at=None):
    """Map a BlackIPS /check JSON body onto SafeGuard's vendor-neutral result."""
    data = payload if isinstance(payload, dict) else {}
    code = data.get('code')
    error = data.get('error')
    if error in ('invalid_ip', 'not_public', 'unsupported_address_family'):
        return reputation_result(PROVIDER_BLACKIPS, ip, 'unsupported', None,
                                 details={'reason': error}, checked_at=checked_at)
    if error in ('dataset_unavailable', 'dataset_invalid', 'dataset_stale',
                 'dataset_incomplete', 'dataset_changed', 'redis_unavailable'):
        return reputation_result(PROVIDER_BLACKIPS, ip, 'unavailable', None,
                                 details={'reason': error}, checked_at=checked_at)
    source = data.get('message') or ''
    if not isinstance(source, str):
        source = str(source)
    reported_ip = str(data.get('ip') or ip)
    try:
        same_ip = parse_ip(reported_ip) == parse_ip(ip)
    except ValueError:
        same_ip = False
    if not same_ip:
        return reputation_result(PROVIDER_BLACKIPS, ip, 'unavailable', None,
                                 details={'reason': 'mismatched_ip'}, checked_at=checked_at)
    details = {}
    snapshot = data.get('data_snapshot')
    if isinstance(snapshot, dict):
        # Keep data provenance without exposing internal Redis keys or settings.
        details['data_snapshot'] = {key: snapshot[key] for key in (
            'repository', 'commit', 'loaded_at', 'refresh_by', 'unique_ips', 'coverage', 'feeds') if key in snapshot}
        if type(snapshot.get('unique_ips')) is not int or snapshot['unique_ips'] < 1:
            return reputation_result(PROVIDER_BLACKIPS, ip, 'unavailable', None,
                                     details={'reason': 'dataset_incomplete'}, checked_at=checked_at)
        try:
            expires = datetime.fromisoformat(snapshot['refresh_by'].replace('Z', '+00:00'))
            if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                raise ValueError('Expired snapshot')
        except (KeyError, TypeError, ValueError, AttributeError):
            return reputation_result(PROVIDER_BLACKIPS, ip, 'unavailable', None,
                                     details={'reason': 'dataset_stale'}, checked_at=checked_at)
    if type(code) is int and code == 1:
        if source:
            details['feed'] = source
        return reputation_result(PROVIDER_BLACKIPS, reported_ip, 'listed', True,
                                 source=source, details=details,
                                 checked_at=checked_at)
    if type(code) is int and code == 0:
        return reputation_result(PROVIDER_BLACKIPS, reported_ip, 'not_listed', False,
                                 source=source, details=details, checked_at=checked_at)
    return reputation_result(PROVIDER_BLACKIPS, reported_ip, 'unavailable', None,
                             details={'reason': 'unexpected_code', 'code': code},
                             checked_at=checked_at)


def load_optional_env_file(path):
    """Load KEY=VALUE pairs from a local .env without overriding the process environment."""
    env_path = Path(path)
    if not env_path.is_file():
        return False
    for raw in env_path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        if line.startswith('export '):
            line = line[7:].strip()
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
    return True


def configured_base_url():
    return (os.environ.get('BLACKIPS_BASE_URL') or '').strip().rstrip('/')


def get_provider():
    mode = (os.getenv('SAFEGUARD_IP_PROVIDER') or 'auto').strip().lower()
    if mode == 'remote':
        return BlackIpsProvider(configured_base_url())
    if mode == 'snapshot':
        from offline_snapshot import SnapshotProvider
        return SnapshotProvider()
    if mode == 'disabled':
        return DisabledProvider()
    if mode != 'auto':
        return DisabledProvider('invalid_provider_mode')
    return FallbackProvider()


class DisabledProvider(IpReputationProvider):
    name = PROVIDER_BLACKIPS

    def __init__(self, reason='disabled'):
        self.reason = reason

    def check(self, ip):
        return reputation_result(self.name, ip, 'unavailable', None, details={'reason': self.reason})


class FallbackProvider(IpReputationProvider):
    name = PROVIDER_BLACKIPS

    def check(self, ip):
        from offline_snapshot import SnapshotProvider
        remote = BlackIpsProvider(configured_base_url()).check(ip)
        if remote['status'] != 'unavailable':
            remote.setdefault('details', {}).update(offline=False, fallback=False)
            return remote
        return SnapshotProvider(fallback=True, remote_reason=remote.get('details', {}).get('reason', 'remote_unavailable')).check(ip)


def _display_base_url(base):
    try:
        endpoint = urllib.parse.urlsplit(base)
        if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            return '[invalid BlackIPS endpoint]'
    except ValueError:
        return '[invalid BlackIPS endpoint]'
    return base


def blackips_status():
    """Controlled connectivity report. Never raises, never includes credentials."""
    try:
        base = configured_base_url()
        mode = (os.getenv('SAFEGUARD_IP_PROVIDER') or 'auto').strip().lower()
        if mode == 'remote' and not base:
            return {
                'provider': PROVIDER_BLACKIPS,
                'configured': False,
                'reachable': False,
                'message': 'BLACKIPS_BASE_URL is not configured',
            }
        probe = get_provider().check(STATUS_PROBE_IP)
        reachable = probe.get('status') in REACHABLE_STATUSES
        offline = bool(probe.get('details', {}).get('offline'))
        status = {
            'provider': probe.get('provider', PROVIDER_BLACKIPS),
            'mode': mode,
            'configured': bool(base) if mode == 'remote' else mode == 'snapshot' or reachable or
                          bool(probe.get('details', {}).get('data_snapshot')) or bool(base) and mode == 'auto',
            'reachable': reachable,
            'offline': offline,
            'fallback': bool(probe.get('details', {}).get('fallback')),
            'stale': bool(probe.get('details', {}).get('stale')),
            'message': (
                'Local IP snapshot is available' if reachable and offline else
                'BlackIPS service is reachable' if reachable else
                'IP reputation is disabled' if mode == 'disabled' else
                'Local IP snapshot is expired' if probe.get('details', {}).get('stale') else
                'BLACKIPS_BASE_URL is not configured' if not base and not offline else
                'BlackIPS is configured but not reachable'
            ),
        }
        if base and mode in ('auto', 'remote'):
            status['base_url'] = _display_base_url(base)
        if probe.get('details', {}).get('data_snapshot'):
            status['data_snapshot'] = probe['details']['data_snapshot']
        if not reachable:
            status['reason'] = probe.get('details', {}).get('reason', 'provider_error')
        return status
    except Exception:
        base = configured_base_url()
        payload = {
            'provider': PROVIDER_BLACKIPS,
            'configured': bool(base),
            'reachable': False,
            'message': 'BlackIPS status check failed',
        }
        if base:
            payload['base_url'] = _display_base_url(base)
        return payload


def check_ip(ip, provider=None):
    """Check a single IP. Invalid addresses raise ValueError. Non-public IPs are skipped."""
    addr = parse_ip(ip)
    adapter = provider or get_provider()
    if not is_public_global_ip(addr):
        return reputation_result(adapter.name, addr.compressed, 'unsupported', None,
                                 details={'reason': 'not_public'})
    return adapter.check(addr.compressed)


def reputation_for_url(url, provider=None):
    """Resolve public destination IPs for a URL and query the configured provider."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or '').lower().rstrip('.')
    if not host:
        return []
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    adapter = provider or get_provider()
    try:
        ips = resolve_public_ips(host, port)
    except OSError as ex:
        return [reputation_result(adapter.name, '', 'unavailable', None,
                                  details={'reason': 'dns_failed', 'error_type': type(ex).__name__})]
    results = []
    for ip in ips:
        try:
            results.append(adapter.check(ip))
        except Exception as ex:
            results.append(reputation_result(adapter.name, ip, 'unavailable', None,
                                             details={'reason': 'provider_error', 'error_type': type(ex).__name__}))
    return results


def merge_ip_evidence(result, records):
    """Attach IP evidence without changing keyword risk scoring."""
    result['ip_reputation'] = records
    limitations = result.setdefault('limitations', [])
    if MISS_LIMITATION not in limitations:
        limitations.append(MISS_LIMITATION)
    facts = result.setdefault('verified_facts', [])
    for item in records or []:
        if item.get('listed') is True:
            provider = item.get('provider') or 'an IP reputation provider'
            fact = f'The destination IP was listed by {provider} at check time.'
            if fact not in facts:
                facts.append(fact)
    return result
