"""Private, provenance-checked IPv4 snapshots. No cloud, model, or Redis required.

Data redistribution rights are not inferred from a public download URL. Snapshot
files belong under ignored local-data; the public project ships only this loader.
"""
from datetime import datetime, timedelta, timezone
from copy import deepcopy
from functools import lru_cache
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

REPOSITORY = 'https://github.com/njcx/blackip_list'
FEED_NAMES = ('abuseipdb_30d.ipset', 'blocklist_de.ipset')
MAX_AGE = timedelta(hours=72)
MAX_FILE_BYTES = 8_000_000


def snapshot_directory():
    configured = os.getenv('BLACKIPS_SNAPSHOT_DIR', '').strip()
    return Path(configured) if configured else Path(
        os.getenv('SAFEGUARD_DATA_DIR') or Path(__file__).parent / 'local-data') / 'blackips-snapshot'


def current_folder(directory):
    directory = Path(directory)
    pointer = directory / 'current.json'
    if not pointer.exists():
        return directory
    value = json.loads(pointer.read_text(encoding='utf-8'))['directory']
    if not re.fullmatch(r'[0-9a-f]{40}-[0-9a-f]{12}', value):
        raise ValueError('invalid_snapshot_pointer')
    folder = directory / 'snapshots' / value
    if not folder.resolve().is_relative_to(directory.resolve()):
        raise ValueError('invalid_snapshot_pointer')
    return folder


def parse_feed(raw):
    text = raw.decode('utf-8')
    match = re.search(r'^# Source File Date:\s*(.+)$', text, re.M)
    if not match:
        raise ValueError('missing_source_timestamp')
    stamp = datetime.strptime(match[1].strip(), '%a %b %d %H:%M:%S UTC %Y').replace(tzinfo=timezone.utc)
    addresses = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        address = ipaddress.ip_address(line)
        if address.version != 4 or not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError('unsupported_feed_entry')
        addresses.add(address.compressed)
    if not addresses:
        raise ValueError('empty_feed')
    return addresses, stamp


def _signature(folder):
    return tuple((name, (folder / name).stat().st_mtime_ns, (folder / name).stat().st_size)
                 for name in ('manifest.json',) + FEED_NAMES)


@lru_cache(maxsize=2)
def _load_cached(folder_text, signature):
    folder = Path(folder_text)
    if any(size > MAX_FILE_BYTES for _, _, size in signature):
        raise ValueError('snapshot_file_too_large')
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    commit = manifest.get('commit', '')
    if manifest.get('repository') != REPOSITORY or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('unrecognized_snapshot_source')
    feeds = manifest.get('feeds', [])
    if len(feeds) != 2 or {entry.get('name') for entry in feeds} != set(FEED_NAMES):
        raise ValueError('unexpected_feed_set')
    records, sources, dates = {}, [], []
    for entry in feeds:
        name = entry['name']
        expected = f'https://raw.githubusercontent.com/njcx/blackip_list/{commit}/{name}'
        raw = (folder / name).read_bytes()
        if entry.get('url') != expected or hashlib.sha256(raw).hexdigest() != entry.get('sha256'):
            raise ValueError('snapshot_checksum_or_source_mismatch')
        addresses, stamp = parse_feed(raw)
        for address in addresses:
            records.setdefault(address, []).append(name.removesuffix('.ipset'))
        dates.append(stamp)
        sources.append({'name': name, 'url': expected, 'sha256': entry['sha256'],
                        'entries': len(addresses), 'source_file_date': stamp.isoformat()})
    metadata = {'repository': REPOSITORY, 'commit': commit, 'unique_ips': len(records),
                'source_date': min(dates).isoformat(),
                'refresh_by': (min(dates) + MAX_AGE).isoformat(), 'feeds': sources,
                'coverage': 'Two exact IPv4 snapshots; no IPv6, CIDR, country or Tor coverage. A miss is not proof of safety.',
                'redistribution': 'not_cleared; private local snapshot only'}
    return records, metadata


def load_snapshot(directory, now=None):
    folder = current_folder(directory)
    records, cached = _load_cached(str(folder.resolve()), _signature(folder))
    now = now or datetime.now(timezone.utc)
    metadata = deepcopy(cached)
    future = any(datetime.fromisoformat(feed['source_file_date']) > now + timedelta(minutes=5)
                 for feed in metadata['feeds'])
    stale = datetime.fromisoformat(metadata['refresh_by']) <= now
    metadata.update(stale=stale, freshness='untrusted_timestamp' if future else 'expired' if stale else 'current')
    return records, metadata


class SnapshotProvider:
    name = 'blackips_snapshot'

    def __init__(self, directory=None, *, fallback=False, remote_reason=None):
        self.directory = Path(directory) if directory is not None else snapshot_directory()
        self.fallback, self.remote_reason = fallback, remote_reason

    def check(self, ip):
        from ip_reputation import reputation_result, is_public_global_ip
        details = {'offline': True, 'fallback': self.fallback, 'snapshot': True}
        if self.remote_reason:
            details['remote_reason'] = self.remote_reason
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return reputation_result(self.name, str(ip), 'unsupported', None, details={**details, 'reason': 'invalid_ip'})
        if not is_public_global_ip(address) or address.version != 4:
            return reputation_result(self.name, address.compressed, 'unsupported', None,
                                     details={**details, 'reason': 'not_public' if not is_public_global_ip(address) else 'unsupported_address_family'})
        try:
            records, metadata = load_snapshot(self.directory)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return reputation_result(self.name, address.compressed, 'unavailable', None,
                                     details={**details, 'reason': 'snapshot_missing_or_invalid', 'usable_as_current_evidence': False})
        details.update(data_snapshot=metadata, stale=metadata['stale'], freshness=metadata['freshness'],
                       usable_as_current_evidence=metadata['freshness'] == 'current')
        if metadata['freshness'] != 'current':
            return reputation_result(self.name, address.compressed, 'unavailable', None,
                                     details={**details, 'reason': 'snapshot_stale' if metadata['stale'] else 'snapshot_timestamp_invalid'})
        sources = records.get(address.compressed, [])
        return reputation_result(self.name, address.compressed, 'listed' if sources else 'not_listed', bool(sources),
                                 source=','.join(sorted(sources)), details=details)
