#!/usr/bin/env python3
"""Download/hash-check private IP snapshots, or import an existing pinned directory.

No SMS, emails, identities, credentials, Redis, or cloud access. Redistribution
rights are not cleared; keep downloaded files out of public releases.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from offline_snapshot import FEED_NAMES, REPOSITORY, MAX_FILE_BYTES, load_snapshot, snapshot_directory, current_folder


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'SafeGuard-Private-Snapshot-Sync/1.0'})
    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise ValueError('Snapshot file exceeds download limit')
    return content


def sync(destination, source=None):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.pending-', dir=destination) as pending:
        stage = Path(pending)
        if source is not None:
            source = current_folder(source)
            for name in ('manifest.json',) + FEED_NAMES:
                if (source / name).stat().st_size > MAX_FILE_BYTES:
                    raise ValueError('Snapshot file exceeds size limit')
                shutil.copyfile(source / name, stage / name)
        else:
            commit = json.loads(download('https://api.github.com/repos/njcx/blackip_list/commits/master'))['sha']
            if not re.fullmatch('[0-9a-f]{40}', commit):
                raise ValueError('Invalid source commit')
            manifest = {'repository': REPOSITORY, 'commit': commit, 'feeds': []}
            for name in FEED_NAMES:
                url = f'https://raw.githubusercontent.com/njcx/blackip_list/{commit}/{name}'
                raw = download(url)
                (stage / name).write_bytes(raw)
                manifest['feeds'].append({'name': name, 'url': url, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        _, metadata = load_snapshot(stage)
        if source is None and metadata['freshness'] != 'current':
            raise ValueError('Downloaded source is expired or future-dated; previous snapshot retained')
        name = metadata['commit'] + '-' + secrets.token_hex(6)
        snapshots = destination / 'snapshots'
        snapshots.mkdir(exist_ok=True)
        final = snapshots / name
        # Copy validated bytes into a new immutable directory. Only the atomic
        # pointer replacement publishes it; failures leave the old pointer intact.
        shutil.copytree(stage, final)
        pointer = destination / ('.pointer-' + secrets.token_hex(6) + '.json')
        pointer.write_text(json.dumps({'directory': name}), encoding='utf-8')
        pointer.replace(destination / 'current.json')
    report = {**metadata, 'synced_at': datetime.now(timezone.utc).isoformat(),
              'private_only': True, 'redistribution': 'not_cleared',
              'note': 'Sync time does not refresh source age. Do not publish downloaded feed files.'}
    (destination / 'sync-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=snapshot_directory())
    parser.add_argument('--from-dir', type=Path, help='Import existing pinned files without network; original timestamps are retained')
    args = parser.parse_args()
    try:
        print(json.dumps(sync(args.destination, args.from_dir), indent=2))
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit('Snapshot sync failed; active pointer unchanged unless validated publication already completed. ' + type(error).__name__) from None
