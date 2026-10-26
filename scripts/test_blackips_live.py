#!/usr/bin/env python3
"""Live BlackIPS check. Not collected by unittest discover."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))

from ip_reputation import (  # noqa: E402
    check_ip,
    is_public_global_ip,
    load_optional_env_file,
    parse_ip,
    configured_base_url,
)


def main(argv):
    load_optional_env_file(ROOT / '.env')
    if len(argv) != 2 or argv[1] in ('-h', '--help'):
        print('Usage: python scripts/test_blackips_live.py <PUBLIC_IP>', file=sys.stderr)
        return 2
    raw = argv[1].strip()
    try:
        addr = parse_ip(raw)
    except ValueError as ex:
        print(f'Invalid IP: {ex}', file=sys.stderr)
        return 2
    if not is_public_global_ip(addr):
        print('Refused: only public/global IP addresses may be sent to BlackIPS.', file=sys.stderr)
        return 2
    base = configured_base_url()
    if not base:
        print('BLACKIPS_BASE_URL is not configured.', file=sys.stderr)
        return 1
    result = check_ip(addr.compressed)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    status = result.get('status')
    if status == 'listed':
        print('Result: listed (external evidence only; not proof the site is malicious).')
        return 0
    if status == 'not_listed':
        print('Result: not listed (a miss is valid and is not a connection failure).')
        return 0
    print('BlackIPS connection or configuration failed.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
