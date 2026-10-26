"""Prepare a separately obtained Zetaris bundle; default is a read-only plan.

Only for first initialization. Refuses existing Zetaris containers or volumes.
No registry authentication, downloads, Docker startup, or cloud resources.
"""
import argparse
import json
from pathlib import Path
import secrets
import string
import subprocess

PROJECT = Path(__file__).resolve().parents[2]


def prepare(bundle, private_dir, *, apply=False, fresh_confirmed=False):
    bundle = Path(bundle).resolve()
    private_dir = Path(private_dir).resolve()
    if bundle.is_relative_to(PROJECT) or private_dir.is_relative_to(PROJECT):
        raise ValueError('Keep licensed bundles and private credentials outside this source tree.')
    env_path = bundle / '.env'
    compose = (bundle / 'docker-compose.yml').read_text(encoding='utf-8')
    original = env_path.read_text(encoding='utf-8')
    if 'name: zetaris' not in compose or '"${UI_PORT:-3000}:3000"' not in compose:
        raise ValueError('Bundle differs from the reviewed Compose contract; review it manually.')
    auth_path = private_dir / 'runtime-auth.json'
    if auth_path.exists():
        raise ValueError('Existing private credentials found; this is not a credential-rotation tool.')
    if not apply:
        return {'mode': 'read_only', 'services_started': False,
                'plan': 'Fresh private administrator/DB passwords; loopback UI; 2-core/2g Spark and 1g API; TLS profile disabled.'}
    if not fresh_confirmed:
        raise ValueError('Applying requires --fresh-install-confirmed; never use on an initialized database.')
    # Even exited containers or retained volumes indicate a previous installation.
    for command in (
        ['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=zetaris'],
        ['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=zetaris'],
    ):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode or result.stdout.strip():
            raise ValueError('Cannot establish a fresh Zetaris installation; stop without changing configuration.')
    alphabet = string.ascii_letters + string.digits
    auth = {'username': 'demo-admin@example.invalid',
            'password': 'Aa1!' + ''.join(secrets.choice(alphabet) for _ in range(40)),
            'postgres_password': ''.join(secrets.choice(alphabet) for _ in range(40))}
    overrides = {
        'UI_PORT': '127.0.0.1:3000', 'ZETARIS_ADMIN_EMAIL': auth['username'],
        'ZETARIS_ADMIN_PASSWORD': auth['password'], 'POSTGRES_PASSWORD': auth['postgres_password'],
        'TELEMETRY_ENABLED': 'false', 'ZSPARK_MASTER_URL': 'local[2]',
        'ZSPARK_DRIVER_MEM': '2g', 'ZSPARK_DRIVER_CORES': '2', 'ZETARIS_API_MAX_HEAP': '1g',
    }
    lines = [line for line in original.splitlines()
             if line.partition('=')[0].strip() not in overrides
             and line.partition('=')[0].strip() != 'COMPOSE_PROFILES']
    lines.extend(f'{key}={value}' for key, value in overrides.items())
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Credentials are recoverable privately if writing the bundle fails.
    with auth_path.open('x', encoding='utf-8') as target:
        auth_path.chmod(0o600)
        json.dump(auth, target)
    env_path.chmod(0o600)
    env_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return {'mode': 'configured', 'services_started': False,
            'credentials': 'Saved only in the supplied private directory; not printed.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--private-dir', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--fresh-install-confirmed', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.bundle, args.private_dir, apply=args.apply,
                                 fresh_confirmed=args.fresh_install_confirmed), indent=2))
    except (OSError, ValueError) as error:
        raise SystemExit('Configuration stopped: ' + str(error)) from None
