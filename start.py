"""Portable local launcher. Uses only Python's standard library."""
import sys

if sys.version_info < (3, 10):
    print('SafeGuard needs Python 3.10 or newer. Install a supported Python release from https://www.python.org/downloads/.')
    raise SystemExit(1)

import argparse
import json
import os
from pathlib import Path
import threading
import webbrowser

PROJECT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description='Start SafeGuard on this computer. No cloud account or pairing code is needed.')
    parser.add_argument('--check', action='store_true', help='Check local prerequisites without creating data or starting a server.')
    parser.add_argument('--no-browser', action='store_true', help='Start without opening the dashboard automatically.')
    args = parser.parse_args()
    os.chdir(PROJECT)
    sys.path.insert(0, str(PROJECT / 'server'))
    try:
        import sqlite3
        import ssl
    except ImportError:
        print('This Python installation is missing SQLite or SSL support. Install a complete supported Python distribution and try again.')
        return 1
    try:
        import app
        ssl.create_default_context()
        with sqlite3.connect(':memory:') as connection:
            connection.execute('SELECT 1').fetchone()
        identity = json.loads((PROJECT / 'server/extension_identity.json').read_text(encoding='utf-8'))
        manifest = json.loads((PROJECT / 'extension/manifest.json').read_text(encoding='utf-8'))
        if not identity.get('extension_id') or not manifest.get('key'):
            raise ValueError('The extension identity is missing. Extract the complete package again.')
        if args.check:
            print('Ready: Python, SQLite, HTTPS support, application files and extension identity are available.')
            print('The default app needs no pip packages, Node.js, Codex, Docker, cloud account or model.')
            print('This local check does not test Internet access or optional cloud services.')
            return 0
        server = app.create_server()
    except (OSError, ValueError, ImportError, sqlite3.Error) as error:
        if isinstance(error, OSError) and (getattr(error, 'winerror', None) in (10013, 10048) or getattr(error, 'errno', None) in (48, 98, 10048)):
            port = os.environ.get('SAFEGUARD_PORT') or '8765'
            print('The SafeGuard port is already in use or reserved by another application. Close the other copy, or open http://127.0.0.1:' + port + ' if it is already running.')
        elif isinstance(error, PermissionError):
            print('SafeGuard cannot write its data. Extract the package into a folder you can edit and start it again.')
        else:
            print('SafeGuard could not start (' + type(error).__name__ + '). Check the complete extracted package and docs/PORTABILITY.md.')
        return 1
    url = 'http://127.0.0.1:' + str(server.server_port)
    print('SafeGuard dashboard: ' + url, flush=True)
    print('Local connection is automatic. Keep this window open while using the app; Ctrl+C stops it.', flush=True)
    if server.server_port != 8765:
        print('The bundled extension requires port 8765. This alternate port serves only the dashboard.', flush=True)
    if not args.no_browser:
        def show_dashboard():
            try:
                webbrowser.open(url)
            except Exception:
                print('Open the dashboard URL above in your browser.', flush=True)
        threading.Thread(target=show_dashboard, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
