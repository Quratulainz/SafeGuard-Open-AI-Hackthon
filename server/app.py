"""Local-only SafeGuard HTTP application; imports do not create files or listeners."""
import json
import os
import re
import secrets
import sqlite3
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ip_reputation import blackips_status, check_ip, load_optional_env_file
from investigation import investigate
from integrations import nightshift_status, zetaris_status
from investigation_memory import InvestigationMemory
from presentation import english_saved_result

ROOT = Path(__file__).resolve().parent
EXTENSION_ID = json.loads((ROOT / 'extension_identity.json').read_text(encoding='utf-8'))['extension_id']
if not re.fullmatch(r'[a-p]{32}', EXTENSION_ID):
    raise ValueError('Invalid bundled extension identity')
EXTENSION_ORIGIN = 'chrome-extension://' + EXTENSION_ID


class ApplicationState:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secret_file = self.data_dir / 'local-token.txt'
        self.db_path = self.data_dir / 'records.sqlite3'
        if not self.secret_file.exists():
            legacy = self.data_dir / 'pairing-key.txt'
            token = legacy.read_text(encoding='utf-8').strip() if legacy.exists() else secrets.token_urlsafe(30)
            self.secret_file.write_text(token, encoding='utf-8')
        try:
            os.chmod(self.secret_file, 0o600)
        except OSError:
            pass
        self.pairing_key = self.secret_file.read_text(encoding='utf-8').strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,128}', self.pairing_key):
            raise ValueError('The local pairing key file is invalid.')
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT, '
                       'name TEXT NOT NULL, domain TEXT, amount TEXT, currency TEXT, renewal TEXT NOT NULL, '
                       'frequency TEXT, created_at TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS investigations(id INTEGER PRIMARY KEY AUTOINCREMENT, '
                       'input TEXT, result TEXT, created_at TEXT NOT NULL)')
            columns = {row['name'] for row in db.execute('PRAGMA table_info(subscriptions)')}
            if 'cancel_on' not in columns:
                db.execute('ALTER TABLE subscriptions ADD COLUMN cancel_on TEXT')
            if 'long_term' not in columns:
                db.execute('ALTER TABLE subscriptions ADD COLUMN long_term INTEGER NOT NULL DEFAULT 0')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()


class SafeGuardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, state):
        self.state = state
        # Public-interface binding is deliberately not configurable.
        super().__init__(('127.0.0.1', port), App)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


class App(BaseHTTPRequestHandler):
    @property
    def state(self):
        return self.server.state

    @property
    def origin(self):
        return f'http://127.0.0.1:{self.server.server_port}'

    @property
    def local_origins(self):
        return {self.origin, f'http://localhost:{self.server.server_port}'}

    def log_message(self, _fmt, *_args):
        # Do not log request bodies, credentials, or URL query strings.
        pass

    def allowed_host(self):
        if self.headers.get('Host', '').lower() not in {
            f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'
        }:
            self.send_json({'error': 'Only the local application host is allowed'}, 403)
            return False
        return True

    def cors(self):
        origin = self.headers.get('Origin', '')
        if origin in self.local_origins or origin == EXTENSION_ORIGIN:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type,X-SafeGuard-Token,X-Pairing-Key')
            self.send_header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')

    def common_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')

    def send_json(self, data, status=200):
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.cors()
        self.common_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, page):
        raw = page.encode('utf-8')
        self.send_response(200)
        self.common_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        origin = self.headers.get('Origin', '')
        if origin and origin not in self.local_origins and origin != EXTENSION_ORIGIN:
            return False
        token = self.headers.get('X-SafeGuard-Token') or self.headers.get('X-Pairing-Key', '')
        return secrets.compare_digest(token.encode(), self.state.pairing_key.encode())

    def local_connection(self):
        # Browser-enforced Origin identifies the bundled extension. Ordinary
        # websites and unrelated installed extensions cannot read this token.
        if self.headers.get('Origin') != EXTENSION_ORIGIN:
            self.read_body()
            return self.send_json({'error': 'Only the installed SafeGuard extension can connect'}, 403)
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise ValueError('Use a JSON connection request')
        self.body()
        return self.send_json({'connected': True, 'token': self.state.pairing_key})

    def service_status(self):
        model = os.getenv('SAFEGUARD_ANALYSIS_MODE', 'rules').strip() == 'model'
        domain = os.getenv('SAFEGUARD_DOMAIN_PROVIDER', 'none').strip() == 'zetaris'
        memory = os.getenv('SAFEGUARD_MEMORY_MODE', 'local').strip() == 'hmem'
        return {
            'analysis': {'status': 'ready', 'mode': 'model' if model else 'rules',
                         'message': 'Model with evidence review' if model else 'Local evidence rules; no model required'},
            'zetaris': zetaris_status() if domain else {'status': 'disabled', 'message': 'Optional cloud data connection'},
            'nightshift': nightshift_status() if model else {'status': 'disabled', 'message': 'Optional model connection'},
            'hmem': InvestigationMemory(data_dir=self.state.data_dir / 'hmem').status() if memory else {
                'status': 'disabled', 'message': 'History is saved locally in SQLite'},
            'blackips': blackips_status(),
        }

    def read_body(self):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Transfer-Encoding is not supported')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('Invalid Content-Length') from None
        if length < 0 or length > 50000:
            raise ValueError('Request too large or invalid')
        return self.rfile.read(length)

    def body(self):
        try:
            payload = json.loads(self.read_body() or b'{}')
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError('Supply a valid JSON object') from None
        if not isinstance(payload, dict):
            raise ValueError('Supply a JSON object')
        return payload

    def do_OPTIONS(self):
        if not self.allowed_host():
            return
        self.send_response(204)
        self.cors()
        self.common_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if not self.allowed_host():
            return
        route = urllib.parse.urlsplit(self.path).path
        if route == '/':
            origin = self.headers.get('Origin', '')
            if ((origin and origin not in self.local_origins)
                    or self.headers.get('Sec-Fetch-Dest') in ('iframe', 'object', 'embed')
                    or (self.headers.get('Sec-Fetch-Site') == 'cross-site'
                        and self.headers.get('Sec-Fetch-Mode') != 'navigate')):
                return self.send_json({'error': 'Open SafeGuard directly on this computer'}, 403)
            page = (ROOT / 'dashboard.html').read_text(encoding='utf-8')
            return self.send_html(page.replace('%%PAIRING_KEY%%', self.state.pairing_key))
        if route == '/api/health':
            return self.send_json({'ok': True, 'mode': 'local evidence investigation',
                                   'integration_status_url': '/api/integrations/status'})
        if not self.authorized():
            return self.send_json({'error': 'Local connection required'}, 401)
        if route == '/api/integrations/blackips/status':
            return self.send_json(blackips_status())
        if route == '/api/integrations/status':
            return self.send_json(self.service_status())
        with self.state.connection() as db:
            if route == '/api/subscriptions':
                return self.send_json([dict(row, long_term=bool(row['long_term']))
                                       for row in db.execute('SELECT * FROM subscriptions ORDER BY renewal')])
            if route == '/api/investigations':
                return self.send_json([
                    {'id': row['id'], 'input': row['input'], 'result': english_saved_result(json.loads(row['result'])),
                     'created_at': row['created_at']}
                    for row in db.execute('SELECT * FROM investigations ORDER BY id DESC LIMIT 30')
                ])
        self.send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        if not self.allowed_host():
            return
        try:
            route = urllib.parse.urlsplit(self.path).path
            if route == '/api/local/connect':
                return self.local_connection()
            if not self.authorized():
                # Drain bounded request bytes before closing HTTP/1.0. Closing
                # over unread bytes can reset the socket on Windows and hide
                # the 401 needed by the extension's automatic reconnection.
                self.read_body()
                return self.send_json({'error': 'Local connection required'}, 401)
            data = self.body()
            if route == '/api/ip-check':
                ip = str(data.get('ip', '')).strip()
                if not ip:
                    raise ValueError('Supply an IP address')
                return self.send_json(check_ip(ip))
            if route == '/api/inspect':
                value = str(data.get('value', '')).strip()
                kind = data.get('kind')
                if not value or len(value) > 30000:
                    raise ValueError('Supply up to 30,000 characters')
                if kind not in ('url', 'message'):
                    raise ValueError('Investigation kind must be url or message')
                # Unsafe URLs are rejected; inspect_url retains evidence on network failure.
                result = investigate(kind, value, data_dir=self.state.data_dir, page_context=data.get('page_context'))
                with self.state.connection() as db:
                    db.execute('INSERT INTO investigations(input,result,created_at) VALUES(?,?,?)',
                               (value[:1000], json.dumps(result), datetime.now(timezone.utc).isoformat()))
                return self.send_json(result)
            if route == '/api/subscriptions':
                return self.add_subscription(data)
            if re.fullmatch(r'/api/subscriptions/[1-9][0-9]*', route):
                return self.update_subscription(int(route.rsplit('/', 1)[-1]), data)
            return self.send_json({'error': 'Not found'}, 404)
        except (ValueError, UnicodeDecodeError) as exc:
            return self.send_json({'error': str(exc)}, 400)
        except Exception:
            return self.send_json({'error': 'The local service could not complete this request'}, 500)

    def subscription_values(self, data):
        name = str(data.get('name', '')).strip()[:100]
        renewal = str(data.get('renewal', ''))
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', renewal):
            raise ValueError('Renewal date must use YYYY-MM-DD')
        datetime.strptime(renewal, '%Y-%m-%d')
        if not name:
            raise ValueError('Service name required')
        domain = str(data.get('domain', ''))[:200]
        if domain:
            parsed = urllib.parse.urlsplit(domain)
            if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError('Website must be an http(s) URL without embedded credentials')
        cancel_on = data.get('cancel_on')
        if cancel_on == '':
            cancel_on = None
        if cancel_on is not None:
            if not isinstance(cancel_on, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', cancel_on):
                raise ValueError('Planned cancellation date must use YYYY-MM-DD')
            datetime.strptime(cancel_on, '%Y-%m-%d')
        long_term = data.get('long_term', False)
        if not isinstance(long_term, bool):
            raise ValueError('Long-term subscription must be true or false')
        frequency = data.get('frequency', 'monthly')
        if frequency not in ('monthly', 'yearly', 'trial'):
            raise ValueError('Choose monthly, yearly or trial')
        return (name, domain, str(data.get('amount', ''))[:25], str(data.get('currency', 'MYR'))[:10],
                renewal, frequency, cancel_on, int(long_term))

    def add_subscription(self, data):
        values = self.subscription_values(data)
        with self.state.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT COUNT(*) FROM subscriptions').fetchone()[0] >= 5:
                return self.send_json({'error': 'Free demo limit: 5 monitored subscriptions.'}, 409)
            cursor = db.execute(
                'INSERT INTO subscriptions(name,domain,amount,currency,renewal,frequency,cancel_on,long_term,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                (*values, datetime.now(timezone.utc).isoformat()))
            subscription_id = cursor.lastrowid
        return self.send_json({'id': subscription_id, 'status': 'User supplied — not independently verified'}, 201)

    def update_subscription(self, subscription_id, data):
        with self.state.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM subscriptions WHERE id=?', (subscription_id,)).fetchone()
            if current is None:
                return self.send_json({'error': 'Subscription not found'}, 404)
            merged = dict(current, long_term=bool(current['long_term']))
            merged.update({key: value for key, value in data.items()
                           if key in {'name', 'domain', 'amount', 'currency', 'renewal', 'frequency', 'cancel_on', 'long_term'}})
            values = self.subscription_values(merged)
            db.execute('UPDATE subscriptions SET name=?,domain=?,amount=?,currency=?,renewal=?,frequency=?,cancel_on=?,long_term=? WHERE id=?',
                       (*values, subscription_id))
        return self.send_json({'id': subscription_id, 'updated': True})

    def do_DELETE(self):
        if not self.allowed_host():
            return
        if not self.authorized():
            return self.send_json({'error': 'Local connection required'}, 401)
        route = urllib.parse.urlsplit(self.path).path
        if route.startswith('/api/subscriptions/'):
            try:
                subscription_id = int(route.rsplit('/', 1)[-1])
            except ValueError:
                return self.send_json({'error': 'Invalid subscription id'}, 400)
            with self.state.connection() as db:
                db.execute('DELETE FROM subscriptions WHERE id=?', (subscription_id,))
            return self.send_json({'deleted': subscription_id})
        self.send_json({'error': 'Not found'}, 404)


def create_server(port=None, data_dir=None):
    load_optional_env_file(ROOT.parent / '.env')
    chosen_port = int(port if port is not None else os.environ.get('SAFEGUARD_PORT', '8765'))
    if not 0 <= chosen_port <= 65535:
        raise ValueError('SAFEGUARD_PORT must be between 0 and 65535')
    chosen_data_dir = data_dir or os.environ.get('SAFEGUARD_DATA_DIR') or ROOT / 'local-data'
    return SafeGuardServer(chosen_port, ApplicationState(chosen_data_dir))


def main():
    server = create_server()
    print(f'SafeGuard dashboard: http://127.0.0.1:{server.server_port}', flush=True)
    print('Local connection is automatic; no pairing code is needed.', flush=True)
    print('The service is accessible only on this computer. Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

