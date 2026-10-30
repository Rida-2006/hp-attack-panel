import os
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent.parent
PAYLOADS_FILE = BASE_DIR / 'payloads.json'
FRONTEND_DIST_DIR = BASE_DIR / 'frontend' / 'dist'
DB_FILE = Path(os.getenv('PANEL_DB_PATH', str(BASE_DIR / 'data' / 'panel.sqlite3')))
HONEYPOT_BASE_URL = os.getenv('HONEYPOT_URL', 'http://127.0.0.1:8080').rstrip('/')
HONEYPOT_NAME = os.getenv('HONEYPOT_NAME', 'Local honeypot')
ALLOWED_TARGET_HOSTS = {h.strip().lower() for h in os.getenv('HONEYPOT_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1').split(',')}
ALLOWED_ORIGINS = {o.strip() for o in os.getenv('PANEL_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000,http://localhost:5173,http://127.0.0.1:5173').split(',')}


def tailscale_request(connection):
    """Trust Serve identity only through the configured loopback proxy host.

    Run Uvicorn with --no-proxy-headers and bind to loopback exclusively.
    """
    host = os.getenv('PANEL_TAILSCALE_HOST', '').strip().lower()
    return bool(host and connection.client.host in ('127.0.0.1', '::1', 'testclient')
                and connection.url.hostname == host
                and connection.headers.get('tailscale-user-login')
                and connection.headers.get('x-forwarded-proto') == 'https')


def validate_target():
    parts = urlsplit(HONEYPOT_BASE_URL)
    if parts.scheme not in ('http', 'https') or parts.hostname not in ALLOWED_TARGET_HOSTS:
        raise ValueError('HONEYPOT_URL must use HTTP(S) and a server-approved host')
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('HONEYPOT_URL must be an origin without credentials, path, query, or fragment')
    return HONEYPOT_BASE_URL


def test_target_url():
    """The harmless button may use a full endpoint; the payload library stays unchanged."""
    url = os.getenv('TEST_TARGET_URL', HONEYPOT_BASE_URL).strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError('TEST_TARGET_URL has an invalid host or port') from exc
    if parts.scheme not in ('http', 'https') or parts.hostname not in ALLOWED_TARGET_HOSTS:
        raise ValueError('TEST_TARGET_URL must use HTTP(S) and a host in HONEYPOT_ALLOWED_HOSTS')
    if parts.username or parts.password or parts.fragment:
        raise ValueError('TEST_TARGET_URL must not contain credentials or a fragment')
    return url


def request_timeout():
    try:
        value = float(os.getenv('TEST_REQUEST_TIMEOUT', '10'))
    except ValueError as exc:
        raise ValueError('TEST_REQUEST_TIMEOUT must be a number between 0 and 60 seconds') from exc
    if not 0 < value <= 60:
        raise ValueError('TEST_REQUEST_TIMEOUT must be greater than 0 and at most 60 seconds')
    return value
