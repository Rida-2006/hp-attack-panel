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


def validate_target():
    parts = urlsplit(HONEYPOT_BASE_URL)
    if parts.scheme not in ('http', 'https') or parts.hostname not in ALLOWED_TARGET_HOSTS:
        raise ValueError('HONEYPOT_URL must use HTTP(S) and a server-approved host')
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('HONEYPOT_URL must be an origin without credentials, path, query, or fragment')
    return HONEYPOT_BASE_URL
