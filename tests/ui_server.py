"""Disposable loopback-only browser QA environment; not a real honeypot."""
import os
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
import uvicorn
from tests.mock_http_server import MockTarget


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as directory:
        os.environ['PANEL_DB_PATH'] = str(Path(directory) / 'qa.sqlite3')
        os.environ['HONEYPOT_URL'] = 'http://127.0.0.1:8099'
        os.environ['TEST_TARGET_URL'] = 'http://127.0.0.1:8099/large'
        os.environ['TEST_REQUEST_TIMEOUT'] = '3'
        os.environ['HONEYPOT_NAME'] = 'Browser QA fixture'
        os.environ['PANEL_ORIGINS'] = 'http://127.0.0.1:5011'
        target = ThreadingHTTPServer(('127.0.0.1', 8099), MockTarget)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            uvicorn.run('backend.app:app', host='127.0.0.1', port=5011)
        finally:
            target.shutdown()
