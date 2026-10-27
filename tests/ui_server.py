"""Disposable loopback-only browser QA environment; not a real honeypot."""
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import uvicorn


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Local test fixture response')

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.do_GET()

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as directory:
        os.environ['PANEL_DB_PATH'] = str(Path(directory) / 'qa.sqlite3')
        os.environ['HONEYPOT_URL'] = 'http://127.0.0.1:8099'
        os.environ['HONEYPOT_NAME'] = 'Browser QA fixture'
        os.environ['PANEL_ORIGINS'] = 'http://127.0.0.1:5011'
        target = ThreadingHTTPServer(('127.0.0.1', 8099), Target)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            uvicorn.run('backend.app:app', host='127.0.0.1', port=5011)
        finally:
            target.shutdown()
