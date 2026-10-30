"""Authorized loopback mock target for manual and automated HTTP integration tests."""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class MockTarget(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/cgi-bin/'):
            return self.do_POST()
        self.respond(200, {'message': 'Local mock HTTP server is running', 'method': 'GET'})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode('utf-8')
        path = urlsplit(self.path).path
        form = parse_qs(raw)
        payload = {
            'message': 'Local mock server received the harmless POST.',
            'method': self.command, 'path': self.path,
            'content_type': self.headers.get('Content-Type'),
            'form': form, 'attack_id': self.headers.get('X-Attack-ID'),
            'literal_text': '<script>window.mockResponseExecuted = true</script>',
            'unicode': 'Actual response: café / ✓',
        }
        query = parse_qs(urlsplit(self.path).query)
        if path == '/large' or query.get('qa_large') == ['1']:
            payload['large_body'] = 'FULL_RESPONSE_START\n' + 'Original server text. ' * 600 + '\nFULL_RESPONSE_END'
        body = json.dumps(payload, ensure_ascii=False, indent=2)
        if hasattr(self.server, 'received'):
            self.server.received.append({'method': self.command, 'path': self.path, 'form': form, 'raw': raw, 'headers': dict(self.headers), 'response_body': body})
        delay = parse_qs(urlsplit(self.path).query).get('delay', ['.5' if path == '/slow' else '0'])[0]
        time.sleep(min(3, max(0, float(delay))))
        self.respond(int(query.get('qa_status', ['503' if path == '/status/503' else '200'])[0]), body)

    def respond(self, status, body):
        if not isinstance(body, str):
            body = json.dumps(body)
        encoded = body.encode('utf-8')
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # Expected when a timeout test disconnects before the slow response.

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), MockTarget)
    print(f'Local mock target: http://127.0.0.1:{server.server_port}/echo', flush=True)
    print('Other test endpoints: /large, /slow, /status/503', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
