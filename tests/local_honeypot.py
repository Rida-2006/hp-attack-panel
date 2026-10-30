"""Loopback harness for the teammate's exact deception source, with explicit test-only faults."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from uuid import uuid4


def load_source():
    path = Path(__file__).parent / 'fixtures' / 'teammate_honeypot.py'
    spec = importlib.util.spec_from_file_location('hg_fixture_' + uuid4().hex, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def events(path):
    if not Path(path).exists():
        return []
    result = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # A concurrent writer may not yet have flushed its final line.
    return result


@contextmanager
def running_honeypot(log_path, port=0, faults=None):
    module = load_source()
    module.HOST = '127.0.0.1'
    module.SERVER_DOMAIN = 'localhost'
    module.LOG_PATH = str(Path(log_path).resolve())
    Path(module.LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    options = faults if faults is not None else {}
    class LocalHandler(module.Handler):
        def _handle_request(self, send_body):
            time.sleep(options.get('delay', 0))
            if options.get('status'):
                ingested = self._ingest()
                action = 'fixture:fault'
                session = module.update_session(ingested['sid'], ingested['cookie_present'], action, False)
                body = b'Explicit local test fixture fault\n'
                self._send(options['status'], 'text/plain', body, send_body, session)
                self._event(ingested, session, options['status'], body, action)
                return
            super()._handle_request(send_body)
        def _handle_options(self):
            time.sleep(options.get('delay', 0))
            super()._handle_options()
    server = module.HoneypotServer(('127.0.0.1', port), LocalHandler)
    module.PORT = server.server_port
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
    thread.start()
    try:
        yield server, module
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--log', default='tests/artifacts/honeypot-events.jsonl')
    args = parser.parse_args()
    with running_honeypot(args.log, args.port) as (server, _):
        print(f'Local Python deception sink: http://127.0.0.1:{server.server_port}', flush=True)
        print(f'Actual event log: {Path(args.log).resolve()}', flush=True)
        try:
            while True:
                time.sleep(.5)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
