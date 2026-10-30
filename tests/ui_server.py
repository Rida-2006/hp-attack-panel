"""Disposable loopback UI QA against the teammate's real Python deception source."""
import os
from pathlib import Path
import tempfile
import uvicorn
from tests.local_honeypot import running_honeypot, events


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as directory:
        log = Path(directory)/'honeypot.jsonl'
        faults = {'delay':1.5}
        with running_honeypot(log, faults=faults) as (target, _):
            os.environ['PANEL_DB_PATH'] = str(Path(directory)/'qa.sqlite3')
            os.environ['HONEYPOT_URL'] = f'http://127.0.0.1:{target.server_port}'
            os.environ['TEST_TARGET_URL'] = os.environ['HONEYPOT_URL']
            os.environ['TEST_REQUEST_TIMEOUT'] = '5'
            os.environ['HONEYPOT_NAME'] = 'Browser QA fixture'
            os.environ['PANEL_ORIGINS'] = 'http://127.0.0.1:5011'
            from backend import catalogue
            from backend.app import app
            catalogue.choose = lambda: catalogue.TRIPWIRES[0]
            @app.post('/qa/target/{mode}')
            async def fixture_target(mode: str):
                faults.clear()
                if mode == 'failure':
                    faults.update(delay=.3,status=503)
                elif mode == 'timeout':
                    faults['delay'] = 1
                else:
                    faults['delay'] = 3 if mode == 'slow' else 1.5
                os.environ['TEST_REQUEST_TIMEOUT'] = '.05' if mode == 'timeout' else '5'
                return {'mode':mode}
            @app.get('/qa/event/{attack_id}')
            async def fixture_event(attack_id: str):
                return [e for e in events(log) if e['http']['request']['headers'].get('X-Attack-ID') == attack_id]
            uvicorn.run(app,host='127.0.0.1',port=5011)
