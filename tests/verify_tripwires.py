"""Run every catalogue case on the supplied source; save real event evidence locally only."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import tempfile
import time
from tests.local_honeypot import running_honeypot, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='tests/artifacts/tripwire-report.json')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    log = output.with_name('verified-honeypot-events.jsonl')
    # Unique log for this run; do not mix earlier evidence into the report.
    log.write_text('', encoding='utf-8')
    with tempfile.TemporaryDirectory() as directory, running_honeypot(log) as (server, _):
        os.environ.update(HONEYPOT_URL=f'http://127.0.0.1:{server.server_port}',
                          TEST_TARGET_URL=f'http://127.0.0.1:{server.server_port}',
                          HONEYPOT_ALLOWED_HOSTS='127.0.0.1', TEST_REQUEST_TIMEOUT='10',
                          PANEL_DB_PATH=str(Path(directory)/'panel.sqlite3'))
        from backend import catalogue, execution
        async def verify():
            report = []
            for definition in catalogue.TRIPWIRES:
                record = await execution.execute_catalogue(definition['id'], source='local-verification')
                deadline = time.monotonic()+2
                matches = []
                while time.monotonic()<deadline:
                    matches = [event for event in events(log) if event['http']['request']['headers'].get('X-Attack-ID') == record['attack_id']]
                    if matches:
                        break
                    await asyncio.sleep(.01)
                observed = matches[0]['sensor']['action'] if len(matches)==1 else None
                passed = record['outcome']=='SUCCESS' and observed==definition['expected_sensor_action']
                report.append({'test_id':definition['id'],'cve_id':definition['cve_id'],'attack_id':record['attack_id'],
                               'timestamp':record['timestamp'],'request_url':record['target_url'],'http_status':record['http_status'],
                               'response_validation':record['validation_result'],'expected_action':definition['expected_sensor_action'],
                               'observed_local_action':observed,'passed':passed,'elasticsearch_verified':False})
                print(f"{'PASS' if passed else 'FAIL'} {definition['id']} {record['attack_id']} {observed}",flush=True)
                await asyncio.sleep(1.05)
            output.write_text(json.dumps({'scope':'local provided Python source only','event_log':str(log),
                                         'passed':sum(item['passed'] for item in report),'total':len(report),'cases':report},indent=2),encoding='utf-8')
            if not all(item['passed'] for item in report):
                raise SystemExit('Tripwire verification failed; inspect '+str(output))
        asyncio.run(verify())
    print('Evidence report: '+str(output),flush=True)


if __name__ == '__main__':
    main()
