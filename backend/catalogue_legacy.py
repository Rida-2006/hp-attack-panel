"""Server-owned, harmless CVE validation modules. Never import the reference exploit."""
import random
from urllib.parse import urlsplit, urlunsplit
from copy import deepcopy

VERSIONS = {'8.2': '<8.2.35', '8.3': '<8.3.36', '8.4': '<8.4.27', '8.5': '<8.5.12'}
TESTS = [
    {
        'id': 'php-oom-http-validation', 'cve_id': 'CVE-2026-109618',
        'name': 'PHP OOM context HTTP validation',
        'vulnerability_name': 'RCE via OOM corruption',
        'description': 'One small form POST validates request visibility and response handling. Does not exhaust memory or test exploitation.',
        'affected_technology': 'PHP', 'affected_versions': VERSIONS,
        'test_type': 'harmless-http-validation', 'enabled': False,
        'expected_detection_indicators': ['X-Attack-ID', 'X-HoneyGuard-CVE', 'X-HoneyGuard-Test', 'content=Honeyguard harmless POST test'],
        'applicability': 'Unknown: PHP runtime, version and configuration must be verified by the honeypot owner.',
        'source': 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
        'module': 'form_marker',
    },
    {
        'id': 'php-stale-state-http-validation', 'cve_id': 'CVE-2026-109619',
        'name': 'PHP stale-state HTTP validation',
        'vulnerability_name': 'RCE via stale global state',
        'description': 'One small form POST checks telemetry plumbing only. Does not manipulate global state, sessions, or memory.',
        'affected_technology': 'PHP', 'affected_versions': VERSIONS,
        'test_type': 'harmless-http-validation', 'enabled': False,
        'expected_detection_indicators': ['X-Attack-ID', 'X-HoneyGuard-CVE', 'X-HoneyGuard-Test', 'content=Honeyguard harmless POST test'],
        'applicability': 'Unknown: an HTTP response cannot establish vulnerability or detection.',
        'source': 'https://cveawg.mitre.org/api/cve/CVE-2026-109619',
        'module': 'form_marker',
    },
]


def form_marker(entry, url):
    from urllib.parse import urlsplit
    return {'id': entry['id'], 'name': entry['name'], 'category': 'cve-validation',
            'method': 'POST', 'path': urlsplit(url).path or '/',
            'headers': {'X-HoneyGuard-CVE': entry['cve_id'], 'X-HoneyGuard-Test': entry['id'], 'X-HoneyGuard-Test-Type': entry['test_type']},
            'form': {'content': 'Honeyguard harmless POST test'}, 'catalogue': deepcopy(entry)}


# Only fixed non-destructive probe builders are enabled for Random Attack.
for cve, versions, encoding in (
    ('CVE-2021-41773', ['2.4.49'], '.%2e'),
    ('CVE-2021-42013', ['2.4.49', '2.4.50'], '.%%32%65'),
):
    TESTS.append({
        'id': 'apache-' + cve.lower() + '-canary', 'cve_id': cve,
        'name': 'Apache encoded traversal canary (' + cve + ')',
        'vulnerability_name': 'Apache HTTP Server path normalization traversal',
        'description': 'One GET using the CVE-associated encoded traversal pattern, requesting only a random nonexistent canary file. No sensitive-file read, CGI command or request body.',
        'affected_technology': 'Apache HTTP Server', 'affected_versions': versions,
        'test_type': 'non-destructive-security-probe', 'enabled': True,
        'expected_detection_indicators': [encoding, '/cgi-bin/', 'honeyguard-canary-', 'hg_attack_id', 'X-Attack-ID'],
        'applicability': 'Unknown: requires the affected Apache version and vulnerable alias/directory configuration. A response or logged probe cannot prove vulnerability.',
        'source': 'https://httpd.apache.org/security/vulnerabilities_24.html#' + cve,
        'module': 'apache_canary', 'encoding': encoding,
    })


def apache_canary(entry, url):
    parts = urlsplit(url)
    path = '/cgi-bin/' + (entry['encoding'] + '/') * 3 + 'honeyguard-canary-{attack_id}.txt'
    payload = form_marker(entry, url)
    payload.update(method='GET', path=path, category='path-traversal',
                   request_url=urlunsplit((parts.scheme, parts.netloc, path, parts.query, '')))
    payload.pop('form')
    return payload


MODULES = {'form_marker': form_marker, 'apache_canary': apache_canary}


def choose():
    enabled = [entry for entry in TESTS if entry['enabled'] and entry['module'] in MODULES]
    if not enabled:
        from fastapi import HTTPException
        raise HTTPException(409, 'No CVE validation tests are enabled')
    return random.choice(enabled)


def definitions(records):
    result = []
    for entry in TESTS:
        latest = next((r for r in records if r['payload_id'] == entry['id']), None)
        result.append({**deepcopy(entry), 'execution_status': latest['status'] if latest else 'not_run'})
    return result
