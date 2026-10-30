# HoneyGuard catalogue and honeypot integration

## Implemented behavior

Random selects one of **22 enabled fixed tests** designed for the actual Python deception source supplied in `instruction.md`. It sends one real HTTP request to the configured, allowlisted origin and streams genuine timestamped selection/request/response/completion events. Only the correlation ID is appended to the query; test metadata is kept in headers so it cannot accidentally influence `decide()` regex matching.

The UI preserves the gold lightning control and black/gold/red theme, then expands into equal left controls/right terminal panes. It displays the actual target URL, test name, optional CVE ID, correlation ID, HTTP code, body excerpt, duration and SUCCESS/FAILED/TIMEOUT. The terminal scrolls automatically, is vertically resizable and stacks on mobile. Custom Shell and its existing commands remain; `list tests` and `test <tripwire ID>` are additional approved commands.

SUCCESS means the actual response matched the definition's HTTP status, content type and exact/contained body text. It does **not** mean a real CVE was exploited or Elasticsearch received an event. A deliberately missing route succeeds when its expected 404/body matches. A wrong body with HTTP 200 fails. Timeouts produce TIMEOUT, while network failures and mismatches produce FAILED. The lock is released in `finally`.

Every event has `X-Attack-ID` and `hg_attack_id` correlation. Expected `sensor.action` is labelled **expected**. The interface retains `detection_status=unverified` / `sensor_action_verified=false` unless independent log evidence is provided; no detector result is invented.

## Catalogue

| ID | Name | Mapping | Method | Expected sensor.action | Expected HTTP |
| --- | --- | --- | --- | --- | --- |
| tw-01-cgi-argument | PHP CGI argument-check simulation | CVE-2024-4577 | POST | lure:phpcgi_arg_check | 200 |
| tw-02-config | Configuration exposure lure | Generic tripwire | GET | lure:config_canary | 200 |
| tw-03-information | PHP information lure | Generic tripwire | GET | lure:phpinfo | 200 |
| tw-04-math | Arithmetic recognition | Generic tripwire | POST | primitive:math_verify | 200 |
| tw-05-digest | MD5 recognition | Generic tripwire | POST | primitive:md5_verify | 200 |
| tw-06-echo | Echo marker recognition | Generic tripwire | POST | primitive:echo_verify | 200 |
| tw-07-identity | Identity pattern recognition | Generic tripwire | POST | primitive:id | 200 |
| tw-08-user | Username pattern recognition | Generic tripwire | POST | primitive:whoami | 200 |
| tw-09-system | System-name pattern recognition | Generic tripwire | POST | primitive:uname | 200 |
| tw-10-file | Simulated passwd file-access recognition | Generic tripwire | POST | primitive:passwd | 200 |
| tw-11-directory | Directory pattern recognition | Generic tripwire | POST | primitive:fs_recon | 200 |
| tw-12-downloader | Inert downloader-string recognition | Generic tripwire | POST | primitive:stage2_dropper | 200 |
| tw-13-upload | Multipart session-progress lure | Generic tripwire | POST | lure:multipart_progress | 200 |
| tw-14-stream | PHP stream-wrapper recognition | Generic tripwire | POST | lure:php_stream | 200 |
| tw-15-token | Synthetic canary-token replay | Generic tripwire | GET | lure:canary_replay | 200 |
| tw-16-source | CGI source-disclosure lure | Generic tripwire | GET | lure:phpcgi_src_disclosure | 200 |
| tw-17-robots | Robots route validation | Generic tripwire | GET | route:robots | 200 |
| tw-18-portal | Portal route validation | Generic tripwire | GET | route:portal | 200 |
| tw-19-missing | Missing route validation | Generic tripwire | GET | route:not_found | 404 |
| tw-20-options | OPTIONS route validation | Generic tripwire | OPTIONS | route:options | 200 |

The CGI check is a **CVE-2024-4577-style simulated check**, not a real PHP exploit. The genuine CVE concerns Windows PHP-CGI and code-page best-fit argument handling; the target supplied here is Python. Primary reference: https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv . Nineteen entries have `cve_id=null`. Two additional 2026-associated traffic checks are explicitly limited to generic multipart coverage, as described below. The old PHP memory-corruption and Apache traversal definitions remain archived and disabled; they are not supported tripwires for this sink.

`backend/catalogue.py` contains serializable fixed definitions and a module registry. Each active entry includes unique `id`, `cve_id` or null, name/description, method/path/headers/body, timeout, expected sensor action, expected status/content type/body rules and correlation policy. A fresh `attack_id`/`correlation_id` is generated on every execution and replay. `GET /api/catalogue` adds the latest execution status.

Routes:
- `POST /api/attacks/random`: randomly select one enabled entry.
- `POST /api/catalogue/{test_id}/execute`: execute one fixed entry, without accepting arbitrary payloads or targets.
- `POST /api/attacks/{attack_id}/replay`: replay a catalogue test with a new ID, including generic tripwires.
- `GET /api/execution/status`: authoritative active execution state.
- `POST /api/attacks/connectivity`: retained simple form-POST transport check; not part of Random.
- Existing payload/console/history/WebSocket/legacy routes are preserved.

## Condition order and controlled inputs

The source checks canary replay before source/config/info lures, math/MD5/echo before command/file patterns, then downloader, multipart, CGI argument and PHP stream patterns, then routes. OPTIONS has its own handler. The catalogue isolates each intended branch and tests the actual emitted event, not a reimplementation of `decide()`.

The CGI check uses encoded option-like query data and an empty body; no PHP program is uploaded. `whoami`, `/etc/passwd`, `curl https://example.invalid/...` and similar strings are inert request data for this known Python simulator. The source returns canned data; neither panel nor source invokes a shell or fetches the URL. Multipart is a tiny inert text upload. Canary replay uses only the synthetic token supplied in the fixture, never a real credential. Do not point this simulator-specific suite at unrelated or unknown applications.

## Exact local startup (PowerShell / VS Code)

One-time setup if dependencies are missing:

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel'
python -m pip install -r requirements.txt
Push-Location frontend
npm install
Pop-Location
```

Terminal 1: the teammate's supplied deception code on loopback, with a writable local event log:

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel'
python -m tests.local_honeypot --port 8080
```

Terminal 2: FastAPI backend:

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel'
$env:HONEYPOT_URL = 'http://127.0.0.1:8080'
$env:TEST_TARGET_URL = 'http://127.0.0.1:8080'
$env:HONEYPOT_ALLOWED_HOSTS = 'localhost,127.0.0.1,::1'
$env:HONEYPOT_NAME = 'Local Python deception sink'
$env:TEST_REQUEST_TIMEOUT = '10'
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

Terminal 3: frontend build/development server:

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel\frontend'
npm run build
npm run dev
```

Open http://127.0.0.1:5173 and click Random once. Alternatively open http://127.0.0.1:5000 after `npm run build` (no dev server required). Keep both Python processes running. Source files need not be run individually in VS Code. Environment changes require a backend restart; `.env.example` is a reference, not auto-loaded.

For the remote authorized sink, set the URL variables and allowlist in the same backend terminal to the origin supplied by its owner. There is no public honeypot address in production code or default configuration. Fixed tripwire paths/queries are built on that origin; a path in TEST_TARGET_URL does not restrict all tests to that endpoint.

## Environment variables

| Variable | Purpose / default |
| --- | --- |
| HONEYPOT_URL | Base HTTP(S) origin for existing approved commands; default http://127.0.0.1:8080 |
| TEST_TARGET_URL | Origin used for fixed tripwire routes; falls back to HONEYPOT_URL. Connectivity uses the exact endpoint. Existing extra query data is not inherited by tripwires. |
| HONEYPOT_ALLOWED_HOSTS | Exact comma-separated hostname/IP allowlist; default localhost,127.0.0.1,::1 |
| TEST_REQUEST_TIMEOUT | Overall request deadline, greater than 0 and at most 60 seconds; default 10. Effective test deadline is the smaller of this and the catalogue entry timeout (10). |
| HONEYPOT_NAME | Display name |
| PANEL_ORIGINS | Browser/WebSocket allowlist; existing localhost/127.0.0.1 ports 5000 and 5173 defaults |
| PANEL_DB_PATH | Existing bounded operational SQLite store; default data/panel.sqlite3 |
| VITE_DEMO_MODE | Frontend build-time option; must be unset/false for genuine HTTP requests |

## Concurrency and recovery

The frontend disables Random immediately, guards rapid submissions and consults backend state on load and every 1.5 seconds. WebSocket reconnect and HTTP event backfill recover output/state after interruptions. The backend uses a process lock plus atomic SQLite lease across all execution paths and processes sharing that DB. Competing calls return HTTP 429 without target traffic. The existing one-second minimum launch interval remains. Requests have an overall deadline; slow WebSocket clients have bounded concurrent sends. Cancellation releases the lease. A hard-crash lease expires conservatively after request timeout + 30 seconds, then orphaned state becomes interrupted. Startup recovery is transactional and does not invalidate another process's live lease. Use one Uvicorn worker for immediate WebSocket fanout; separate database files/installations cannot share a lock.

## Verification and evidence

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel'
python -m unittest discover -s tests -v
python -m tests.verify_tripwires
```

The full suite has **52 tests**, including 22 individually named cases that use real HTTP against the exact supplied source and assert the actual JSONL `sensor.action`. It also checks precedence, unique IDs, canary issue/replay session flags, response mismatch despite HTTP 200, random selection, WebSocket frames, replay, target allowlists, concurrent clients/routes, timeout/error recovery, retained POST transport behavior and Custom Shell.

The verification command starts its own loopback source instance and writes `tests/artifacts/tripwire-report.json` plus `verified-honeypot-events.jsonl`. It does not connect to a public target. All artefact paths are ignored by Git. The report distinguishes observed local actions from unverified Elasticsearch ingestion.

Browser QA: run `python -m tests.ui_server`, then `node tests/browser_smoke.cjs` with Playwright available (`PLAYWRIGHT_MODULE` can point to an installed package). It uses the same source and checks the CGI response and actual action, split transition, desktop/mobile, rapid clicks, shell commands, failure/timeout, WebSocket reconnect, refresh and second-client recovery. `/qa/*` routes and fault injection exist only in this disposable test process, not the production app.

The fixture Python code block was copied verbatim from `instruction.md`; its hash/provenance is recorded in `tests/fixtures/README.md`. The harness overrides only binding/configuration at runtime, keeps the original detection logic, and adds explicit test-only fault injection. Never run the fixture source directly with its original public-binding/Linux-log constants.

## Files created and modified

Created for this integration:
- backend/catalogue_legacy.py — previous definitions preserved as disabled history.
- tests/fixtures/teammate_honeypot.py and README.md — supplied source and provenance.
- tests/local_honeypot.py — loopback harness / local event log.
- tests/verify_tripwires.py — repeatable per-case evidence report.

Updated:
- backend/catalogue.py — 20 simulator-specific definitions, builders, response matcher.
- backend/execution.py — exact raw queries, correlation, deadline, genuine validation/outcomes and response excerpts.
- backend/api.py — deterministic catalogue route, generic replay and approved console additions.
- frontend/src/App.jsx — tripwire labels, expected action and validation outcome.
- tests/test_catalogue.py — source-backed integration and action/precedence assertions.
- tests/ui_server.py, tests/browser_smoke.cjs — source-backed UI regression checks.
- .env.example, README.md, docs/MVP.md, docs/DETECTION.md — current setup and handoff.

Existing working changes to backend/app.py, storage.py, ws.py, usePanel.js, styles/index.css and the transport fixtures were preserved. Local frontend/dist was rebuilt; no new dependencies or repositories were created.

## Remaining integration

Local response/action verification does not verify the deployed source revision, reverse-proxy routing or Elasticsearch ingestion. Follow docs/DETECTION.md with Gurpratap's actual data view/field mapping and a newly displayed attack ID. No Elasticsearch dashboard, persistent SIEM store or live detection acknowledgement is implemented here. No push, merge or deployment was performed.

## Completed local checks

- Frontend production build passed (Vite, 35 modules).
- Backend suite: 52 tests passed.
- Repeatable per-case evidence run: The initial 20/20 evidence run is retained; the expanded 22-case suite passes, including both new multipart event checks..
- Edge browser checks passed: CGI response/action correlation, split transition and equal panes, safe HTML-as-text rendering, responsive layout, rapid-click rejection, Custom Shell, failure/timeout, WebSocket recovery, refresh and second-client protection.
- Desktop/mobile screenshots are saved under ignored tests/artifacts and visually inspected.
- FastAPI QA server startup and git diff --check passed.
- Elasticsearch ingestion/alerts and this new catalogue against a deployed source revision were not verified.

## 2026-associated multipart checks

- `tw-21-2026-progress` / CVE-2026-109618: one small multipart request with a session-progress field, adapted from the input shape in the referenced PoC; races, memory pressure and exploit code are omitted.
- `tw-22-2026-chunked` / CVE-2026-109619: one small chunked multipart request without a progress field, covering the supplied sink's chunked-upload branch. Chunked framing is generic transport coverage, not a unique signature or diagnostic for this CVE.

Both expect `lure:multipart_progress` and the actual upload-buffered JSON. Both are marked `coverage_level=associated_tripwire_only`, with an explicit UI limitation. These are not distinct CVE-specific detectors. They do not exercise OOM corruption or stale global state. The association is contextual to PHP2Shell/multipart testing, and response validation cannot distinguish these vulnerabilities. No claim of exploitation or Elasticsearch detection is made.

Primary records: https://cveawg.mitre.org/api/cve/CVE-2026-109618 and https://cveawg.mitre.org/api/cve/CVE-2026-109619 . The maintained branches listed there are PHP 8.2 before 8.2.35, 8.3 before 8.3.36, 8.4 before 8.4.27 and 8.5 before 8.5.12. The actual supplied honeypot is Python.

Local tests verify the chunked request has Transfer-Encoding: chunked without Content-Length, the exact bounded body, no session-progress field in the chunked case, and the actual resulting action. A reverse proxy may dechunk/reframe that request; if it strips the transfer encoding, the second case may fall through to a portal response and fail validation. Inspect the upstream event rather than inventing success.

Public tests through the running panel returned HTTP 503 for both entries: `ATK-75DD9320EF` and `ATK-EB6D746FC7`. Raw responses are saved in ignored tests/artifacts/public-2026-checks.json. This verifies receipt of a service-unavailable response, not successful backend detection. No push or deployment was performed.
