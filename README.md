# Honeyguard Attack Panel

Approved attack runner with local access and optional private Tailscale HTTPS hosting. This repository contains the Random Attack control, live execution terminal, optional allowlisted Custom Shell, FastAPI orchestration, payloads, and operational execution records. It has no SIEM navigation, detection analytics, or reporting routes.

Threat monitoring, event history, AI explanations, analytics, and PDF reports belong to the separate [honeypot repository](https://github.com/Rida-2006/honeypot), under `threat-intelligence/`.

## Run (PowerShell)

```powershell
python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

Open http://127.0.0.1:5000 . For frontend development, run `npm run dev` inside `frontend/` in a second terminal and open http://127.0.0.1:5173 . Keep FastAPI running on port 5000.

Private hosting: [Tailscale setup and access](docs/PRIVATE-HOSTING.md). VPN behavior: [IP control](docs/IP-CONTROL.md).

Random Attack starts one test on the first click and reveals Random Attack and Rotate IP beside live logs.

## Target configuration

Before starting FastAPI:

```powershell
$env:HONEYPOT_URL = 'http://127.0.0.1:8080'
$env:HONEYPOT_NAME = 'Local honeypot'
```

Set `HONEYPOT_ALLOWED_HOSTS` to explicitly approve a different lab hostname. No target URL can be supplied by the browser. Bind to loopback and run one backend worker. The application restricts hosts/origins/clients, disables redirects and environment proxies, enforces request timeouts and launch rate limits, and permits only fixed service operations for its optional WireGuard control. Custom Shell never executes OS commands.

The existing six payloads in `payloads.json` are preserved: reconnaissance, authentication, traversal-shaped input, SQL-shaped input, arithmetic template expression, and an inert reflection marker. Confirm target paths and expected request bodies with the honeypot developer before end-to-end testing.

## Execution console

Random Attack selects one of 22 enabled tests for the actual Python deception sink supplied in `instruction.md`. It checks real response status, content type and body, streams timestamped request/response events, and reports SUCCESS, FAILED or TIMEOUT. One is CVE-2024-4577-style, two are explicitly labelled CVE-2026-associated multipart traffic checks, and 19 are generic tripwires. The 2026 checks exercise a shared generic multipart tripwire, not the actual PHP memory-corruption bugs. The expected `sensor.action` is shown separately from log verification, which remains pending in the UI. [MVP/startup guide](docs/MVP.md) · [Elasticsearch verification](docs/DETECTION.md).

Custom Shell retains its existing approved payloads and commands. `list tests` and `test <tripwire ID>` are also available. Historical Apache/PHP definitions are retained disabled in the catalogue and cannot be selected by Random.

The live terminal streams genuine request, response and completion events over `/ws`. Tripwire results validate status, content type and expected body text, and show a response excerpt capped at 4,096 characters; the actual complete response is retained in the operational result. Legacy connectivity/payload flows retain their response handling. Expected 404 route validation can succeed; a mismatched HTTP 200 body fails. Connection errors/timeouts never invent a response. SUCCESS is response validation, not proof of real exploitation, sensor action or Elasticsearch ingestion. Clear view affects only the browser. Existing operational SQLite retention stays bounded to seven days / 1,000 executions / 5,000 events.

## API boundary

| API | Responsibility |
| --- | --- |
| `GET /api/catalogue` | Fixed tripwire definitions and execution status |
| `POST /api/catalogue/{test_id}/execute` | One approved fixed tripwire by ID |
| `GET /api/execution/status` | Shared active execution state |
| `GET /api/payloads` | Server-approved payload library |
| `GET /api/honeypot/info`, `/api/honeypot/status` | Target configuration and HTTP reachability |
| `POST /api/attacks/random` | One random approved test |
| `POST /api/attacks/execute` | One test by `payload_id` |
| `POST /api/console/execute` | Allowlisted `command` |
| `GET /api/events`, `/api/attacks` | Operational execution output/backfill |
| `POST /api/attacks/{id}/replay` | Compatibility operation using the approved configuration |
| `WS /ws` | Live panel execution events |
| `POST /fire-random` | Legacy compatibility route |

`/api/analytics` and `/api/reports/attacks.csv` have been removed. There are no reporting or detection APIs in this application.

## Honeypot integration

Every test carries `X-Attack-ID`. The honeypot should preserve that value in its own recorded event. Threat Intelligence reads those honeypot records directly through its documented JSONL/internal-HTTP adapter; it does not consume the Attack Panel database as detections. See [the event contract](https://github.com/Rida-2006/honeypot/blob/main/docs/event-interface.md).

The teammate supplied the actual Python deception sink in instruction.md. Its code block is copied verbatim under tests/fixtures for local integration testing, with runtime-only loopback/log-path overrides in tests.local_honeypot. Production honeypot hosting and Elasticsearch ingestion remain separate; configure the owner-supplied target origin and allowlist.

## Verification

```powershell
python -m unittest discover -s tests -v
cd frontend
npm run build
```

The backend tests include 22 individually named real HTTP/action-log checks against the supplied source, plus precedence, failures, locking and existing feature regressions. Tests use disposable databases and loopback targets. The browser QA server also uses the supplied source. No external target is probed by the test suite.

## Static demonstration

`VITE_DEMO_MODE=true` builds a clearly labelled browser-local simulation. It never sends API/WebSocket/honeypot traffic. The normal build connects to FastAPI. Do not treat simulation output as real threat evidence. Remove `Env:VITE_DEMO_MODE` before building the real version.

## Visual language

Midnight Black `#0A0A0E`, Dark Charcoal `#1B1820`, Metallic Gold `#D8A84B`, Light Gold `#F6D68A`, Neon Red `#FF174F`, and Terminal Green `#39FF88`. The metallic lightning illustration is inline SVG, with accessible button labels, keyboard focus styles, responsive layout, and reduced-motion support.

## Test the real HTTP workflow locally

No external server or challenge URL is needed. From the project root, run the supplied Python deception target in one terminal:

```powershell
python -m tests.local_honeypot --port 8080
```

In another terminal, start FastAPI:

```powershell
$env:TEST_TARGET_URL = 'http://127.0.0.1:8080'
$env:TEST_REQUEST_TIMEOUT = '10'
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

In a third terminal, run the existing frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173 and click Random Attack. Alternatively, run `npm run build` and open http://127.0.0.1:5000. Keep VITE_DEMO_MODE unset or false for real HTTP execution. The existing public static demo is unchanged and remains simulated.

TEST_TARGET_URL accepts a complete HTTP(S) endpoint on an allowlisted host. Connectivity checks use that exact endpoint. Tripwire modules use its origin and their own fixed paths and queries, avoiding accidental earlier matches in the simulator. If unset, the button uses HONEYPOT_URL (default http://127.0.0.1:8080). TEST_REQUEST_TIMEOUT defaults to 10 seconds and must be greater than zero and at most 60. Environment changes require a backend restart; .env.example is a reference, not an automatically loaded configuration file.

The provided deception source runs through tests.local_honeypot and writes genuine local JSONL events. The separate tests.mock_http_server remains available for low-level full-response, /large, /status/503 and /slow transport checks. Automated integration tests start their own mock server on a free loopback port and verify actual transmitted form data, full response equality, WebSocket events, safe browser rendering, connection failure, and timeout behavior. Mock fixture data is explicitly identified and is never presented as a real honeypot detection.

```powershell
python -m unittest discover -s tests -v
```
