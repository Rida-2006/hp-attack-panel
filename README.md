# Honeyguard Attack Panel

Standalone, local-only approved attack runner. This repository contains the Random Attack control, live execution terminal, optional allowlisted Custom Shell, FastAPI orchestration, payloads, and operational execution records. It has no SIEM navigation, detection analytics, or reporting routes.

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

## Target configuration

Before starting FastAPI:

```powershell
$env:HONEYPOT_URL = 'http://127.0.0.1:8080'
$env:HONEYPOT_NAME = 'Local honeypot'
```

Set `HONEYPOT_ALLOWED_HOSTS` to explicitly approve a different lab hostname. No target URL can be supplied by the browser. Bind to loopback and run one backend worker. The application restricts hosts/origins/clients, disables redirects and environment proxies, enforces request timeouts and launch rate limits, and has no OS command execution.

The existing six payloads in `payloads.json` are preserved: reconnaissance, authentication, traversal-shaped input, SQL-shaped input, arithmetic template expression, and an inert reflection marker. Confirm target paths and expected request bodies with the honeypot developer before end-to-end testing.

## Execution console

Random Attack sends a harmless form POST containing `content=Honeyguard harmless POST test` to the server-configured `TEST_TARGET_URL`. It does not select an exploit payload. Custom Shell retains the existing approved payload library. Custom Shell accepts `help`, `status`, `list attacks`, `test <category or payload ID>`, `logs`, `history`, and `clear`. `history` is an operational execution log, not a threat-intelligence dashboard. All test commands use the same backend execution service.

The live terminal streams initiated, target, request, response-status, full response-body, error, and completion events over `/ws`. The full decoded response body is rendered as text, never as executable HTML. A 2xx response is a successful HTTP test; non-2xx responses retain their actual body and report an HTTP error outcome. Connection failures and timeouts are recorded without inventing a response status. HTTP status and timing describe what the panel observed; they never establish honeypot detection or successful exploitation. Clear view affects only the browser terminal. Operational SQLite records remain bounded to seven days / 1,000 executions / 5,000 events, and the payload library remains server-managed.

## API boundary

| API | Responsibility |
| --- | --- |
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

The existing `Rida-2006/honeypot` repository was empty when inspected, so the actual honeypot services, startup instructions, real event source, and endpoint mapping remain integration requirements. No honeypot implementation is copied into this repository.

## Verification

```powershell
python -m unittest discover -s tests -v
cd frontend
npm run build
```

Tests mock HTTP requests and use temporary databases. Authorized loopback fixtures are used for browser QA. No external target is probed.

## Static demonstration

`VITE_DEMO_MODE=true` builds a clearly labelled browser-local simulation. It never sends API/WebSocket/honeypot traffic. The normal build connects to FastAPI. Do not treat simulation output as real threat evidence. Remove `Env:VITE_DEMO_MODE` before building the real version.

## Visual language

Midnight Black `#0A0A0E`, Dark Charcoal `#1B1820`, Metallic Gold `#D8A84B`, Light Gold `#F6D68A`, Neon Red `#FF174F`, and Terminal Green `#39FF88`. The metallic lightning illustration is inline SVG, with accessible button labels, keyboard focus styles, responsive layout, and reduced-motion support.

## Test the real HTTP workflow locally

No external server or challenge URL is needed. From the project root, run the mock target in one terminal:

```powershell
python -m tests.mock_http_server --port 8080
```

In another terminal, start FastAPI:

```powershell
$env:TEST_TARGET_URL = 'http://127.0.0.1:8080/echo'
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

TEST_TARGET_URL accepts a complete HTTP(S) endpoint, including path/query, on a host explicitly approved by HONEYPOT_ALLOWED_HOSTS. If unset, the button uses HONEYPOT_URL (default http://127.0.0.1:8080). TEST_REQUEST_TIMEOUT defaults to 10 seconds and must be greater than zero and at most 60. Environment changes require a backend restart; .env.example is a reference, not an automatically loaded configuration file.

Use /large on the mock server to check an untruncated response, /status/503 for an actual HTTP error response, or /slow with TEST_REQUEST_TIMEOUT=0.05 for a read timeout. Automated integration tests start their own mock server on a free loopback port and verify actual transmitted form data, full response equality, WebSocket events, safe browser rendering, connection failure, and timeout behavior. Mock fixture data is explicitly identified and is never presented as a real honeypot detection.

```powershell
python -m unittest discover -s tests -v
```
