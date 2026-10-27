# Honeyguard — Honeypot Attack Panel

A local FastAPI + React workspace for approved honeypot simulations, built with the Stealth Red palette: `#101014`, `#25252D`, `#EF4444`, `#F97316`, `#D1D5DB`.

## Start locally (PowerShell)

From the project root:

```powershell
python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

Open **http://127.0.0.1:5000**. Build the frontend again after changing its source.

For hot reload, keep FastAPI running and open a second terminal:

```powershell
cd frontend
npm run dev
```

Open **http://127.0.0.1:5173**. Vite proxies `/api`, `/fire-random`, and `/ws` to port 5000. Port 5173 is fixed so browser origin checks remain predictable.

## Features

- Responsive dashboard, hourly activity, test distribution, real stored metrics.
- Random launch and six predefined probes: reconnaissance, authentication, traversal-shaped input, SQL-shaped input, arithmetic template expression, and an inert reflection marker.
- Allowlisted console: `help`, `status`, `list attacks`, `test <category or payload ID>`, `logs`, `history`, `clear`.
- Timestamped request/response/error events over WebSockets, with reconnect and backfill.
- Event filters, pause view, follow latest, copy visible events, and detail inspection.
- SQLite attack history, category explanations, replay of the current approved configuration.
- CSV download and a printable report; choose **Save as PDF** in the browser print dialog.
- Server-managed target configuration and HTTP reachability checks.

React was already present in this repository and is retained. Educational notes are predefined content, not AI-generated explanations.

## Configure the target

The default is `http://127.0.0.1:8080`. Set environment variables before starting FastAPI:

```powershell
$env:HONEYPOT_URL = 'http://127.0.0.1:8001'
$env:HONEYPOT_NAME = 'Demo honeypot'
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

For a separately hosted authorized lab, also configure `HONEYPOT_ALLOWED_HOSTS` with the exact hostname. Defaults allow localhost, 127.0.0.1, and ::1 only. URL changes require a backend restart. `.env.example` documents the options; it is not automatically loaded.

The frontend cannot submit target URLs or arbitrary shell commands. The backend disables redirects and environment proxies, times out requests after 10 seconds, allows one in-flight execution, and enforces one second between starts. Browser origins and request hosts are checked. Access is restricted to loopback clients; run a single backend worker bound to 127.0.0.1. This is a local lab application, not a multi-user internet service. Use operating-system user isolation for local data access. Do not expose it through a public proxy without adding authentication and deployment controls.

## Data and evidence

SQLite lives at `data/panel.sqlite3` (ignored by Git). Override with `PANEL_DB_PATH`. Records are pruned on reads/writes: seven days, at most 1,000 attacks and 5,000 events. Restarted in-progress executions are marked interrupted. Run one backend worker; rate limits are process-local.

Events currently originate from the **panel**. Receiving an HTTP response means the target replied, including responses such as 403 or 500. It does not prove exploitation, detection, or honeypot recording. The panel never renders a response body as HTML.

Honeypot detections, unique source IPs, and uptime are deliberately unavailable until the honeypot developer provides an API contract. The health check uses `GET /` every 30 seconds while the UI is open, cached for ten seconds; any HTTP response indicates reachability. Health traffic may appear in the honeypot's own logs and is excluded from panel execution counts.

Before a demo, the honeypot developer should confirm the six payload paths and bodies in `payloads.json`. There is no external challenge URL or original SSTI1 request in this repository, so the SSTI probe uses `{{7*7}}` on the configured local target. The XSS-category entry is explicitly an inert reflection marker, not an executable XSS payload.

## API contract

Interactive documentation: **http://127.0.0.1:5000/docs**.

| Endpoint | Behavior |
| --- | --- |
| `GET /api/payloads` | Approved payload library and educational notes |
| `GET /api/honeypot/info` | Server-approved target and integration capabilities |
| `GET /api/honeypot/status` | Cached HTTP reachability check |
| `POST /api/attacks/random` | Random approved test |
| `POST /api/attacks/execute` | Body: `{"payload_id":"p-005"}` |
| `POST /api/attacks/{attack_id}/replay` | Replay current approved payload by ID, new attack ID |
| `GET /api/attacks` | Retained execution history, newest first |
| `GET /api/events` | Retained panel events, newest first |
| `GET /api/analytics` | Stored execution metrics; detection fields are null |
| `POST /api/console/execute` | Body: `{"command":"test ssti"}` |
| `GET /api/reports/attacks.csv` | Retained execution records |
| `WS /ws` | Structured events with ID, time, type, severity, source, attack ID |
| `POST /fire-random` | Compatibility route for the earlier panel |

A completed or failed execution returns `attack_id`, `payload_id`, `attack_type`, `timestamp`, `method`, `path`, `source`, `status`, `http_status`, `duration_ms`, `error`, `replay_of`, and `honeypot_confirmed: false`. Transport failures are recorded execution results, not fabricated HTTP responses. Invalid commands return 400, unknown IDs 404, and rate-limited launches 429.

Every outgoing simulation includes an `X-Attack-ID` header. Agree with the honeypot developer on an authenticated log interface and event schema carrying that identifier. No inbound event-ingestion endpoint is exposed until that contract exists.

## Verification

```powershell
python -m unittest discover -s tests -v
cd frontend
npm run build
```

Backend integration tests use a temporary SQLite database and mocked HTTP target; they never send probes to an external target. Tests cover command rejection, execution, correlation, failed requests, persistence, replay, rate limiting, origin/host/client checks, WebSocket streaming, CSV, and retention.

## Public demonstration build

To build a static, browser-only demo without the FastAPI backend:

```powershell
cd frontend
$env:VITE_DEMO_MODE = 'true'
npm run build
```

This mode prominently labels all results as simulated. It sends no API, WebSocket, or honeypot requests. Simulated history stays in the visitor's browser storage. CSV reports include a `simulated` column. Remove the environment variable (`Remove-Item Env:VITE_DEMO_MODE`) before rebuilding the normal full-stack version.
