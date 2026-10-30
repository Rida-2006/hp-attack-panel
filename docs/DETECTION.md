# Tripwire event verification in Elasticsearch

## What is verified automatically

The panel verifies response status, MIME type and expected text. Local integration tests separately read the supplied Python server's real JSONL output and match each event by `http.request.headers.X-Attack-ID`. They confirm all 20 expected sensor actions. This does not mean a real PHP CVE was exploited or Elasticsearch received the event.

The production panel has no Elasticsearch read access. It shows `expected_sensor_action` and `detection_status=unverified`; SUCCESS is response validation only. A response body does not directly expose `sensor.action` and is not treated as such an acknowledgement.

## Source event fields

The provided source emits:

- `http.request.headers.X-Attack-ID`: unique correlation ID.
- `http.request.headers.X-HoneyGuard-Test`: fixed catalogue ID.
- `http.request.headers.X-HoneyGuard-Test-Type`: generic-tripwire or cve-style-tripwire.
- `http.request.headers.X-HoneyGuard-CVE`: only set for the CGI argument check.
- `url.original`, `url.query`, `url.decoded`: the `hg_attack_id` query fallback and actual requested route.
- `sensor.action`: the action chosen by `decide()` / OPTIONS handler.
- `@timestamp`, `http.request.method`, `http.response.status_code`.
- `session.id`, `session.canary_issued`, `session.canary_replayed`, `session.action_history`.

Header capitalization/dynamic field names can change in an ingest pipeline. Check the expanded document before assuming the indexed field names match the raw source.

## Gurpratap's procedure

1. Confirm the reverse proxy routes to the supplied Python deception service and the shipper reads its raw_events JSONL file. A proxy access log alone may not contain `sensor.action` or captured headers.
2. Run a single panel test against the owner-supplied allowlisted origin. Copy its attack ID, test ID, expected sensor.action, method and UTC timestamp from the terminal.
3. In the correct Kibana Discover data view, use a time range around that timestamp. If fields retain source names, use:

```text
http.request.headers.X-Attack-ID : "ATK-REPLACE-WITH-ACTUAL-ID"
```

If headers are lowercased/flattened, use the actual indexed field name shown in an expanded document. As a fallback, search the raw `url.query` / `url.original` for the same `hg_attack_id=ATK-...` value. Do not rely on source-IP geolocation for correlation.

4. Expand the matching event and verify the exact header ID, request method/path and response status. Compare its **actual** `sensor.action` with the panel's **expected** action. Record Elasticsearch `_index`, `_id`, timestamp and action as evidence.
5. For example, the CGI test must have `sensor.action = lure:phpcgi_arg_check`. An event with `route:portal` means routing/decoding/source revision did not match the expected branch, even if the response was HTTP 200.
6. An indexed event confirms ingestion and action selection, not a security-rule alert. If the MVP requires an alert, confirm a separate alert/rule event with the same correlation ID. Do not claim the panel installed or verified that rule.

There are no Elasticsearch credentials or direct queries built into the Attack Panel. Verification is manual unless that independent source is connected later.

## Local verification without Elasticsearch

```powershell
Set-Location 'C:\Users\Administrator\Documents\Honeypot-cybersecurity\hp-attack-panel'
python -m tests.verify_tripwires
Get-Content tests/artifacts/tripwire-report.json
```

This runs all 20 cases on the exact supplied server, preserves genuine JSONL events and writes per-test expected/observed actions with actual attack IDs and response outcomes. `elasticsearch_verified` remains false in every report row.

For manual Random tests, run `python -m tests.local_honeypot --port 8080`; its log defaults to `tests/artifacts/honeypot-events.jsonl`. In another terminal:

```powershell
$attackId = 'ATK-REPLACE-WITH-DISPLAYED-ID'
Get-Content tests/artifacts/honeypot-events.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.http.request.headers.'X-Attack-ID' -eq $attackId } |
  Select-Object @{Name='AttackId';Expression={$_.http.request.headers.'X-Attack-ID'}}, @{Name='Action';Expression={$_.sensor.action}}, @{Name='Status';Expression={$_.http.response.status_code}}
```

## Order-sensitive cases

Canary tokens win before all other checks. Config/source/info lures can override command-looking input. Math/MD5/echo win before later patterns. Multipart progress precedes CGI argument and stream checks. OPTIONS bypasses `decide()` and logs route:options. Test labels are sent in headers rather than the URI, avoiding accidental echo matching across the URI/body newline. The raw `%ADd` CGI query and `?-s` source-check prefix are preserved rather than decoded/re-encoded by the panel.

Only tw-01-cgi-argument is labelled CVE-2024-4577-style, based on the supplied check and PHP's advisory. The target is Python, with advertised PHP/Apache banners generated by the simulator. The other 19 cases are generic deception tripwires. Earlier Apache traversal probes and PHP memory-corruption-labelled markers remain archived, disabled and outside the active suite.

## 2026-associated traffic coverage

The active suite now has 22 cases. `tw-21-2026-progress` (CVE-2026-109618 context) sends a bounded session-progress multipart request. `tw-22-2026-chunked` (CVE-2026-109619 context) sends bounded chunked multipart data without the progress field. Both exercise the same generic `lure:multipart_progress` action; neither is a CVE-specific detector or an implementation of PHP memory corruption. Their result metadata and UI expose that limitation.

Search by the unique X-Attack-ID and compare the actual source event. The public checks with IDs `ATK-75DD9320EF` and `ATK-EB6D746FC7` received HTTP 503, so the expected action was not verified. A proxy response alone is not evidence of ingestion at the Python backend. The panel keeps detection_status unverified.
