# siem_query

Read-only SIEM alert/event query tool for a security operations (SecOps) team.
First hop of the alert-triage flow (`harnesses/alert-triage`): pull the events
for a host / technique / severity / id / time window, then pivot to enrichment,
asset lookup, and ticketing.

> **CLEARLY-LABELED MOCK DATA for POC / testing only.** This is **not** a real
> SIEM and returns **no** real threat intelligence. Every event comes from the
> fictional `mockdata` world (RFC 5737 documentation IPs, `example.test` /
> `example.com` domains, generic host ids). See `mockdata/README.md`.

## Purpose

Given exactly one query selector, return the matching **normalized SIEM
events** from the shared fictional world. Because `siem_query`, `asset_lookup`,
`enrich_ioc`, and `create_ticket` all read the same `mockdata.load_world()`,
the host an alert names here is the same host `asset_lookup` knows and the IP it
carries is the same indicator `enrich_ioc` scores.

The headline cross-link: `alert-1001` (Log4Shell, ATT&CK `T1190`) on `web-01`
from C2 IP `203.0.113.66` — findable here **by host `web-01`** and **by
technique `T1190`**.

## Signature

```python
def handler(event, context) -> dict
```

`event` supports one selector per call:

| Query shape | Returns |
|---|---|
| `{"host": "web-01"}` | all events for that host |
| `{"technique": "T1190"}` | all events with that ATT&CK technique id (case-insensitive) |
| `{"severity": "high"}` | all events at that severity band |
| `{"alert_id": "alert-1001"}` | the single event with that id |
| `{"since": "2026-06-30T00:00:00Z"}` | events at/after that ISO-8601 instant |
| `{"query": "*"}` | the whole alert stream |

`context` is a Lambda-style context (unused by the stub).

## Output

```json
{
  "ok": true,
  "source": "stub",
  "count": 1,
  "events": [
    {
      "alert_id": "alert-1001",
      "ts": "2026-06-28T14:03:11Z",
      "severity": "critical",
      "rule_name": "Log4Shell JNDI Exploit Attempt",
      "host": "web-01",
      "src_ip": "203.0.113.66",
      "dst_ip": "192.0.2.10",
      "technique": "T1190",
      "summary": "Inbound HTTP request ... Log4Shell ...",
      "false_positive": false
    }
  ]
}
```

Events are normalized (raw `raw_summary` → `summary`, `false_positive` defaulted
to `false`) and sorted by `ts` then `alert_id`, so output ordering is stable.

## Input validation

- Exactly **one** recognized selector must be present.
- An empty event, an unknown/typo'd selector key, more than one selector, a
  non-string value, or a blank/over-long value → `validation_error`.
- An unknown **value** for a valid selector (e.g. an unknown host) is **not** an
  error: it returns an empty `events` list, so "no matches" stays
  distinguishable from "malformed query".

## Read-only

This tool performs **no writes** to the mock world or anywhere. `load_world()`
returns a fresh deep copy each call, so filtering can never mutate the shared
source. No clock, no randomness — the same query returns the same events.

## Offline / stubbed by default

- Runs with zero network I/O by default, reading the embedded `mockdata` world.
- Set `SIEM_QUERY_LIVE=1` (and `SIEM_QUERY_URL`) to opt into a live SIEM backend
  later. The live path is a documented, guarded stub: it raises an explicit
  `upstream_error` until a concrete backend is wired, and **never** silently
  falls back to the mock fixtures.

## Egress & secrets control

- Egress happens only when `SIEM_QUERY_LIVE=1` and the runtime network policy
  permits it. Default mode makes no outbound calls.
- Optional `SIEM_QUERY_URL` / `SIEM_QUERY_TOKEN` are read from the environment
  only — never hardcoded or logged.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python handler.py
```
