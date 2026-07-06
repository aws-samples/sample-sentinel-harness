# create_ticket

Ticketing **WRITE** tool for a security operations (SecOps) team. Terminal step
of the alert-triage flow (`harnesses/alert-triage`): turns a triaged finding
into a ticket record.

> **CLEARLY-LABELED MOCK TOOL for POC / testing only.** In offline mode this
> tool does **not** talk to any real ticketing system (Jira / ServiceNow / SIM /
> GitHub Issues). It "creates" a ticket as an in-process, returned data
> structure only — nothing is persisted, nothing leaves the process, zero
> network I/O. It is **not** a real tracker.

## Purpose

Given a triaged finding (title + severity + description, plus optional links
back to the alert / IOC-host that motivated it), record it as a ticket with an
id, a `status: "open"`, and a `created_ts`. This closes the
alert → IOC → asset → **ticket** chain modelled in `mockdata/world.py`.

## HITL gate (containment / ticketing needs a human)

Opening a ticket is a **containment / ticketing action**, which the alert-triage
design treats as **human-in-the-loop (HITL) gated**: an autonomous agent
*proposes* the ticket, but a human *approves* before it fires against any real
tracker. The offline mock is deliberately side-effect-free so the POC can
exercise the full write *shape* end-to-end without a human ever gating a real
mutation. When wired live (see below), the HITL approval must sit in front of
the real POST.

## Signature

```python
def handler(event, context) -> dict
```

- `event`:
  - `title` (str, required)
  - `severity` (str, required) — one of `low` | `medium` | `high` | `critical`
  - `description` (str, required)
  - `assignee` (str, optional)
  - `related_alert_id` (str, optional) — e.g. `"alert-1001"`
  - `related_host` (str, optional) — e.g. `"web-01"`
- `context`: Lambda-style context (unused by the stub).

## Output

```jsonc
{
  "ok": true,
  "source": "stub",            // "live" when CREATE_TICKET_LIVE=1
  "ticket": {
    "ticket_id": "SEC-<12-hex>", // deterministic content-hash id (offline)
    "status": "open",
    "created_ts": "2026-01-01T00:00:00Z#<8-hex>", // derived, not wall clock
    "title": "...",
    "severity": "critical",
    "description": "...",
    "assignee": "secops",         // or null
    "related_alert_id": "alert-1001", // or null
    "related_host": "web-01"          // or null
  }
}
```

On a bad request: `{"ok": false, "error": "validation_error", "message": "..."}`.

## Input validation

- `title`, `severity`, `description` are all **required** non-empty strings.
- `severity` must be in `{low, medium, high, critical}` (`info` is rejected — you
  don't open a containment ticket for an informational event). A bad enum →
  `validation_error`.
- Optional fields (`assignee`, `related_alert_id`, `related_host`), when present,
  must be non-empty strings; they pass through onto the ticket unchanged.
- Free-text fields are length-bounded. Anything invalid → `validation_error`.
- Exceptions are never swallowed.

## Determinism — why a content-hash id

The offline `ticket_id` is `"SEC-" + sha256(content)[:12]`, a stable digest of
the ticket's semantic content (title + severity + description + optional links).
`created_ts` is likewise derived from that digest, never the wall clock. So:

- **the same input always yields the same id** (test-friendly, reproducible);
- identical requests naturally **de-duplicate** to the same id (idempotent
  "create");
- there is **no shared mutable state** — no process counter, no clock, no I/O.

The mock world (`mockdata.tickets_seed()`) seeds two tickets (`SEC-1001`,
`SEC-1002`) and hints the next monotonic id would be `SEC-1003`. That monotonic
sequence is documented for the **live** path — a real tracker assigns its own
sequential id — but the offline mock deliberately does **not** use a process
counter, because a content hash is the cleaner, deterministic choice offline.

## Live opt-in (future)

- `CREATE_TICKET_LIVE=1` opts into a real tracker; the client is not wired yet
  and raises an explicit `upstream_error` (never a fabricated "created" ticket).
  A HITL approval must gate the real POST.
- `CREATE_TICKET_URL` / `CREATE_TICKET_TOKEN` are read from the environment only
  — never hardcoded, logged, or echoed. Default (offline) mode makes no outbound
  calls.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python handler.py
```
