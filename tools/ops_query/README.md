# ops_query

Read-only **multi-account operations query** tool for an ops-automation
supervisor. The multi-account analog of `asset_lookup` — it feeds the
`harnesses/ops-automation` supervisor with the account estate and its open
operational findings so the agent can triage them and open tickets.

## Purpose

Given one selector, return a deterministic multi-account view:

- `{"account": "111111111111"}` — one account's full record (resources +
  findings).
- `{"query": "*"}` — every account in the estate (resource footprint +
  findings).
- `{"finding_type": "public_s3"}` — every open finding of one type across the
  estate, each tagged with the account it belongs to.

Intended to be wired into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: exactly ONE of `account` / `query` / `finding_type`.
- `context`: Lambda-style context (unused by the stub).

## Input validation

- Exactly one selector must be present — zero selectors, or more than one, is a
  `validation_error` (the query intent is never ambiguous).
- `account` must be a 12-digit id (shape only; an unknown-but-well-formed id is
  not an error, it simply matches nothing).
- `query` supports only the wildcard `"*"`.
- `finding_type` must be one of the known closed vocabulary
  (`public_s3`, `over_permissive_role`, `unencrypted_volume`, `mfa_disabled`).
- Anything else returns a `validation_error`.

## Output contract

Account / wildcard selectors return an `accounts` list:

```json
{"ok": true, "source": "stub", "accounts": [ { "account_id": "...", "name": "...",
  "environment": "prod", "region": "us-east-1",
  "resources": {"ec2": 24, "s3_buckets": 12, "iam_roles": 18},
  "findings": [ ... ] } ]}
```

A `finding_type` selector returns a flat `findings` list, each finding tagged
with `account_id` / `account_name`:

```json
{"ok": true, "source": "stub", "finding_type": "public_s3",
 "findings": [ {"account_id": "111111111111", "account_name": "prod-payments (fictional)",
   "finding_id": "OPS-111-001", "finding_type": "public_s3", "severity": "high",
   "resource": "payments-invoices-archive", "description": "..."} ]}
```

Validation failures return `{"ok": false, "error": "validation_error", "message": ...}`.

## What is real vs. stubbed

- The **offline inventory is real, deterministic data** — sourced from
  `mockdata/accounts.py`. The same query always yields the same
  accounts/findings. It is *synthetic* (no real environment), but nothing is
  fabricated at call time.
- The **live path is a REAL, dependency-free HTTP client** (`urllib.request`
  from the standard library — no third-party SDK): with `OPS_QUERY_LIVE=1` it
  POSTs the validated selector as JSON to `OPS_QUERY_URL`, parses the JSON
  reply, and returns it in the **same** output contract as the stub, tagged
  `source="live"`. An optional bearer token from `OPS_QUERY_TOKEN` is sent as an
  `Authorization` header. Any failure (missing URL, timeout, non-2xx, malformed
  JSON, connection refused) surfaces as an explicit `upstream_error`. It
  **never** silently falls back to fixtures, so opting into live and getting
  nothing back is never mistaken for "no accounts". The client is exercised
  offline in `tests/test_ops_query_live.py` against an in-process **mock**
  `http.server` on `127.0.0.1` (ephemeral port) — proving request shape,
  response parsing, and error handling with ZERO external network; no real ops
  backend is contacted.

## Mock data disclaimer

The account ids (`111111111111`, `222222222222`, `333333333333`,
`444444444444`) are **obviously-fictional repeated-digit demo ids** — they are
NOT real AWS account numbers, and never appear in an `arn:` / `iam::` context.
See `mockdata/accounts.py`.

## Egress & secrets control

- Egress happens only when `OPS_QUERY_LIVE=1` and the runtime network policy
  permits it. Default mode makes no outbound calls.
- Optional `OPS_QUERY_URL` / `OPS_QUERY_TOKEN` are read from the environment
  only — never hardcoded or logged.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python -m tools.ops_query.handler   # or: python handler.py from the tool dir
```
