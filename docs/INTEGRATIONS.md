# Integrations — bring your own model / SIEM / TI / CMDB / ticketing

> **The ~15-minute runbook.** `sentinel-harness` ships offline-by-default: every
> data-plane tool serves clearly-labeled **mock** data (RFC 5737 IPs,
> `example.com`/`example.test` domains) so the whole platform is testable in CI
> with no network, no secrets, no AWS. This doc is the copy-paste path to swap
> those mocks for **your** backends — one model id, four HTTP seams — and to
> verify the swap end-to-end against the real alert-triage walk.
>
> Nothing here needs a rebuild: each live path is a config change (an env var).
> The client is real stdlib `urllib` (no third-party deps) and is already unit-
> tested offline. What you supply is the endpoint + (optional) token.

Contents:

1. [The model — pin a working id](#1-the-model--pin-a-working-id)
2. [The four `*_LIVE` seams](#2-the-four-_live-seams) — env vars, HTTP contract, switch, failure semantics
3. [Worked example — wire a SIEM in ~15 minutes](#3-worked-example--wire-a-siem-in-15-minutes)
4. [Verify it live + keep it least-privilege](#4-verify-it-live--keep-it-least-privilege)
5. [Honest note — what still needs a real account / GA type](#5-honest-note--what-still-needs-a-real-account--ga-type)

---

## 1. The model — pin a working id

The harness picks a Bedrock model by **model id**. Three ids are read from the
environment (see `sentinel_harness/core.py`), each with a cross-region-inference
default:

| Env var | Default (in `core.py`) | Used for |
|---|---|---|
| `SENTINEL_MODEL_HAIKU` | `global.anthropic.claude-haiku-4-5-20251001-v1:0` | cheap/fast, high alert volume (alert-triage) |
| `SENTINEL_MODEL_SONNET` | `global.anthropic.claude-sonnet-4-6` | ambiguous alerts, heavier reasoning |
| `SENTINEL_MODEL_OPUS` | `us.anthropic.claude-opus-4-5-20251101-v1:0` | deepest reasoning specialists |

### ⚠️ The one rule that will silently burn you

**A Bedrock invoke against a model id that lacks a full version suffix fails
*silently* — no exception, no events, an empty stream.** Always pin the full
`...-<YYYYMMDD>-v1:0` suffix. Notice the Haiku/Opus defaults above already carry
one; the Sonnet default (`...-sonnet-4-6`) is a shorthand alias pattern — pin it
before you invoke:

```bash
# Pin a KNOWN-GOOD, fully-versioned id for each tier (override the defaults).
export SENTINEL_MODEL_HAIKU="global.anthropic.claude-haiku-4-5-20251001-v1:0"
export SENTINEL_MODEL_SONNET="global.anthropic.claude-sonnet-4-5-20250929-v1:0"
export SENTINEL_MODEL_OPUS="us.anthropic.claude-opus-4-5-20251101-v1:0"
```

Rules of the road:

- **Full suffix or it silently fails.** `global.anthropic.claude-haiku-4-5` (no
  date) is *not* invokable — use `...-4-5-20251001-v1:0`.
- **Enable model access first.** In the Bedrock console, enable each model in
  your region, or the invoke returns `AccessDeniedException`.
- **The region prefix must match a valid inference profile** for your region
  (`global.` / `us.` / `eu.` …). `SENTINEL_REGION` (default `us-east-1`) selects
  the region; the model-id prefix must be offered there.
- Harness YAML picks up these ids via `core.MODEL_HAIKU` etc. — e.g.
  `harnesses/alert-triage/harness.yaml` pins
  `modelId: global.anthropic.claude-haiku-4-5-20251001-v1:0` and documents that
  `SENTINEL_MODEL_HAIKU` overrides it.
- **Session ids must be ≥ 33 chars.** Unrelated to the model, but the same class
  of silent failure — `core.new_session()` returns a 54-char id (a `sentinel-`
  prefix + a 36-char hyphenated UUID + an 8-hex suffix); don't hand-roll a
  shorter one.

---

## 2. The four `*_LIVE` seams

Four data-plane tools are **backend-pluggable**. Each defaults to its offline
mock and flips to a real HTTP backend when you set its `*_LIVE=1` env var. The
client is identical in spirit across all four:

- **stdlib only** — `urllib.request`, no third-party SDK, so it runs anywhere the
  handler runs.
- **POST JSON in, JSON out.** The tool sends the *already-validated* query as the
  request body and normalizes your reply into the **exact same output contract**
  the offline stub emits — downstream reasoning cannot tell live from offline
  apart from the top-level `"source": "live"` marker.
- **Bearer auth from the environment only.** The optional token is read from the
  env, placed solely in the outbound `Authorization: Bearer <token>` header, and
  **never** logged, echoed into a response, or interpolated into an error message.
- **No silent fallback.** If you opt into live and the backend is missing/broken,
  you get `{"ok": false, "error": "upstream_error", "message": ...}` — never a
  fabricated or misleadingly-empty "success". Opting into live and getting
  nothing back always tells you *why*.
- **Bounded.** Each call has a connect/read timeout and a max-response-bytes cap,
  so a hung or oversized backend can never wedge the tool.

### The offline → live switch (and back)

```bash
# LIVE: point the tool at your backend and flip its switch.
export SIEM_QUERY_URL="https://siem.example.internal/agentcore/siem_query"
export SIEM_QUERY_TOKEN="…"        # optional; env only, never committed
export SIEM_QUERY_LIVE=1            # the switch

# OFFLINE again: just unset the switch (URL/TOKEN can stay set, they're ignored).
unset SIEM_QUERY_LIVE
```

Every tool follows the same shape — swap the prefix (`SIEM_QUERY` /
`ASSET_LOOKUP` / `ENRICH_IOC` / `OPS_QUERY`).

### Failure semantics (all four, identical)

| Condition | Result |
|---|---|
| `*_LIVE=1` but `*_URL` unset | `upstream_error` — message says to unset `*_LIVE` to use the offline mock |
| DNS / connection refused / TLS / timeout | `upstream_error` |
| non-2xx HTTP status | `upstream_error` (status only; response body is **not** echoed — it could leak request context) |
| body over the byte cap | `upstream_error` — refuses to parse |
| malformed / non-JSON body, or wrong JSON shape | `upstream_error` |
| malformed **input** (bad selector) | `validation_error` (caught before any network I/O) |

> A malformed *input* is a `validation_error`; a broken *backend* is an
> `upstream_error`. They are distinct on purpose so you know which side to fix.

---

### 2a. `siem_query` — read-only SIEM alert/event query

**Backend contract**

| Field | Value |
|---|---|
| Switch env | `SIEM_QUERY_LIVE=1` |
| Endpoint env | `SIEM_QUERY_URL` (**required** when live) |
| Token env | `SIEM_QUERY_TOKEN` (optional bearer) |
| Method | `POST` |
| Request headers | `Content-Type: application/json`, `Accept: application/json`, `User-Agent: sentinel-harness`, `Authorization: Bearer <token>` (if token set) |
| Request body | The one validated selector as a single-key object: `{"host":"web-01"}` · `{"technique":"T1190"}` · `{"severity":"high"}` · `{"alert_id":"alert-1001"}` · `{"since":"2026-06-30T00:00:00Z"}` · `{"query":"*"}` |
| Response body | `{"events": [ …event… ]}` **or** a bare list `[ …event… ]` |
| Event shape (10 fields, normalized) | `alert_id`, `ts`, `severity`, `rule_name`, `host`, `src_ip`, `dst_ip`, `technique`, `summary` (or `raw_summary`), `false_positive` |
| Timeout / max body | 15 s / 2,000,000 bytes |
| On success | `{"ok":true,"source":"live","count":N,"events":[…]}` (sorted by `ts`,`alert_id`) |

Your backend receives exactly one selector key per call and must return the
matching events. Missing optional fields are defaulted (`false_positive`→`false`,
`summary`←`raw_summary`←`""`); you don't have to send every field.

**Named connectors (plug-and-play — no shim to write).** If your SIEM isn't the
generic `{selector: value}` → `{"events":[…]}` contract above (most aren't), set
`SIEM_QUERY_CONNECTOR` to a shipped adapter and the tool translates the request
into the backend's native query DSL and parses its native response envelope for
you (`sentinel_harness/connectors/`):

| `SIEM_QUERY_CONNECTOR` | Native request | Native response envelope |
|---|---|---|
| `splunk` | SPL search (`search index=* … host="web-01"`, `output_mode=json`) | `{"results":[ … ]}` |
| `elastic` | ES query DSL (`{"query":{"term":{"host.keyword":"web-01"}}}` → `POST …/_search`) | `{"hits":{"hits":[{"_source":{…}}]}}` |
| `opensearch` | same DSL/envelope as `elastic` | `{"hits":{"hits":[…]}}` |
| `qradar` | AQL (`SELECT * FROM events WHERE sourceip = '…' LAST 24 HOURS`) | `{"events":[ … ]}` |
| `microsoft_sentinel` | KQL (`SecurityAlert \| where Computer == "web-01"`) | columnar `{"tables":[{"columns":[…],"rows":[[…]]}]}` |

```bash
export SIEM_QUERY_LIVE=1
export SIEM_QUERY_URL="https://splunk.example.internal:8089/services/search/jobs/export"
export SIEM_QUERY_CONNECTOR=splunk   # translate to SPL + parse results[]
```

Connectors are **pure translation, no network** (the HTTP round-trip stays in the
tool's SSRF-guarded live path), so each is deterministic and contract-tested with
a native-response fixture. Field-name drift is absorbed (a source IP under
`src`/`src_ip`/`source.ip` all map to the neutral `src_ip`), for both flat-dotted
and nested keys. An unknown connector name fails loudly as `upstream_error`
listing the known adapters — it never silently degrades. Leave
`SIEM_QUERY_CONNECTOR` unset to use the generic contract above. Ticketing has the
same mechanism via `CREATE_TICKET_CONNECTOR` (`servicenow` / `jira` / `pagerduty`).

The `microsoft_sentinel` connector shows the framework isn't limited to
lists-of-objects: it projects the KQL **columnar** envelope (parallel `columns`
+ `rows` arrays) into neutral events by zipping each row against the column names.

---

### 2b. `asset_lookup` — exposure / asset-surface (CMDB / scanner)

**Backend contract**

| Field | Value |
|---|---|
| Switch env | `ASSET_LOOKUP_LIVE=1` |
| Endpoint env | `ASSET_LOOKUP_URL` (**required** when live) |
| Token env | `ASSET_LOOKUP_TOKEN` (optional bearer) |
| Method | `POST` |
| Request headers | `Content-Type: application/json`, `Accept: application/json`, `Authorization: Bearer <token>` (if token set) |
| Request body | `{"query": "<q>"}` where `<q>` is a host id (`web-01`), a CIDR (`10.0.0.0/24`), a bare IP, or `*` |
| Response body | `{"surface": {"hosts":[…],"trust_edges":[…]}}` **or** a bare `{"hosts":[…],"trust_edges":[…]}` |
| `host` shape | `id`, `subnet`, `internet_exposed`, `services:[{port,proto,name,known_vuln,cve_id}]` |
| `trust_edge` shape | `{src, dst, kind}` (e.g. `ssh_key_reuse` / `shared_admin_cred` / `flat_network` / `service_account`) |
| Timeout / max body | 10 s / 8 MiB |
| On success | `{"ok":true,"source":"live","query":"<q>","surface":{…}}` |

`hosts` and `trust_edges` must each be a list (a non-list is an
`upstream_error`). `known_vuln` defaults to `false` and `cve_id` to `null` if
absent — the client never *fabricates* a vulnerability.

---

### 2c. `enrich_ioc` — IOC reputation / threat-intel

**Backend contract**

| Field | Value |
|---|---|
| Switch env | `ENRICH_IOC_LIVE=1` |
| Endpoint env | `ENRICH_IOC_URL` (**required** when live) |
| Token env | `ENRICH_IOC_TOKEN` (optional bearer) |
| Method | `POST` |
| Request headers | `Content-Type: application/json`, `Accept: application/json`, `Authorization: Bearer <token>` (if token set) |
| Request body | Always the batch form: `{"indicators": ["203.0.113.66", …]}` (a single-indicator call still sends a one-element list) |
| Response body | `{"results": {"<indicator>": {…rec…}}}` **or** a flat `{"<indicator>": {…rec…}}` |
| `rec` shape | `type` (`ip`/`domain`/`sha256`), `known` (bool), `threat_category` (or alias `category`), `confidence`, `first_seen`, `related_hosts` (or alias `relates_to`), `verdict` (`malicious`/`suspicious`/`benign`/`unknown`) |
| Timeout / max body | 10 s / 4 MiB |
| On success | `{"ok":true,"source":"live","results":{…}}` |

The client normalizes **per requested indicator**: an indicator your backend
omits degrades to `known:false` / `verdict:"unknown"` (never a missing key or a
crash). If you don't send an explicit `verdict`, the client derives one from
`threat_category`+`confidence` using the same policy as the offline stub.

---

### 2d. `ops_query` — read-only multi-account operations

**Backend contract**

| Field | Value |
|---|---|
| Switch env | `OPS_QUERY_LIVE=1` |
| Endpoint env | `OPS_QUERY_URL` (**required** when live) |
| Token env | `OPS_QUERY_TOKEN` (optional bearer) |
| Method | `POST` |
| Request headers | `Content-Type: application/json`, `Accept: application/json`, `Authorization: Bearer <token>` (if token set) |
| Request body | Exactly one selector: `{"account":"000000000000"}` (12-digit id) · `{"query":"*"}` (estate-wide) · `{"finding_type":"public_s3"}` |
| Response body | account/wildcard → `{"accounts":[…]}`; finding_type → `{"findings":[…]}` |
| Timeout / max body | 10 s / 4 MiB |
| On success (accounts) | `{"ok":true,"source":"live","accounts":[…]}` |
| On success (findings) | `{"ok":true,"source":"live","finding_type":"<t>","findings":[…]}` |

The reply must be a JSON object carrying the list field matching the selector
(`accounts` for account/wildcard, `findings` for finding_type). A missing or
non-list field is an `upstream_error`.

---

## 3. Worked example — wire a SIEM in ~15 minutes

Goal: replace the mock SIEM with a real one at a placeholder endpoint
`https://siem.example.internal`. The other three seams follow the identical
pattern (swap the env prefix and body/response shape from the tables above).

### Step 1 — implement the backend contract (any language)

Your SIEM adapter must accept a `POST` with a single-selector JSON body and
return `{"events":[…]}` in the 10-field shape. A minimal reference adapter:

```python
# siem_adapter.py — a thin shim from sentinel-harness's siem_query contract to YOUR SIEM.
# Run behind TLS at https://siem.example.internal/agentcore/siem_query
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

def query_your_siem(selector: dict) -> list[dict]:
    # selector is exactly one of: {"host":...} {"technique":...} {"severity":...}
    #                             {"alert_id":...} {"since":...} {"query":"*"}
    # Translate to your SIEM's query language, then map each hit into this shape:
    return [{
        "alert_id": "alert-1001",
        "ts": "2026-06-28T14:03:11Z",
        "severity": "critical",
        "rule_name": "Log4Shell JNDI Exploit Attempt",
        "host": "web-01",
        "src_ip": "203.0.113.66",       # RFC 5737 documentation IP
        "dst_ip": "192.0.2.10",         # RFC 5737 documentation IP
        "technique": "T1190",
        "summary": "Inbound JNDI exploitation attempt against public web tier",
        "false_positive": False,
    }]

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # (Validate Authorization: Bearer <token> here against your secret.)
        n = int(self.headers.get("Content-Length", 0))
        selector = json.loads(self.rfile.read(n) or b"{}")
        body = json.dumps({"events": query_your_siem(selector)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8443), Handler).serve_forever()  # front with real TLS
```

### Step 2 — point the tool at it and flip the switch

```bash
export SIEM_QUERY_URL="https://siem.example.internal/agentcore/siem_query"
export SIEM_QUERY_TOKEN="$(cat ~/.secrets/siem_token)"   # env only — never commit
export SIEM_QUERY_LIVE=1
```

### Step 3 — smoke the seam directly (no AWS, no LLM)

```bash
uv run --no-project --python 3.13 --with . python - <<'PY'
import json
from tools.siem_query.handler import handler
print(json.dumps(handler({"technique": "T1190"}, None), indent=2))
PY
```

Expect `"source": "live"` and your events. If the backend is down you'll get a
clean `{"ok": false, "error": "upstream_error", "message": "could not reach SIEM
backend at 'https://siem.example.internal/…': …"}` — **not** a silent fall back
to the mock world. That distinction is the whole point of the seam.

---

## 4. Verify it live + keep it least-privilege

### Verify against the real triage walk

The `alert-triage` POC drives the full SIEM → IOC → asset → correlate → ticket
walk. Run it offline first (the acceptance baseline — no AWS, no network, no
LLM):

```bash
uv run --no-project --python 3.13 --with . --with boto3 \
  python scenarios/scenario_alert_triage_poc.py
# → closed:true, verdict true_positive on alert-1001; evidence/alert_triage_poc_result.json
```

Then flip the seams you've wired (`SIEM_QUERY_LIVE=1`, etc.) and re-run: the same
correlation logic now consumes your live planes. Because the live output is the
same 10-field contract as the mock, a green run against your backends is a
faithful end-to-end proof. To run it as a real *agent* (not just the tool walk),
deploy the declarative harness and gateway — see
`harnesses/alert-triage/harness.yaml`, whose `allowedTools` are an explicit
allowlist `@gateway/{siem_query,asset_lookup,enrich_ioc,create_ticket}` +
`code_interpreter`, with a human-in-the-loop gate in front of the ticket write.

For the frozen live milestone proofs (Gateway create→READY→delete on the GA API,
etc.) use the smoke suite — offline by default, opt-in live:

```bash
make smoke                        # offline: internal consistency, no AWS
SENTINEL_SMOKE_LIVE=1 make smoke  # also runs live checks IF AWS creds resolve (else SKIP, never fail-by-default)
```

### Keep it least-privilege

- **Secrets live in the env, never the repo.** The `*_TOKEN` values are read only
  from environment variables and never logged or echoed. In AgentCore, prefer the
  **Identity token vault** so the agent never sees raw third-party credentials
  (see `docs/SETUP.md`). `.gitignore` already excludes `.env*` / `*secrets*`.
- **Egress is controlled.** A live call happens only when the `*_LIVE` switch is
  set **and** the runtime network policy permits egress. Run harnesses in a VPC
  with NAT egress restricted to an allowlist of your backend hostnames.
- **The execution-role policy** in `docs/SETUP.md` deliberately omits
  `bedrock-agentcore:InvokeAgentRuntimeCommand` (it runs shell on the microVM as
  root, bypassing the LLM and `allowedTools`). Keep it omitted.
- **All four seams are read-only** except `create_ticket` (a write, which is
  HITL-gated in the alert-triage harness). Scope your backend token to read-only
  on the SIEM/CMDB/TI side.
- **Use a non-prod account** for all live runs (`AWS_PROFILE=<non-prod>`).

---

## 5. Honest note — what still needs a real account / GA type

This repo is deliberately precise about what is proven vs. what you must still
supply. For integrations specifically:

- **No bundled reference backend.** The `*_LIVE` *client* is real and unit-tested
  offline, but there is no shipped SIEM/TI/CMDB/ticketing server — you point it at
  **your** endpoint (or the adapter shim in §3). Wiring the seams to a real
  backend is the open item called out in the README roadmap.
- **You need a real account for the AWS plane.** Model invoke needs Bedrock model
  access enabled in your region; running the agent (vs. the tool walk) needs a
  deployed Gateway + execution role on a non-prod AWS account.
- **Registry / Runtime native CFN types are not GA.** The IaC synthesizes them
  (synth-only), and the Registry **control-plane API** is live-verified via
  `sentinel_harness/registry_live.py` on a non-prod account — but the native
  CloudFormation resource types are not yet generally available.
- **`CreateAgentRuntime` is blocked by an org SCP** on the primary dev account
  used for validation, so the A2A-on-Runtime path is validated where policy
  permits and documented honestly where it does not.
- **Long-term (semantic) memory extraction is asynchronous (minutes)** — a
  cross-session recall immediately after a write may return empty. Teach, wait,
  then recall.

See `docs/FIDELITY-REPORT.md` for the full self-audit and `docs/SETUP.md` for the
least-privilege policy and live-run configuration.
