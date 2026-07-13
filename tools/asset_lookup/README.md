# asset_lookup

Exposure / asset-surface lookup tool template for a security operations (SecOps)
team. Feeds the attack-path reasoning specialist (`specialists/attack-mapper`).

## Purpose

Given an asset or subnet query, return the **exposure surface** the attack-path
reasoner works over:

- **hosts** — id, subnet, whether internet-exposed;
- **services** — per host: port, proto, name, a `known_vuln` flag and optional
  `cve_id`;
- **trust_edges** — directed pivot edges (`ssh_key_reuse`, `shared_admin_cred`,
  `flat_network`, `service_account`) that turn a single foothold into a chain.

Intended to be wired into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"query": "10.0.0.0/24"}` — a CIDR subnet, a single host id
  (`"web-01"`), or `"*"` for the whole known surface.
- `context`: Lambda-style context (unused by the stub).

## Input validation

- `query` must be a non-empty string ≤ 128 chars.
- A `/`-bearing or bare-IP query must parse as a valid network (bad CIDR →
  `validation_error`, never a silent empty result).
- A host-id query must be alphanumeric plus `-_.`.
- Anything else returns a `validation_error`.

## What is real vs. stubbed

- The **offline surface is real, deterministic data** — the same query always
  yields the same hosts/services/edges. It is *synthetic* (no real environment),
  but nothing is fabricated at call time.
- The **live path is a documented, guarded stub**: with `ASSET_LOOKUP_LIVE=1` it
  raises an explicit `upstream_error` until a concrete backend (CMDB / asset
  inventory / scanner API) is wired in M5. It **never** silently falls back to
  fixtures.

## Offline / stubbed by default

- Runs with zero network I/O by default and returns a small synthetic three-tier
  environment: an internet-exposed, Log4Shell-vulnerable `web-01` that pivots
  (`ssh_key_reuse` → `shared_admin_cred`) to a crown-jewel `db-01`, plus a
  fully-patched `bastion-01` for negative testing.
- Set `ASSET_LOOKUP_LIVE=1` (and `ASSET_LOOKUP_URL`) to opt into a live backend.

## Egress & secrets control

- Egress happens only when `ASSET_LOOKUP_LIVE=1` and the runtime network policy
  permits it. Default mode makes no outbound calls.
- Optional `ASSET_LOOKUP_URL` / `ASSET_LOOKUP_TOKEN` are read from the
  environment only — never hardcoded or logged.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python handler.py
```
