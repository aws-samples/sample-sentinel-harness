# enrich_ioc

IOC reputation / enrichment tool for a security operations (SecOps) team. Feeds
alert triage by turning a raw indicator into a normalized reputation verdict and
a pivot back to the affected asset(s).

> **CLEARLY-LABELED MOCK DATA — POC / testing only.** This tool is *not* real
> threat intelligence and *not* a real reputation feed. Every indicator it
> scores comes from the shared fictional world in `mockdata/world.py`: RFC 5737
> documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
> `example.test` / `example.com` domains, and fabricated-but-valid-length
> SHA-256 hashes. Do not treat any verdict as a real-world judgement.

## Purpose

Given one indicator or a batch, return each indicator's reputation:

- **type** — auto-detected from shape: `ip` | `domain` | `sha256`;
- **known** — was it in the mock IOC set?
- **threat_category** — `c2` | `scanner` | `phishing` | `malware` |
  `bruteforce` | `exfiltration` | `anonymizer` | `benign` (or `None` if unknown);
- **confidence** — `high` | `medium` | `low` (or `None` if unknown);
- **first_seen** — ISO-8601 timestamp (or `None` if unknown);
- **related_hosts** — host ids the indicator was observed against (the pivot to
  `asset_lookup`), e.g. the C2 IP relates to `web-01`;
- **verdict** — `malicious` | `suspicious` | `benign` | `unknown`.

Intended to be wired into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"indicator": "203.0.113.66"}` (single) or
  `{"indicators": ["203.0.113.66", "assets.example.com", "..."]}` (batch).
  The type is auto-detected by shape; the caller does not declare it.
- `context`: Lambda-style context (unused by the stub).

## Verdict policy (deterministic)

| category               | confidence      | verdict      |
| ---------------------- | --------------- | ------------ |
| `benign`               | any             | `benign`     |
| `scanner` / `anonymizer` (low-signal) | any | `suspicious` |
| everything else        | `high`          | `malicious`  |
| everything else        | `medium` / `low`| `suspicious` |
| *(not in mock set)*    | —               | `unknown`    |

Low-signal categories (a Tor exit node, an opportunistic scanner) are capped at
`suspicious` on purpose — on their own they are not a confirmed compromise, so
triage should not auto-escalate them to `malicious`.

## The Log4Shell cross-link

The C2 IP `203.0.113.66` (tied to `alert-1001`, the Log4Shell attempt) resolves
to **`verdict: "malicious"`** with **`related_hosts: ["web-01"]`** — the spine
that lets triage pivot indicator → asset. This invariant is asserted by
`tests/test_enrich_ioc.py`.

## Input validation

- Provide exactly one of `indicator` (str) or `indicators` (`list[str]`).
- Each indicator must be a non-empty string ≤ 256 chars; a batch is ≤ 256 items.
- Each indicator must classify as an IP, a domain, or a 64-char SHA-256 hash;
  an unrecognizable shape (blank, junk, non-string) is a `validation_error`,
  never a silent unknown.
- An indicator that classifies fine but is simply **not in the mock set** is not
  an error — it returns `known: false` / `verdict: "unknown"`.

## What is real vs. stubbed

- The **offline reputation is real, deterministic data** — the same indicator
  always yields the same category/confidence/verdict/related_hosts. It is
  *synthetic* (from `mockdata.world`), but nothing is fabricated at call time.
- The **live path is a documented, guarded stub**: with `ENRICH_IOC_LIVE=1` it
  raises an explicit `upstream_error` until a concrete reputation backend
  (VirusTotal / GreyNoise / internal TIP) is wired in later. It **never**
  silently falls back to the mock data.

## Egress & secrets control

- Egress happens only when `ENRICH_IOC_LIVE=1` and the runtime network policy
  permits it. Default mode makes no outbound calls.
- Optional `ENRICH_IOC_URL` / `ENRICH_IOC_TOKEN` are read from the environment
  only — never hardcoded or logged.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python handler.py
```
