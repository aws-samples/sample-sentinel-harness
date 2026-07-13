# epss_kev

Exploitability enrichment tool template for a security operations (SecOps)
team: EPSS score + CISA KEV catalog status.

## Purpose

CVSS says how bad a vulnerability *could* be; EPSS and KEV say how likely it
is to actually be exploited. This tool enriches one or more CVEs with:

- **EPSS**: 0..1 exploitation probability plus percentile.
- **CISA KEV**: whether the CVE is in the Known Exploited Vulnerabilities
  catalog, with `date_added` and `due_date`.

Wire it into an Amazon Bedrock AgentCore Gateway as an MCP target so an agent
can prioritize remediation by real-world risk.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"cve_ids": ["CVE-2021-44228", ...]}` or `{"cve_id": "CVE-..."}`
- `context`: Lambda-style context (unused by the stub).

## Input validation

- Accepts `cve_id` (string) or `cve_ids` (list). Each id must match
  `CVE-YYYY-NNNN`. Ids are normalized and de-duplicated.
- Batch size is capped at 50 per call. Invalid input returns
  `validation_error`.

## Offline / stubbed by default

- No network I/O by default; returns fixture EPSS/KEV data.
- Set `EPSS_KEV_LIVE=1` to query the public EPSS API (first.org) and the CISA
  KEV JSON feed.

## Egress & secrets control

- Egress only when `EPSS_KEV_LIVE=1` and the network policy permits it.
- EPSS and KEV require no credentials; no secrets are read or stored.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No hardcoded account IDs or ARNs.

## Run locally

```bash
python handler.py
```
