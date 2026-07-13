# nvd_lookup

CVE metadata lookup tool template for a security operations (SecOps) team.

## Purpose

Given a CVE identifier, return authoritative vulnerability metadata
(description, CVSS v3 score/severity, CWE identifiers, references) sourced
from the NVD (National Vulnerability Database). Intended to be wired into an
Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"cve_id": "CVE-2021-44228"}`
- `context`: Lambda-style context (unused by the stub).

## Input validation

- `cve_id` must be a non-empty string matching `CVE-YYYY-NNNN` (4–19 digit
  sequence). Input is normalized to upper case. Anything else returns a
  `validation_error`.

## Offline / stubbed by default

- Runs with zero network I/O by default and returns fixture data (Log4Shell
  `CVE-2021-44228` and a generic npm supply-chain CVE ship as examples).
- Set `NVD_LIVE=1` to enable a live call to the public NVD 2.0 API.

## Egress & secrets control

- Egress happens only when `NVD_LIVE=1` and the runtime network policy permits
  it. Default mode makes no outbound calls.
- Optional `NVD_API_KEY` is read from the environment only — never hardcoded
  or logged.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No account IDs or ARNs are hardcoded.

## Run locally

```bash
python handler.py
```
