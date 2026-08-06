# nvd_lookup

CVE metadata lookup tool template for a security operations (SecOps) team.

> **CLEARLY-LABELED MOCK DATA for POC / testing only.** By default this returns a
> deterministic **stub** (`"source": "stub"` in every reply), **not** real NVD data —
> the CVSS scores and severities below are fictional and must never drive a real
> patch-or-defer decision. Set `NVD_LIVE=1` (plus an egress policy that permits it)
> to query the real NVD; the reply then carries `"source": "nvd"`. Always branch on
> the `source` field rather than assuming.

## Purpose

Given a CVE identifier, return vulnerability metadata (description, CVSS v3
score/severity, CWE identifiers, references). **Under `NVD_LIVE=1`** that metadata is
authoritative, sourced from the NVD (National Vulnerability Database); by default it is
the fictional stub described above. Intended to be wired into an Amazon Bedrock
AgentCore Gateway as an MCP target.

The conditional wording is deliberate, not pedantry: this sentence used to state that
claim unconditionally while the default reply carries `"source": "stub"`. A reader who
believed it would treat a fictional CVSS score as grounds to defer a real patch.

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
