# attack_lookup

MITRE ATT&CK technique lookup tool template for a security operations
(SecOps) team.

## Purpose

Map observed behavior to the MITRE ATT&CK framework. Given a technique id
(`T1059`) or sub-technique id (`T1059.001`), return the name, tactic(s), a
short description, applicable platforms, and reference links. Useful for
alert enrichment and detection engineering. Wire it into an Amazon Bedrock
AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"technique_id": "T1059.001"}`
- `context`: Lambda-style context (unused by the stub).

## Input validation

- `technique_id` must be a non-empty string matching `Tnnnn` or
  `Tnnnn.nnn`. Input is normalized to upper case. Invalid input returns
  `validation_error`.

## Offline / stubbed by default

- Ships with an offline slice of the public ATT&CK Enterprise matrix
  (execution, initial-access, discovery, supply-chain examples). No network
  I/O by default.
- Set `ATTACK_LIVE=1` to download and parse the full ATT&CK STIX bundle from
  the public MITRE CTI repository.

## Egress & secrets control

- Egress only when `ATTACK_LIVE=1` and the network policy permits it.
- ATT&CK data requires no credentials; no secrets are read or stored.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No hardcoded account IDs or ARNs.

## Run locally

```bash
python handler.py
```
