---
name: soc-ip-lookup
description: Standard operating procedure for triaging a single suspicious IP address in a SOC. Use when an IP arrives from an alert, firewall log, or threat feed and an analyst must decide whether it is malicious, whether it touched any asset in the estate, and whether to escalate or contain. Uses enrich_ioc for the reputation verdict and asset_lookup to establish whether the IP relates to a known host, keeps the verdict deterministic, applies collateral-damage checks for shared infrastructure, and human-gates any block or containment.
---

# Suspicious-IP Triage SOP

The fast-path an analyst runs on a single IP: is it bad, did it touch us, and what do we do next. This is the IP-specific, operational sibling of the broader `ioc-vetting` SOP — narrower, quicker, and explicit about the asset-relation and escalate/contain decision. The goal is to avoid both missed intrusions and self-inflicted outages from blocking shared cloud/CDN infrastructure.

## Operating Principles

1. **Reputation via `enrich_ioc`, never by connecting.** Get the verdict from `enrich_ioc`. Never resolve-and-connect to the IP, port-scan it, or fetch content from it.
2. **Deterministic verdict.** The disposition is a function of the `enrich_ioc` verdict/confidence and the asset relation — not analyst intuition.
3. **Asset relation matters.** An IP's meaning changes entirely depending on whether it touched a crown-jewel or an isolated test box — always resolve the relation via `asset_lookup`.
4. **Collateral-damage check is mandatory.** Before recommending a block, confirm the IP is not shared cloud/CDN/NAT infrastructure whose block would cause an outage.
5. **Containment is human-gated.** This SOP recommends escalate / contain / monitor; a human approves before any block or isolation fires.

## Step 1 — Validate and classify the IP

- Validate it is a well-formed IPv4/IPv6 address; reject malformed input as a `validation_error`.
- Note if it is RFC1918/private, a documentation range, shared cloud/CDN space, or a known egress/NAT/proxy — this drives the collateral check in Step 4.

## Step 2 — Reputation lookup (`enrich_ioc`)

Call `enrich_ioc` with the IP. Read:

| Field | Use |
|---|---|
| `verdict` | malicious / suspicious / benign / unknown |
| `known` | was it in the reputation set at all |
| `threat_category` | c2 / scanner / phishing / malware / … |
| `confidence` | high / medium / low |
| `first_seen` | age / recency of the badness |
| `related_hosts` | hosts the IP was seen against — the bridge to Step 3 |

An IP not in the set returns `known: false` / `verdict: "unknown"` — that is a valid result, not a failure. Do not invent a score for it.

## Step 3 — Establish the asset relation (`asset_lookup`)

Take the `related_hosts` from Step 2 (and any host from the originating alert) and query `asset_lookup` for each:

- **Exposure** of the touched host: internet-facing / internal / isolated.
- **Criticality**: crown-jewel / production / non-production (unknown → production).
- **Trust edges** outward from the touched host — what the IP's foothold could reach if the contact was a real compromise.

If the IP relates to **no known asset**, the incident is lower-urgency (external noise) but still logged. If it relates to a **crown-jewel or internet-facing production host**, urgency rises regardless of confidence band.

## Step 4 — Collateral-damage / false-positive checks (mandatory)

- **Shared infrastructure**: is the IP cloud/CDN/hosting/SaaS shared space? Blocking it risks collateral outage — recommend blocking the specific service/domain, not the raw IP.
- **Egress / NAT / scanner**: known egress, NAT, proxy, or a security-vendor scanner is likely a false positive in an inbound context.
- **Own/partner infrastructure**: if `asset_lookup` shows the IP belongs to your or a partner's estate, it is a hard false positive.

A failed check downgrades the disposition or narrows the recommended scope from "block" to "monitor / narrow-scope".

## Step 5 — Disposition and escalate/contain decision (deterministic)

| enrich_ioc verdict + confidence | Asset relation | Disposition | Recommendation |
|---|---|---|---|
| malicious (high), collateral check passed | touched crown-jewel / prod host | CONFIRMED-MALICIOUS | **ESCALATE to incident + CONTAIN** (block IP + isolate host) → human approval |
| malicious (high), collateral check passed | touched non-prod / no asset | MALICIOUS | **BLOCK** candidate → human approval |
| suspicious / medium | touched any asset | SUSPICIOUS | **MONITOR + hunt** related activity; narrow-scope block only with approval |
| any verdict | shared-infra / own-infra (check failed) | LIKELY FALSE POSITIVE | **NO-ACTION / narrow-scope**; document rationale |
| benign | any | BENIGN | **NO-ACTION** (allowlist if it keeps re-alerting) |
| unknown | touched crown-jewel / prod | UNKNOWN | **ESCALATE for enrichment** (treat cautiously) |
| unknown | no asset relation | UNKNOWN | **MONITOR**; re-check later |

**When to escalate to an incident**: a malicious/suspicious verdict that touched a production or crown-jewel asset, OR any confirmed inbound success against an internet-facing host. Escalation opens an incident ticket (see the `incident-ticketing` SOP). **When to contain**: only after escalation and human approval — containment is a mutating action.

## Step 6 — Emit structured output

```json
{
  "ip": "<value>",
  "enrich": {"verdict": "...", "known": true, "threat_category": "...",
             "confidence": "...", "first_seen": "...", "related_hosts": ["..."]},
  "asset_relation": [{"host": "...", "exposure": "...", "criticality": "..."}],
  "collateral_checks": [{"check": "shared-infra", "result": "pass|fail", "note": "..."}],
  "disposition": "CONFIRMED-MALICIOUS|MALICIOUS|SUSPICIOUS|BENIGN|UNKNOWN|LIKELY_FALSE_POSITIVE",
  "recommendation": "ESCALATE|CONTAIN|BLOCK|MONITOR|NO-ACTION|NARROW-SCOPE",
  "escalate": false,
  "citations": ["tool:enrich_ioc", "tool:asset_lookup"],
  "requires_human_approval": true
}
```

## Guardrails

- Never connect to, scan, resolve-and-fetch from, or otherwise touch the IP — reputation lookup only.
- Never auto-block or auto-isolate; blocking shared infrastructure can cause outages, so containment is always human-approved.
- Prefer the narrowest scope: block a specific service/host over a shared IP.
- An `unknown` IP is not a benign IP — if it touched a crown-jewel, escalate for enrichment rather than dismissing it.
- Persist the verdict + asset relation to memory so repeat sightings of the same IP are consistent.
