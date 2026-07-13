---
name: multi-account-ops
description: Standard operating procedure for triaging security/operations findings across a multi-account estate. Use when posture or ops findings arrive from several accounts and an analyst must query them with ops_query, decide which findings are noise versus which warrant a ticket or a change, and route real ones through a human-in-the-loop gate. Keeps prioritization deterministic, groups findings by account and resource, correlates to asset context where possible, and human-gates every change or ticket action. All account identifiers used here are obviously-fictional demo ids on mock data.
---

# Multi-Account Ops Findings Triage SOP

How a security operations team triages a stream of findings spread across many accounts — the "one analyst covering the whole estate" workflow. Findings arrive from posture/ops scanners per account; the job is to separate systemic noise from the few findings that genuinely warrant a ticket or a change, and to route those through a human gate. The output is a deterministic, per-account prioritization plus a small set of human-approvable actions.

## Mock-world / honesty note

This SOP runs on **mock, offline data**. All account identifiers in examples are **obviously-fictional demo ids** — `111111111111`, `222222222222` — chosen as clearly-fake repeated-digit placeholders, NOT real 12-digit AWS account numbers, and never written in an `iam::`/`arn:` context. A `*_LIVE` opt-in is the seam to a real posture plane later; this SOP never claims to be reading a live account.

## Operating Principles

1. **Query, do not assume.** Findings come from `ops_query` over the mock multi-account world — never from guessing what an account "probably" has misconfigured.
2. **Deterministic prioritization.** Finding severity and the ticket/change decision follow fixed rules from the finding class, resource exposure, and account criticality — not intuition.
3. **Group before you act.** The same misconfiguration across 20 accounts is one systemic finding, not 20 tickets. Group by finding class and by account/resource before deciding.
4. **Assume prod when uncertain.** An account or resource of unknown criticality is treated as production.
5. **Every change is human-gated.** This SOP proposes tickets and changes; a human approves before any change is applied or any real ticket fires.

## Step 1 — Pull the findings (`ops_query`)

Query `ops_query` to enumerate findings across the scope. Bound the query by account, resource type, finding class, or severity as the tool supports. For each finding capture: the **account id** (fictional demo id), the **resource**, the **finding class** (e.g. public exposure, weak/again-open access path, missing encryption, disabled logging, drift from baseline), and the scanner-assigned **severity**.

## Step 2 — Group and deduplicate

- Group identical finding classes across accounts — a control gap present in many accounts is a **systemic finding** (one root cause, one owning team) even though it surfaces N times.
- Within an account, group by resource so a single misconfigured resource is not double-counted.
- Distinguish **new** findings from **recurring/known-accepted** ones (a documented risk acceptance is not a fresh ticket).

## Step 3 — Correlate to asset context (where possible)

Where a finding names a host/resource that the estate inventory knows, pivot to `asset_lookup` to enrich:

- **Exposure**: is the affected resource internet-facing, internal, or isolated?
- **Criticality**: crown-jewel / production / non-production (unknown → production).
- **Trust edges**: could this misconfiguration widen an existing attack path?

Findings that lack an inventory match are triaged on the finding class and account criticality alone, with the gap noted.

## Step 4 — Prioritize (deterministic)

| Condition | Priority |
|---|---|
| Exposure/access finding on an internet-facing or crown-jewel resource | P1 |
| High-severity control gap (disabled logging, public data store) on a production account | P2 |
| Systemic finding across many accounts (broad blast radius, one root cause) | P2 |
| Medium finding on a single non-prod / isolated resource | P3 |
| Recurring finding with a documented, in-date risk acceptance | Track-only |

## Step 5 — Decide: ticket, change, or track (deterministic)

- **Warrants a ticket** (open via the `incident-ticketing` SOP + `create_ticket`): any P1/P2 finding, or a systemic finding needing an owning team to drive remediation. One ticket per root cause, not per occurrence — link the affected accounts in the description.
- **Warrants a change**: a finding whose fix is a concrete configuration change (close the exposure, enable logging, tighten the access path). The change is **proposed** here and **applied only after human approval** — never applied by the agent.
- **Track-only**: P3 or documented risk-acceptance findings — log and monitor, no ticket.
- **No-action**: confirmed false positive or expected-by-design configuration — document the rationale.

## Step 6 — Human-in-the-loop gate

Every change and every real ticket write passes a human gate:

- Present the proposed change with its blast radius (which accounts/resources, what the change does, what could break) and the citing `ops_query`/`asset_lookup` results.
- The human approves, rejects, or requests narrowing. The agent applies nothing autonomously.
- When wired to a live posture/change plane (`*_LIVE` opt-in, future work), the HITL approval sits in front of the real mutation — the default here is offline and proposal-only.

## Step 7 — Emit structured output

```json
{
  "scope": {"accounts": ["111111111111", "222222222222"], "note": "fictional demo ids, mock data"},
  "findings": [
    {"account": "111111111111", "resource": "...", "class": "public-exposure",
     "severity": "high", "exposure": "internet-facing", "criticality": "production",
     "priority": "P1", "decision": "TICKET+CHANGE"}
  ],
  "systemic_findings": [{"class": "disabled-logging", "accounts": ["111111111111","222222222222"], "priority": "P2", "decision": "TICKET"}],
  "proposed_changes": [{"account": "111111111111", "change": "...", "blast_radius": "...", "requires_human_approval": true}],
  "citations": ["tool:ops_query", "tool:asset_lookup"],
  "requires_human_approval": true
}
```

## Guardrails

- Never apply a change or fire a real ticket autonomously — every mutation is human-approved; the default plane is offline/mock.
- Never write a real 12-digit account id, real hostname/IP, ARN, or secret into any field — use the fictional demo ids and mock-world identifiers only, and never in an `iam::`/`arn:` context.
- Never open one ticket per occurrence of a systemic finding — group by root cause and link the affected accounts.
- Every finding and decision traces to an `ops_query` (and optional `asset_lookup`) result or is flagged `UNKNOWN`; do not fabricate accounts, resources, or findings.
- Persist the disposition per root cause so recurring/accepted findings are handled consistently across runs.
