---
name: incident-ticketing
description: Standard operating procedure for opening and annotating a security incident ticket at the end of a triage flow. Use when a triaged finding needs to be recorded as a ticket so a human can own containment and remediation. Covers the create_ticket field contract, deterministic severity mapping, writing a defensible title/description with citations, linking back to the motivating alert/host/IOC, and the mandatory human-in-the-loop sign-off before any real tracker write fires.
---

# Incident-Ticketing SOP

How a security operations team records a triaged finding as a ticket — the terminal, *write* step of a triage flow. A ticket is where autonomous analysis stops and human ownership begins: the agent proposes a well-formed, cited ticket; a human approves it before it fires against any real tracker. The goal is a ticket that a responder can act on without re-doing the triage.

## Operating Principles

1. **A ticket is a write — human-gated.** Opening a ticket is a containment/ticketing action. The agent produces the ticket *record*; a human approves before it POSTs to a real tracker. The offline `create_ticket` mock is side-effect-free precisely so the shape can be exercised end-to-end without gating a real mutation.
2. **Deterministic severity mapping.** Ticket severity is mapped by fixed rules from the triage disposition, never re-guessed at ticket time.
3. **Cite the triage.** The description must trace the finding to the tool results that produced it (`siem_query` / `enrich_ioc` / `asset_lookup` / `nvd_lookup`). No unsupported claims in a ticket.
4. **Link back.** Always attach the motivating `related_alert_id`, `related_host`, and (where relevant) the IOC so the responder can pivot without hunting.
5. **Idempotent by content.** The same finding yields the same ticket id (content-hash `SEC-<hex>`), so re-proposing a finding de-duplicates rather than spamming the tracker.

## When to open a ticket

Open a ticket only for a finding that warrants human ownership:

- A **TRUE POSITIVE** at HIGH/CRITICAL severity from the `soc-triage` rubric.
- A **confirmed-malicious IP** touching a production/crown-jewel asset (`soc-ip-lookup` escalation).
- A **P1/P2 CVE** with affected internet-facing or crown-jewel assets (`cve-asset-triage`).
- A multi-account ops finding that warrants a change (`multi-account-ops`).

Do **not** open a ticket for a false positive (that goes to the tuning loop), a benign/expected event, or a NEEDS-MORE-INFO finding (enrich first).

## Step 1 — Assemble the finding

Gather from the upstream triage record: the disposition, the corroborating planes, the affected host(s), the motivating alert id, and any malicious indicators. If the finding is not yet a confirmed TP/escalation, stop — ticketing is not the right next step.

## Step 2 — Map severity (deterministic)

`create_ticket` accepts exactly `{"low", "medium", "high", "critical"}` — note `info` is intentionally NOT a ticket severity (you do not open a containment ticket for informational events). Map from the triage severity:

| Triage disposition / severity | Ticket severity |
|---|---|
| Confirmed compromise of crown-jewel / internet-facing prod, active exploitation | `critical` |
| TRUE POSITIVE, HIGH severity, production asset | `high` |
| TRUE POSITIVE, MEDIUM severity, or non-prod asset | `medium` |
| Low-confidence TP being tracked for monitoring | `low` |

## Step 3 — Fill the `create_ticket` field contract

```json
{
  "title": "Log4Shell exploitation attempt against web-01",   // required, <=256 chars, specific
  "severity": "critical",                                      // required enum
  "description": "Inbound JNDI payload matched CVE-2021-44228 on web-01 (internet-facing). enrich_ioc: 203.0.113.66 verdict=malicious/c2. asset_lookup: web-01 known_vuln=CVE-2021-44228. Corroborated across siem+ioc+asset.",  // required, cited
  "assignee": "secops",             // optional — team alias only, never a personal name
  "related_alert_id": "alert-1001", // optional — link back to the SIEM alert
  "related_host": "web-01"          // optional — the affected asset
}
```

Field rules:
- **title**: a specific, behavior-describing one-liner (what + where). Not "suspicious activity". Bounded to 256 chars.
- **description**: state the finding, the affected asset and its exposure, and the **citations** (which tool produced each claim). This is the responder's briefing and the audit trail. Bounded to 8192 chars.
- **severity**: the Step-2 mapping. No `info`.
- **assignee / related_alert_id / related_host**: optional, each bounded to 256 chars; use a team alias for assignee (no personal names, no account ids/ARNs).

## Step 4 — Propose, then human sign-off (HITL gate)

- Call `create_ticket` to produce the ticket record (offline: `source: "stub"`, a deterministic `SEC-<hex>` id, `status: "open"`, echoed fields).
- Present the proposed ticket to a human for sign-off **before** it is treated as a real tracker write. When wired live (`CREATE_TICKET_LIVE=1`), the HITL approval must sit in front of the real POST — the agent never fires a live ticket unattended.
- On a `validation_error` (missing required field, bad severity, over-length), fix the field and re-propose; never drop a required field to force success.

## Step 5 — Annotate and close-loop (human-owned)

- The human owner drives containment/remediation; the agent may **annotate** (append citations, link related tickets, attach the triage record) but must not mark the ticket resolved or closed autonomously.
- If new corroborating evidence arrives, update the description with the additional citation rather than opening a duplicate (content-hash de-dup already helps here).

## Step 6 — Emit structured output

```json
{
  "ticket": {
    "ticket_id": "SEC-...", "status": "open", "created_ts": "2026-...Z",
    "title": "...", "severity": "critical", "description": "...",
    "assignee": "secops", "related_alert_id": "alert-1001", "related_host": "web-01"
  },
  "source": "stub",
  "severity_mapping_rationale": "...",
  "citations": ["tool:siem_query", "tool:enrich_ioc", "tool:asset_lookup"],
  "requires_human_approval": true
}
```

## Guardrails

- Never fire a live ticket write without human sign-off; the offline mock is the default and is side-effect-free.
- Never put secrets, tokens, personal names, real hostnames/IPs, or account ids/ARNs in any ticket field — team aliases and mock-world identifiers only.
- Never auto-resolve or auto-close a ticket; closure is a human action.
- Never open a ticket for a false positive or benign event — route those to the tuning loop or document them.
- Every claim in the description must cite the tool that produced it; an uncited ticket is not defensible.
