---
name: soc-triage
description: General true-positive / false-positive alert triage rubric for a SOC analyst. Use when any SIEM alert needs a disposition and the analyst must corroborate the signal across siem_query, asset_lookup, and enrich_ioc, assign a severity, decide TP/FP/benign/escalate, and feed confirmed false positives back into a whitelist tuning loop. Keeps severity and disposition deterministic, requires corroboration from at least two independent planes before a true-positive call, and human-gates any containment or ticket-closing action.
---

# SOC Alert Triage Rubric

The everyday decision an analyst makes on an incoming alert: is it a **true positive** worth acting on, a **false positive** to tune out, or **benign** expected activity — and if it is real, how severe and does it escalate. This is the general rubric that the IP-specific (`soc-ip-lookup`) and CVE-specific (`cve-asset-triage`) SOPs specialize. The goal is a consistent, auditable disposition and a feedback loop that makes tomorrow's queue quieter.

## Operating Principles

1. **Corroborate across planes.** A single signal is a lead, not a verdict. A true-positive call requires agreement across at least two independent planes: SIEM events (`siem_query`), asset context (`asset_lookup`), and IOC reputation (`enrich_ioc`).
2. **Deterministic severity & disposition.** Severity and TP/FP mapping follow fixed rules from the corroborated signals and asset criticality — never analyst mood or alert-fatigue.
3. **Assume prod when uncertain.** Unknown asset criticality → treated as production; this raises, not lowers, the severity floor.
4. **False positives are data.** A confirmed FP is not "just closed" — it feeds the whitelist/suppression tuning loop so the same noise does not return.
5. **Actions are human-gated.** This rubric produces a disposition and recommendation; containment, blocking, and ticket-closing are human-approved.

## Step 1 — Pull the alert and its context (`siem_query`)

Retrieve the alert(s) via `siem_query` — by `alert_id`, `host`, `technique`, `severity`, or `since`. Capture:

- The **ATT&CK technique** and the raw signal (what fired, on what host, when).
- Any **related indicators** (IPs, domains, hashes) named in the event.
- The **base severity** the detection assigned (this is a starting point, not the answer).

## Step 2 — Corroborate across independent planes

Build the case by checking the signal against each plane:

| Plane | Tool | Question |
|---|---|---|
| Asset | `asset_lookup` | Does the target host exist, is it exposed, how critical, does it carry a matching `known_vuln`? |
| IOC reputation | `enrich_ioc` | Do the alert's indicators resolve to a malicious/suspicious verdict? |
| SIEM breadth | `siem_query` | Are there corroborating events (same host, adjacent techniques, a sequence) or is it a lone hit? |

Count how many planes **independently support** the alert being real. Zero–one plane = weak; two+ = corroborated.

## Step 3 — Assign severity (deterministic)

Severity is driven by the corroborated technique impact **and** the target's criticality:

- **CRITICAL**: corroborated exploitation/active-compromise technique (e.g. exploit of a public-facing app, C2 beacon) against an internet-facing or crown-jewel asset, with a malicious IOC verdict.
- **HIGH**: corroborated malicious signal against a production asset, OR a critical technique against a lower-value asset.
- **MEDIUM**: single-plane suspicious signal, or a real technique against an isolated/non-prod asset.
- **LOW**: weak/benign-leaning signal, no asset impact.

Unknown criticality is treated as production and raises the tier to at least HIGH when the technique is exploitation-class.

## Step 4 — Disposition (TP / FP / benign / escalate)

| Corroboration | IOC verdict | Disposition |
|---|---|---|
| 2+ planes support, asset real & impacted | malicious / suspicious | **TRUE POSITIVE** → escalate per severity |
| 2+ planes support | benign / unknown but technique real on prod | **TRUE POSITIVE (low-confidence)** → monitor + hunt |
| 1 plane only, indicators benign / shared-infra | benign | **FALSE POSITIVE** → tune (Step 6) |
| Signal matches known expected activity (admin tooling, scanner, backup) | any | **BENIGN / EXPECTED** → document, allowlist if recurring |
| Missing data on a key plane | unknown | **NEEDS-MORE-INFO** → enrich before disposing |

**Escalate to an incident** when the disposition is TRUE POSITIVE at HIGH/CRITICAL severity, or any confirmed compromise of a production/crown-jewel asset — hand off to the `incident-ticketing` SOP.

## Step 5 — Recommend action (human-gated)

- **TRUE POSITIVE (HIGH/CRITICAL)** → ESCALATE + propose containment (block IOC / isolate host) for human approval; open an incident ticket.
- **TRUE POSITIVE (low-confidence)** → MONITOR + threat-hunt for corroborating activity.
- **FALSE POSITIVE** → propose a suppression/whitelist clause (Step 6); do not silently close.
- **BENIGN / EXPECTED** → document; allowlist if it recurs.
- **NEEDS-MORE-INFO** → enrich (`enrich_ioc` / `siem_query`) and re-run the rubric.

## Step 6 — Feedback loop (false-positive tuning)

For every FALSE POSITIVE, close the loop rather than just dismissing:

- Isolate the **discriminating benign field** (the CDN domain, the admin process, the scanner CIDR) that distinguishes this noise from a real hit.
- Propose a suppression/whitelist clause that quiets the noisy rule **without** suppressing a known true positive (over-fit guard: the clause must still fire on the TP example).
- Route the proposed clause to detection-engineering review and a human publish gate. This is where the `whitelist_optimizer` tool and the `detection-writing-sop` skill pick up.

## Step 7 — Emit structured output

```json
{
  "alert_id": "alert-1001",
  "technique": "T1190",
  "host": "web-01",
  "planes_corroborating": ["siem", "asset", "ioc"],
  "corroboration_count": 3,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "disposition": "TRUE_POSITIVE|FALSE_POSITIVE|BENIGN|NEEDS_MORE_INFO",
  "escalate": true,
  "recommendation": "ESCALATE|CONTAIN|MONITOR|TUNE|DOCUMENT|ENRICH",
  "whitelist_feedback": {"discriminating_field": "...", "guarded_true_positive": "alert-1001"},
  "citations": ["tool:siem_query", "tool:asset_lookup", "tool:enrich_ioc"],
  "requires_human_approval": true
}
```

## Guardrails

- Never declare a true positive from a single plane — a lone signal is a lead requiring corroboration.
- Never auto-close, auto-block, or auto-isolate; those are human-approved actions.
- Never silently suppress an alert to clear the queue — every FALSE POSITIVE produces a documented, over-fit-guarded tuning proposal or it stays open.
- Every field in the output traces to a tool result or is flagged `UNKNOWN`; do not fabricate hosts, techniques, or verdicts.
- Persist the disposition + rationale to memory so recurring alerts get consistent handling and the FP loop can measure noise reduction.
