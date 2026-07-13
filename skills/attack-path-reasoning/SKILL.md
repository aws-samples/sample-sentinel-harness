---
name: attack-path-reasoning
description: Standard operating procedure for reasoning about attack paths from exposed assets using the MITRE ATT&CK framework. Use when analyzing how an adversary could move from an internet-facing or exposed asset toward crown-jewel targets, to enumerate plausible paths, map each step to ATT&CK tactics/techniques, rate likelihood and impact, and recommend where to break the chain. Grounds every technique in ATT&CK, keeps scoring deterministic, and treats offensive validation as human-gated.
---

# Attack-Path Reasoning SOP

How a security operations team reasons about the routes an adversary could take from an exposed asset to a high-value target. Output is a prioritized set of attack paths, each mapped to MITRE ATT&CK, with the cheapest effective chokepoint to break the chain. This is analytical reasoning — not live exploitation.

## Operating Principles

1. **ATT&CK-driven.** Every step in a path maps to an ATT&CK tactic and technique ID. Use `attack_lookup` for canonical technique data; do not invent technique IDs.
2. **Assets and reachability from inventory.** Base reachability on the asset inventory / network model (`asset_lookup`), not assumptions. Unknown reachability → assume reachable and flag it.
3. **Deterministic scoring.** Likelihood and impact tiers follow fixed rules from exposure, exploitability, and target value — not intuition.
4. **Reasoning, not execution.** This SOP describes *possible* paths. Any live validation (BAS, scanning, exploitation) is a separate, human-gated activity — never triggered here.
5. **Assume prod / crown-jewel when uncertain.** If a target's value is unknown, treat it as high-value.

## Step 1 — Establish the terrain

- **Entry points**: internet-facing or externally-exposed assets (from `asset_lookup`) — the path origins.
- **Crown jewels**: high-value targets (identity providers, key stores, data stores, admin planes, payment/settlement systems) — the path destinations.
- **Topology**: trust relationships, network reachability, shared credentials/roles, and identity boundaries between them.

## Step 2 — Model the kill chain per path

For each entry point, walk the ATT&CK tactics in order and ask "what technique enables the next hop?":

| Tactic | Question |
|---|---|
| Initial Access | How does the adversary land on the exposed asset? (e.g. T1190 Exploit Public-Facing Application — think Log4Shell; T1078 Valid Accounts; supply-chain via a compromised npm/package dependency, T1195.002) |
| Execution | How do they run code? (T1059 Command/Scripting) |
| Persistence / Priv-Esc | How do they stay / gain rights? (T1547, T1068) |
| Credential Access | What secrets are reachable? (T1552 Unsecured Credentials, T1555) |
| Discovery | What can they enumerate? (T1046 Network Service Discovery, T1087) |
| Lateral Movement | How do they hop toward the crown jewel? (T1021 Remote Services, T1550 Use Alternate Auth Material) |
| Collection / Exfil / Impact | What is the objective at the target? (T1005, T1041, T1486) |

Confirm each technique via `attack_lookup` (tactic, description, common data sources, detections). A path is an ordered list of `(tactic, technique_id, hop_from → hop_to)` steps.

## Step 3 — Enumerate candidate paths

- Generate the plausible distinct routes from each entry point to each crown jewel.
- Prefer the *shortest* and *cheapest* paths (fewest hops, lowest required privilege) — those are what an adversary picks first.
- Note where multiple paths share a common hop (an asset or credential) — shared hops are high-value chokepoints.

## Step 4 — Score each path (deterministic)

**Likelihood** — driven by the weakest (easiest) step in the chain:
- **HIGH**: entry via a known-exploited public vuln (KEV) or valid-account reuse, AND no strong control on any hop.
- **MEDIUM**: requires privilege escalation or a non-trivial lateral hop, but the techniques are commodity.
- **LOW**: requires multiple hardened hops, unique conditions, or controls that must each fail.

**Impact** — driven by the destination's value:
- **CRITICAL**: crown jewel (identity provider, key/secret store, admin plane, core data/settlement system).
- **HIGH**: production system with sensitive data or broad blast radius.
- **MEDIUM/LOW**: limited-value target.

**Priority** = combination: `HIGH likelihood + CRITICAL impact` = P1; degrade from there. A short path to a crown jewel outranks a long path to a minor asset.

## Step 5 — Identify the chokepoint to break the chain

For each high-priority path, find the single cheapest control that severs it:

- **At the entry**: patch/mitigate the exposed vuln (see the CVE triage SOP), reduce exposure, or add auth.
- **At a lateral hop**: segmentation, removing shared credentials/roles, phishing-resistant MFA, least-privilege.
- **At the target**: encryption, access controls, monitoring on the crown jewel.

Prefer chokepoints on **shared hops** — one control that breaks multiple paths gives the best return. Map each recommended control to the ATT&CK technique(s) it mitigates and to a detection opportunity (a data source / event that would reveal that step — feeds detection authoring).

## Step 6 — Emit structured output

```json
{
  "paths": [
    {
      "path_id": "P1",
      "entry_point": "<asset>",
      "target": "<crown-jewel>",
      "steps": [
        {"tactic": "Initial Access", "technique": "T1190", "hop": "internet -> web-tier"},
        {"tactic": "Credential Access", "technique": "T1552", "hop": "web-tier -> creds"},
        {"tactic": "Lateral Movement", "technique": "T1021", "hop": "web-tier -> identity-plane"}
      ],
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "priority": "P1|P2|P3",
      "chokepoint": {"hop": "...", "control": "...", "mitigates": ["T1552","T1021"]},
      "detection_opportunities": ["<data source / event per step>"]
    }
  ],
  "shared_chokepoints": [{"hop": "...", "breaks_paths": ["P1","P3"], "control": "..."}],
  "assumptions": ["reachability assumed where inventory incomplete"],
  "citations": ["tool:asset_lookup", "tool:attack_lookup"],
  "requires_human_review": true
}
```

## Guardrails

- Never execute any step. No scanning, no exploitation, no credential use — this is reasoning only. Live validation goes through a separate, human-approved, sandboxed process.
- Every technique ID must be confirmed via `attack_lookup`; flag any step you cannot map to a real ATT&CK technique.
- Use generic, public examples (Log4Shell / T1190, npm supply-chain / T1195.002, network scanning / T1046). No private topology details in examples.
- Feed the `detection_opportunities` and `chokepoint` outputs into the detection-writing and CVE-triage workflows to close the loop.
