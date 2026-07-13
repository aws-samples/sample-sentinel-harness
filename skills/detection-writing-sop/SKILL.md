---
name: detection-writing-sop
description: Standard operating procedure for writing a Sigma or YARA detection rule and self-checking it before it goes to adversarial review. Use when authoring a new detection for a technique, log source, or malware family. Covers hypothesis framing, choosing Sigma vs YARA, rule structure, false-positive scoping, a deterministic lint pass, and a mandatory self-review checklist so the rule is defensible before a reviewer or human sign-off.
---

# Detection-Writing SOP

How a security operations team authors a detection rule that survives adversarial review. The goal is a rule that is **specific enough to matter, general enough to catch variants, and honest about its false-positive surface** before anyone else looks at it.

## Operating Principles

1. **Every rule starts from a hypothesis.** State the adversary behavior you are trying to catch and why the chosen signal reveals it. No hypothesis, no rule.
2. **Deterministic lint is not optional.** Syntax/schema validation runs through the `sigma_yara_lint` tool (pure, no model judgment) before self-review.
3. **Self-review before adversarial review.** You must complete the self-check below. The adversarial reviewer's job is to find what you missed, not what you skipped.
4. **Ground it in a real technique.** Map to a public reference (e.g. MITRE ATT&CK technique ID, a public CVE, or a documented malware family). Generic public examples only.
5. **Publishing is human-gated.** This SOP produces a *candidate* rule; a human approves before it goes live.

## Step 1 — Frame the hypothesis

Write these three lines before touching rule syntax:

- **Behavior**: what the adversary does (e.g. "spawns `cmd.exe` from an Office process" → ATT&CK T1059).
- **Signal**: the observable that reveals it (process-creation event with specific parent/child, a file byte pattern, a network indicator).
- **Assumption**: what must be true for the signal to fire, and what benign activity shares it.

## Step 2 — Choose the rule type

| Use | When |
|---|---|
| **Sigma** | Log/event-based detection (process creation, auth, DNS, cloud audit logs, EDR telemetry). Generic and back-end agnostic. |
| **YARA** | File/memory content matching — malware families, packers, embedded strings, byte patterns in samples. |

If the behavior is best seen in *events*, write Sigma. If it lives in *file/memory bytes*, write YARA. If both, write two rules, not one hybrid.

## Step 3 — Write the rule

### Sigma structure

```yaml
title: <Concise, behavior-describing title>
id: <UUID>
status: experimental
description: <what it detects and the hypothesis>
references:
  - <ATT&CK technique URL / advisory / public writeup>
tags:
  - attack.txxxx           # ATT&CK technique
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    Image|endswith: '\cmd.exe'
  filter_benign:
    CommandLine|contains:
      - '<known-benign pattern>'
  condition: selection and not filter_benign
falsepositives:
  - <named benign scenario 1>
  - <named benign scenario 2>
level: high
```

Rules:
- Anchor string matches (`endswith`/`startswith`) instead of bare `contains` where possible — reduces evasion and FP.
- Model the `filter_*` / whitelist blocks explicitly; an empty FP list is a red flag, not a clean rule.
- `level` must match the hypothesis, not aspiration.

### YARA structure

```
rule Family_Behavior_Descriptor
{
    meta:
        author = "secops"
        description = "<what it matches + hypothesis>"
        reference = "<public sample hash / writeup>"
        date = "YYYY-MM-DD"
    strings:
        $s1 = "unique-string" ascii wide
        $b1 = { E8 ?? ?? ?? ?? 6A 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*, $b*)
}
```

Rules:
- Prefer multiple weak indicators combined in `condition` over one broad string.
- Gate with a file-type magic check (`uint16(0) == 0x5A4D` for PE) to cut FPs.
- Avoid strings that appear in legitimate libraries/toolchains.

## Step 4 — Scope false positives

- List concrete benign sources that could trigger the rule (admin tooling, backup jobs, CI runners, security scanners).
- Encode the safe ones as explicit filter/whitelist conditions — do not silently rely on tuning later.
- Estimate FP volume qualitatively (rare / occasional / noisy). Noisy rules need a tighter condition or a correlation, not a higher `level`.

## Step 5 — Deterministic lint

Run `sigma_yara_lint`. Fix every error and warning. This validates:
- Schema/syntax correctness.
- Field names exist for the declared log source (Sigma).
- Condition references only defined selections/strings.
- No unused selections or dangling identifiers.

A rule that does not lint clean does not proceed.

## Step 6 — Self-review checklist (mandatory before adversarial review)

- [ ] Hypothesis (behavior/signal/assumption) is written and the rule matches it.
- [ ] Mapped to a public technique/CVE/family reference.
- [ ] Correct rule type for the data (Sigma for events, YARA for files/memory).
- [ ] `falsepositives` / benign scenarios are named, not empty.
- [ ] Explicit filter/whitelist conditions for known-benign activity.
- [ ] String/byte matches are anchored/specific — not trivially evadable, not trivially over-broad.
- [ ] `level`/severity matches the actual hypothesis.
- [ ] `sigma_yara_lint` passes with zero errors and zero warnings.
- [ ] I can name at least one variant this rule would catch AND one it would miss (evasion honesty).

## Step 7 — Hand off

Emit the candidate rule plus a short rationale (hypothesis, references, known FP sources, self-review notes). It then goes to the adversarial reviewer and, on approval, to a human publish gate. Do not mark a rule production-ready yourself.

## Guardrails

- Never author a rule against a private/internal detail; use generic public techniques and examples only.
- Do not download live malware to build a YARA rule — reference public sample hashes and writeups via `web_search`.
- If you cannot name the false-positive surface, the rule is not ready — say so rather than shipping a blind rule.
