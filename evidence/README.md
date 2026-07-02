# Evidence — live validation

These are **captured results from real runs** against the GA Amazon Bedrock AgentCore
Harness API on a **non-production dev account**. Account IDs have been scrubbed to
`<ACCOUNT_ID>`. Each `*_result.json` is written by the matching script in
`scenarios/`; each `*.log` is the raw run log. Proof, not claims.

## Scenario 1 — CVE triage with a human-in-the-loop gate
`scenarios/scenario_cve_triage.py` → `cve_triage_result.json`

| Check | Result |
|---|---|
| `hit_human_review_gate` | ✅ `true` — the agent called `request_human_review` and stopped (`stopReason=tool_use`) before recommending anything |
| `did_deterministic_calc` | ✅ `true` — used the code interpreter for the affected-asset math instead of guessing |

One harness combines a code interpreter, an `inline_function` human gate, and managed
memory — **zero orchestration code**. Security decisions are not made by the AI alone.

## Scenario 2 — Multi-harness parallelism + supervisor
`scenarios/scenario_multi_harness.py` → `multi_harness_result.json`

| Check | Result |
|---|---|
| pattern | multi-harness parallel + supervisor synthesis |
| **parallel speedup vs serial** | ✅ **~2.6×** (3 specialist harnesses run concurrently; a supervisor merges them) |

This is the answer to "a harness is single-agent": parallelism comes from running
**multiple** harnesses and synthesizing. (Speedup varies run to run with model latency.)

## Scenario 3 — Detection generation with an independent adversarial reviewer
`scenarios/scenario_detection_gen.py` → `detection_gen_result.json`

| Check | Result |
|---|---|
| `generator_and_reviewer_are_separate_harnesses` | ✅ `true` — generator and reviewer are distinct harnesses |
| `reviewer_emitted_parseable_verdict` | ✅ `true` — the reviewer now leads its reply with `VERDICT: approve` / `VERDICT: revise` (verdict-first, so it survives truncation) followed by concrete issues |
| `no_stray_shell_tool` | ✅ `true` — `allowedTools` scoped to only the gate kept the built-in `shell` off |
| `publish_correctly_controlled` | ✅ nothing reaches production except through the human gate — an **approve** routes through `request_publish_approval`; a **revise** withholds publish (the publisher correctly refuses to advance a rejected rule) |

Demonstrates generation ≠ evaluation end-to-end: an **independent** reviewer harness (no
self-approval bias) emits a real verdict, and the flawed rule is **stopped** — exactly the
point. On an `approve` run the human publish gate fires instead. Either path is safe.

### HITL, full pause → approve → resume
`scenarios/scenario_hitl_resume.py` → `hitl_resume_result.json`

| Check | Result |
|---|---|
| `paused_on_gate` / `captured_tool_use` | ✅ harness paused on `request_containment_approval`; the call (toolUseId + input) was reconstructed |
| `resumed_and_finished` | ✅ resumed the same session via the two-message `toolUse`→`toolResult` contract |
| `closed_hitl_loop` | ✅ `true` — analyst approval flowed back and the agent delivered a human-sanctioned final action |

### Play Mode adversary emulation (Layer 2)
`scenarios/scenario_play_mode.py` → `play_mode_result.json`

| Check | Result |
|---|---|
| `every_step_gated` | ✅ every offensive `exec_technique` step paused on a human gate |
| `approved_step_resumed` / `reject_halts_plan` | ✅ approve resumes the session; a rejection halts the plan |
| `checkpoint_roundtrip` / `closed_loop` | ✅ plan state checkpointed to JSON and round-tripped; **no real system touched** (simulated no-ops) |

## Honest limitations (as observed live)

- **Long-term memory extraction is asynchronous (minutes-scale).** A cross-session
  semantic recall issued seconds after a write can return empty. In demos: teach → wait
  → recall. This is expected behavior, not a defect.
- **A single harness is single-agent.** Multi-agent orchestration/graph/hooks are not
  native; use multiple harnesses + a supervisor (shown here), or export to Strands code
  and run on AgentCore Runtime.

## Reproduce

```bash
export AWS_PROFILE=<non-prod>; export SENTINEL_REGION=us-east-1
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<role>"
python scenarios/scenario_cve_triage.py
python scenarios/scenario_multi_harness.py
python scenarios/scenario_detection_gen.py
sentinel cleanup sentinel_        # tear down
```
