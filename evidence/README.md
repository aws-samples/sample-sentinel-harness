# Evidence — live validation

These are **captured results from real runs** against the GA Amazon Bedrock AgentCore
Harness API on a **non-production dev account**. Account IDs have been scrubbed to
`<ACCOUNT_ID>`. Each `*_result.json` is written by the matching script in
`scenarios/`; each `*.log` is the raw run log. Proof, not claims.

> **Scope of this file.** The sections below walk the **core Layer-1 scenarios** in
> detail. The repo now ships **22 evidence artifacts** across 15 scenarios plus two
> live on-account captures (`live_verify_result.json`, `live_a2a_runtime_result.json`).
> For the full, current per-scenario ledger see the **Scenarios & evidence** table in
> the [root README](../README.md#-scenarios--evidence); every `evidence/*_result.json`
> here is written by the matching `scenarios/scenario_*.py`.

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
| `generator_and_reviewer_are_separate_harnesses` | ✅ `true` — generator and reviewer are distinct harnesses (independent judgment, no self-approval bias) |
| `reviewer_reached_independent_verdict` | ✅ `true` — verdict `revise`, backed by concrete objections: `/.ssh/known_hosts` read by legit SSH-cloning npm scripts, `/run/secrets/` k8s mounts, over-broad substring matches (`private_key`, `server.key`), and a real logic gap — `ParentImage`/`Image` are *process* fields but the rule's `logsource.category: file_event` makes them EDR-dependent/often absent |
| `no_stray_shell_tool` | ✅ `true` — `allowedTools` scoped to only the gate kept the built-in `shell` off |
| `publish_correctly_controlled` | ✅ `true` — the flawed rule was **withheld from publish**; the only path to production is the human `request_publish_approval` gate |

Demonstrates generation ≠ evaluation end-to-end: an **independent** reviewer harness reached
a substantively-correct `revise`, and the flawed rule is **stopped** before any publish. On
an `approve` run the human publish gate fires instead — either path is safe.

**Transport honesty (`verdict_via_structured_tool: false` this run).** The reviewer is given a
structured `submit_review_verdict` tool (deterministic to parse) and the publisher a
`request_publish_approval` gate. On this run the model chose to express both as *final prose*
(the reviewer wrote its analysis; the publisher wrote a `<tool_call>…` block with
`stop_reason=end_turn`) rather than emit a real `toolUse` invocation — a known model-behavior
quirk that `allowedTools` scoping narrows but does **not** force. That is why the scenario
defines success on the **substance** (an independent verdict was reached + the flawed rule was
withheld + no stray shell), with a robust prose parser (`parse_verdict`) as the fallback and
the structured-tool path as a best-effort fast-path. `core._consume_stream`'s structured-call
reconstruction is unit-tested (`test_structured_verdict_reconstructed_from_stream`) so a real
tool invocation *is* captured deterministically when the model does emit one.

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
