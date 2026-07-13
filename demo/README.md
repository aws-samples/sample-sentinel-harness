# M2 self-improvement loop — runnable demo

**An agent scores, improves, and promotes an agent.**

`m2_self_improving_demo.py` is a single, narrated script that walks the whole M2
self-improvement loop and prints it step by step:

```
request  ->  weak agent answer  ->  judge scores it (FAIL, with reasons)
         ->  improve the prompt  ->  judge scores again (PASS)
         ->  human-in-the-loop APPROVE  ->  promote to a production endpoint
         ->  a REJECT path proves a passing agent is NOT promoted without a human
```

This is the *loop* at the heart of an evaluation-driven agent platform: a weak
agent is **scored by an independent LLM-judge**, improved via retry-with-reasoning
until it clears the bar, gated by a human, and only then **promoted to a
production endpoint**. A rejected agent is never promoted.

## What the demo shows

| Beat | Mechanism |
|------|-----------|
| Build an **independent** judge harness | The judge is a separate harness, so an agent cannot grade its own homework. |
| Build a **deliberately weak** agent | A one-line prompt that answers with a single useless word. |
| Score the weak answer → **FAIL** | The real `run_evaluation` tool invokes the judge and parses a structured verdict (score below the pass bar, with concrete suggestions). |
| **Self-improve** | A full-replacement prompt rewrite; the update mints a new harness version. |
| Re-score → **PASS** | The improved answer clears the pass bar (score rises 0.0 → 0.95). |
| **HITL APPROVE → promote** | `CreateHarnessEndpoint` points a `prod` endpoint at the passing agent. |
| **HITL REJECT → withhold** | The same passing agent, rejected by a human, is *not* promoted (no endpoint call). |
| **Teardown** | Endpoint is deleted before its harness (the order the control plane requires). |

The scoring is genuine: the demo loads the production `tools/run_evaluation`
handler and its **pure verdict parser** — it does not hand-roll any scoring.

## Two modes

### Offline / mock (default) — no AWS, deterministic, seconds to run

Every AWS seam is monkeypatched with an in-memory fake (the same seams the offline
test suite uses: `core.create_harness`, `core.invoke`, `core.update_harness`,
`core.wait_ready`, `core.create_harness_endpoint`, `core.get_harness_endpoint`,
`core.delete_harness`, `core.delete_harness_endpoint`, `core.new_session`,
`core.list_harnesses`). The judge's verdicts are **fixed canned replies**, so the
run is fully deterministic — no `random`, no network, no wall-clock sleeps. It
exits `0` when the loop closes end to end.

```bash
# one command, no AWS, no credentials needed:
python demo/m2_self_improving_demo.py
```

### Live — real AgentCore

`--live` (or `SENTINEL_DEMO_LIVE=1`) delegates to
[`scenarios/scenario_self_improve_loop.py`](../scenarios/scenario_self_improve_loop.py)
and runs against a real AgentCore control plane: real harnesses, real model
invokes, a real endpoint. The demo does **not** duplicate the scenario logic — it
imports and calls it.

```bash
python demo/m2_self_improving_demo.py --live
```

Live mode requires:

- AWS credentials (a non-prod profile), e.g. `AWS_PROFILE=<non-prod>`
- `SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::<account>:role/<harness-role>`
- `SENTINEL_REGION` (defaults to `us-east-1`)
- enough **InvokeHarness quota** — a heavy day can exhaust the account's invoke
  budget and return HTTP 403 on the second score. That is an environment limit,
  not a mechanism failure, and the live scenario reports it honestly rather than
  faking a score.

## Expected output (offline)

The run prints a banner, then `STEP 0` … `STEP 6`, and ends with a summary:

```
SUMMARY — what this demo proved
  [PASS] weak agent was really scored by an independent judge
  [PASS] weak agent scored BELOW the pass bar (FAIL)
  [PASS] a prompt update minted a new harness version
  [PASS] re-score rose and cleared the bar (PASS)
  [PASS] HITL APPROVE promoted the agent to a prod endpoint
  [PASS] HITL REJECT withheld promotion (no endpoint)

  loop closed end to end: True
```

Process exit code `0` on success.

## Evidence (the real proof)

The offline narrative is the *demo*; the live *proof* lives under
[`evidence/`](../evidence/):

- [`evidence/self_improve_loop_result.json`](../evidence/self_improve_loop_result.json)
  — a real run: the weak agent scored `0.0` via the independent judge, the update
  produced a new harness version, and the outcome is recorded (including an honest
  note when the second score was throttled by the account's invoke quota).
- [`evidence/endpoint_promote_result.json`](../evidence/endpoint_promote_result.json)
  — the `CreateHarnessEndpoint` promote-to-production step, validated on real
  AgentCore.

## Test

The demo is covered by an offline test that runs it in mock mode and asserts it
exits `0` and its narrative hits the beats in order:

```bash
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
    python -m pytest tests/test_m2_demo.py -q
```
