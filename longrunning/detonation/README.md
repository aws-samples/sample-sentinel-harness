# detonation — sample-detonation long-running Runtime skeleton (SIMULATED)

The M3 "sample detonation" tier: a **genuinely long-running AgentCore Runtime**
that, for one sample, **acquires a fresh one-shot microVM keyed by the
`runtimeSessionId`, walks a small plan of controlled detonation steps, then
destroys the microVM after use**. Every offensive/detonation step is a
**simulated no-op that a human must approve** (Play Mode). A sample enters only by
**reference** — an `s3://` dropbox uri / dropbox id — and is **never fetched**.

> **SIMULATED / DEFENSIVE ONLY.** No real malware, no real VM/hypervisor, no real
> exploit, no network, no `subprocess`. Nothing detonates. This is an import-safe
> skeleton that models the *lifecycle* and enforces the *safety invariants*.

## What is REAL vs SIMULATED

| Concern | Status | Notes |
|---|---|---|
| One-shot microVM lifecycle (`acquire → run_action → destroy`) | **REAL** state machine | In-memory handle; using a `DESTROYED` handle raises. Destroy-after-use is enforced. |
| Destroy-after-use | **REAL / enforced** | `destroy` flips the handle to `DESTROYED`; any later `run_action` raises `VMAlreadyDestroyedError`. The entrypoint destroys in a `finally`, so it holds even on a halt/cap. |
| One-shot / no-reuse | **REAL / enforced** | `acquire` refuses a second live VM until the first is destroyed. |
| Safety gate on every action | **REAL / deterministic** | Every `run_action` is routed through `sentinel_harness.sandbox_hooks.validate_command` / `validate_path`; a path-traversal or disallowed command is **REFUSED** (`ActionRefused`) before any simulated run. |
| Sample-by-reference | **REAL / enforced** | A sample is only an `s3://` uri / dropbox id (`Sample`); a live-fetch-shaped ref (`http(s)://`, local path) is rejected. Bytes are never opened, read, downloaded, or hashed. |
| HITL Play-Mode gating | **REAL** (reused) | The plan is driven through `sentinel_harness.simulation.PlayModeRunner` via bas-runner's `BasRunnerLoop`. Reject halts; ungated step halts. |
| Long-task machinery (async-gen entrypoint, checkpoint, session-cap self-restart) | **REAL** (reused) | Same `add_async_task` + `HEALTHY_BUSY` ping + WIP-checkpoint + `SessionCapReached` restart as bas-runner. |
| The microVM itself | **SIMULATED (no-op)** | No hypervisor / Firecracker / container / `subprocess`. `acquire` mints an in-memory handle; `run_action` returns a canned deterministic "would do X" result. |
| The detonation | **SIMULATED (no-op)** | No sample code is ever executed. Ever. |
| boto3 in the default path | **NONE** | The abstraction is pure Python so it imports and unit-tests with zero cloud dependency. |

## How every offensive step is human-gated

Identical to bas-runner: the plan is driven through Play Mode. Before each
detonation step the harness **pauses on the `exec_technique` `inline_function`
gate** (`stop_reason=tool_use`); a human decision is applied:

- **APPROVE** → resume the same session (two-message `toolUse`+`toolResult`) and
  record a **simulated no-op** execution.
- **REJECT** → the plan **halts** (Play-Mode invariant). An ungated step is also a
  protocol violation and halts.

`runner_loop.py` (reused from bas-runner) owns cadence/lifetime; `PlayModeRunner`
owns the HITL invariant — the "every step gated" guarantee lives in one place.

## The sample dropbox abstraction (never a live fetch)

A controlled upstream (a quarantine bucket in production) places a sample and
publishes a **reference**. The Runtime receives only:

```json
{ "sample_s3_uri": "s3://<quarantine-bucket>/<key>",
  "dropbox_id": "drop-...",
  "sample_sha256": "<supplied-by-upstream, NOT computed here>" }
```

`Sample.__post_init__` fails closed unless `s3_uri` starts with `s3://`, so no
code path can be steered into an `http(s)://` download or a local-file read.

## How this maps to a real Runtime + microVM in production

| Skeleton call | Production behavior |
|---|---|
| `OneShotMicroVM.acquire(session_id)` | Provision a genuinely isolated one-shot microVM (own kernel, no shared FS, **egress-denied** network) keyed by the `runtimeSessionId`. |
| `run_action(handle, action)` | Run a controlled analysis step inside that microVM via the Runtime's own tool surface — **still behind the sandbox hooks and still HITL-gated by Play Mode**. |
| `destroy(handle)` | Terminate the microVM and delete its disk so **nothing — including the sample — persists** between analyses. |
| `Sample(s3_uri=...)` | The Runtime's execution role reads the object from the quarantine dropbox *inside* the isolated VM only after approval; the supervisor never handles bytes. |

The skeleton keeps the exact call shape, so the swap to a real microVM provider is
mechanical while CI stays green with zero AWS / zero heavy deps.

## Safety posture (summary)

- **Deny-by-default** command/path validation on every action (one source of
  truth: `sentinel_harness.sandbox_hooks`).
- **Destroy-after-use** enforced by the state machine and by a `finally` in the
  driver — a VM cannot outlive its analysis or be reused after teardown.
- **No live fetch, no bytes** — samples are references only.
- **No real execution** — detonation is a logged no-op; nothing runs.
- **HITL on every offensive step** — reject or an ungated step halts the plan.

## Files

| File | Role |
|---|---|
| `bedrock_entrypoint.py` | `@app.entrypoint` async generator: `add_async_task` + `HEALTHY_BUSY` ping, acquires the one-shot microVM, drives the gated plan via the reused `BasRunnerLoop`, destroys the VM in a `finally`, yields a `restart_required` event at the session cap. `bedrock_agentcore` imports are **guarded** so the module imports without it. |
| `src/vm.py` | `OneShotMicroVM` abstraction (`acquire` / `run_action` / `destroy`), `VMHandle`, `Sample`. Pure Python; every action gated through `sandbox_hooks`; every result SIMULATED. |

## Configuration (12-factor — nothing hardcoded)

| Env var | Meaning | Default |
|---|---|---|
| `SENTINEL_EXECUTION_ROLE_ARN` | Runtime → Bedrock execution role (from `core`) | required for a live run |
| `SENTINEL_REGION` | AWS region | `us-east-1` |
| `SENTINEL_DETONATION_CHECKPOINT_DIR` | Local checkpoint directory | `detonation_checkpoints` |
| `SENTINEL_DETONATION_MAX_STEPS_PER_SESSION` | Session cap (steps) before WIP-restart | unset (no cap) |
| `SENTINEL_SANDBOX_ROOTS` | Sandbox roots for the safety gate | `/workspace:/mnt` |

## Invoke payload

```json
{ "harness_arn": "arn:aws:bedrock-agentcore:...:harness/...",
  "sample_s3_uri": "s3://quarantine-bucket/samples/abc123",
  "dropbox_id": "drop-001",
  "plan_id": "detonation-lab-01",
  "mode": "continuous",
  "resume": false }
```

`plan` may be supplied to override the default SIMULATED detonation plan.

## Offline import check

```bash
# No bedrock_agentcore needed — guarded import; no boto3 in the simulated path.
python -c "import sys; sys.path.insert(0,'longrunning/detonation/src'); import vm; print(vm.ACQUIRED)"
```

Tests: `tests/test_detonation.py` (offline, zero AWS, zero network, zero real VM).
