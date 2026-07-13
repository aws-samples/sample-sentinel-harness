# bas-runner — long-running BAS / attack-path Runtime skeleton

A Breach-and-Attack-Simulation (BAS) run on a **genuinely long-running AgentCore
Runtime**, not a harness. Every offensive step is a **simulated no-op that a human
must approve** before it is "executed" (logged). Follows the
`sample-long-running-app-harness` pattern (BLUEPRINT §4.1 / Layer 2).

> SIMULATED / DEFENSIVE ONLY. No step attacks, scans, or touches any real system.
> An offensive step only records `would execute technique <T-id>` — and only after
> a human approves its gate. All technique content is generic and illustrative.

## Why a Runtime, not a harness

The Layer-1 harnesses (`create_harness`) run **one server-side ReAct loop bounded
by `timeoutSeconds`** (minutes). A BAS / attack-path run is a different shape:

| A harness | This long-running Runtime |
|---|---|
| One bounded loop, minutes, sync request/response | Many gated steps over **hours**; may **exceed `timeoutSeconds`** |
| Result returned inline | **Async + polled**: registers an async task, the ping reports `HEALTHY_BUSY` while it works |
| Dies at the end of the loop | **Checkpoints plan state** and **self-restarts** at the session-lifetime cap, resuming mid-plan |
| Context lives in the loop | **Fresh context per turn**; durable state lives only in the checkpoint |

So this tier is hosted as a container Runtime we drive ourselves. The HITL Play-Mode
guarantee is unchanged — it is reused, not re-implemented.

## Files

| File | Role |
|---|---|
| `bedrock_entrypoint.py` | `@app.entrypoint` async generator: `add_async_task` + `HEALTHY_BUSY` ping, runs the gated plan, checkpoints (local JSON default, S3 optional), yields a `restart_required` event at the session cap. Imports of `bedrock_agentcore` are **guarded** so the module imports without it. |
| `runner_loop.py` | The state machine — `continuous` / `run_once` / `pause`, fresh-context-per-turn, WIP-checkpoint + `SessionCapReached` at the cap. AWS-free / dependency-injected. |
| `src/security.py` | PreToolUse / PostToolUse sandbox hooks. **Reuses** `sentinel_harness.sandbox_hooks` (`validate_command` / `validate_path`) — one source of truth for the allowlist + destructive-verb denylist + path confinement. |
| `Dockerfile` | `linux/arm64`, non-root (`basrunner`, uid 10001), multi-stage. |

## How every offensive step is human-gated

The plan is driven through `sentinel_harness.simulation.PlayModeRunner` (Play
Mode). Before emulating each `exec_technique` step the harness **pauses on an
`inline_function` gate** (`stop_reason=tool_use`); a human decision is applied:

- **APPROVE** → resume the same session (two-message `toolUse`+`toolResult`
  contract) and record a **simulated no-op** execution.
- **REJECT** → the plan **halts** (Play-Mode invariant: no action without a human
  confirmation). An ungated step is also treated as a protocol violation and halts.

`runner_loop.py` owns cadence/lifetime; `PlayModeRunner` owns the HITL invariant —
so the "every step gated" guarantee lives in exactly one place.

## Checkpoint & restart

Plan state is checkpointed as JSON (atomic write). By default checkpoints go to
`$SENTINEL_BAS_CHECKPOINT_DIR` (local). Set `SENTINEL_BAS_S3_BUCKET` to also mirror
each checkpoint to `s3://<bucket>/<SENTINEL_BAS_S3_PREFIX>/<plan_id>.json`
(best-effort; the local checkpoint stays authoritative if the mirror fails).

At the session cap (`SENTINEL_BAS_MAX_STEPS_PER_SESSION`, standing in for the ~8h
Runtime lifetime) the loop WIP-commits and raises `SessionCapReached`; the
entrypoint yields `restart_required`. On relaunch, invoke with `{"resume": true}`
and the run continues from the next pending step **without re-approving** earlier
steps.

## Configuration (12-factor — nothing hardcoded)

| Env var | Meaning | Default |
|---|---|---|
| `SENTINEL_EXECUTION_ROLE_ARN` | Runtime → Bedrock execution role (from `core`) | required for a live run |
| `SENTINEL_REGION` | AWS region | `us-east-1` |
| `SENTINEL_BAS_CHECKPOINT_DIR` | Local checkpoint directory | `bas_checkpoints` |
| `SENTINEL_BAS_S3_BUCKET` | Optional S3 bucket to mirror checkpoints | unset (local only) |
| `SENTINEL_BAS_S3_PREFIX` | S3 key prefix | `bas-checkpoints` |
| `SENTINEL_BAS_MAX_STEPS_PER_SESSION` | Session cap (steps) before restart | unset (no cap) |
| `SENTINEL_SANDBOX_ROOTS` | Sandbox roots for the security hooks | `/workspace:/mnt` |

## Invoke payload

```json
{ "harness_arn": "arn:aws:bedrock-agentcore:...:harness/...",
  "plan_id": "bas-lab-01",
  "mode": "continuous",
  "resume": false }
```

`plan` may be supplied to override the default SIMULATED ATT&CK-style kill chain.

## Build & run (offline import check)

```bash
docker build --platform linux/arm64 -t bas-runner .
# Offline sanity (no bedrock_agentcore needed — guarded import):
python -c "import bedrock_entrypoint; print(bedrock_entrypoint._HAS_AGENTCORE)"
```

Tests: `tests/test_bas_runner.py` (offline, zero AWS).
