"""
bas-runner · long-running Runtime entrypoint (BAS / attack-path)
================================================================
The BEDROCK AGENTCORE RUNTIME tier for Breach-and-Attack-Simulation. A harness
runs one bounded ReAct loop; a BAS run is the opposite shape — a stepwise plan
where every offensive step is human-gated, spread over hours, that must survive a
session-cap restart. That does not fit ``timeoutSeconds``, so we host it as a
long-running Runtime we drive ourselves, following the
``sample-long-running-app-harness`` skeleton (BLUEPRINT §4.1 / Layer 2).

What this entrypoint does per invocation
-----------------------------------------
1. **Register an async task + HEALTHY_BUSY ping.** ``add_async_task`` marks the
   Runtime busy so the platform's ping reports ``HEALTHY_BUSY`` (not idle) while
   the plan runs — the heartbeat contract for a genuinely long job.
2. **Run a stepwise BAS plan, every offensive step HITL-gated.** We REUSE the
   Play-Mode idea from :mod:`sentinel_harness.simulation`: each ``exec_technique``
   step PAUSES on an ``inline_function`` gate; approve resumes the same session
   and records a SIMULATED no-op; reject HALTS the plan. We do not duplicate that
   logic — we build on :class:`PlayModeRunner` via :class:`BasRunnerLoop`.
3. **Checkpoint plan state.** Local JSON by default (atomic write via the
   simulation checkpoint helpers); S3 optionally when ``SENTINEL_BAS_S3_BUCKET``
   is set — the checkpoint is mirrored to ``s3://<bucket>/<prefix>/<plan>.json``.
4. **WIP-commit + self-restart at the session cap.** When the loop signals
   :class:`SessionCapReached` we persist a WIP checkpoint and yield a
   ``restart_required`` event; the platform relaunches and we resume from the
   next pending step without re-approving earlier ones.

SIMULATED / DEFENSIVE SCOPE ONLY
--------------------------------
Every offensive step is a no-op that only logs ``would execute technique <T-id>``
and only after a human approves the gate. Nothing here attacks, scans, or touches
any real system. All technique content is generic and illustrative.

Guarded imports
---------------
``bedrock_agentcore`` is only present in the Runtime image. Import is guarded so
this module is importable (and unit-testable) without it — ``app`` is then None
and :func:`build_loop` / :func:`run_plan` still work for offline tests.
"""
from __future__ import annotations

import os
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

from sentinel_harness import core
from sentinel_harness import simulation as sim

from runner_loop import BasRunnerLoop, SessionCapReached, CONTINUOUS

# --------------------------------------------------------------- guarded import
# bedrock_agentcore only exists inside the Runtime image. Guard it so the module
# imports (and unit-tests run) without it. When absent, `app` is None and the
# pure-Python plan driver below is still fully usable.
try:  # pragma: no cover - import path depends on runtime image
    from bedrock_agentcore.runtime import BedrockAgentCoreApp

    app: Optional[Any] = BedrockAgentCoreApp()
    _HAS_AGENTCORE = True
except ImportError:  # pragma: no cover - exercised implicitly in offline tests
    app = None
    _HAS_AGENTCORE = False


# ------------------------------------------------------------------ config
def _checkpoint_dir() -> str:
    """Local checkpoint directory (12-factor). Defaults to ``./bas_checkpoints``."""
    return os.environ.get("SENTINEL_BAS_CHECKPOINT_DIR", "bas_checkpoints")


def _checkpoint_path(plan_id: str) -> str:
    return os.path.join(_checkpoint_dir(), f"{plan_id}.json")


def _session_cap() -> Optional[int]:
    """Steps-per-session cap standing in for the Runtime's ~8h lifetime cap.
    ``SENTINEL_BAS_MAX_STEPS_PER_SESSION`` overrides; unset disables the cap."""
    raw = os.environ.get("SENTINEL_BAS_MAX_STEPS_PER_SESSION")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            f"SENTINEL_BAS_MAX_STEPS_PER_SESSION must be an int, got {raw!r}"
        ) from exc


# ------------------------------------------------------------------ S3 mirror
def _mirror_to_s3(local_path: str, plan_id: str) -> Optional[str]:
    """Optionally mirror the local checkpoint to S3 (durable long-run state).

    Enabled only when ``SENTINEL_BAS_S3_BUCKET`` is set — local JSON is the
    default so the runner works with no cloud dependency. Never raises into the
    plan loop: a mirror failure is logged and the authoritative local checkpoint
    still stands. Returns the ``s3://`` URI on success, else None.
    """
    bucket = os.environ.get("SENTINEL_BAS_S3_BUCKET")
    if not bucket:
        return None
    prefix = os.environ.get("SENTINEL_BAS_S3_PREFIX", "bas-checkpoints").strip("/")
    key = f"{prefix}/{plan_id}.json" if prefix else f"{plan_id}.json"
    try:
        import boto3  # local import: no boto3 at module import time

        boto3.client("s3", region_name=core.REGION).upload_file(local_path, bucket, key)
        return f"s3://{bucket}/{key}"
    except Exception as exc:  # noqa: BLE001 - mirror is best-effort; local wins
        print(f"[bas-runner] S3 checkpoint mirror failed ({exc}); local checkpoint stands")
        return None


# ------------------------------------------------------------------ build loop
def build_loop(
    harness_arn: str,
    *,
    plan: Optional[List[Dict[str, str]]] = None,
    plan_id: str = "bas",
    session_id: Optional[str] = None,
    decision_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    mode: str = CONTINUOUS,
    resume: bool = False,
    invoke_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    resume_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    heartbeat_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> BasRunnerLoop:
    """Build a resumable :class:`BasRunnerLoop` over a Play-Mode runner.

    If ``resume`` and a checkpoint exists, rebuild from it (continuing without
    re-approving earlier steps); otherwise start a fresh plan. Dependency-injected
    (``invoke_fn`` / ``resume_fn`` / ``decision_fn``) so offline tests need no AWS.
    """
    ckpt = _checkpoint_path(plan_id)
    runner_kwargs: Dict[str, Any] = dict(
        decision_fn=decision_fn or sim.auto_approve,
        invoke_fn=invoke_fn,
        resume_fn=resume_fn,
    )
    if resume and os.path.isfile(ckpt):
        runner = sim.PlayModeRunner.resume_from_checkpoint(harness_arn, ckpt, **runner_kwargs)
    else:
        runner = sim.PlayModeRunner(
            harness_arn,
            plan=plan or sim.DEFAULT_PLAN,
            plan_id=plan_id,
            session_id=session_id,
            checkpoint_path=ckpt,
            **runner_kwargs,
        )
    return BasRunnerLoop(
        runner,
        mode=mode,
        max_steps_per_session=_session_cap(),
        heartbeat_fn=heartbeat_fn,
    )


def run_plan(loop: BasRunnerLoop) -> Dict[str, Any]:
    """Drive the loop once and shape a serializable status event.

    Catches :class:`SessionCapReached` and turns it into a ``restart_required``
    event (WIP-committed) rather than an error — the caller/entrypoint relaunches
    and resumes. After every turn the checkpoint is mirrored to S3 if configured.
    """
    plan_id = loop.state.plan_id
    try:
        turn = loop.run()
    except SessionCapReached as cap:
        s3_uri = _mirror_to_s3(cap.checkpoint_path, plan_id) if cap.checkpoint_path else None
        return {
            "event": "restart_required",
            "reason": str(cap),
            "checkpoint_path": cap.checkpoint_path,
            "s3_uri": s3_uri,
            "steps_done": cap.steps_done,
            "verdict": loop.runner.verdict(),
        }

    s3_uri = _mirror_to_s3(loop.runner.checkpoint_path, plan_id) if loop.runner.checkpoint_path else None
    return {
        "event": "plan_complete" if turn.complete else ("plan_halted" if turn.halted else "turn_done"),
        "turn": turn.as_dict(),
        "checkpoint_path": loop.runner.checkpoint_path,
        "s3_uri": s3_uri,
        "verdict": loop.runner.verdict(),
    }


# ------------------------------------------------------------------ entrypoint
async def _bas_entrypoint(payload: Dict[str, Any], context: Any = None) -> AsyncIterator[Dict[str, Any]]:
    """The async-generator body wired to ``@app.entrypoint``.

    Kept as a standalone async generator (separate from the decorator) so the plan
    behaviour is unit-testable without ``bedrock_agentcore`` installed. Yields a
    ``started`` (HEALTHY_BUSY) event, then a terminal / restart event.

    ``payload`` keys (all optional): ``harness_arn`` (required for a live run),
    ``plan``, ``plan_id``, ``session_id``, ``mode``, ``resume``.
    """
    payload = payload or {}
    harness_arn = payload.get("harness_arn")
    if not harness_arn:
        yield {"event": "error", "reason": "payload.harness_arn is required for a BAS run"}
        return

    plan_id = payload.get("plan_id", "bas")

    # Mark the Runtime busy so the platform ping reports HEALTHY_BUSY while the
    # (potentially hours-long) plan runs. Guarded: only when running in-image.
    if _HAS_AGENTCORE and app is not None:
        try:  # pragma: no cover - only meaningful inside the Runtime image
            app.add_async_task("bas_plan")
        except Exception as exc:  # noqa: BLE001 - never fail the run on heartbeat wiring
            print(f"[bas-runner] add_async_task unavailable ({exc}); continuing")

    yield {"event": "started", "status": "HEALTHY_BUSY", "plan_id": plan_id}

    loop = build_loop(
        harness_arn,
        plan=payload.get("plan"),
        plan_id=plan_id,
        session_id=payload.get("session_id"),
        mode=payload.get("mode", CONTINUOUS),
        resume=bool(payload.get("resume", False)),
    )
    result = run_plan(loop)
    yield result


if _HAS_AGENTCORE and app is not None:  # pragma: no cover - requires the Runtime image
    @app.entrypoint
    async def bas_agent(payload: Dict[str, Any], context: Any = None) -> AsyncIterator[Dict[str, Any]]:
        async for event in _bas_entrypoint(payload, context):
            yield event


if __name__ == "__main__":  # pragma: no cover - container start
    if not _HAS_AGENTCORE or app is None:
        raise SystemExit(
            "bedrock_agentcore is not installed; this module is meant to run inside "
            "the bas-runner Runtime image. It stays importable for offline tests."
        )
    app.run()
