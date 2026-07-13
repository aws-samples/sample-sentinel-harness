"""
detonation · long-running sample-detonation Runtime entrypoint (SIMULATED)
==========================================================================
The BEDROCK AGENTCORE RUNTIME tier for **sample detonation**. A detonation run is
a long-running, human-gated lifecycle that does NOT fit a harness's bounded
``timeoutSeconds``: for one sample we acquire a fresh one-shot microVM keyed by
the ``runtimeSessionId``, walk a small plan of controlled detonation steps (each
HITL-gated via Play Mode), then destroy the microVM after use. We host it as a
long-running Runtime we drive ourselves, following the
``sample-long-running-app-harness`` skeleton (BLUEPRINT §4.1 / Layer 2) — the
SAME async-gen + checkpoint + session-cap machinery the ``bas-runner`` already
implements, which we REUSE rather than re-writing.

What this entrypoint does per invocation
-----------------------------------------
1. **Register an async task + HEALTHY_BUSY ping.** ``add_async_task`` marks the
   Runtime busy so the platform's ping reports ``HEALTHY_BUSY`` (not idle) while
   the (potentially long) detonation plan runs.
2. **Acquire a one-shot microVM for this session.** Via
   :class:`longrunning.detonation.src.vm.OneShotMicroVM` — SIMULATED; the sample
   is referenced only by an ``s3://`` dropbox uri, never fetched.
3. **Run the detonation plan, every offensive step HITL-gated.** We REUSE the
   Play-Mode driver (:class:`sentinel_harness.simulation.PlayModeRunner`) via the
   bas-runner's :class:`BasRunnerLoop` — each detonation step PAUSES on the
   ``exec_technique`` gate; approve resumes and records a SIMULATED no-op, reject
   HALTS the plan.
4. **Checkpoint plan state + WIP-commit at the session cap.** Reuses the same
   local-JSON checkpoint / ``SessionCapReached`` restart contract as bas-runner.
5. **Destroy the microVM after use** in a ``finally`` — destroy-after-use holds
   even if the plan halts or the session cap fires.

SIMULATED / DEFENSIVE SCOPE ONLY
--------------------------------
No real malware, no real VM, no real exploit, no network. Detonation "steps" are
no-ops that only log after a human approves the gate; the microVM is an in-memory
abstraction; the sample is only ever an ``s3://`` uri. See ``README.md`` for the
real-vs-simulated boundary.

Guarded imports
---------------
``bedrock_agentcore`` is only present in the Runtime image. Import is guarded so
this module imports (and unit-tests run) without it — ``app`` is then None and the
pure-Python :func:`build_runner` / :func:`run_detonation` driver still works.
"""
from __future__ import annotations

import os
import sys
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

from sentinel_harness import simulation as sim

# The long-running state machine + WIP-restart contract already exist in
# bas-runner; REUSE them. bas-runner modules live under longrunning/bas-runner/
# (a sibling dir, not an installed package), so make them importable by path —
# the same convention tests/test_bas_runner.py uses.
_BAS_DIR = os.path.join(os.path.dirname(__file__), "..", "bas-runner")
if os.path.isdir(_BAS_DIR):
    _BAS_ABS = os.path.abspath(_BAS_DIR)
    if _BAS_ABS not in sys.path:
        sys.path.insert(0, _BAS_ABS)

from runner_loop import BasRunnerLoop, SessionCapReached, CONTINUOUS  # noqa: E402

# The one-shot microVM abstraction. Support both package-style and path-style
# import so the module works whether ``longrunning`` is on the path as a package
# or ``src`` is imported directly (as the bas-runner sibling does).
try:  # pragma: no cover - exercised via whichever import path resolves
    from longrunning.detonation.src.vm import OneShotMicroVM, Sample
except ImportError:  # pragma: no cover
    _SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "src"))
    if _SRC_DIR not in sys.path:
        sys.path.insert(0, _SRC_DIR)
    from vm import OneShotMicroVM, Sample  # type: ignore

# --------------------------------------------------------------- guarded import
# bedrock_agentcore only exists inside the Runtime image. Guard it so the module
# imports (and unit-tests run) without it. When absent, `app` is None and the
# pure-Python detonation driver below is still fully usable.
try:  # pragma: no cover - import path depends on runtime image
    from bedrock_agentcore.runtime import BedrockAgentCoreApp

    app: Optional[Any] = BedrockAgentCoreApp()
    _HAS_AGENTCORE = True
except ImportError:  # pragma: no cover - exercised implicitly in offline tests
    app = None
    _HAS_AGENTCORE = False


# ------------------------------------------------------------------ config
def _checkpoint_dir() -> str:
    """Local checkpoint directory (12-factor). Defaults to ``./detonation_checkpoints``."""
    return os.environ.get("SENTINEL_DETONATION_CHECKPOINT_DIR", "detonation_checkpoints")


def _checkpoint_path(plan_id: str) -> str:
    return os.path.join(_checkpoint_dir(), f"{plan_id}.json")


def _session_cap() -> Optional[int]:
    """Steps-per-session cap standing in for the Runtime's ~8h lifetime cap.
    ``SENTINEL_DETONATION_MAX_STEPS_PER_SESSION`` overrides; unset disables it."""
    raw = os.environ.get("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            f"SENTINEL_DETONATION_MAX_STEPS_PER_SESSION must be an int, got {raw!r}"
        ) from exc


# A generic, SIMULATED detonation plan. Each step is an offensive/analysis action
# that Play Mode gates before the microVM would (simulated-)run it. Technique ids
# are illustrative public ATT&CK ids; nothing is executed for real.
DEFAULT_DETONATION_PLAN: List[Dict[str, str]] = [
    {"phase": "detonation-setup", "technique": "T1204",
     "objective": "Emulate staging the referenced sample in the one-shot microVM (simulated)."},
    {"phase": "execution", "technique": "T1059",
     "objective": "Emulate detonating the sample via a script interpreter (simulated)."},
    {"phase": "collection", "technique": "T1005",
     "objective": "Emulate collecting behavioral artifacts from the sandbox (simulated)."},
]


# ------------------------------------------------------------------ build runner
def build_runner(
    harness_arn: str,
    *,
    plan: Optional[List[Dict[str, str]]] = None,
    plan_id: str = "detonation",
    session_id: Optional[str] = None,
    decision_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    mode: str = CONTINUOUS,
    resume: bool = False,
    invoke_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    resume_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    heartbeat_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> BasRunnerLoop:
    """Build the resumable Play-Mode loop that drives the detonation plan.

    REUSES :class:`BasRunnerLoop` over :class:`sentinel_harness.simulation.PlayModeRunner`
    verbatim — the detonation plan is just a different (SIMULATED) plan fed through
    the same per-step HITL gate + checkpoint + session-cap machinery. If ``resume``
    and a checkpoint exists, rebuild from it (continuing without re-approving
    earlier steps); otherwise start fresh. Dependency-injected (``invoke_fn`` /
    ``resume_fn`` / ``decision_fn``) so offline tests need no AWS.
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
            plan=plan or DEFAULT_DETONATION_PLAN,
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


def run_detonation(
    loop: BasRunnerLoop,
    *,
    vm: OneShotMicroVM,
    session_id: str,
    sample: Optional[Sample] = None,
) -> Dict[str, Any]:
    """Acquire a one-shot microVM, drive the gated plan, then DESTROY the VM.

    The microVM lifecycle wraps the plan: acquire before the first step, destroy
    in a ``finally`` so **destroy-after-use holds even when the plan halts or the
    session cap fires**. A :class:`SessionCapReached` is turned into a
    ``restart_required`` event (WIP-committed) rather than an error — the caller
    relaunches and resumes.

    The sample is passed only by reference (an :class:`Sample` holding an
    ``s3://`` uri); nothing here fetches or reads its bytes.
    """
    handle = vm.acquire(session_id, sample=sample)
    event: Dict[str, Any]
    try:
        try:
            turn = loop.run()
            event = {
                "event": "plan_complete" if turn.complete else (
                    "plan_halted" if turn.halted else "turn_done"),
                "turn": turn.as_dict(),
                "checkpoint_path": loop.runner.checkpoint_path,
                "verdict": loop.runner.verdict(),
            }
        except SessionCapReached as cap:
            event = {
                "event": "restart_required",
                "reason": str(cap),
                "checkpoint_path": cap.checkpoint_path,
                "steps_done": cap.steps_done,
                "verdict": loop.runner.verdict(),
            }
    finally:
        # Destroy-after-use: the one-shot microVM never outlives its analysis,
        # whatever the plan outcome. Idempotent, so this is safe in a finally.
        destroy_result = vm.destroy(handle)
        loop.runner._log(destroy_result["note"])
    # Report the microVM state AFTER the destroy so the evidence trail proves
    # destroy-after-use (the snapshot reflects the torn-down handle).
    event["vm"] = handle.as_dict()
    return event


# ------------------------------------------------------------------ entrypoint
async def _detonation_entrypoint(
    payload: Dict[str, Any], context: Any = None
) -> AsyncIterator[Dict[str, Any]]:
    """The async-generator body wired to ``@app.entrypoint``.

    Kept standalone (separate from the decorator) so the detonation behaviour is
    unit-testable without ``bedrock_agentcore`` installed. Yields a ``started``
    (HEALTHY_BUSY) event, then a terminal / restart event.

    ``payload`` keys: ``harness_arn`` (required), ``sample_s3_uri`` (the dropbox
    reference), and optionally ``dropbox_id`` / ``sample_sha256`` / ``plan`` /
    ``plan_id`` / ``session_id`` / ``mode`` / ``resume``.
    """
    payload = payload or {}
    harness_arn = payload.get("harness_arn")
    if not harness_arn:
        yield {"event": "error", "reason": "payload.harness_arn is required for a detonation run"}
        return

    plan_id = payload.get("plan_id", "detonation")
    # The runtimeSessionId keys the one-shot microVM; fall back to a derived id.
    session_id = payload.get("session_id") or (
        context.session_id if context is not None and hasattr(context, "session_id") else None
    )

    # A sample enters ONLY by reference (s3 dropbox uri) — never a live fetch.
    sample: Optional[Sample] = None
    s3_uri = payload.get("sample_s3_uri")
    if s3_uri:
        try:
            sample = Sample(
                s3_uri=s3_uri,
                dropbox_id=payload.get("dropbox_id"),
                sha256=payload.get("sample_sha256"),
            )
        except ValueError as exc:
            yield {"event": "error", "reason": f"invalid sample reference: {exc}"}
            return

    # Mark the Runtime busy so the platform ping reports HEALTHY_BUSY while the
    # (potentially long) detonation runs. Guarded: only when running in-image.
    if _HAS_AGENTCORE and app is not None:
        try:  # pragma: no cover - only meaningful inside the Runtime image
            app.add_async_task("detonation_plan")
        except Exception as exc:  # noqa: BLE001 - never fail the run on heartbeat wiring
            print(f"[detonation] add_async_task unavailable ({exc}); continuing")

    yield {"event": "started", "status": "HEALTHY_BUSY", "plan_id": plan_id,
           "sample": sample.as_dict() if sample else None}

    loop = build_runner(
        harness_arn,
        plan=payload.get("plan"),
        plan_id=plan_id,
        session_id=session_id,
        mode=payload.get("mode", CONTINUOUS),
        resume=bool(payload.get("resume", False)),
    )
    vm = OneShotMicroVM()
    result = run_detonation(
        loop, vm=vm, session_id=loop.state.session_id, sample=sample
    )
    yield result


if _HAS_AGENTCORE and app is not None:  # pragma: no cover - requires the Runtime image
    @app.entrypoint
    async def detonation_agent(
        payload: Dict[str, Any], context: Any = None
    ) -> AsyncIterator[Dict[str, Any]]:
        async for event in _detonation_entrypoint(payload, context):
            yield event


if __name__ == "__main__":  # pragma: no cover - container start
    if not _HAS_AGENTCORE or app is None:
        raise SystemExit(
            "bedrock_agentcore is not installed; this module is meant to run inside "
            "the detonation Runtime image. It stays importable for offline tests."
        )
    app.run()
