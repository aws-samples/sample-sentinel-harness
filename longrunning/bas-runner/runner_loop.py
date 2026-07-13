"""
bas-runner · long-running state machine (continuous / run_once / pause)
=======================================================================
A harness (``create_harness``) runs a single server-side ReAct loop bounded by
``timeoutSeconds`` (minutes). A genuinely long-running BAS / attack-path run can
exceed that: many gated steps, spread over hours, surviving a session-cap
restart. That tier needs a Runtime we drive ourselves — this module is its
control loop, kept AWS-free and dependency-injected so the state-machine logic is
unit-testable offline.

Design (borrowed from the long-running-app-harness skeleton)
------------------------------------------------------------
- **Modes.** ``CONTINUOUS`` advances the plan step-by-step until it is complete,
  halted (a rejected gate), or the session cap is hit. ``RUN_ONCE`` advances
  exactly one gated step and returns (a poller / test drives one turn at a time).
  ``PAUSE`` performs no work — the operator has parked the run; the loop idles and
  the checkpoint is authoritative.
- **Fresh context per turn.** Each step is a self-contained pause→decide→resume
  round trip driven through :class:`~sentinel_harness.simulation.PlayModeRunner`;
  the loop holds no accumulated in-memory conversation between turns. Durable
  state lives only in the checkpoint, so a restart rebuilds identical state from
  disk rather than from a fragile in-process history.
- **Session cap → WIP-commit + self-restart.** A Runtime session has a hard max
  lifetime (~8h). Before the cap we checkpoint (a "WIP commit") and raise
  :class:`SessionCapReached`; the entrypoint's restart hook relaunches and
  ``PlayModeRunner.resume_from_checkpoint`` continues from the next pending step
  WITHOUT re-approving earlier steps.

No AWS calls happen here. The loop drives an injected ``PlayModeRunner`` (which is
itself dependency-injected over Layer-1 invoke/resume), so tests need no network.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from sentinel_harness.simulation import (
    EXECUTED,
    REJECTED,
    PlanState,
    PlayModeRunner,
)

# ------------------------------------------------------------------ modes
CONTINUOUS = "continuous"
RUN_ONCE = "run_once"
PAUSE = "pause"

_VALID_MODES = frozenset({CONTINUOUS, RUN_ONCE, PAUSE})


class SessionCapReached(Exception):
    """Raised when the run hits its session-lifetime cap mid-plan.

    Carries the checkpoint path so the entrypoint's restart hook can relaunch and
    resume from it. This is a control-flow signal, not an error — the plan is
    intentionally suspended and durably checkpointed, not lost."""

    def __init__(self, checkpoint_path: Optional[str], steps_done: int) -> None:
        super().__init__(
            f"session cap reached after {steps_done} step(s); "
            f"WIP-checkpointed to {checkpoint_path!r} — restart to resume"
        )
        self.checkpoint_path = checkpoint_path
        self.steps_done = steps_done


@dataclass
class TurnResult:
    """Result of one loop advance — a small, serializable status snapshot."""

    mode: str
    steps_advanced: int
    complete: bool
    halted: bool
    halted_reason: Optional[str]
    counts: Dict[str, int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "steps_advanced": self.steps_advanced,
            "complete": self.complete,
            "halted": self.halted,
            "halted_reason": self.halted_reason,
            "counts": self.counts,
        }


class BasRunnerLoop:
    """Drive a :class:`PlayModeRunner` as a resumable long-running state machine.

    The loop owns *cadence and lifetime* (which mode, how many steps this turn,
    when to checkpoint-and-restart); the runner owns *the HITL invariant* (every
    offensive step gated, reject halts). Separating them keeps the Play-Mode
    guarantee in exactly one place.

    Parameters
    ----------
    runner:
        A :class:`PlayModeRunner` (already bound to a harness ARN + a plan, or
        rebuilt via ``resume_from_checkpoint``). Dependency-injected: in tests it
        wraps fake invoke/resume so no AWS is touched.
    mode:
        One of ``CONTINUOUS`` / ``RUN_ONCE`` / ``PAUSE``.
    max_steps_per_session:
        Stand-in for the Runtime session cap. After this many steps advance in a
        single ``run()`` the loop WIP-checkpoints and raises
        :class:`SessionCapReached`. ``None`` disables the cap.
    heartbeat_fn:
        Optional callable invoked once per advanced step with a status dict — the
        ``HEALTHY_BUSY`` heartbeat the entrypoint publishes. No AWS here.
    clock:
        Injectable ``time.time``-style clock (tests pass a fake).
    """

    def __init__(
        self,
        runner: PlayModeRunner,
        *,
        mode: str = CONTINUOUS,
        max_steps_per_session: Optional[int] = None,
        heartbeat_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {mode!r}")
        self.runner = runner
        self.mode = mode
        self.max_steps_per_session = max_steps_per_session
        self._heartbeat = heartbeat_fn or (lambda status: None)
        self._clock = clock

    # -- state views ---------------------------------------------------------
    @property
    def state(self) -> PlanState:
        return self.runner.state

    def _heartbeat_status(self, steps_advanced: int) -> Dict[str, Any]:
        """The payload emitted per step — mirrors a HEALTHY_BUSY ping."""
        return {
            "status": "HEALTHY_BUSY",
            "plan_id": self.state.plan_id,
            "session_id": self.state.session_id,
            "steps_advanced": steps_advanced,
            "counts": self.state.counts(),
            "ts": self._clock(),
        }

    # -- one turn ------------------------------------------------------------
    def _advance_one(self) -> bool:
        """Advance exactly one pending step. Returns True if a step was run,
        False if there was nothing pending (plan already complete/halted)."""
        step = self.state.next_pending()
        if step is None or self.state.halted:
            return False
        self.runner.run_step(step)
        return True

    # -- run -----------------------------------------------------------------
    def run(self) -> TurnResult:
        """Advance the plan according to ``mode``.

        * ``PAUSE``   → no work; report current state (checkpoint is authoritative).
        * ``RUN_ONCE`` → advance at most one gated step, then return.
        * ``CONTINUOUS`` → advance until complete, halted, or the session cap is
          hit (which WIP-checkpoints and raises :class:`SessionCapReached`).

        Raises
        ------
        SessionCapReached
            In ``CONTINUOUS`` mode when ``max_steps_per_session`` steps have run
            and the plan is not yet finished — the signal to self-restart.
        """
        if self.mode == PAUSE:
            return self._result(0)

        if self.mode == RUN_ONCE:
            advanced = 1 if self._advance_one() else 0
            if advanced:
                self._heartbeat(self._heartbeat_status(advanced))
            self.runner._checkpoint()
            return self._result(advanced)

        # CONTINUOUS
        advanced = 0
        while not self.state.is_complete():
            if not self._advance_one():
                break
            advanced += 1
            self._heartbeat(self._heartbeat_status(advanced))
            cap = self.max_steps_per_session
            if cap is not None and advanced >= cap and not self.state.is_complete():
                # WIP-commit before the session dies, then signal a restart.
                self.runner._checkpoint()
                raise SessionCapReached(self.runner.checkpoint_path, advanced)
        self.runner._checkpoint()
        return self._result(advanced)

    def _result(self, advanced: int) -> TurnResult:
        return TurnResult(
            mode=self.mode,
            steps_advanced=advanced,
            complete=self.state.is_complete() and not self.state.halted,
            halted=self.state.halted,
            halted_reason=self.state.halted_reason,
            counts=self.state.counts(),
        )

    # -- terminal verdict ----------------------------------------------------
    def is_finished(self) -> bool:
        """True when the plan reached a terminal state (all steps executed/rejected
        or the plan halted). A capped-but-incomplete run is NOT finished — it is
        meant to resume after restart."""
        return self.state.is_complete() or all(
            s.status in (EXECUTED, REJECTED) for s in self.state.steps
        )
