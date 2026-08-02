"""
sentinel-harness · Layer 2 (Simulation) — Play Mode attack-simulation driver
============================================================================
A minimal, long-running **adversary-emulation** runner with a *Play Mode*
human-in-the-loop gate on *every* offensive step.

Why this exists
---------------
Layer 1 (``core``) gives us a harness that can PAUSE on an ``inline_function``
gate and RESUME the same session with the two-message toolUse+toolResult
contract. Layer 2 turns that single round-trip into a **multi-step plan**: an
ATT&CK-style kill chain (recon -> initial-access -> execution -> persistence)
where the agent must request approval before *each* offensive ``exec_technique``
step. A human decision (approve/reject) is applied per step; a rejected step
HALTS the plan — that is what "Play Mode" means: no offensive action happens
without an explicit human confirmation.

SIMULATED / DEFENSIVE SCOPE ONLY
--------------------------------
This is an **emulation** harness for validating detections and the approval
workflow. Technique "execution" here is a **no-op**: we only log
``would execute technique <T-id>``. Nothing in this module attacks, scans, or
touches any real system. All technique content is generic and illustrative.

Long-running / resume
---------------------
Plan state (which steps are approved / executed / rejected) is checkpointed to a
JSON file so a run interrupted after N steps can resume from step N without
re-approving earlier steps. This stands in for a long-running Runtime skeleton;
it is deliberately simple and real (atomic write, plain JSON).

No AWS calls happen in this module directly — it drives an injected ``invoke`` /
``invoke_with_tool_result`` pair (Layer 1 by default, a fake in tests).
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

# hashlib/hmac back the checkpoint integrity digest (INV-PLAY-1). hmac only for
# compare_digest — a constant-time comparison, so a caller cannot learn the expected
# digest byte-by-byte from timing.
import hashlib
import hmac

from .logutil import get_logger

# ------------------------------------------------------------------ statuses
PENDING = "pending"
APPROVED = "approved"
EXECUTED = "executed"
REJECTED = "rejected"

# ---------------------------------------------------------------- kill chain
# A generic, SIMULATED ATT&CK-style plan. `technique` values are illustrative
# ATT&CK IDs; nothing here is executed for real.
DEFAULT_PLAN: List[Dict[str, str]] = [
    {"phase": "recon",           "technique": "T1595",
     "objective": "Emulate active scanning against the lab target (simulated)."},
    {"phase": "initial-access",  "technique": "T1190",
     "objective": "Emulate exploitation of a public-facing app in the lab (simulated)."},
    {"phase": "execution",       "technique": "T1059",
     "objective": "Emulate command/script interpreter execution (simulated)."},
    {"phase": "persistence",     "technique": "T1547",
     "objective": "Emulate a boot/logon autostart persistence step (simulated)."},
]


# ---------------------------------------------------------------- plan state
@dataclass
class StepState:
    """One step in the emulation plan and its human-gated lifecycle."""
    index: int
    phase: str
    technique: str
    objective: str
    status: str = PENDING
    tool_use_id: Optional[str] = None      # the gate call the harness paused on
    decision: Optional[Dict[str, Any]] = None   # the human decision payload
    execution_log: Optional[str] = None    # the SIMULATED no-op record

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlanState:
    """Full plan state — the unit that is checkpointed / resumed."""
    plan_id: str
    session_id: str
    steps: List[StepState] = field(default_factory=list)
    halted: bool = False
    halted_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "session_id": self.session_id,
            "halted": self.halted,
            "halted_reason": self.halted_reason,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PlanState":
        steps = [StepState(**s) for s in d.get("steps", [])]
        return cls(
            plan_id=d["plan_id"],
            session_id=d["session_id"],
            steps=steps,
            halted=d.get("halted", False),
            halted_reason=d.get("halted_reason"),
        )

    # ---- convenience views ------------------------------------------------
    def next_pending(self) -> Optional[StepState]:
        for s in self.steps:
            if s.status == PENDING:
                return s
        return None

    def is_complete(self) -> bool:
        return self.halted or all(s.status in (EXECUTED, REJECTED) for s in self.steps)

    def counts(self) -> Dict[str, int]:
        c = {PENDING: 0, APPROVED: 0, EXECUTED: 0, REJECTED: 0}
        for s in self.steps:
            c[s.status] = c.get(s.status, 0) + 1
        return c


# ---------------------------------------------------------------- checkpoint
class CheckpointError(Exception):
    """Raised when a checkpoint fails its integrity or consistency checks.

    Distinct from an I/O error so a caller can tell "the file is not there" from
    "the file was altered after it was written" — those need different responses.
    """


# Digest sidecar key. Kept INSIDE the checkpoint (not a separate file) because the
# runner is handed one path; the digest covers everything except itself.
_DIGEST_KEY = "state_digest"
_DIGEST_VERSION = "sha256-v1"


def _canonical_state(payload: Dict[str, Any]) -> str:
    """Canonical JSON of a checkpoint body for digesting.

    Keys sorted and no incidental whitespace, so the digest depends only on the
    VALUES — never on dict ordering or indentation. Mirrors
    ``provenance._canonical``; the two are deliberately the same shape because they
    solve the same problem (a record that must not change without detection).
    """
    body = {k: v for k, v in payload.items() if k != _DIGEST_KEY}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _state_digest(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_state(payload).encode("utf-8")).hexdigest()


def save_checkpoint(state: PlanState, path: str) -> str:
    """Atomically persist plan state to a JSON file (write-temp + rename).

    The written object carries a ``state_digest`` over its own canonical form, so
    :func:`load_checkpoint` can refuse a file that was edited after it was written.
    See that function for why this matters (INV-PLAY-1).
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    d = os.path.dirname(os.path.abspath(path)) or "."
    payload = state.to_dict()
    payload[_DIGEST_KEY] = {"algorithm": _DIGEST_VERSION, "value": _state_digest(payload)}
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def load_checkpoint(path: str, *, require_digest: bool = True) -> PlanState:
    """Load plan state from a checkpoint, REFUSING one that was tampered with.

    INV-PLAY-1. This used to be a bare ``PlanState.from_dict(json.load(f))`` with no
    validation at all, and ``resume_from_checkpoint`` then did
    ``runner.state = state`` to "keep prior statuses/decisions". Play Mode's entire
    reason to exist is the claim that *no offensive step happens without an explicit
    human confirmation* — and that claim was falsifiable by editing a JSON file.
    Three reproduced attacks, in increasing severity:

    1. Marking every step ``executed`` made the runner ask the human ZERO times
       while producing counts byte-identical to a real run.
    2. Setting ``halted: false`` and reverting ``rejected`` steps to ``pending``
       ERASED a human rejection from the record.
    3. Rewriting ``rejected`` to ``executed`` with a fabricated
       ``decision.approver`` made the audit record assert that a named security lead
       approved every step of an offensive plan they were never asked about.

    The technique execution itself is genuinely a no-op (verified: the module holds
    no subprocess/socket/exec primitive), so the harm is not a real attack — it is
    that the AUDIT ARTIFACT can be forged after the fact, in the direction that says
    "this was authorized". For a red-team authorization record that is the whole
    value of the file.

    Reachability is not theoretical: ``longrunning/detonation/bedrock_entrypoint.py``
    and ``longrunning/bas-runner/`` both resume from a runtime-supplied path.

    THREAT MODEL — stated plainly, because the digest is NOT a signature
    -------------------------------------------------------------------
    ``state_digest`` is an UNKEYED SHA-256. Anyone who can write the file can
    recompute it, so this defends against **accidental or careless modification**
    (a hand-edit, a truncated write, a partial sync, a buggy external writer) —
    NOT against a determined attacker with write access to the checkpoint. Verified
    experimentally: after recomputing the digest, a self-consistent forged state
    (every step ``executed`` with a fabricated APPROVED decision) is still accepted,
    because nothing distinguishes it from a genuine one.

    Closing that gap needs a key the checkpoint writer does not hold, or an anchor
    in storage it cannot rewrite — exactly what ``provenance.py`` says about its own
    ledger ("for real governance the anchor belongs in storage the ledger writer
    cannot rewrite", INV-GOV-4). That is a deployment decision, not a code one, and
    pretending otherwise here would be the same self-certification this round audits.

    What IS enforced, in three layers:

    - **Integrity** — the digest must match. Catches every accidental change, and
      forces a deliberate one to be deliberate rather than a one-character edit.
    - **Consistency** — even a correctly-digested state must be one the runner could
      have produced: known statuses, indexes matching positions, an approved or
      executed step carrying a decision that actually says APPROVED, a rejected step
      halting the plan, a halt naming its reason. Catches a state written by a buggy
      or older writer, which integrity alone cannot see.
    - **Plan binding** (in :meth:`PlayModeRunner.resume_from_checkpoint`) — the
      resumed plan must be the plan that was checkpointed. Consistency cannot detect
      a wholly SUBSTITUTED plan, because a substituted plan is perfectly consistent.

    ``require_digest=False`` accepts a legacy checkpoint written before digests
    existed, and is the ONLY way to load one. It still runs the consistency checks.
    A caller that uses it is opting out of tamper detection and should say why.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as exc:
        raise CheckpointError(f"checkpoint {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CheckpointError(
            f"checkpoint {path} must be a JSON object, got {type(raw).__name__}"
        )

    stamp = raw.get(_DIGEST_KEY)
    if stamp is None:
        if require_digest:
            raise CheckpointError(
                f"checkpoint {path} carries no {_DIGEST_KEY!r}: it predates tamper "
                "detection or was rewritten by something other than "
                "save_checkpoint(). Pass require_digest=False to load it anyway — "
                "which forgoes the guarantee that a human approval in this file was "
                "actually given."
            )
    else:
        if not isinstance(stamp, dict) or "value" not in stamp:
            raise CheckpointError(f"checkpoint {path} has a malformed {_DIGEST_KEY}")
        if stamp.get("algorithm") != _DIGEST_VERSION:
            raise CheckpointError(
                f"checkpoint {path} uses digest algorithm {stamp.get('algorithm')!r}, "
                f"this build understands {_DIGEST_VERSION!r}"
            )
        expected = _state_digest(raw)
        if not hmac.compare_digest(str(stamp["value"]), expected):
            raise CheckpointError(
                f"checkpoint {path} FAILED its integrity check — the file was "
                f"modified after it was written. Refusing to resume: a plan state "
                f"that cannot be trusted cannot attest that its offensive steps "
                f"were human-approved."
            )

    try:
        state = PlanState.from_dict(raw)
    except (KeyError, TypeError) as exc:
        raise CheckpointError(f"checkpoint {path} is malformed: {exc}") from exc
    _assert_consistent(state, path)
    return state


def _assert_consistent(state: PlanState, path: str) -> None:
    """Reject a plan state that is internally contradictory (INV-PLAY-2).

    Runs on every load, digest or not. Integrity proves the file did not change;
    this proves the state it holds is one the runner could actually have produced.
    A state that passes integrity but not consistency means the WRITER was wrong —
    a different failure that the digest cannot see.
    """
    seen_indexes = set()
    for pos, step in enumerate(state.steps):
        where = f"{path} step {pos}"
        if step.status not in (PENDING, APPROVED, EXECUTED, REJECTED):
            raise CheckpointError(
                f"{where}: unknown status {step.status!r} (expected one of "
                f"{PENDING}/{APPROVED}/{EXECUTED}/{REJECTED})"
            )
        # The index is what `reject_after` and the gate policies key on, so a
        # duplicated or out-of-order index silently mis-targets a decision.
        if step.index != pos:
            raise CheckpointError(
                f"{where}: index {step.index} does not match its position {pos}"
            )
        if step.index in seen_indexes:
            raise CheckpointError(f"{where}: duplicate step index {step.index}")
        seen_indexes.add(step.index)
        # An approved or executed step MUST carry the decision that authorized it.
        # This is the check that kills the forged-approval attack even for a
        # hand-crafted state: a step cannot claim to be executed with no decision,
        # and a decision that does not say APPROVED cannot have authorized it.
        if step.status in (APPROVED, EXECUTED):
            if not isinstance(step.decision, dict):
                raise CheckpointError(
                    f"{where}: status {step.status!r} with no decision payload — an "
                    "executed offensive step must carry the approval that "
                    "authorized it"
                )
            if not _is_approved(step.decision):
                raise CheckpointError(
                    f"{where}: status {step.status!r} but its decision is "
                    f"{step.decision.get('decision')!r}, not APPROVED"
                )
        if step.status == REJECTED and isinstance(step.decision, dict):
            if _is_approved(step.decision):
                raise CheckpointError(
                    f"{where}: status 'rejected' but its decision says APPROVED"
                )
    # A halted plan must name why, and a plan with a rejected step must be halted —
    # "rejected but still running" is precisely the state attack (2) manufactured.
    rejected = [s for s in state.steps if s.status == REJECTED]
    if rejected and not state.halted:
        raise CheckpointError(
            f"{path}: step {rejected[0].index} is rejected but the plan is not "
            "halted — a human rejection must halt the plan"
        )
    if state.halted and not state.halted_reason:
        raise CheckpointError(f"{path}: plan is halted with no halted_reason recorded")


def _assert_plan_matches(
    state: PlanState, expected_plan: List[Dict[str, str]], path: str
) -> None:
    """Refuse a checkpoint whose plan is not the plan the caller authorized.

    INV-PLAY-3. Compares the (phase, technique) sequence — the identity of the kill
    chain. ``objective`` is prose and deliberately NOT compared: rewording it does
    not change which technique gets emulated, and demanding a byte match would make
    the guard brittle enough that callers would stop passing ``expected_plan``.
    """
    got = [(s.phase, s.technique) for s in state.steps]
    want = [(str(p.get("phase")), str(p.get("technique"))) for p in expected_plan]
    if got != want:
        raise CheckpointError(
            f"{path}: checkpoint plan does not match the authorized plan. "
            f"authorized={want} checkpointed={got}. Refusing to resume a plan the "
            "operator did not approve — a substituted plan is internally consistent "
            "and its digest can be recomputed, so this comparison is the only thing "
            "that can catch it."
        )


# ---------------------------------------------------------------- decisions
def auto_approve(step: StepState, tool_use: Dict[str, Any]) -> Dict[str, Any]:
    """A decision policy that approves every gate (for tests / unattended live)."""
    return {"decision": "APPROVED", "approver": "auto",
            "note": f"Auto-approved emulation of {step.technique} ({step.phase})."}


def auto_reject(step: StepState, tool_use: Dict[str, Any]) -> Dict[str, Any]:
    """A decision policy that rejects every gate (demonstrates reject-halts)."""
    return {"decision": "REJECTED", "approver": "auto",
            "note": f"Rejected emulation of {step.technique} ({step.phase})."}


def reject_after(n: int) -> Callable[[StepState, Dict[str, Any]], Dict[str, Any]]:
    """Approve the first ``n`` steps, then reject — for demonstrating a halt."""
    def policy(step: StepState, tool_use: Dict[str, Any]) -> Dict[str, Any]:
        if step.index < n:
            return auto_approve(step, tool_use)
        return auto_reject(step, tool_use)
    return policy


def _is_approved(decision: Dict[str, Any]) -> bool:
    return str(decision.get("decision", "")).strip().upper() == "APPROVED"


# ---------------------------------------------------------------- runner
class PlayModeRunner:
    """Drive a harness through a SIMULATED kill chain with a per-step HITL gate.

    Every offensive step is gated by an ``exec_technique`` inline_function: the
    harness PAUSES (stop_reason=tool_use), the runner captures the reconstructed
    call, applies a human ``decision_fn`` (approve/reject), and RESUMES the same
    session via ``invoke_with_tool_result``. A rejected step halts the plan.

    Dependency-injected so tests need no AWS:
      * ``invoke_fn(harness_arn, session_id, text)`` -> result dict with
        ``stop_reason`` and (when paused) ``tool_use``.
      * ``resume_fn(harness_arn, session_id, tool_use, result, status=...)`` ->
        result dict for the resumed turn.

    Defaults bind to :mod:`sentinel_harness.core` (live). The technique
    EXECUTION is always a no-op: :meth:`_simulate_execution` only logs.
    """

    GATE_NAME = "exec_technique"

    def __init__(
        self,
        harness_arn: str,
        *,
        plan: Optional[List[Dict[str, str]]] = None,
        session_id: Optional[str] = None,
        plan_id: str = "playmode",
        checkpoint_path: Optional[str] = None,
        invoke_fn: Optional[Callable[..., Dict[str, Any]]] = None,
        resume_fn: Optional[Callable[..., Dict[str, Any]]] = None,
        decision_fn: Optional[Callable[[StepState, Dict[str, Any]], Dict[str, Any]]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.harness_arn = harness_arn
        self.plan_id = plan_id
        self.checkpoint_path = checkpoint_path
        self.decision_fn = decision_fn or auto_approve
        # Default to the library logger (stderr, level-gated) rather than stdout so
        # Play Mode's operational lines don't pollute a caller's stdout; a caller can
        # still inject any ``logger`` callable (e.g. a scenario's print) to override.
        self._log = logger or get_logger(f"{__name__}.playmode").info

        # Bind Layer-1 lazily so importing this module never requires AWS creds.
        if invoke_fn is None or resume_fn is None:
            from . import core as _core  # local import: avoid boto3 at module import
            invoke_fn = invoke_fn or _core.invoke
            resume_fn = resume_fn or _core.invoke_with_tool_result
            if session_id is None:
                session_id = _core.new_session("playmode")
        if session_id is None:
            session_id = f"{plan_id}-session-0000000000000000000000000000"
        self.invoke_fn = invoke_fn
        self.resume_fn = resume_fn

        plan = plan or DEFAULT_PLAN
        self.state = PlanState(
            plan_id=plan_id,
            session_id=session_id,
            steps=[
                StepState(index=i, phase=p["phase"], technique=p["technique"],
                          objective=p["objective"])
                for i, p in enumerate(plan)
            ],
        )

    # -- resume-from-checkpoint constructor ---------------------------------
    @classmethod
    def resume_from_checkpoint(
        cls,
        harness_arn: str,
        checkpoint_path: str,
        **kwargs: Any,
    ) -> "PlayModeRunner":
        """Rebuild a runner from a saved checkpoint (resumes long runs).

        ``expected_plan`` binds the resume to the plan the operator authorized
        (INV-PLAY-3). Without it the checkpoint is the ONLY source of the plan — the
        plan handed to ``cls()`` below is reconstructed from the checkpoint's own
        steps — so a wholly SUBSTITUTED plan resumes with nothing to compare against.
        That substitution survives both other layers by construction: it is
        internally consistent, and its digest can be recomputed.

        This is the one layer an attacker with write access cannot defeat, because
        the reference value lives with the caller rather than in the file. A
        long-running entrypoint that knows which plan it launched should pass it.
        """
        expected_plan = kwargs.pop("expected_plan", None)
        require_digest = kwargs.pop("require_digest", True)
        state = load_checkpoint(checkpoint_path, require_digest=require_digest)
        if expected_plan is not None:
            _assert_plan_matches(state, expected_plan, checkpoint_path)
        runner = cls(
            harness_arn,
            plan=[{"phase": s.phase, "technique": s.technique, "objective": s.objective}
                  for s in state.steps],
            session_id=state.session_id,
            plan_id=state.plan_id,
            checkpoint_path=checkpoint_path,
            **kwargs,
        )
        runner.state = state  # keep prior statuses/decisions (validated above)
        return runner

    # -- SIMULATED execution (NO-OP) ----------------------------------------
    def _simulate_execution(self, step: StepState) -> str:
        """The technique 'execution' — a pure no-op. NEVER attacks anything."""
        msg = (f"[SIMULATED] would execute technique {step.technique} "
               f"({step.phase}): {step.objective} — no action taken.")
        self._log(msg)
        return msg

    def _checkpoint(self) -> None:
        if self.checkpoint_path:
            save_checkpoint(self.state, self.checkpoint_path)

    def _prompt_for(self, step: StepState) -> str:
        return (
            f"Adversary-emulation plan step {step.index + 1} of {len(self.state.steps)}. "
            f"Phase: {step.phase}. Technique: {step.technique}. "
            f"Objective (SIMULATED): {step.objective} "
            f"Before emulating this offensive step you MUST call {self.GATE_NAME} to "
            f"request human approval (phase, technique, objective). Do not describe the "
            f"technique until you receive an approval result."
        )

    # -- one gated step ------------------------------------------------------
    def run_step(self, step: StepState) -> StepState:
        """Drive a single step through pause -> human decision -> resume.

        Approve => the harness resumes and we record a SIMULATED no-op execution.
        Reject  => the plan halts (Play Mode invariant: every action confirmed).
        """
        r1 = self.invoke_fn(self.harness_arn, self.state.session_id, self._prompt_for(step))
        tool_use = r1.get("tool_use") if r1.get("stop_reason") == "tool_use" else None

        if not tool_use:
            # The gate was NOT hit — in Play Mode an ungated offensive step is a
            # protocol violation, so we halt rather than let it proceed.
            self.state.halted = True
            self.state.halted_reason = (
                f"step {step.index} ({step.technique}) did not pass through the "
                f"{self.GATE_NAME} gate (stop_reason={r1.get('stop_reason')!r})")
            self._log(f"[HALT] {self.state.halted_reason}")
            self._checkpoint()
            return step

        step.tool_use_id = tool_use.get("toolUseId")
        decision = self.decision_fn(step, tool_use)
        step.decision = decision

        if not _is_approved(decision):
            step.status = REJECTED
            self.state.halted = True
            self.state.halted_reason = (
                f"step {step.index} ({step.technique}) rejected by "
                f"{decision.get('approver', 'human')}")
            self._log(f"[REJECT] step {step.index} {step.technique} -> plan halted")
            # Close the loop honestly: tell the harness the gate was denied.
            self.resume_fn(self.harness_arn, self.state.session_id, tool_use,
                           decision, status="error")
            self._checkpoint()
            return step

        # Approved: resume the session, then record a SIMULATED no-op execution.
        step.status = APPROVED
        self.resume_fn(self.harness_arn, self.state.session_id, tool_use, decision)
        step.execution_log = self._simulate_execution(step)
        step.status = EXECUTED
        self._log(f"[APPROVE] step {step.index} {step.technique} -> executed (simulated)")
        self._checkpoint()
        return step

    # -- full plan -----------------------------------------------------------
    def run(self) -> PlanState:
        """Run the plan from the first pending step until done or halted."""
        while not self.state.halted:
            step = self.state.next_pending()
            if step is None:
                break
            self.run_step(step)
        self._checkpoint()
        return self.state

    # -- verdict for evidence ------------------------------------------------
    def verdict(self) -> Dict[str, Any]:
        """Summarize the Play Mode invariants for an evidence file."""
        gated = [s for s in self.state.steps if s.tool_use_id]
        reached = [s for s in self.state.steps if s.status != PENDING]
        every_step_gated = all(s.tool_use_id is not None for s in reached) and bool(reached)
        approved_resumed = any(s.status == EXECUTED for s in self.state.steps)
        rejected = [s for s in self.state.steps if s.status == REJECTED]
        reject_halts = bool(rejected) and self.state.halted
        return {
            "every_step_gated": every_step_gated,
            "approved_step_resumed": approved_resumed,
            "reject_halts_plan": reject_halts,
            "closed_loop": approved_resumed or reject_halts,
            "counts": self.state.counts(),
            "halted": self.state.halted,
            "halted_reason": self.state.halted_reason,
            "gated_steps": len(gated),
            "note": "Play Mode: each offensive exec_technique step paused on a human "
                    "gate; approvals resumed the session (execution is a SIMULATED "
                    "no-op), a rejection halted the plan. No real system was touched.",
        }


# ---------------------------------------------------------------- gate tool
def exec_technique_gate() -> Dict[str, Any]:
    """The inline_function gate the Play Mode harness must call before each step.

    Built via Layer-1 ``tool_inline`` so it shares the exact pause contract.
    """
    from . import core as _core
    return _core.tool_inline(
        PlayModeRunner.GATE_NAME,
        "Request human approval before EMULATING an offensive ATT&CK technique in a "
        "SIMULATED adversary-emulation exercise. Human-in-the-loop Play Mode gate; "
        "no technique is emulated until a human approves.",
        {"type": "object",
         "properties": {
             "phase": {"type": "string", "description": "kill-chain phase"},
             "technique": {"type": "string", "description": "ATT&CK technique id, e.g. T1059"},
             "objective": {"type": "string", "description": "what the simulated step would do"}},
         "required": ["technique"]},
    )


PLAY_MODE_SYSTEM = (
    "You are a defensive adversary-emulation agent running a SIMULATED ATT&CK-style "
    "exercise in an authorized lab. This is Play Mode: before EMULATING any offensive "
    "technique you MUST call the exec_technique gate (phase, technique, objective) and "
    "wait for a human approval result. If approval is denied, stop and do not proceed. "
    "You never attack real systems; all steps are simulated for detection validation. "
    "Be concise."
)
