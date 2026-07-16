"""
sentinel-harness · autonomous self-improvement controller
==========================================================
The reusable decision engine a self-improving agent follows to turn one
under-performing harness into a promoted-or-refused one — **without a human
script hardcoding each decision**.

.. warning::
   **This is the DETERMINISTIC control logic, decoupled from I/O.** It never
   invokes a model, calls AWS, reads a clock, or touches the network. It is
   driven entirely by two INJECTED callables — ``score_fn`` (score a candidate)
   and ``revise_fn`` (produce the next candidate from the last score's feedback)
   — so the SAME controller runs (a) fully offline in CI with the deterministic
   assertion scorer + a canned reviser, and (b) live with ``run_evaluation`` as
   ``score_fn`` and an ``agent-ops`` invoke as ``revise_fn``. Same inputs →
   identical decision trace.

Why this exists (the gap it closes)
-----------------------------------
``scenarios/scenario_self_improve_loop.py`` proved the north-star loop end-to-end,
but the *decisions* (score → below bar → revise → re-score → promote) were spelled
out step-by-step in the script. That is "a human wrote the loop", not "the agent
runs the loop". This module lifts that logic into a component:

    run_improvement_loop(initial_candidate, score_fn, revise_fn, ...) -> LoopResult

so the self-improving harness (or any driver) supplies the two domain callables
and the controller owns the control flow: the retry-with-reasoning loop, the hard
cap, the regression guard + safety veto (reused from ``loop_safety``), and the
HITL promotion gate. The runner shrinks to "wire the callables"; the *policy*
lives here, once, tested.

The decision policy (fail-closed)
---------------------------------
1. Score the candidate. If it clears the bar AND passes the safety veto → stop
   improving (a candidate can't be improved past passing).
2. Otherwise, if rounds remain, ``revise_fn`` produces the next candidate FROM the
   score's feedback (a concrete reasoning change is required each round — a reviser
   that returns an unchanged candidate ends the loop, never spins forever).
3. After the loop, gate promotion on ALL of: the final candidate passed the safety
   veto, cleared the pass bar, cleared the ``regression_guard`` vs the incumbent
   best, AND a human approval callback (``approve_fn``) said yes. Any single false
   → NOT promoted, with the blocking reason recorded.

Every step is captured in an auditable trace so the evidence shows exactly why the
loop promoted or refused — never a bare boolean.

Nothing here is customer- or company-specific.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import loop_safety

# --------------------------------------------------------------------------- #
# Types for the injected callables (documentation — not enforced at runtime)  #
# --------------------------------------------------------------------------- #
# score_fn(candidate) -> a score dict carrying at least:
#   {"score": float in [0,1], "dimension_scores": {dim: score, ...}, "feedback": Any}
# The dimension_scores feed the safety veto; feedback feeds the next revise.
ScoreFn = Callable[[Any], Dict[str, Any]]
# revise_fn(candidate, score) -> the next candidate (any type the score_fn accepts).
ReviseFn = Callable[[Any, Dict[str, Any]], Any]
# approve_fn(candidate, score) -> bool  (the HITL promotion gate).
ApproveFn = Callable[[Any, Dict[str, Any]], bool]


@dataclass(frozen=True)
class Attempt:
    """One scored candidate in the loop (the auditable per-round record)."""

    round: int
    score: float
    passed_bar: bool
    safety_vetoed: bool
    failed_safety: List[str]
    revised: bool                 # did a revision happen AFTER this attempt?


@dataclass(frozen=True)
class LoopResult:
    """The full outcome of an autonomous improvement loop — an audit record.

    ``promoted`` is the single bottom-line; ``reason`` explains it; ``attempts``
    is the per-round trace; ``final_score`` is the last candidate's score."""

    promoted: bool
    reason: str
    final_score: float
    rounds_used: int
    attempts: List[Attempt]
    passed_bar: bool
    safety_ok: bool
    regression_ok: bool
    human_approved: bool
    notes: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Score-shape helpers                                                         #
# --------------------------------------------------------------------------- #
def _score_value(score: Dict[str, Any]) -> float:
    """Pull the aggregate float from a score dict, clamped to [0, 1].

    Tolerant of ``score`` / ``aggregate`` keys and numeric strings; a missing or
    unparseable value is treated as 0.0 (a score we can't read is not a pass).
    **NaN / ±inf also coerce to 0.0** — a non-finite score must fail-closed (never
    promote), not crash the loop downstream (``loop_safety._as_score`` rejects
    non-finite); NaN also defeats the ``v<0``/``v>1`` clamp since both compare
    False, so it is handled explicitly here. **A ``bool`` is rejected to 0.0** —
    ``bool`` is an ``int`` subclass so ``float(True)==1.0`` would silently
    auto-promote on a judge that returned a pass-FLAG under ``score``; the rest of
    the platform (``loop_safety._as_score``) fails loud on bool, so we fail-closed."""
    import math
    for key in ("score", "aggregate"):
        if key in score:
            v_raw = score[key]
            if isinstance(v_raw, bool):  # bool is an int subclass -> reject (fail-closed)
                return 0.0
            try:
                v = float(v_raw)
            except (TypeError, ValueError):
                return 0.0
            if not math.isfinite(v):  # NaN / inf -> fail-closed
                return 0.0
            return 0.0 if v < 0 else 1.0 if v > 1 else v
    return 0.0


# Keys that ``loop_safety.parse_dimension_scores`` treats as a NESTED dimension
# block and RE-DESCENDS into. If such a key rides inside our dimension_scores, the
# parser would parse only the child and silently drop the sibling safety dims —
# an audited safety-veto bypass. We strip them so the veto sees the real dims.
_NESTED_DIM_KEYS = ("dimensions", "dimension_scores")


def _dimension_scores(score: Dict[str, Any]) -> Dict[str, Any]:
    """Pull per-dimension scores from a score dict (empty if absent).

    Strips any nested ``dimensions``/``dimension_scores`` child key: those cause
    ``loop_safety.parse_dimension_scores`` to re-descend and drop the sibling
    safety dimensions, letting an unsafe candidate promote (audited HIGH bypass).
    A safety score must never hide behind such a nested key."""
    dims = score.get("dimension_scores")
    if not isinstance(dims, dict):
        return {}
    return {k: v for k, v in dims.items() if k not in _NESTED_DIM_KEYS}


def evaluate_gate(
    score: Dict[str, Any],
    *,
    threshold: float,
    incumbent_best: Optional[float],
    require_strict_improvement: bool = False,
) -> Dict[str, Any]:
    """Combine the safety veto + pass bar + regression guard for one candidate. PURE.

    Returns ``{"passed_bar", "safety_ok", "failed_safety", "regression_ok",
    "promotable_pre_human", "reason"}``. ``promotable_pre_human`` is True iff every
    machine gate passed (the human gate is applied separately by the loop). Reusing
    ``loop_safety`` keeps this the SAME veto/guard the rest of the platform uses."""
    agg = _score_value(score)
    dims = _dimension_scores(score)

    veto = loop_safety.apply_safety_veto(dims, aggregate=agg, threshold=threshold)
    safety_ok = not veto["vetoed"]
    passed_bar = veto["aggregate_passed"]

    guard = loop_safety.regression_guard(
        incumbent_best, agg, min_pass=threshold,
        require_strict_improvement=require_strict_improvement,
    )
    regression_ok = guard["promote"]

    promotable = safety_ok and passed_bar and regression_ok
    if promotable:
        reason = "all machine gates passed (safety ok, cleared bar, no regression)"
    else:
        parts = []
        if not safety_ok:
            parts.append(veto["reason"])
        if not passed_bar:
            parts.append(f"aggregate {agg:.4g} below bar {threshold:.4g}")
        if not regression_ok:
            parts.append(guard["reason"])
        reason = "; ".join(parts)
    return {
        "passed_bar": passed_bar,
        "safety_ok": safety_ok,
        "failed_safety": veto["failed_safety"],
        "regression_ok": regression_ok,
        "promotable_pre_human": promotable,
        "reason": reason,
    }


# --------------------------------------------------------------------------- #
# The autonomous loop                                                         #
# --------------------------------------------------------------------------- #
def run_improvement_loop(
    initial_candidate: Any,
    score_fn: ScoreFn,
    revise_fn: ReviseFn,
    *,
    threshold: float,
    max_rounds: int = 3,
    incumbent_best: Optional[float] = None,
    approve_fn: Optional[ApproveFn] = None,
    require_strict_improvement: bool = False,
) -> LoopResult:
    """Drive one candidate through score → revise-until-passing → gated promotion.

    Parameters
    ----------
    initial_candidate:
        The starting candidate (e.g. a weak harness spec). Opaque to the
        controller — only ``score_fn`` / ``revise_fn`` interpret it.
    score_fn:
        ``candidate -> {"score": float, "dimension_scores": {...}, "feedback": ...}``.
        The one place scoring happens (offline scorer in CI, live judge in prod).
    revise_fn:
        ``(candidate, score) -> next_candidate``. Must make a concrete change from
        the feedback; returning an unchanged candidate ends the loop (no spin).
    threshold:
        Pass bar in [0, 1] (``eval/criteria.yaml``'s ``pass_threshold``).
    max_rounds:
        Hard cap on total scored attempts (>=1). The loop can NEVER exceed this —
        the anti-infinite-loop guarantee.
    incumbent_best:
        Best score any promoted agent achieved so far (regression guard baseline);
        ``None`` for the first candidate.
    approve_fn:
        The HITL promotion gate ``(candidate, score) -> bool``. If ``None``,
        promotion is treated as human-REFUSED (fail-closed: no silent auto-promote).
    require_strict_improvement:
        Passed through to ``regression_guard`` (tie with incumbent not enough).

    Returns
    -------
    A :class:`LoopResult` audit record. Deterministic given deterministic
    ``score_fn``/``revise_fn``.
    """
    if max_rounds < 1:
        raise ValueError("max_rounds must be >= 1")

    candidate = initial_candidate
    attempts: List[Attempt] = []
    last_score: Dict[str, Any] = {}
    last_gate: Dict[str, Any] = {}
    rounds_used = 0

    for rnd in range(1, max_rounds + 1):
        rounds_used = rnd
        last_score = score_fn(candidate)
        gate = evaluate_gate(
            last_score, threshold=threshold, incumbent_best=incumbent_best,
            require_strict_improvement=require_strict_improvement,
        )
        last_gate = gate

        # Stop early only when the candidate is FULLY promotable (bar + safety +
        # no regression) — i.e. the actual promotion gate. Using only bar+safety
        # here was an audited bug: a candidate that clears the bar and is safe but
        # REGRESSES below the incumbent would terminate the loop and refuse a
        # promotion a further revision could have earned — and, perversely, a WORSE
        # starting candidate (below bar) would keep revising and promote while a
        # better-but-regressing one stopped and failed. Gating on the full
        # promotion condition keeps revising until it truly beats the incumbent.
        done = gate["promotable_pre_human"]
        revised = False
        if not done and rnd < max_rounds:
            nxt = revise_fn(candidate, last_score)
            # A reviser that makes no change ends the loop — never spin uselessly.
            if nxt is not None and nxt != candidate:
                candidate = nxt
                revised = True

        attempts.append(Attempt(
            round=rnd,
            score=_score_value(last_score),
            passed_bar=gate["passed_bar"],
            safety_vetoed=not gate["safety_ok"],
            failed_safety=list(gate["failed_safety"]),
            revised=revised,
        ))

        if done:
            break
        if not revised:
            # No further revision possible (converged or reviser gave up) — stop.
            break

    # Final promotion gating: machine gates (from the last attempt) AND the human.
    passed_bar = last_gate.get("passed_bar", False)
    safety_ok = last_gate.get("safety_ok", False)
    regression_ok = last_gate.get("regression_ok", False)
    machine_ok = last_gate.get("promotable_pre_human", False)

    human_approved = False
    if machine_ok and approve_fn is not None:
        human_approved = bool(approve_fn(candidate, last_score))

    promoted = machine_ok and human_approved

    if promoted:
        reason = "PROMOTED: " + last_gate.get("reason", "") + " + human approved"
    elif not machine_ok:
        reason = "NOT promoted (machine gate): " + last_gate.get("reason", "")
    elif approve_fn is None:
        reason = "NOT promoted: machine gates passed but no approval callback (fail-closed)"
    else:
        reason = "NOT promoted: machine gates passed but human REJECTED"

    return LoopResult(
        promoted=promoted,
        reason=reason,
        final_score=_score_value(last_score),
        rounds_used=rounds_used,
        attempts=attempts,
        passed_bar=passed_bar,
        safety_ok=safety_ok,
        regression_ok=regression_ok,
        human_approved=human_approved,
        notes=[
            "Deterministic control logic; scoring/revision/approval are injected "
            "callables (offline scorer + canned reviser in CI; run_evaluation + "
            "agent-ops invoke + inline_function gate in prod).",
            f"Hard cap: at most {max_rounds} scored attempts (no infinite loop).",
        ],
    )


def result_to_dict(result: LoopResult) -> Dict[str, Any]:
    """Serialize a :class:`LoopResult` to a plain JSON-able dict (evidence)."""
    return {
        "promoted": result.promoted,
        "reason": result.reason,
        "final_score": result.final_score,
        "rounds_used": result.rounds_used,
        "passed_bar": result.passed_bar,
        "safety_ok": result.safety_ok,
        "regression_ok": result.regression_ok,
        "human_approved": result.human_approved,
        "attempts": [
            {
                "round": a.round, "score": a.score, "passed_bar": a.passed_bar,
                "safety_vetoed": a.safety_vetoed, "failed_safety": a.failed_safety,
                "revised": a.revised,
            }
            for a in result.attempts
        ],
        "notes": result.notes,
    }
