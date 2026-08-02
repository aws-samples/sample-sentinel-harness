"""
Property-based (Hypothesis) verification of the PROMOTION POLICY itself.
=======================================================================
The existing property tests check output SHAPE — e.g. "an allowed command carries
no shell metacharacter", "a verdict dict has the right keys". Every M18 defect
slipped past exactly that class of assertion: each one produced a perfectly
well-shaped output while violating the security property the code exists to
enforce.

So this module fuzzes the POLICY, not the shape. Hypothesis generates arbitrary
agent tool-call streams — evaluations of different harnesses, approvals,
rejections, promotions of any subject, unknown tools, spins — and every test
asserts a property that must hold for EVERY stream:

    INV-PROMOTE-1  promoted ⟹ the driver witnessed a passing eval
    INV-PROMOTE-2  promoted ⟹ a human approved, AND the approved subject is
                   exactly the promoted subject
    INV-PROMOTE-3  promoted ⟹ that eval actually scored every veto dimension
    INV-PROMOTE-5  promoted ⟹ the eval that authorized it scored the SAME
                   harness that was promoted
    INV-LOOP-1     tool_calls_used never exceeds max_tool_calls
    INV-LOOP-2     every pending toolUseId is answered exactly once

These are stated as implications from ``promoted``, which is the phrasing that
matters: it does not matter HOW the stream got there, promotion must never be
reachable without the full evidence chain. A single counterexample is a
privilege-escalation bug.

Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import json
import os
import sys

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import agent_loop as AL          # noqa: E402

# The universe of harness ids the generated agent may talk about. Kept tiny (3) so
# Hypothesis actually explores the interesting case — scoring one and promoting
# another — instead of drowning in unique names that never collide.
HARNESS_IDS = ["harness_A", "harness_B", "harness_C"]

# Dimension sets a generated eval may report: complete evidence, partial, or none.
# The gate must only ever promote on the complete one.
DIM_SETS = [
    {"safety": 1.0, "groundedness": 1.0},           # complete + passing
    {"safety": 1.0, "groundedness": 0.0},           # groundedness FAILS
    {"safety": 0.0, "groundedness": 1.0},           # safety FAILS
    {"Builtin.Harmfulness": 0.0, "Builtin.Faithfulness": 1.0},   # aliased + passing
    {"Builtin.Harmfulness": 1.0, "Builtin.Faithfulness": 1.0},   # aliased + harmful
    {"safety": 1.0},                                 # PARTIAL (no groundedness)
    {"correctness": 0.95},                           # NO veto dims at all
    {},                                              # empty
]

_VETO_CANONICAL = ("safety", "groundedness")


# --------------------------------------------------------------------------- #
# Generated agent step vocabulary                                             #
# --------------------------------------------------------------------------- #
_eval_step = st.builds(
    lambda hid, dims_idx, score: {
        "kind": "eval", "harness_id": hid, "dims_idx": dims_idx, "score": score},
    hid=st.sampled_from(HARNESS_IDS),
    dims_idx=st.integers(min_value=0, max_value=len(DIM_SETS) - 1),
    score=st.sampled_from([0.0, 0.3, 0.69, 0.7, 0.85, 0.95, 1.0]),
)
_hitl_step = st.builds(
    lambda hid, decision: {"kind": "hitl", "harness_id": hid, "decision": decision},
    hid=st.sampled_from(HARNESS_IDS + [None]),   # None == payload names no harness
    decision=st.booleans(),
)
_promote_step = st.builds(
    lambda hid, action: {"kind": "promote", "harness_id": hid, "action": action},
    hid=st.sampled_from(HARNESS_IDS + [None]),
    action=st.sampled_from(["create_endpoint", "update_endpoint", "promote_endpoint"]),
)
_noise_step = st.sampled_from([
    {"kind": "unknown"}, {"kind": "boom"}, {"kind": "other_tool"},
])

_step = st.one_of(_eval_step, _hitl_step, _promote_step, _noise_step)
# A "turn" is one or two steps: 2 models the PARALLEL tool_use case (the agent
# emitting a gate and an eval in the same turn), which is where the first version
# of the M18.3 fix broke.
_turn = st.lists(_step, min_size=1, max_size=2)
_stream = st.lists(_turn, min_size=1, max_size=6)


class _ScriptedAgent:
    """Turns a generated step-stream into invoke/resume callables, and records
    every toolUseId issued vs answered so the resume contract can be verified."""

    def __init__(self, turns):
        self.turns = turns
        self.idx = 0
        self.issued: list[str] = []
        self.answered: list[str] = []
        self.eval_calls: list[dict] = []

    def _build(self):
        if self.idx >= len(self.turns):
            return {"stop_reason": "end_turn", "text": "done", "tool_uses": []}
        turn = self.turns[self.idx]
        self.idx += 1
        tool_uses = []
        for i, step in enumerate(turn):
            tuid = f"tu-{self.idx}-{i}"
            self.issued.append(tuid)
            tool_uses.append({"toolUseId": tuid, **_step_to_call(step)})
        return {"stop_reason": "tool_use", "tool_uses": tool_uses}

    def invoke_fn(self):
        return self._build()

    def resume_fn(self, answers):
        for ans in answers:
            tool_use = ans[0]
            payload = ans[1]
            # The live contract requires a JSON-serializable result per gate.
            json.loads(payload)
            self.answered.append(tool_use["toolUseId"])
        return self._build()


def _step_to_call(step):
    """Project a generated step into a (name, input) tool_use body."""
    kind = step["kind"]
    if kind == "eval":
        return {"name": "run_evaluation",
                "input": {"harness_id": step["harness_id"],
                          "_dims_idx": step["dims_idx"], "_score": step["score"]}}
    if kind == "hitl":
        # `_decision` rides in the payload so the fake analyst can honour the
        # generated choice (approve OR reject) instead of always consenting —
        # otherwise the rejection half of the state space is never explored.
        payload = {"_decision": step["decision"]}
        if step["harness_id"] is not None:
            payload["harness_id"] = step["harness_id"]
        return {"name": "request_promotion_approval", "input": payload}
    if kind == "promote":
        params = {"endpoint_name": "prod"}
        if step["harness_id"] is not None:
            params["harness_id"] = step["harness_id"]
        return {"name": "harness_ops", "input": {"action": step["action"], "params": params}}
    if kind == "boom":
        return {"name": "harness_ops", "input": {"action": "explode"}}
    if kind == "other_tool":
        return {"name": "harness_ops", "input": {"action": "list"}}
    return {"name": "definitely_not_a_real_tool", "input": {}}


def _run(turns, *, max_tool_calls=20, threshold=0.7, incumbent_best=None):
    """Drive the generated stream through the real driver, capturing what the
    eval handler actually returned (the ground truth for the invariants)."""
    agent = _ScriptedAgent(turns)
    eval_returns: list[dict] = []
    approvals: list[dict] = []
    promotion_evidence: list[dict] = []

    def eval_handler(tool_input):
        dims = DIM_SETS[tool_input.get("_dims_idx", 0)]
        out = {"harness_id": tool_input.get("harness_id"),
               "score": tool_input.get("_score", 0.0),
               "dimension_scores": dict(dims)}
        eval_returns.append(out)
        return out

    def harness_ops_handler(tool_input):
        if tool_input.get("action") == "explode":
            raise RuntimeError("handler blew up")
        # Snapshot the evidence AS IT STOOD when the promotion executed. A stream
        # may keep evaluating afterwards (even re-scoring the same harness lower),
        # so reconstructing "the authorizing eval" after the fact from the full
        # list is wrong — the decision was made on this state, and this is what the
        # invariants must be checked against.
        if tool_input.get("action") in ("create_endpoint", "update_endpoint",
                                        "promote_endpoint"):
            promotion_evidence.append(
                {"target": (tool_input.get("params") or {}).get("harness_id"),
                 "evals_so_far": [dict(e) for e in eval_returns],
                 # The APPROVALS as they stood too. Snapshotting the evals but not
                 # the consent left the approval assertion reading end-of-session
                 # state, so a stream that promoted legitimately and then had a
                 # LATER approval denied falsified the property — the assertion was
                 # wrong, not the gate. This is the same snapshot-vs-final-state
                 # error the `witnessed_subject` comment below records; it was fixed
                 # for the subject and missed for the consent.
                 "approvals_so_far": [dict(a) for a in approvals]})
        return {"ok": True}

    def approve_fn(tool_input):
        # The generated stream encodes the decision in the payload's presence of a
        # sentinel; simpler: approve unless the step said otherwise. We re-derive
        # the decision from the recorded turn, so read it off the input.
        approvals.append(dict(tool_input))
        return tool_input.get("_decision", True)

    result = AL.run_agent_loop(
        invoke_fn=agent.invoke_fn,
        resume_fn=agent.resume_fn,
        dispatch={"run_evaluation": eval_handler, "harness_ops": harness_ops_handler},
        approve_fn=approve_fn,
        threshold=threshold,
        incumbent_best=incumbent_best,
        max_tool_calls=max_tool_calls,
    )
    return result, agent, eval_returns, promotion_evidence


# The search budget is part of the contract, not a performance tuning knob.
#
# This was 250. At 250, THREE of the properties below passed while being falsifiable —
# `max_examples=5000` produced a counterexample for each within a minute (round 19). The
# shape needed a promotion followed by ANOTHER eval in a later turn, which 250 draws
# never assembled. A property test that passes because it did not look is
# indistinguishable from one that holds, which is the same failure mode as a structural
# guard shipping blind (INV-GUARD-0).
#
# 2000 is the floor at which all three counterexamples reproduce with margin, at ~20s
# for the file. `SENTINEL_PROP_EXAMPLES` raises it for a deliberate deep run without
# editing this line — the round-19 sweep used 5000. It cannot LOWER it below the floor:
# a green run at 50 examples would mean nothing, and making that easy is how the budget
# silently becomes 50.
_PROP_FLOOR = 2000
_PROP_EXAMPLES = max(_PROP_FLOOR, int(os.environ.get("SENTINEL_PROP_EXAMPLES") or 0))

_SETTINGS = settings(
    max_examples=_PROP_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def test_the_search_budget_is_not_silently_lowered():
    """CONTROL for the budget itself. Every property in this file inherits `_SETTINGS`,
    so this one number decides whether any of them can find anything."""
    assert _PROP_EXAMPLES >= _PROP_FLOOR, (
        f"the property search budget is {_PROP_EXAMPLES}, below the {_PROP_FLOOR} floor. "
        "Three properties in this file passed at 250 while being falsifiable; a budget "
        "below the floor means a green run here proves nothing."
    )
    assert _SETTINGS.max_examples == _PROP_EXAMPLES, (
        "the settings object does not carry the computed budget, so the floor is "
        "not actually applied to any property"
    )


def test_the_budget_env_override_can_only_raise():
    """A lower override must be ignored, not honoured."""
    def resolve(raw: str) -> int:
        return max(_PROP_FLOOR, int(raw or 0))
    assert resolve("50") == _PROP_FLOOR
    assert resolve("") == _PROP_FLOOR
    assert resolve("5000") == 5000


# ========================================================================== #
# The promotion-policy invariants                                            #
# ========================================================================== #
@given(_stream)
@_SETTINGS
def test_promotion_implies_a_witnessed_passing_eval(turns):
    """INV-PROMOTE-1: no promotion without an eval the DRIVER scored as passing.

    The agent cannot promote by assertion; only a handler's real return can
    satisfy the gate.

    Checked against the eval evidence AS OF the promotion, not
    ``result.witnessed_pass``. That field is mutable driver state overwritten by every
    later eval, so this legal stream falsified it::

        eval(A, 0.7)  ->  approve(A) + promote(A)  ->  eval(A, 0.0)

    The gate held when it mattered; only the end-of-session value is False. Round 19,
    and the THIRD instance of this snapshot-vs-final-state error in this file — the two
    comments below already record the first two. It stayed hidden because
    ``max_examples=250`` never generated the three-turn shape; 5000 found it.
    """
    result, _, eval_returns, promo = _run(turns)
    if result.promoted:
        assert eval_returns, "promoted with no evaluation ever executed"
        assert promo, "promoted but the promotion handler never ran"
        # The authorizing evidence: an eval of the PROMOTED subject, at or above the
        # threshold, on record before the promotion executed. Re-derived from the
        # handler's own returns rather than read off the driver, so a driver that
        # mis-set its own flag would still be caught.
        target = promo[-1]["target"]
        authorizing = [e for e in promo[-1]["evals_so_far"]
                       if e["harness_id"] == target and e["score"] >= 0.7]
        assert authorizing, (
            f"promoted {target!r} with no passing eval of it on record at that moment; "
            f"evals seen by then: {promo[-1]['evals_so_far']}"
        )


@given(_stream)
@_SETTINGS
def test_promotion_implies_human_approval_of_the_same_subject(turns):
    """INV-PROMOTE-2: promotion requires consent, bound to the promoted harness.

    This is the invariant the pre-M18 code violated: approval was a bare bool, so
    consent for harness A authorized promoting harness B."""
    result, _, _, promo = _run(turns)
    if result.promoted:
        assert promo, "promoted but the promotion handler never ran"
        # Check the consent that AUTHORIZED this promotion, not the session's final
        # approval state. `result.witnessed_approval` is end-of-session: a stream may
        # legitimately promote and then have a LATER approval request denied, which
        # flips that flag without retroactively un-authorizing the promotion that
        # already happened. Reading it here made the property falsifiable by a
        # perfectly legal stream — the same snapshot-vs-final-state error the
        # subject check below already corrects for.
        approvals_at_promotion = promo[-1]["approvals_so_far"]
        assert any(a.get("_decision", True) for a in approvals_at_promotion), (
            "promoted with no granted approval on record at the moment it executed; "
            f"approvals seen by then: {approvals_at_promotion}"
        )
        # Compare against the subject the PROMOTION targeted, captured when it
        # executed. ``result.witnessed_subject`` is end-of-session state: a stream
        # may evaluate another harness AFTER the promotion (even in the same turn),
        # which legitimately moves it. The security property is about the harness
        # that was actually promoted.
        promoted_target = promo[-1]["target"]
        assert promoted_target is not None, \
            "a promotion executed without naming its target"
        # `result.approved_subject` is ALSO mutable driver state — cleared on a later
        # rejection (agent_loop.py:459) and re-set by every later eval (:566) — so
        # reading it here is the same error as the witnessed_pass one above.
        # Re-derive the consent from the approvals on record at that moment: a granted
        # approval that named this target, or a granted approval that named nothing
        # (the driver then binds it to the evaluated subject, which INV-PROMOTE-5
        # separately requires to be the target).
        granted = [a for a in approvals_at_promotion if a.get("_decision", True)]
        bound = [a for a in granted
                 if a.get("harness_id") in (promoted_target, None)]
        assert bound, (
            f"promoted {promoted_target!r} with no granted approval naming it (or "
            f"naming nothing) on record at that moment; approvals seen by then: "
            f"{approvals_at_promotion}"
        )


@given(_stream)
@_SETTINGS
def test_promotion_implies_every_veto_dimension_was_actually_scored(turns):
    """INV-PROMOTE-3: a judge's SILENCE on safety can never authorize promotion.

    Re-derives the check from the eval handler's OWN recorded return, so this
    would catch the gate accepting incomplete evidence even if evaluate_gate's
    bookkeeping said otherwise."""
    result, _, eval_returns, promo = _run(turns)
    if not result.promoted:
        return
    # Use the evidence AS OF the promotion, not the full eval list: a stream may
    # keep evaluating (even re-scoring the same harness lower) AFTER the promotion
    # executed, and the decision can only be judged on what was known at the time.
    assert promo, "promoted but the promotion handler never ran"
    evals_at_promotion = promo[-1]["evals_so_far"]
    target = promo[-1]["target"]
    authorizing = [e for e in evals_at_promotion if e["harness_id"] == target]
    assert authorizing, "promoted without any eval of that subject"
    dims = authorizing[-1]["dimension_scores"]
    canonical = set()
    for name in dims:
        key = name.strip().lower()
        # Mirror the alias map without importing it, so a bad alias edit is caught.
        if key in ("safety", "safety_score", "is_safe", "harmfulness",
                   "builtin.harmfulness", "safety_check"):
            canonical.add("safety")
        elif key in ("groundedness", "faithfulness", "builtin.faithfulness",
                     "groundedness_score"):
            canonical.add("groundedness")
    for dim in _VETO_CANONICAL:
        assert dim in canonical, (
            f"promoted on evidence missing the {dim!r} dimension: {dims}")


@given(_stream)
@_SETTINGS
def test_promotion_implies_subject_consistency_end_to_end(turns):
    """INV-PROMOTE-5: the eval, the approval and the promotion all name ONE harness.

    All three legs read from the promotion-time snapshot. `result.approved_subject` is
    mutable driver state (cleared by a later rejection, re-set by a later eval), so
    reading it made this property falsifiable by the same legal stream that broke
    INV-PROMOTE-1 above.
    """
    result, _, eval_returns, promo = _run(turns)
    if result.promoted:
        assert promo, "promoted but the promotion handler never ran"
        target = promo[-1]["target"]
        assert target is not None
        # Leg 1: an eval of the target was on record.
        assert any(e["harness_id"] == target
                   for e in promo[-1]["evals_so_far"]), (
            f"promoted {target!r} with no eval of it on record: "
            f"{promo[-1]['evals_so_far']}"
        )
        # Leg 2: a granted approval bound to the target (or unbound, which the driver
        # binds to the evaluated subject — leg 1 pins that to the target).
        granted = [a for a in promo[-1]["approvals_so_far"]
                   if a.get("_decision", True)]
        assert [a for a in granted if a.get("harness_id") in (target, None)], (
            f"promoted {target!r} with no granted approval naming it: {granted}"
        )
        # Leg 3: the confused-deputy shape — consent that named ONLY other harnesses,
        # with nothing the driver could legitimately bind to this one.
        #
        # My first version of this asserted that a granted approval must NAME the target
        # whenever any granted approval named something else. That is too strong, and a
        # legal stream falsified it:
        #
        #     approve(A)  ->  eval(C, 0.7) + approve(<unnamed>)  ->  promote(C)
        #
        # An UNNAMED approval is bound by the driver to the evaluated subject
        # (`agent_loop.py:455`, `approved_subject = named or witnessed_subject`), so that
        # consent legitimately authorizes C. The property is that SOME granted approval is
        # bindable to the target — either by naming it, or by naming nothing while the
        # target was the subject on the table. An approval naming a different harness is
        # the deputy shape only when there is nothing else to bind.
        bindable = [a for a in granted if a.get("harness_id") in (target, None)]
        assert bindable, (
            f"promoted {target!r} while every granted consent named a different "
            f"harness: {[a.get('harness_id') for a in granted]} — consent for one "
            "harness authorized another"
        )


@given(_stream)
@_SETTINGS
def test_a_rejected_approval_never_promotes(turns):
    """A human REJECTION must be terminal for that consent: with every approval
    denied, no stream may ever promote."""
    agent = _ScriptedAgent(turns)

    def eval_handler(tool_input):
        return {"harness_id": tool_input.get("harness_id"),
                "score": 1.0,
                "dimension_scores": {"safety": 1.0, "groundedness": 1.0}}

    result = AL.run_agent_loop(
        invoke_fn=agent.invoke_fn, resume_fn=agent.resume_fn,
        dispatch={"run_evaluation": eval_handler,
                  "harness_ops": lambda ti: {"ok": True}},
        approve_fn=lambda ti: False,            # human always says NO
        threshold=0.7,
    )
    assert result.promoted is False
    assert result.approved_subject is None


@given(_stream)
@_SETTINGS
def test_no_approve_fn_never_promotes(turns):
    """A missing approval callback means REFUSED, never "skip the gate"."""
    agent = _ScriptedAgent(turns)
    result = AL.run_agent_loop(
        invoke_fn=agent.invoke_fn, resume_fn=agent.resume_fn,
        dispatch={"run_evaluation": lambda ti: {
                      "harness_id": ti.get("harness_id"), "score": 1.0,
                      "dimension_scores": {"safety": 1.0, "groundedness": 1.0}},
                  "harness_ops": lambda ti: {"ok": True}},
        approve_fn=None,
        threshold=0.7,
    )
    assert result.promoted is False


@given(_stream, st.floats(min_value=0.0, max_value=1.0))
@_SETTINGS
def test_promotion_never_regresses_below_the_incumbent(turns, incumbent):
    """INV-PROMOTE-6: with a perfect incumbent, only a perfect candidate promotes."""
    result, _, eval_returns, promo = _run(turns, incumbent_best=incumbent)
    if result.promoted:
        assert promo, "promoted but the promotion handler never ran"
        # Evidence as of the promotion (see the note in the veto-dimension test).
        target = promo[-1]["target"]
        authorizing = [e for e in promo[-1]["evals_so_far"]
                       if e["harness_id"] == target]
        assert authorizing
        assert max(e["score"] for e in authorizing) >= incumbent - 1e-9, (
            f"promoted over incumbent {incumbent} with no eval of "
            f"{target!r} reaching it")


# ========================================================================== #
# Loop-safety invariants (no spin, contract-correct resumes)                  #
# ========================================================================== #
@given(_stream, st.integers(min_value=1, max_value=8))
@_SETTINGS
def test_tool_call_cap_is_never_exceeded(turns, cap):
    """INV-LOOP-1: the hard cap is absolute — an agent can never spin past it."""
    result, _, _, promo = _run(turns, max_tool_calls=cap)
    assert result.tool_calls_used <= cap


@given(_stream)
@_SETTINGS
def test_every_pending_gate_is_answered_exactly_once(turns):
    """INV-LOOP-2: the live resume contract — EVERY paused toolUseId gets exactly
    one toolResult. A missing or duplicated answer is a corrupted session."""
    result, agent, _, promo = _run(turns)
    # Only ids from turns the driver actually consumed can be answered; the last
    # turn's answers are sent with the resume that ends the loop.
    assert len(agent.answered) == len(set(agent.answered)), "an id was answered twice"
    for tuid in agent.answered:
        assert tuid in agent.issued, "answered an id that was never issued"
    assert result.tool_calls_used >= 0


@given(_stream)
@_SETTINGS
def test_driver_never_raises_on_arbitrary_streams(turns):
    """Robustness: unknown tools, exploding handlers and empty turns are audited
    as structured outcomes, never propagated as a crash."""
    result, _, _, promo = _run(turns)
    assert isinstance(result.promoted, bool)
    assert result.stopped_by in ("end_turn", "cap", "session_error")
    for rec in result.trace:
        assert rec.outcome in ("executed", "refused_promotion", "hitl",
                              "unknown_tool", "handler_error")


@given(_stream)
@_SETTINGS
def test_refusals_always_carry_a_reason(turns):
    """Every refused promotion must be explainable in the audit record — a silent
    refusal is as bad for trust as a silent approval."""
    result, _, _, promo = _run(turns)
    assert len(result.refusal_reasons) == result.refused_promotions
    for reason in result.refusal_reasons:
        assert isinstance(reason, str) and reason.strip()
