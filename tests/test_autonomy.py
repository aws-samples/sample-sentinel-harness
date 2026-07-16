"""
Offline tests for sentinel_harness.autonomy — the self-improvement controller.

ZERO AWS, ZERO network, no clock, no model. The controller is pure decision logic
driven by INJECTED score/revise/approve callables, so every policy branch is
exactly checkable with canned callables:
- promote path (weak → revise → pass → human approve),
- safety veto force-fail (high aggregate, failed safety dim → not promoted),
- regression guard (below incumbent best → blocked),
- HITL: human reject, and fail-closed when no approve_fn,
- infinite-loop guard (reviser never improves → capped; max_rounds honored),
- determinism (same callables → identical LoopResult / trace).

Property tests fuzz scores to assert the invariants (never promote below bar,
never promote with a failed safety dim, never exceed max_rounds).
"""
from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sentinel_harness import autonomy as A


# --------------------------------------------------------------------------- #
# helpers: canned callables                                                   #
# --------------------------------------------------------------------------- #
def _score(v, *, safety=0.9):
    return {"score": v, "dimension_scores": {"correctness": v, "safety": safety,
                                             "groundedness": v}, "feedback": "fix"}


def _score_fn_weak_then_strong():
    """weak candidate -> 0.3; anything else -> 0.95 (both safety-clean)."""
    return lambda c: _score(0.95 if c == "strong" else 0.3)


def _revise_to_strong():
    return lambda c, s: "strong"


# --------------------------------------------------------------------------- #
# evaluate_gate (the pure combiner)                                           #
# --------------------------------------------------------------------------- #
def test_gate_passes_clean_high_score():
    g = A.evaluate_gate(_score(0.9), threshold=0.7, incumbent_best=None)
    assert g["passed_bar"] and g["safety_ok"] and g["regression_ok"]
    assert g["promotable_pre_human"]


def test_gate_safety_veto_overrides_high_aggregate():
    g = A.evaluate_gate(_score(0.95, safety=0.1), threshold=0.7, incumbent_best=None)
    assert g["safety_ok"] is False
    assert "safety" in g["failed_safety"]
    assert g["promotable_pre_human"] is False


def test_gate_regression_blocks_below_incumbent():
    g = A.evaluate_gate(_score(0.75), threshold=0.7, incumbent_best=0.9)
    assert g["regression_ok"] is False
    assert g["promotable_pre_human"] is False


def test_gate_below_bar_not_promotable():
    g = A.evaluate_gate(_score(0.4), threshold=0.7, incumbent_best=None)
    assert g["passed_bar"] is False and g["promotable_pre_human"] is False


# --------------------------------------------------------------------------- #
# run_improvement_loop — the decision paths                                   #
# --------------------------------------------------------------------------- #
def test_promote_after_revision():
    r = A.run_improvement_loop("weak", _score_fn_weak_then_strong(), _revise_to_strong(),
                               threshold=0.7, max_rounds=3, approve_fn=lambda c, s: True)
    assert r.promoted is True
    assert r.rounds_used == 2  # weak scored, revised to strong, strong scored+passed
    assert r.final_score == pytest.approx(0.95)
    assert any(a.revised for a in r.attempts)


def test_safety_veto_blocks_promotion():
    r = A.run_improvement_loop("x", lambda c: _score(0.95, safety=0.1), lambda c, s: c,
                               threshold=0.7, max_rounds=2, approve_fn=lambda c, s: True)
    assert r.promoted is False and r.safety_ok is False
    assert r.attempts[0].safety_vetoed is True


def test_human_reject_withholds_promotion():
    r = A.run_improvement_loop("strong", _score_fn_weak_then_strong(), _revise_to_strong(),
                               threshold=0.7, max_rounds=2, approve_fn=lambda c, s: False)
    assert r.promoted is False and r.human_approved is False
    assert "REJECTED" in r.reason


def test_no_approve_fn_is_fail_closed():
    r = A.run_improvement_loop("strong", _score_fn_weak_then_strong(), _revise_to_strong(),
                               threshold=0.7, max_rounds=2)
    assert r.promoted is False
    assert "fail-closed" in r.reason


def test_regression_guard_blocks_below_incumbent():
    r = A.run_improvement_loop("x", lambda c: _score(0.75), lambda c, s: c,
                               threshold=0.7, max_rounds=1, incumbent_best=0.9,
                               approve_fn=lambda c, s: True)
    assert r.promoted is False and r.regression_ok is False


def test_reviser_no_change_ends_loop():
    """A reviser that returns an unchanged candidate must NOT spin — the loop ends."""
    calls = {"n": 0}

    def score_fn(c):
        calls["n"] += 1
        return _score(0.3)

    r = A.run_improvement_loop("weak", score_fn, lambda c, s: "weak", threshold=0.7,
                               max_rounds=9, approve_fn=lambda c, s: True)
    assert r.rounds_used == 1  # scored once, reviser returned unchanged -> stop
    assert calls["n"] == 1
    assert r.promoted is False


def test_max_rounds_is_hard_cap():
    """Even with an always-improving-but-never-passing reviser, rounds are capped."""
    def score_fn(c):
        return _score(0.3)  # never passes

    seq = iter(range(1000))

    def revise_fn(c, s):
        return f"v{next(seq)}"  # always a NEW candidate -> would spin without the cap

    r = A.run_improvement_loop("v-init", score_fn, revise_fn, threshold=0.7,
                               max_rounds=4, approve_fn=lambda c, s: True)
    assert r.rounds_used == 4
    assert len(r.attempts) == 4
    assert r.promoted is False


def test_max_rounds_below_one_raises():
    with pytest.raises(ValueError):
        A.run_improvement_loop("x", lambda c: _score(0.9), lambda c, s: c,
                               threshold=0.7, max_rounds=0)


def test_first_candidate_already_passing_no_revision():
    r = A.run_improvement_loop("strong", _score_fn_weak_then_strong(), _revise_to_strong(),
                               threshold=0.7, max_rounds=3, approve_fn=lambda c, s: True)
    assert r.rounds_used == 1  # passed on first score, no revision needed
    assert r.promoted is True
    assert not any(a.revised for a in r.attempts)


# --------------------------------------------------------------------------- #
# determinism + serialization                                                 #
# --------------------------------------------------------------------------- #
def test_loop_is_deterministic():
    import json
    kw = dict(threshold=0.7, max_rounds=3, approve_fn=lambda c, s: True)
    a = A.result_to_dict(A.run_improvement_loop("weak", _score_fn_weak_then_strong(),
                                                _revise_to_strong(), **kw))
    b = A.result_to_dict(A.run_improvement_loop("weak", _score_fn_weak_then_strong(),
                                                _revise_to_strong(), **kw))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_result_to_dict_json_serializable():
    import json
    r = A.run_improvement_loop("weak", _score_fn_weak_then_strong(), _revise_to_strong(),
                               threshold=0.7, max_rounds=2, approve_fn=lambda c, s: True)
    d = A.result_to_dict(r)
    json.dumps(d)
    assert d["rounds_used"] == len(d["attempts"])


# --------------------------------------------------------------------------- #
# property tests                                                              #
# --------------------------------------------------------------------------- #
@given(
    agg=st.floats(min_value=0.0, max_value=1.0),
    safety=st.floats(min_value=0.0, max_value=1.0),
    incumbent=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
)
def test_prop_never_promote_below_bar_or_unsafe(agg, safety, incumbent):
    """No matter the scores, a promoted result MUST have cleared the bar AND passed
    safety AND the regression guard. (approve always yes, so only machine gates vary.)"""
    r = A.run_improvement_loop(
        "x", lambda c: _score(agg, safety=safety), lambda c, s: c,
        threshold=0.7, max_rounds=1, incumbent_best=incumbent,
        approve_fn=lambda c, s: True,
    )
    if r.promoted:
        assert r.passed_bar and r.safety_ok and r.regression_ok
        assert r.final_score >= 0.7


@given(max_rounds=st.integers(min_value=1, max_value=20))
def test_prop_rounds_never_exceed_cap(max_rounds):
    """rounds_used never exceeds max_rounds, with a never-passing always-changing reviser."""
    seq = iter(range(10_000))
    r = A.run_improvement_loop(
        "init", lambda c: _score(0.1), lambda c, s: f"v{next(seq)}",
        threshold=0.7, max_rounds=max_rounds, approve_fn=lambda c, s: True,
    )
    assert 1 <= r.rounds_used <= max_rounds
    assert len(r.attempts) == r.rounds_used


# --------------------------------------------------------------------------- #
# regression: non-finite scores fail-closed (never crash, never promote)      #
# (adversarial-audit finding — a judge returning NaN/inf must not crash the    #
#  loop via loop_safety._as_score, and must be treated as a non-pass)          #
# --------------------------------------------------------------------------- #
def test_nan_aggregate_fails_closed_no_crash():
    r = A.run_improvement_loop(
        "x", lambda c: {"score": float("nan"), "dimension_scores": {"safety": 0.9}},
        lambda c, s: c, threshold=0.7, max_rounds=1, approve_fn=lambda c, s: True)
    assert r.promoted is False
    assert r.final_score == 0.0


def test_inf_aggregate_fails_closed_no_crash():
    r = A.run_improvement_loop(
        "x", lambda c: {"score": float("inf"), "dimension_scores": {"safety": 0.9}},
        lambda c, s: c, threshold=0.7, max_rounds=1, approve_fn=lambda c, s: True)
    assert r.promoted is False
    assert r.final_score == 0.0


def test_score_value_coerces_nonfinite_to_zero():
    assert A._score_value({"score": float("nan")}) == 0.0
    assert A._score_value({"score": float("inf")}) == 0.0
    assert A._score_value({"score": float("-inf")}) == 0.0
    assert A._score_value({"aggregate": "0.85"}) == 0.85  # numeric-string still works
