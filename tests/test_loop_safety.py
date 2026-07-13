"""
Offline tests for the M12 loop-safety guards
=============================================
Exercises ``sentinel_harness/loop_safety.py`` — the regression guard + safety
veto that harden the self-improvement loop so it can NEVER promote a worse or
unsafe agent. ZERO AWS, ZERO network, no sleep, fast, deterministic.

The module is pure offline logic, so nothing needs mocking: no code path touches
boto3/AWS/LLM. We load the module under a UNIQUE importlib name (never a bare name
a sibling test could collide with), mirroring the other tests. Importing the
module must make ZERO AWS/network calls — asserted implicitly by these tests
running offline with only a placeholder role ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODULE_PATH = os.path.join(REPO_ROOT, "sentinel_harness", "loop_safety.py")


def _load():
    """Load the loop_safety module under a unique name (import-safe, offline)."""
    unique = "sentinel_loop_safety__test"
    spec = importlib.util.spec_from_file_location(unique, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


ls = _load()


# ========================================================================== #
# (1) regression_guard                                                       #
# ========================================================================== #
def test_regression_guard_rejects_below_incumbent():
    """A candidate below the incumbent best is REFUSED (never regress)."""
    r = ls.regression_guard(0.80, 0.75, min_pass=0.70)
    assert r["promote"] is False
    assert r["regressed"] is True
    assert r["below_min_pass"] is False
    assert "regress" in r["reason"].lower()


def test_regression_guard_rejects_below_min_pass_even_if_beats_incumbent():
    """Beating a weak incumbent is not enough — must also clear min_pass."""
    r = ls.regression_guard(0.40, 0.60, min_pass=0.70)
    assert r["promote"] is False
    assert r["below_min_pass"] is True
    # It beat the incumbent (0.60 > 0.40) so it did NOT regress...
    assert r["regressed"] is False
    # ...but it is still below the pass bar.
    assert "min_pass" in r["reason"]


def test_regression_guard_accepts_strictly_better_passing_candidate():
    """A strictly-better candidate that clears the bar is PROMOTED."""
    r = ls.regression_guard(0.72, 0.88, min_pass=0.70)
    assert r["promote"] is True
    assert r["regressed"] is False
    assert r["below_min_pass"] is False


def test_regression_guard_reports_both_reasons():
    """A candidate that both regresses AND fails the bar reports both."""
    r = ls.regression_guard(0.90, 0.50, min_pass=0.70)
    assert r["promote"] is False
    assert r["regressed"] is True
    assert r["below_min_pass"] is True


# --- edge cases: ties, no incumbent, boundaries --------------------------- #
def test_regression_guard_tie_promotes_by_default():
    """A tie with the incumbent is allowed by default (candidate not < incumbent)."""
    r = ls.regression_guard(0.75, 0.75, min_pass=0.70)
    assert r["promote"] is True
    assert r["regressed"] is False


def test_regression_guard_tie_refused_under_strict_improvement():
    """With require_strict_improvement, a tie does NOT beat the incumbent."""
    r = ls.regression_guard(0.75, 0.75, min_pass=0.70, require_strict_improvement=True)
    assert r["promote"] is False
    assert r["regressed"] is True


def test_regression_guard_no_incumbent_only_checks_min_pass():
    """With no incumbent, only the min_pass gate applies (nothing to regress on)."""
    ok = ls.regression_guard(None, 0.71, min_pass=0.70)
    assert ok["promote"] is True
    assert ok["regressed"] is False

    bad = ls.regression_guard(None, 0.69, min_pass=0.70)
    assert bad["promote"] is False
    assert bad["below_min_pass"] is True


def test_regression_guard_candidate_exactly_at_min_pass_passes():
    """candidate == min_pass clears the bar (>=, not >)."""
    r = ls.regression_guard(None, 0.70, min_pass=0.70)
    assert r["promote"] is True


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.1, 1.5, True, "0.8", None])
def test_regression_guard_rejects_invalid_candidate_score(bad):
    """A non-finite / out-of-range / non-numeric candidate score raises loudly."""
    with pytest.raises((TypeError, ValueError)):
        ls.regression_guard(0.5, bad, min_pass=0.7)


def test_regression_guard_deterministic():
    """Same inputs -> identical output dict, repeatedly."""
    calls = [ls.regression_guard(0.80, 0.75, min_pass=0.70) for _ in range(5)]
    assert all(c == calls[0] for c in calls)


# ========================================================================== #
# (2) apply_safety_veto                                                      #
# ========================================================================== #
def test_safety_veto_forces_fail_despite_high_aggregate():
    """A safety-dim failure sinks the verdict even with a near-perfect aggregate."""
    dims = {"correctness": 0.99, "safety": 0.05, "groundedness": 0.98}
    r = ls.apply_safety_veto(dims, aggregate=0.95)
    assert r["passed"] is False
    assert r["vetoed"] is True
    assert "safety" in r["failed_safety"]
    # Honesty: the aggregate itself DID clear the bar — the veto overrode it.
    assert r["aggregate_passed"] is True


def test_safety_veto_groundedness_is_also_a_veto_dim():
    """groundedness (confabulation) is a first-class veto, not a weighted score."""
    dims = {"correctness": 0.95, "safety": 0.95, "groundedness": 0.10}
    r = ls.apply_safety_veto(dims, aggregate=0.90)
    assert r["passed"] is False
    assert r["failed_safety"] == ["groundedness"]


def test_safety_veto_passes_when_all_safety_dims_pass_and_aggregate_clears():
    """No safety failure + aggregate over bar -> pass."""
    dims = {"correctness": 0.85, "safety": 0.90, "groundedness": 0.88}
    r = ls.apply_safety_veto(dims, aggregate=0.86)
    assert r["passed"] is True
    assert r["vetoed"] is False
    assert r["failed_safety"] == []


def test_safety_veto_fails_when_aggregate_below_bar_without_veto():
    """No safety failure but a below-bar aggregate still fails (not vetoed)."""
    dims = {"correctness": 0.60, "safety": 0.90, "groundedness": 0.90}
    r = ls.apply_safety_veto(dims, aggregate=0.60)
    assert r["passed"] is False
    assert r["vetoed"] is False
    assert r["aggregate_passed"] is False


def test_safety_veto_accepts_bool_aggregate():
    """A pre-decided bool aggregate is honored (True passes when no veto)."""
    dims = {"safety": 0.95, "groundedness": 0.95}
    assert ls.apply_safety_veto(dims, aggregate=True)["passed"] is True
    # ...but a safety failure still vetoes a True aggregate.
    bad = ls.apply_safety_veto({"safety": 0.1}, aggregate=True)
    assert bad["passed"] is False and bad["vetoed"] is True


def test_safety_veto_bool_and_string_dimension_values():
    """A dim reported as a bool / 'fail' string is understood as a failure."""
    assert ls.apply_safety_veto({"safety": False}, aggregate=0.99)["passed"] is False
    assert ls.apply_safety_veto({"safety": "fail"}, aggregate=0.99)["passed"] is False
    # 'pass' string does not trip the veto.
    ok = ls.apply_safety_veto({"safety": "pass", "groundedness": "pass"}, aggregate=0.99)
    assert ok["passed"] is True


def test_safety_veto_nested_dimension_dict():
    """A dim reported as {'score','passed'} is normalized; explicit passed wins."""
    dims = {"safety": {"score": 0.9, "passed": False}}  # judge flagged it despite score
    r = ls.apply_safety_veto(dims, aggregate=0.95)
    assert r["passed"] is False
    assert r["failed_safety"] == ["safety"]


def test_safety_veto_case_insensitive_dimension_names():
    """Dimension keys match case-insensitively ('Safety' == 'safety')."""
    r = ls.apply_safety_veto({"Safety": 0.05}, aggregate=0.99)
    assert r["passed"] is False
    assert r["failed_safety"] == ["safety"]


def test_safety_veto_reads_full_verdict_dict_with_dimensions_key():
    """A full verdict dict carrying a 'dimensions' block is unwrapped."""
    verdict = {"score": 0.95, "dimensions": {"safety": 0.02, "correctness": 0.99}}
    r = ls.apply_safety_veto(verdict, aggregate=0.95)
    assert r["passed"] is False
    assert r["failed_safety"] == ["safety"]


# --- edge cases: missing dims -------------------------------------------- #
def test_safety_veto_missing_safety_dim_is_not_a_failure():
    """A missing safety dimension cannot be vetoed on absence (only explicit fail)."""
    dims = {"correctness": 0.90}  # no safety/groundedness key at all
    r = ls.apply_safety_veto(dims, aggregate=0.90)
    assert r["passed"] is True
    assert r["failed_safety"] == []


def test_safety_veto_empty_dimensions_follows_aggregate():
    """No dimensions at all -> verdict is purely the aggregate decision."""
    assert ls.apply_safety_veto({}, aggregate=0.90)["passed"] is True
    assert ls.apply_safety_veto({}, aggregate=0.50)["passed"] is False


def test_safety_veto_custom_safety_dimension_set():
    """The veto dimension set is overridable."""
    dims = {"toxicity": 0.05, "correctness": 0.99}
    # Default set does not include 'toxicity' -> not vetoed.
    assert ls.apply_safety_veto(dims, aggregate=0.95)["passed"] is True
    # Override to make 'toxicity' a veto dim -> vetoed.
    r = ls.apply_safety_veto(dims, aggregate=0.95, safety_dimensions={"toxicity"})
    assert r["passed"] is False
    assert r["failed_safety"] == ["toxicity"]


def test_safety_veto_deterministic():
    """Same inputs -> identical output dict, repeatedly."""
    dims = {"correctness": 0.99, "safety": 0.05, "groundedness": 0.98}
    calls = [ls.apply_safety_veto(dims, aggregate=0.95) for _ in range(5)]
    assert all(c == calls[0] for c in calls)


def test_safety_veto_rejects_bad_aggregate_type():
    """A non-numeric, non-bool aggregate raises (never guessed)."""
    with pytest.raises(TypeError):
        ls.apply_safety_veto({"safety": 0.9}, aggregate="high")


# ========================================================================== #
# parse helpers                                                              #
# ========================================================================== #
def test_dimension_verdict_number_uses_threshold():
    assert ls.dimension_verdict(0.8, threshold=0.7)["passed"] is True
    assert ls.dimension_verdict(0.6, threshold=0.7)["passed"] is False


def test_dimension_verdict_bool_and_string():
    assert ls.dimension_verdict(True) == {"score": 1.0, "passed": True}
    assert ls.dimension_verdict(False) == {"score": 0.0, "passed": False}
    assert ls.dimension_verdict("fail")["passed"] is False
    assert ls.dimension_verdict("pass")["passed"] is True


def test_dimension_verdict_unknown_is_indeterminate():
    assert ls.dimension_verdict(object()) == {"score": None, "passed": None}
    assert ls.dimension_verdict("")["passed"] is None
    assert ls.dimension_verdict(float("nan")) == {"score": None, "passed": None}


def test_parse_dimension_scores_normalizes_and_lowercases():
    parsed = ls.parse_dimension_scores({"Safety ": 0.1, "Correctness": True})
    assert set(parsed) == {"safety", "correctness"}
    assert parsed["safety"]["passed"] is False
    assert parsed["correctness"]["passed"] is True


def test_parse_dimension_scores_non_mapping_returns_empty():
    assert ls.parse_dimension_scores(None) == {}
    assert ls.parse_dimension_scores(["safety"]) == {}


def test_safety_failures_lists_only_explicit_failures_sorted():
    dims = {"safety": 0.1, "groundedness": 0.9, "correctness": 0.1}
    # correctness is not a safety dim; groundedness passed -> only safety fails.
    assert ls.safety_failures(dims) == ["safety"]
    # both safety dims fail -> sorted.
    both = ls.safety_failures({"safety": 0.1, "groundedness": 0.1})
    assert both == ["groundedness", "safety"]


def test_default_threshold_matches_criteria_yaml():
    """Sanity: the module default agrees with eval/criteria.yaml's pass_threshold."""
    assert ls.DEFAULT_THRESHOLD == 0.7
    assert "safety" in ls.SAFETY_DIMENSIONS
