"""
Offline tests for M12 drift-triggered regeneration
==================================================
Exercises ``sentinel_harness.feedback.detect_score_decay`` — the eval-score-decay
edge of the feedback loop that, when a PROMOTED harness's eval score drifts down
past a threshold (or below an absolute floor), emits a ``rule_regeneration`` task
handed off to the M1/M2 self-improving loop. This mirrors the existing only-FP
``rule_regeneration`` trigger shape in ``detect_triggers`` but is driven by an
eval score history instead of alert dispositions.

ZERO AWS, ZERO network, no sleep, fast, deterministic. The engine is pure offline
logic, so nothing needs mocking. We load the module under a UNIQUE importlib name
(never a bare name a sibling test could collide with), mirroring the other tests.
Importing the module must make ZERO AWS/network calls — asserted implicitly by
these tests running offline with only a placeholder role ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODULE_PATH = os.path.join(REPO_ROOT, "sentinel_harness", "feedback.py")


def _load_feedback():
    """Load the feedback module under a unique name (import-safe, offline)."""
    unique = "sentinel_feedback__drift_test"
    spec = importlib.util.spec_from_file_location(unique, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


fb = _load_feedback()

HARNESS = "Log4Shell-Detection-Harness"


# --------------------------------------------------------------------------
# A decayed score sequence auto-emits a regeneration task.
# --------------------------------------------------------------------------
def test_decayed_history_emits_regeneration_task():
    # Promoted at 0.90, re-scored down to 0.55 -> decay 0.35 >= 0.1 default.
    task = fb.detect_score_decay(HARNESS, scores=[0.90, 0.82, 0.70, 0.55])
    assert task is not None
    # Mirrors the existing rule_regeneration trigger shape exactly.
    assert task["type"] == fb.REGENERATION_TASK_TYPE == "rule_regeneration"
    assert task["target"] == fb.REGENERATION_TARGET == "m1_m2_self_improving_loop"
    assert task["trigger"] == fb.SCORE_DECAY_TRIGGER == "eval_score_decay"
    assert task["rule_name"] == HARNESS
    assert task["harness_id"] == HARNESS
    assert task["baseline_score"] == 0.90  # oldest = promoted-at score
    assert task["latest_score"] == 0.55    # newest re-score
    assert task["decay"] == pytest.approx(0.35)
    assert task["below_floor"] is False
    assert task["sample_size"] == 4
    assert "decayed" in task["reason"]


def test_latest_vs_baseline_pair_emits_regeneration_task():
    # No history — just a latest re-score vs the promoted baseline.
    task = fb.detect_score_decay(HARNESS, latest=0.6, baseline=0.9)
    assert task is not None
    assert task["decay"] == pytest.approx(0.3)
    assert task["baseline_score"] == 0.9
    assert task["latest_score"] == 0.6
    assert task["sample_size"] == 0  # no history supplied


# --------------------------------------------------------------------------
# A healthy / stable score emits NONE.
# --------------------------------------------------------------------------
def test_stable_score_emits_nothing():
    # Wobbles within 0.1 of baseline -> no drift-driven regeneration.
    assert fb.detect_score_decay(HARNESS, scores=[0.90, 0.88, 0.92, 0.85]) is None


def test_improved_score_emits_nothing():
    # Score went UP since promotion -> negative decay -> nothing.
    assert fb.detect_score_decay(HARNESS, scores=[0.75, 0.80, 0.91]) is None


def test_single_score_history_never_decays():
    # Only the promoted score exists (baseline == latest) -> decay 0 -> nothing.
    assert fb.detect_score_decay(HARNESS, scores=[0.83]) is None


# --------------------------------------------------------------------------
# Threshold boundary cases (inclusive, mirroring fp_rate >= fp_threshold).
# --------------------------------------------------------------------------
def test_decay_exactly_at_threshold_triggers():
    # decay == threshold -> inclusive boundary triggers.
    task = fb.detect_score_decay(HARNESS, baseline=0.9, latest=0.8, decay_threshold=0.1)
    assert task is not None
    assert task["decay"] == pytest.approx(0.1)


def test_decay_just_below_threshold_does_not_trigger():
    # decay 0.09 < 0.1 -> healthy.
    assert fb.detect_score_decay(HARNESS, baseline=0.90, latest=0.81, decay_threshold=0.1) is None


def test_custom_threshold_gates_the_trigger():
    # Same 0.15 decay: fires at threshold 0.15, stays quiet at 0.2.
    assert fb.detect_score_decay(HARNESS, baseline=0.9, latest=0.75, decay_threshold=0.15) is not None
    assert fb.detect_score_decay(HARNESS, baseline=0.9, latest=0.75, decay_threshold=0.2) is None


# --------------------------------------------------------------------------
# Absolute quality floor: fires even on a gentle slope.
# --------------------------------------------------------------------------
def test_below_floor_triggers_even_with_small_decay():
    # decay only 0.05 (< 0.1 threshold) but latest 0.60 < 0.65 floor -> triggers.
    task = fb.detect_score_decay(HARNESS, baseline=0.65, latest=0.60, min_score=0.65)
    assert task is not None
    assert task["below_floor"] is True
    assert "quality floor" in task["reason"]


def test_at_floor_does_not_trigger():
    # latest == floor is NOT below the floor; decay also under threshold -> None.
    assert fb.detect_score_decay(HARNESS, baseline=0.70, latest=0.65, min_score=0.65) is None


def test_floor_and_threshold_both_reported_when_both_breached():
    task = fb.detect_score_decay(HARNESS, baseline=0.90, latest=0.50, min_score=0.6)
    assert task is not None
    assert task["below_floor"] is True
    assert "decayed" in task["reason"] and "quality floor" in task["reason"]


# --------------------------------------------------------------------------
# Determinism: same input -> byte-identical task, twice.
# --------------------------------------------------------------------------
def test_detect_score_decay_is_deterministic():
    scores = [0.92, 0.80, 0.61]
    t1 = fb.detect_score_decay(HARNESS, scores=scores)
    t2 = fb.detect_score_decay(HARNESS, scores=scores)
    assert t1 == t2
    # Float boundary is stable across the equivalent history/explicit forms.
    t3 = fb.detect_score_decay(HARNESS, baseline=0.92, latest=0.61)
    assert t3["decay"] == t1["decay"]


def test_explicit_values_override_history():
    # Explicit baseline/latest win over the supplied history endpoints.
    task = fb.detect_score_decay(
        HARNESS, scores=[0.5, 0.5, 0.5], baseline=0.95, latest=0.60
    )
    assert task is not None
    assert task["baseline_score"] == 0.95
    assert task["latest_score"] == 0.60
    assert task["sample_size"] == 3  # history length is still reported


# --------------------------------------------------------------------------
# Validation / guards.
# --------------------------------------------------------------------------
def test_requires_harness_id():
    with pytest.raises(ValueError):
        fb.detect_score_decay("", scores=[0.9, 0.5])


def test_requires_baseline_or_history():
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, latest=0.5)  # no baseline, no history


def test_requires_latest_or_history():
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, baseline=0.9)  # no latest, no history


def test_rejects_out_of_range_scores():
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, scores=[1.5, 0.5])
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, baseline=0.9, latest=-0.1)


def test_rejects_bad_decay_threshold():
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, scores=[0.9, 0.5], decay_threshold=0.0)
    with pytest.raises(ValueError):
        fb.detect_score_decay(HARNESS, scores=[0.9, 0.5], decay_threshold=1.5)


def test_rejects_non_numeric_and_bool_scores():
    with pytest.raises(TypeError):
        fb.detect_score_decay(HARNESS, scores=[0.9, "0.5"])
    with pytest.raises(TypeError):
        fb.detect_score_decay(HARNESS, baseline=True, latest=0.5)  # bool is not a score


def test_exported_in_all():
    assert "detect_score_decay" in fb.__all__
    assert "SCORE_DECAY_TRIGGER" in fb.__all__
