"""
Offline tests for the deterministic deployment benchmark model.

ZERO AWS, ZERO network, ZERO clock. The benchmark is pure arithmetic over dated
unit-price constants, so every property below is exactly checkable:
- determinism (same workload → byte-identical report),
- the model-cost invariant (identical across modes for one workload+model),
- the billing-shape math (standing vs. per-invoke),
- ranking + savings correctness,
- render round-trips (markdown + dict never crash, carry the headline number).

Property tests (Hypothesis) fuzz workloads to assert the invariants hold for any
non-negative sizing, mirroring the repo's other ``test_prop_*`` suites.
"""
from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sentinel_harness import benchmark as bm
from sentinel_harness.benchmark_models import (
    DEFAULT_WORKLOAD,
    HOURS_PER_MONTH,
    MODEL_PRICES,
    MODES,
    ModeModel,
    Workload,
)


# --------------------------------------------------------------------------- #
# model_cost_usd                                                              #
# --------------------------------------------------------------------------- #
def test_model_cost_matches_hand_calc():
    w = Workload("t", invokes_per_month=1000, input_tokens=1000, output_tokens=1000)
    # sonnet: 0.003 in + 0.015 out per 1k → per invoke = 0.003 + 0.015 = 0.018 → ×1000
    assert bm.model_cost_usd(w, "sonnet") == pytest.approx(18.0)


def test_model_cost_unknown_model_raises():
    with pytest.raises(KeyError):
        bm.model_cost_usd(DEFAULT_WORKLOAD, "does-not-exist")


def test_model_cost_zero_workload_is_zero():
    w = Workload("z", invokes_per_month=0, input_tokens=0, output_tokens=0)
    for model in MODEL_PRICES:
        assert bm.model_cost_usd(w, model) == 0.0


# --------------------------------------------------------------------------- #
# compute_cost_usd — the two billing shapes                                   #
# --------------------------------------------------------------------------- #
def test_standing_compute_is_hourly_times_month():
    mode = next(m for m in MODES if m.billing == "standing")
    w = Workload("t", invokes_per_month=999999, input_tokens=1, output_tokens=1)
    # standing cost must NOT depend on invoke volume — it is fixed always-on.
    assert bm.compute_cost_usd(w, mode) == pytest.approx(mode.hourly_usd * HOURS_PER_MONTH)


def test_per_invoke_compute_scales_with_volume():
    mode = next(m for m in MODES if m.billing == "per_invoke")
    w = Workload("t", invokes_per_month=5000, input_tokens=1, output_tokens=1)
    assert bm.compute_cost_usd(w, mode) == pytest.approx(mode.per_invoke_usd * 5000)


def test_per_invoke_idle_is_free():
    """The managed mode's compute is zero at zero volume — the 'idle costs nothing'
    claim, made exact."""
    mode = next(m for m in MODES if m.billing == "per_invoke")
    w = Workload("idle", invokes_per_month=0, input_tokens=4000, output_tokens=800)
    assert bm.compute_cost_usd(w, mode) == 0.0


def test_unknown_billing_shape_raises():
    bad = ModeModel(
        key="bad", label="bad", billing="weekly", hourly_usd=1, per_invoke_usd=1,
        latency_overhead_ms=0, ops_hours_per_month=0, owns_agent_loop=False,
    )
    with pytest.raises(ValueError):
        bm.compute_cost_usd(DEFAULT_WORKLOAD, bad)


# --------------------------------------------------------------------------- #
# run_benchmark — the model-cost invariant + ranking                          #
# --------------------------------------------------------------------------- #
def test_model_cost_identical_across_modes():
    """The load-bearing honesty point: you pay Bedrock the same per token however
    you host the loop, so model_usd must be equal across every mode."""
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet")
    model_costs = {res.cost.model_usd for res in r.results}
    assert len(model_costs) == 1


def test_results_sorted_cheapest_first():
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet")
    totals = [res.cost.total_usd for res in r.results]
    assert totals == sorted(totals)
    assert r.cheapest_mode == r.results[0].mode


def test_total_is_model_plus_compute():
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "opus")
    for res in r.results:
        assert res.cost.total_usd == pytest.approx(res.cost.model_usd + res.cost.compute_usd)


def test_savings_math_consistent():
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet")
    baseline = max(res.cost.total_usd for res in r.results)
    cheapest = min(res.cost.total_usd for res in r.results)
    assert r.savings_vs_baseline_usd == pytest.approx(baseline - cheapest, abs=0.01)
    assert 0.0 <= r.savings_vs_baseline_pct <= 100.0


def test_managed_mode_wins_default_workload():
    """For the default bursty SecOps workload, the managed mode should be cheapest
    (standing EKS bills 24×7). Guards the headline procurement claim."""
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet")
    assert r.cheapest_mode == "agentcore_harness"
    assert r.baseline_mode == "self_hosted_eks"


def test_every_mode_present_in_report():
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "haiku")
    assert {res.mode for res in r.results} == {m.key for m in MODES}


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_report_is_deterministic():
    a = bm.report_to_dict(bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet"))
    b = bm.report_to_dict(bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet"))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --------------------------------------------------------------------------- #
# Rendering                                                                   #
# --------------------------------------------------------------------------- #
def test_markdown_carries_headline_and_all_modes():
    r = bm.run_benchmark(DEFAULT_WORKLOAD, "sonnet")
    md = bm.report_to_markdown(r)
    assert "Deployment benchmark" in md
    assert "Headline" in md
    for res in r.results:
        assert res.label in md
    # the cheapest total appears in the headline
    assert f"{r.results[0].cost.total_usd:,.2f}" in md


def test_dict_is_json_serializable():
    d = bm.report_to_dict(bm.run_benchmark(DEFAULT_WORKLOAD, "opus"))
    json.dumps(d)  # must not raise
    assert d["cheapest_mode"] in {m.key for m in MODES}
    assert len(d["modes"]) == len(MODES)


# --------------------------------------------------------------------------- #
# Property tests — invariants hold for any non-negative workload              #
# --------------------------------------------------------------------------- #
_workloads = st.builds(
    Workload,
    name=st.just("prop"),
    invokes_per_month=st.integers(min_value=0, max_value=10_000_000),
    input_tokens=st.integers(min_value=0, max_value=1_000_000),
    output_tokens=st.integers(min_value=0, max_value=1_000_000),
)


@given(w=_workloads, model=st.sampled_from(sorted(MODEL_PRICES)))
def test_prop_model_cost_nonnegative(w, model):
    assert bm.model_cost_usd(w, model) >= 0.0


@given(w=_workloads, model=st.sampled_from(sorted(MODEL_PRICES)))
def test_prop_model_cost_identical_across_modes(w, model):
    r = bm.run_benchmark(w, model)
    assert len({res.cost.model_usd for res in r.results}) == 1


@given(w=_workloads, model=st.sampled_from(sorted(MODEL_PRICES)))
def test_prop_totals_sorted_and_savings_bounded(w, model):
    r = bm.run_benchmark(w, model)
    totals = [res.cost.total_usd for res in r.results]
    assert totals == sorted(totals)
    assert r.savings_vs_baseline_usd >= 0.0
    assert 0.0 <= r.savings_vs_baseline_pct <= 100.0


@given(w=_workloads, model=st.sampled_from(sorted(MODEL_PRICES)))
def test_prop_total_equals_parts(w, model):
    r = bm.run_benchmark(w, model)
    for res in r.results:
        assert res.cost.total_usd == pytest.approx(
            res.cost.model_usd + res.cost.compute_usd, abs=0.01
        )


# --------------------------------------------------------------------------- #
# regression: negative workload rejected (audited — produced negative $/%)     #
# --------------------------------------------------------------------------- #
def test_negative_workload_rejected():
    import pytest as _pytest
    for bad in (dict(invokes_per_month=-1, input_tokens=10, output_tokens=10),
                dict(invokes_per_month=10, input_tokens=-1, output_tokens=10),
                dict(invokes_per_month=10, input_tokens=10, output_tokens=-1)):
        with _pytest.raises(ValueError):
            Workload(name="neg", **bad)


def test_bool_workload_field_rejected():
    import pytest as _pytest
    with _pytest.raises(ValueError):
        Workload(name="b", invokes_per_month=True, input_tokens=10, output_tokens=10)
