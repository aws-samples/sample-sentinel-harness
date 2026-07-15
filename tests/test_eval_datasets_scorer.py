"""
Offline tests for sentinel_harness.eval_datasets — the all-domain scorer.

ZERO AWS, ZERO network, no LLM. Pins the deterministic offline scorer's two
load-bearing properties:
  1. DISCRIMINATION — the golden reference answers clear the bar in every domain,
     while a wrong/generic answer scores 0.
  2. SAFETY GATE — a safety-trap row force-fails unless the answer refuses, so a
     fluent-but-complying answer can never pass (mirrors loop_safety veto).

Plus loader hygiene (all 5 domains discoverable, every row scores, determinism).
"""
from __future__ import annotations

import pytest

from sentinel_harness import eval_datasets as ed

_EXPECTED_DOMAINS = {"cve_triage", "detection_gen", "alert_triage", "attack_path", "feedback_loop"}


# --------------------------------------------------------------------------- #
# discovery + loading                                                         #
# --------------------------------------------------------------------------- #
def test_all_five_domains_discoverable():
    assert _EXPECTED_DOMAINS.issubset(set(ed.available_domains()))


def test_load_pass_threshold_reads_criteria():
    thr = ed.load_pass_threshold()
    assert 0.0 < thr <= 1.0
    assert thr == pytest.approx(0.7, abs=0.001)  # eval/criteria.yaml


@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_load_dataset_nonempty(domain):
    rows = ed.load_dataset(domain)
    assert len(rows) >= 22
    for r in rows:
        assert "assertions" in r and r["assertions"]


def test_dataset_path_unknown_domain_raises():
    with pytest.raises(FileNotFoundError):
        ed.dataset_path("no_such_domain")


# --------------------------------------------------------------------------- #
# discrimination: good answers pass, wrong answers fail                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_golden_reference_answers_clear_the_bar(domain):
    """Scoring each row's own `expected` answer should pass a solid majority —
    the reference 'good answer' must clear the bar or the scorer is miscalibrated."""
    rep = ed.run_domain_offline(domain, lambda r: r["expected"])
    assert rep.pass_rate >= 0.6, f"{domain} golden pass_rate {rep.pass_rate} too low"
    assert rep.mean_score >= 0.6


@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_wrong_generic_answer_fails_hard(domain):
    """A generic non-answer must score ~0 in every domain (no false credit)."""
    rep = ed.run_domain_offline(domain, lambda r: "Everything looks fine, no action needed.")
    assert rep.pass_rate == 0.0
    assert rep.mean_score < 0.2


@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_good_beats_wrong_gap(domain):
    """The whole point: good ≫ wrong. The mean-score gap must be large."""
    good = ed.run_domain_offline(domain, lambda r: r["expected"]).mean_score
    wrong = ed.run_domain_offline(domain, lambda r: "no action").mean_score
    assert good - wrong >= 0.5


# --------------------------------------------------------------------------- #
# safety gate                                                                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_safety_trap_complying_answer_force_fails(domain):
    """For every safety trap, the tempting `unsafe_answer` (a fluent compliance)
    must score 0 and fail — safety_ok False — no matter its assertion overlap."""
    traps = [r for r in ed.load_dataset(domain) if r.get("category") == "safety_trap"]
    assert traps, f"{domain} has no safety traps to check"
    for r in traps:
        comply = r["safety_trap"]["unsafe_answer"]
        s = ed.score_answer_offline(comply, r)
        assert s.safety_ok is False, f"{domain}/{r['id']} complying answer marked safety_ok"
        assert s.score == 0.0
        assert s.passed is False


@pytest.mark.parametrize("domain", sorted(_EXPECTED_DOMAINS))
def test_safety_trap_refusal_passes(domain):
    """The row's own `expected` refusal should satisfy the safety gate."""
    traps = [r for r in ed.load_dataset(domain) if r.get("category") == "safety_trap"]
    for r in traps:
        s = ed.score_answer_offline(r["expected"], r)
        assert s.safety_ok is True, f"{domain}/{r['id']} refusal not recognized"


# --------------------------------------------------------------------------- #
# determinism + report shape                                                  #
# --------------------------------------------------------------------------- #
def test_scoring_is_deterministic():
    rows = ed.load_dataset("cve_triage")
    a = ed.score_answer_offline(rows[0]["expected"], rows[0])
    b = ed.score_answer_offline(rows[0]["expected"], rows[0])
    assert a == b


def test_report_to_dict_json_serializable():
    import json
    rep = ed.run_domain_offline("alert_triage", lambda r: r["expected"])
    d = ed.report_to_dict(rep)
    json.dumps(d)  # must not raise
    assert d["n_rows"] == len(d["rows"])
    assert 0.0 <= d["pass_rate"] <= 1.0


def test_empty_answer_scores_zero():
    rows = ed.load_dataset("attack_path")
    s = ed.score_answer_offline("", rows[0])
    assert s.score == 0.0 and s.passed is False
