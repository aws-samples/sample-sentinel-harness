"""
Offline test for scenarios/scenario_e2e_pipeline.py — the cross-domain E2E flow.

Runs the whole pipeline in-process (zero AWS/network/LLM/clock) and asserts the
end-to-end contract: campaign ingested, triage splits TP/FP, the kill-chain is
multi-stage, the observed lateral movement realizes a real crown-jewel attack
path (via the REAL reasoner), feedback triggers fire, autonomy promotes, and it
all ran under one trace. verdict.closed is true.
"""
from __future__ import annotations

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_e2e_pipeline.py")
_spec = importlib.util.spec_from_file_location("scenario_e2e_pipeline_undertest", _PATH)
scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scenario)


def _fresh():
    scenario.RESULT.clear()
    scenario.RESULT.update({"scenario": "e2e_pipeline", "steps": []})


def test_pipeline_closes():
    _fresh()
    r = scenario.run()
    assert r["verdict"]["closed"] is True
    assert all(s["ok"] for s in r["steps"])


def test_all_stages_present_and_ordered():
    _fresh()
    r = scenario.run()
    step_names = [s["step"] for s in r["steps"]]
    for stage in ("ingest", "triage", "correlate", "attack_path", "feedback", "autonomy", "verdict"):
        assert stage in step_names, f"missing pipeline stage {stage}"
    # ingest precedes triage precedes correlate precedes attack_path ...
    order = [step_names.index(s) for s in ("ingest", "triage", "correlate", "attack_path", "feedback", "autonomy")]
    assert order == sorted(order), "pipeline stages ran out of order"


def test_triage_separates_signal_from_noise():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["triage_split"]["tp"] > 0 and v["triage_split"]["fp"] > 0


def test_observed_intrusion_realizes_a_crown_jewel_path():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["realized_attack_paths"], "no realized crown-jewel attack path found"
    # the canonical Log4Shell chain must be among them
    paths = [tuple(c["path"]) for c in v["realized_attack_paths"]]
    assert ("web-01", "app-01", "db-01") in paths


def test_feedback_triggers_fire_with_real_types():
    _fresh()
    v = scenario.run()["verdict"]
    types = {t["type"] for t in v["feedback_triggers"]}
    assert "allowlist_optimization" in types


def test_autonomy_round_promotes():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["autonomy"]["promoted"] is True
    assert v["autonomy"]["start_score"] < v["autonomy"]["final_score"]


def test_single_trace_over_whole_pipeline():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["single_trace_id"] is True
    assert v["span_count"] >= 6  # ingest + 5 stage spans


def test_scrub_masks_accounts():
    assert scenario._scrub("acct 123456789012") == "acct 000000000000"
