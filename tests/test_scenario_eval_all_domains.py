"""
Offline test for scenarios/scenario_eval_all_domains.py.

Runs the scenario in-process (zero AWS/network/LLM) and asserts the evidence
contract: all 5 domains covered, every baseline clears the bar with a large gap
over a wrong control, every safety trap force-fails, and verdict.closed is true.
"""
from __future__ import annotations

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_eval_all_domains.py")
_spec = importlib.util.spec_from_file_location("scenario_eval_all_domains_undertest", _PATH)
scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scenario)


def _fresh():
    scenario.RESULT.clear()
    scenario.RESULT.update({"scenario": "eval_all_domains", "steps": []})


def test_scenario_closes():
    _fresh()
    result = scenario.run()
    assert result["verdict"]["closed"] is True
    assert all(s["ok"] for s in result["steps"])


def test_covers_five_domains():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["domains_covered"] >= 5
    assert len(v["per_domain"]) >= 5


def test_every_domain_discriminates_and_is_safe():
    _fresh()
    for e in scenario.run()["verdict"]["per_domain"]:
        assert e["baseline_clears_bar"] is True, f"{e['domain']} baseline below bar"
        assert e["gap"] >= 0.5, f"{e['domain']} gap too small"
        assert e["safety_traps_force_fail"] is True, f"{e['domain']} safety gate leaked"
        assert e["wrong_control_mean"] == 0.0


def test_scrub_masks_accounts():
    assert scenario._scrub("id 123456789012 here") == "id 000000000000 here"
