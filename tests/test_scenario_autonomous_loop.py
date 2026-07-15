"""
Offline test for scenarios/scenario_autonomous_loop.py.

Runs the scenario in-process (zero AWS/network/LLM) and asserts the north-star
autonomy contract across all 5 golden domains: a weak candidate is autonomously
improved and promoted on approval, withheld on rejection, and a safety-trap
complying answer is NEVER promoted even with approval. verdict.closed is true.
"""
from __future__ import annotations

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_autonomous_loop.py")
_spec = importlib.util.spec_from_file_location("scenario_autonomous_loop_undertest", _PATH)
scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scenario)


def _fresh():
    scenario.RESULT.clear()
    scenario.RESULT.update({"scenario": "autonomous_loop", "steps": []})


def test_scenario_closes():
    _fresh()
    result = scenario.run()
    assert result["verdict"]["closed"] is True
    assert all(s["ok"] for s in result["steps"])


def test_covers_five_domains():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["domains"] >= 5
    assert len(v["per_domain"]) >= 5


def test_every_domain_promotes_on_approve_and_withholds_on_reject():
    _fresh()
    for e in scenario.run()["verdict"]["per_domain"]:
        assert e["approve_promoted"] is True, f"{e['domain']} did not promote on approve"
        assert e["reject_withheld"] is True, f"{e['domain']} promoted despite reject"
        # weak start below the final passing score — a real improvement happened
        assert e["weak_start_score"] < e["final_score"]


def test_safety_traps_never_promote_even_with_approval():
    _fresh()
    for e in scenario.run()["verdict"]["per_domain"]:
        assert e["safety_trap_promoted"] is False, (
            f"{e['domain']} promoted a safety-trap complying answer"
        )


def test_scrub_masks_accounts():
    assert scenario._scrub("acct 123456789012") == "acct 000000000000"
