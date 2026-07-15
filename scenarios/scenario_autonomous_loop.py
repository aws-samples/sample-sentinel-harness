"""
Scenario — AUTONOMOUS self-improvement loop, driven by the controller (C1)
==========================================================================
Closes the last north-star gap: the improve→score→gate→promote DECISIONS are no
longer spelled out step-by-step in a runner — they are owned by the reusable
``sentinel_harness.autonomy`` controller. The runner here only WIRES the domain
callables (score_fn / revise_fn / approve_fn); the *policy* lives in the
controller, once, tested.

.. warning::
   **DETERMINISTIC OFFLINE — zero AWS, zero network, no LLM.** ``score_fn`` is the
   real offline assertion-grounding scorer over the golden datasets
   (``sentinel_harness.eval_datasets``); ``revise_fn`` swaps a deliberately-weak
   candidate answer for the golden reference (the "retry with reasoning" step
   modelled offline). In production the SAME controller runs with
   ``run_evaluation`` as score_fn and an ``agent-ops`` invoke as revise_fn — this
   proves the control flow with no quota. Same inputs → byte-identical evidence.

What it proves (verdict.closed)
-------------------------------
For EVERY golden domain (cve_triage / detection_gen / alert_triage / attack_path /
feedback_loop):
  1. a deliberately-weak candidate scores BELOW the bar,
  2. the controller autonomously revises (to the golden reference) and re-scores
     ABOVE the bar,
  3. the machine gates (safety veto + regression guard) pass,
  4. a human APPROVE promotes; a human REJECT withholds (checked once) — so the
     HITL gate is real, not decorative,
  5. a SAFETY-TRAP candidate (a complying unsafe answer) is NEVER promoted, even
     with human approval — the safety veto is structural.

Egress & secrets posture
------------------------
Zero network / AWS / LLM I/O. No secrets/account ids; evidence writer scrubs
12-digit ids defensively, like the other scenarios.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import autonomy as A       # noqa: E402
from sentinel_harness import eval_datasets as ed  # noqa: E402

RESULT: dict = {"scenario": "autonomous_loop", "steps": []}

# A deliberately-weak candidate answer — generic, covers no assertion.
_WEAK_ANSWER = "Looks fine, no action needed."


def rec(step: str, ok: bool, data: Any) -> None:
    RESULT["steps"].append({"step": step, "ok": bool(ok), "data": data})


_ACCT_RE = re.compile(r"\b\d{12}\b")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ACCT_RE.sub("000000000000", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _make_score_fn(row: Dict[str, Any], threshold: float):
    """score_fn for the controller: score a candidate ANSWER against one golden row
    using the real offline scorer, projected into the controller's score shape
    (aggregate + per-dimension, so the safety veto can bite)."""
    def score_fn(candidate_answer: str) -> Dict[str, Any]:
        s = ed.score_answer_offline(candidate_answer, row, threshold=threshold)
        # Map the offline RowScore into the controller's {score, dimension_scores}.
        # 'safety' dimension reflects the hard safety gate: 0 if a trap answer did
        # not refuse (force-fail), else the base score.
        safety_dim = 0.0 if not s.safety_ok else s.score
        return {
            "score": s.score,
            "dimension_scores": {"correctness": s.score, "safety": safety_dim},
            "feedback": {"covered": s.covered, "total": s.total},
        }
    return score_fn


def _revise_fn(candidate_answer: str, score: Dict[str, Any], *, golden: str) -> str:
    """revise_fn: the retry-with-reasoning step, modelled offline as replacing the
    weak candidate with the golden reference answer (a concrete change)."""
    return golden


def run() -> dict:
    """Drive the autonomous controller across all golden domains; build evidence."""
    domains = ed.available_domains()
    threshold = ed.load_pass_threshold()
    rec("discover", len(domains) >= 5, {"domains": domains, "threshold": threshold})

    per_domain = []
    all_promoted = True
    all_traps_safe = True

    for dom in domains:
        rows = ed.load_dataset(dom)
        # pick a "clear" row as the improvable case, and a safety_trap row.
        clear = next((r for r in rows if r.get("category") == "clear"), rows[0])
        trap = next((r for r in rows if r.get("category") == "safety_trap"), None)

        golden = clear["expected"]
        score_fn = _make_score_fn(clear, threshold)

        # (1) autonomous improve: weak -> revise-to-golden -> pass -> APPROVE -> promote
        approved = A.run_improvement_loop(
            _WEAK_ANSWER, score_fn,
            lambda c, s, g=golden: _revise_fn(c, s, golden=g),
            threshold=threshold, max_rounds=3, incumbent_best=None,
            approve_fn=lambda c, s: True,
        )
        # (2) same loop but human REJECTS -> must NOT promote
        rejected = A.run_improvement_loop(
            _WEAK_ANSWER, score_fn,
            lambda c, s, g=golden: _revise_fn(c, s, golden=g),
            threshold=threshold, max_rounds=3,
            approve_fn=lambda c, s: False,
        )

        # (3) safety trap: a complying unsafe answer must NEVER promote (veto)
        trap_promoted = None
        if trap is not None:
            trap_score = _make_score_fn(trap, threshold)
            comply = trap["safety_trap"]["unsafe_answer"]
            trap_res = A.run_improvement_loop(
                comply, trap_score, lambda c, s: c,  # no revision — test the veto as-is
                threshold=threshold, max_rounds=1,
                approve_fn=lambda c, s: True,  # even WITH approval
            )
            trap_promoted = trap_res.promoted

        domain_ok = (approved.promoted and not rejected.promoted
                     and (trap_promoted is False))
        all_promoted = all_promoted and approved.promoted and (not rejected.promoted)
        if trap is not None:
            all_traps_safe = all_traps_safe and (trap_promoted is False)

        entry = {
            "domain": dom,
            "weak_start_score": approved.attempts[0].score,
            "final_score": approved.final_score,
            "rounds_used": approved.rounds_used,
            "approve_promoted": approved.promoted,
            "reject_withheld": not rejected.promoted,
            "safety_trap_promoted": trap_promoted,
        }
        per_domain.append(entry)
        rec(f"autonomous:{dom}", domain_ok, entry)

    closed = (len(domains) >= 5) and all_promoted and all_traps_safe
    RESULT["verdict"] = {
        "domains": len(domains),
        "all_approve_promote_reject_withhold": all_promoted,
        "all_safety_traps_never_promote": all_traps_safe,
        "per_domain": per_domain,
        "closed": closed,
        "note": (
            "The improve/score/gate/promote DECISIONS are owned by "
            "sentinel_harness.autonomy (a reusable, tested controller), not "
            "hardcoded in this runner. Offline scorer + canned reviser here; the "
            "SAME controller runs live with run_evaluation + agent-ops invoke + an "
            "inline_function HITL gate. Safety veto + regression guard reused from "
            "loop_safety."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    run()
    out = os.path.join(REPO_ROOT, "evidence", "autonomous_loop_result.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("saved evidence/autonomous_loop_result.json  ·  closed:", RESULT["verdict"]["closed"])
    for e in RESULT["verdict"]["per_domain"]:
        print(f"  {e['domain']:15s} {e['weak_start_score']:.2f} -> {e['final_score']:.2f} "
              f"promote={e['approve_promoted']} reject_withheld={e['reject_withheld']} "
              f"trap_promoted={e['safety_trap_promoted']}")
