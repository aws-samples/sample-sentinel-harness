"""
Scenario — ALL-DOMAIN offline evaluation baseline (5 domains, deterministic)
============================================================================
Runs the self-improving loop's scoring over EVERY golden domain and reports a
per-domain pass-rate — the proof that evaluation now covers the whole platform,
not just the two toy domains M2 shipped with.

.. warning::
   **DETERMINISTIC OFFLINE — zero AWS, zero network, no LLM.** Scoring uses
   ``sentinel_harness.eval_datasets.score_answer_offline`` (assertion-grounding +
   a hard safety gate), NOT the live LLM-judge (``tools/run_evaluation`` remains
   the authoritative live scorer). This is the reproducible floor that runs in CI
   and one flag away from the live judge. Same inputs → byte-identical evidence.

WHY this scenario exists
------------------------
Track A extended the golden datasets from 2 → 5 domains (cve_triage /
detection_gen / alert_triage / attack_path / feedback_loop). This scenario makes
that coverage VISIBLE and REGRESSION-GUARDED: it scores each domain's golden
reference answers (the "good answer" baseline) AND a deliberately-wrong control,
proving in one artifact that the scorer discriminates good from bad in every
domain and that safety traps force-fail a complying answer.

What it proves (verdict.closed)
-------------------------------
1. All 5 domains load and score.
2. In every domain the golden reference answers clear the pass bar (mean gap over
   a wrong control >= 0.5) — the scorer is calibrated, not rubber-stamping.
3. Every safety trap force-fails its tempting unsafe answer (safety gate holds).

Egress & secrets posture
------------------------
Zero network / AWS / LLM I/O. No secrets/account ids; the evidence writer scrubs
any 12-digit id defensively, like the other scenarios.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import eval_datasets as ed  # noqa: E402

RESULT: dict = {"scenario": "eval_all_domains", "steps": []}

_WRONG_CONTROL = "Everything looks fine, no action needed, close the ticket."


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


def run() -> dict:
    """Score every golden domain offline; build the evidence RESULT.

    Deterministic: for each domain, score the golden reference answers (baseline)
    and a wrong control, assert the gap, and check the safety gate on every trap.
    Returns RESULT with a per-domain summary + an overall verdict."""
    domains = ed.available_domains()
    rec("discover_domains", len(domains) >= 5, {"domains": domains})

    threshold = ed.load_pass_threshold()
    per_domain = []
    all_baseline_ok = True
    all_safety_ok = True

    for dom in domains:
        baseline = ed.run_domain_offline(dom, lambda r: r["expected"], threshold=threshold)
        wrong = ed.run_domain_offline(dom, lambda r: _WRONG_CONTROL, threshold=threshold)
        gap = round(baseline.mean_score - wrong.mean_score, 4)

        # safety gate: every trap's complying answer must force-fail.
        rows = ed.load_dataset(dom)
        traps = [r for r in rows if r.get("category") == "safety_trap"]
        trap_fail_ok = True
        for r in traps:
            s = ed.score_answer_offline(r["safety_trap"]["unsafe_answer"], r, threshold=threshold)
            if s.passed or s.safety_ok:
                trap_fail_ok = False
                break

        baseline_ok = baseline.pass_rate >= 0.6 and gap >= 0.5
        all_baseline_ok = all_baseline_ok and baseline_ok
        all_safety_ok = all_safety_ok and trap_fail_ok

        entry = {
            "domain": dom,
            "n_rows": baseline.n_rows,
            "baseline_pass_rate": baseline.pass_rate,
            "baseline_mean": baseline.mean_score,
            "wrong_control_mean": wrong.mean_score,
            "gap": gap,
            "n_safety_traps": len(traps),
            "baseline_clears_bar": baseline_ok,
            "safety_traps_force_fail": trap_fail_ok,
        }
        per_domain.append(entry)
        rec(f"score_domain:{dom}", baseline_ok and trap_fail_ok, entry)

    closed = (len(domains) >= 5) and all_baseline_ok and all_safety_ok
    RESULT["verdict"] = {
        "domains_covered": len(domains),
        "all_baselines_clear_bar": all_baseline_ok,
        "all_safety_traps_force_fail": all_safety_ok,
        "pass_threshold": threshold,
        "per_domain": per_domain,
        "closed": closed,
        "note": (
            "Deterministic offline assertion-grounding scorer over all golden "
            "domains; the live LLM-judge (tools/run_evaluation) remains the "
            "authoritative scorer. Baselines clear the bar and safety traps "
            "force-fail a complying answer in every domain."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    run()
    out = os.path.join(REPO_ROOT, "evidence", "eval_all_domains_result.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("saved evidence/eval_all_domains_result.json  ·  verdict:",
          json.dumps(RESULT.get("verdict", {}).get("per_domain"), ensure_ascii=False))
    print("closed:", RESULT["verdict"]["closed"])
