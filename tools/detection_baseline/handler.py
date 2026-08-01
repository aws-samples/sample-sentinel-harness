"""detection_baseline — regression baseline for a Sigma rule library.

SecOps purpose
--------------
A rule library's health can silently DEGRADE over time: someone edits a rule and
breaks its lint, a refactor drops an ATT&CK tag (a new blind spot), or a
copy-paste introduces a duplicate. ``detection_audit`` measures health at a point
in time; this tool turns that into a REGRESSION GATE: capture a baseline snapshot,
then on every change compare the current audit against it and FAIL if the library
got worse — the detection-engineering analogue of a coverage floor in CI.

Two modes:
  - ``snapshot``  — reduce a ``detection_audit`` result to a compact, stable
                    baseline object (health score, totals, and the SETS that must
                    not grow: invalid rules, uncovered techniques, duplicate pairs).
  - ``compare``   — diff a current ``detection_audit`` result against a baseline and
                    return ``regressed: True`` (with itemized reasons) when the
                    library degraded: health score dropped, OR a NEW invalid rule /
                    NEW uncovered technique / NEW duplicate pair appeared that was
                    not in the baseline. Improvements never fail; they are reported
                    so the baseline can be refreshed.

Why set-diff, not just the score
--------------------------------
A health score alone hides churn: fixing one rule while breaking another can leave
the score flat. So ``compare`` also checks the SETS — a specific rule going invalid
or a specific technique losing coverage is a regression even if the score is
unchanged. This makes the gate catch real degradations a scalar would miss.

Determinism & posture
----------------------
DETERMINISTIC and LLM-FREE: no model, no tokens, no network, no clock. Same inputs
→ same output; all emitted lists are sorted. Pure Python. It operates on an audit
RESULT you pass in (produced by ``detection_audit``), so it does no rule parsing
itself and inherits that tool's conservative semantics.

Input contract
--------------
Snapshot mode:
    event = {"mode": "snapshot", "audit": <detection_audit result>}
Compare mode:
    event = {"mode": "compare", "audit": <current detection_audit result>,
             "baseline": <a prior snapshot's "baseline" object>,
             "allow_score_drop": 0}   # optional: tolerated health-score decrease (default 0)

Output contract (on success)
----------------------------
snapshot: {"ok": True, "mode": "snapshot", "baseline": {...compact...}}
compare:  {"ok": True, "mode": "compare", "regressed": bool,
           "health_delta": int, "reasons": [..], "improvements": [..],
           "current": {...compact...}, "baseline": {...compact...}}
On bad input: {"ok": False, "error": "validation_error", "message": "..."}

Egress & secrets posture
------------------------
ZERO egress, ZERO tokens, ZERO secrets. Pure Python; deterministic.
"""
from __future__ import annotations

from typing import Any, Dict, List


class _BaselineError(ValueError):
    """Malformed request (bad input shape)."""


def _validate(event: Dict[str, Any]) -> str:
    if not isinstance(event, dict):
        raise _BaselineError("event must be a dict")
    mode = event.get("mode")
    if mode not in ("snapshot", "compare"):
        raise _BaselineError("'mode' must be 'snapshot' or 'compare'")
    audit = event.get("audit")
    if not isinstance(audit, dict) or not audit.get("ok"):
        raise _BaselineError("'audit' must be a successful detection_audit result (ok=True)")
    if mode == "compare":
        baseline = event.get("baseline")
        if not isinstance(baseline, dict):
            raise _BaselineError("compare mode requires a 'baseline' object (from a prior snapshot)")
        # FAIL CLOSED on a malformed/empty baseline. R12 reproduced the fail-OPEN:
        # an empty {} (a truncated file), or the whole snapshot RESULT passed instead
        # of its ["baseline"] field, left health_score defaulting to 0 — so every
        # current library scored an "improvement" and the gate passed green. A
        # regression gate that cannot read its baseline must FAIL, not wave the
        # change through. A valid baseline is the output of snapshot mode, which
        # always carries an integer health_score and a rule_count.
        if "health_score" not in baseline or "rule_count" not in baseline:
            raise _BaselineError(
                "baseline is missing required fields (health_score, rule_count) — it "
                "is empty, truncated, or you passed the whole snapshot result instead "
                "of its 'baseline' object. Refusing to compare against an unreadable "
                "baseline (a regression must never pass green because the baseline "
                "could not be read)."
            )
        for fld in ("health_score", "rule_count"):
            if not isinstance(baseline.get(fld), int) or isinstance(baseline.get(fld), bool):
                raise _BaselineError(
                    f"baseline '{fld}' must be an integer (got "
                    f"{type(baseline.get(fld)).__name__}); the baseline is corrupt."
                )
    return mode


def _compact(audit: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a detection_audit result to the stable, comparable baseline fields.

    Keeps the health score, the totals, and the SETS whose change is a regression:
    invalid rules, uncovered techniques, duplicate pairs (each pair canonicalized +
    sorted so it is order-stable), AND the COVERED technique set + target list.

    Why covered + target, not just uncovered: R12 reproduced two ways a real
    regression hid behind an uncovered-only diff. (a) A shrinking rule library
    dropped coverage of a technique that had been covered — but if the caller ran
    audit with NO target list, that technique never appears in `uncovered`, so its
    loss was invisible. Snapshotting the COVERED set makes a technique leaving it a
    regression. (b) Trimming the target list shrinks `uncovered` (fewer targets =
    fewer blind spots), which the old diff read as "resolved uncovered technique(s)"
    — a real blind spot relabelled an improvement. Snapshotting the target list lets
    compare refuse to credit an "improvement" that is really a smaller question."""
    totals = audit.get("totals") or {}
    lint = audit.get("lint") or {}
    dedup = audit.get("dedup") or {}
    coverage = audit.get("coverage") or {}

    invalid_rules = sorted(str(x.get("rule")) for x in (lint.get("invalid") or []))
    uncovered = sorted(str(t) for t in (coverage.get("uncovered") or []))
    covered = sorted(str(c.get("technique")) for c in (coverage.get("covered") or []))
    target = coverage.get("target_count")
    # a duplicate pair -> "a|b" with the two ids sorted so it is symmetric/stable
    duplicate_pairs = sorted(
        "|".join(sorted((str(d.get("a")), str(d.get("b")))))
        for d in (dedup.get("duplicates") or [])
    )
    return {
        "health_score": int(audit.get("health_score", 0)),
        "rule_count": int(audit.get("rule_count", 0)),
        "totals": {k: int(v) for k, v in totals.items()},
        "invalid_rules": invalid_rules,
        "uncovered_techniques": uncovered,
        "covered_techniques": covered,
        "target_count": int(target) if isinstance(target, int) else None,
        "duplicate_pairs": duplicate_pairs,
    }


def _compare(current: Dict[str, Any], baseline: Dict[str, Any],
             allow_score_drop: int) -> Dict[str, Any]:
    """Diff current vs baseline compact snapshots; itemize regressions + improvements."""
    reasons: List[str] = []
    improvements: List[str] = []

    cur_score = current["health_score"]
    base_score = baseline.get("health_score", 0)
    health_delta = cur_score - base_score
    # A health-score drop beyond the tolerated slack is a regression.
    if health_delta < -abs(allow_score_drop):
        reasons.append(
            f"health_score dropped {base_score} -> {cur_score} "
            f"(delta {health_delta}, tolerated -{abs(allow_score_drop)})"
        )
    elif health_delta > 0:
        improvements.append(f"health_score improved {base_score} -> {cur_score} (+{health_delta})")

    # Set growth = regression; set shrink = improvement. Compare against the baseline
    # sets so a NEW item (not present before) is flagged even if the count is flat.
    for label, key in (("invalid rule", "invalid_rules"),
                       ("uncovered technique", "uncovered_techniques"),
                       ("duplicate pair", "duplicate_pairs")):
        base_set = set(baseline.get(key) or [])
        cur_set = set(current.get(key) or [])
        new_items = sorted(cur_set - base_set)
        fixed_items = sorted(base_set - cur_set)
        if new_items:
            reasons.append(f"new {label}(s): {new_items}")
        if fixed_items:
            improvements.append(f"resolved {label}(s): {fixed_items}")

    # LOST COVERAGE is a regression the uncovered-set diff can miss entirely: with
    # no target list, a dropped technique never enters `uncovered`, so a shrinking
    # library silently loses detections. A technique leaving the COVERED set is a
    # regression regardless of whether it reappears in uncovered.
    base_cov = set(baseline.get("covered_techniques") or [])
    cur_cov = set(current.get("covered_techniques") or [])
    lost_cov = sorted(base_cov - cur_cov)
    gained_cov = sorted(cur_cov - base_cov)
    if lost_cov:
        reasons.append(f"lost coverage of technique(s): {lost_cov}")
    if gained_cov:
        improvements.append(f"newly covered technique(s): {gained_cov}")

    # A SHRINKING rule library is suspicious on its own: fewer rules cannot cover
    # more, and R12 showed a 8->3 shrink sailing through as an "improvement" because
    # the score happened to rise. Flag the shrink so it cannot pass silently; the
    # covered-set diff above carries the specifics.
    base_rc = baseline.get("rule_count")
    cur_rc = current.get("rule_count")
    if isinstance(base_rc, int) and isinstance(cur_rc, int) and cur_rc < base_rc:
        reasons.append(f"rule library shrank {base_rc} -> {cur_rc} rule(s)")

    # A CHANGED target list makes the uncovered/covered diffs incomparable: trimming
    # targets shrinks `uncovered` (fewer questions asked), which must NOT be credited
    # as resolved blind spots. Refuse to treat a smaller question as an improvement.
    base_tc = baseline.get("target_count")
    cur_tc = current.get("target_count")
    if base_tc != cur_tc:
        reasons.append(
            f"target technique list changed ({base_tc} -> {cur_tc}); coverage deltas "
            "are not comparable across different target sets — re-baseline instead of "
            "reading this as an improvement"
        )

    # Saturated deduction classes (untagged/non_actionable) can grow unboundedly
    # while the health_score stays flat (already at its deduction ceiling). Their
    # growth in the totals is a real degradation the score cannot show.
    base_tot = baseline.get("totals") or {}
    cur_tot = current.get("totals") or {}
    for key in ("untagged_rules", "non_actionable_rules", "invalid_tags",
                "rules_with_warnings", "fp_prone_rules"):
        bv, cv = int(base_tot.get(key, 0)), int(cur_tot.get(key, 0))
        if cv > bv:
            reasons.append(f"{key} grew {bv} -> {cv} (a degradation the score may have saturated)")
        elif cv < bv:
            improvements.append(f"{key} shrank {bv} -> {cv}")

    return {
        "ok": True,
        "mode": "compare",
        "regressed": bool(reasons),
        "health_delta": health_delta,
        "reasons": reasons,
        "improvements": improvements,
        "current": current,
        "baseline": baseline,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Snapshot or compare a detection-library health baseline. Pure, deterministic,
    offline. Never raises: a malformed request is a ``validation_error``. In compare
    mode ``regressed`` is True iff the library degraded (score drop beyond the
    tolerance, or a NEW invalid rule / uncovered technique / duplicate pair)."""
    try:
        mode = _validate(event)
    except _BaselineError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    current = _compact(event["audit"])
    if mode == "snapshot":
        return {"ok": True, "mode": "snapshot", "baseline": current}

    raw_allow = event.get("allow_score_drop", 0)
    if isinstance(raw_allow, bool) or not isinstance(raw_allow, int):
        # Reject a float/str/bool loudly rather than int()-coercing it: 2.9 -> 2 and
        # True -> 1 would silently change the gate's tolerance.
        return {"ok": False, "error": "validation_error",
                "message": "'allow_score_drop' must be a non-negative integer"}
    if raw_allow < 0:
        # A NEGATIVE tolerance is nonsensical as "allowed drop". The old code abs()'d
        # it, so --allow-score-drop=-100 became a 100-point allowance that disabled
        # the score gate entirely (R12). Clamp to 0 (strictest): a drop tolerance
        # below zero can only mean "tolerate nothing".
        allow = 0
    else:
        allow = raw_allow
    return _compare(current, event["baseline"], allow)


if __name__ == "__main__":
    import json

    base_audit = {"ok": True, "health_score": 90, "rule_count": 3,
                  "totals": {"invalid_rules": 0, "duplicate_pairs": 0, "uncovered_techniques": 1},
                  "lint": {"invalid": []},
                  "dedup": {"duplicates": []},
                  "coverage": {"uncovered": ["T1190"]}}
    snap = handler({"mode": "snapshot", "audit": base_audit}, None)
    print("SNAPSHOT:", json.dumps(snap["baseline"], indent=2))

    worse_audit = {"ok": True, "health_score": 70, "rule_count": 3,
                   "totals": {"invalid_rules": 1, "duplicate_pairs": 1, "uncovered_techniques": 2},
                   "lint": {"invalid": [{"rule": "r-broken", "errors": ["no condition"]}]},
                   "dedup": {"duplicates": [{"a": "r1", "b": "r2"}]},
                   "coverage": {"uncovered": ["T1190", "T1046"]}}
    cmp = handler({"mode": "compare", "audit": worse_audit, "baseline": snap["baseline"]}, None)
    print("COMPARE:", json.dumps({k: cmp[k] for k in ("regressed", "health_delta", "reasons")}, indent=2))
