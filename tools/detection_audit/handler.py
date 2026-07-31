"""detection_audit — one-shot deterministic health check for a Sigma rule library.

SecOps purpose
--------------
A detection team owns a growing Sigma library and needs a single, repeatable
"is my rule set healthy?" report rather than running four tools by hand. This tool
is the AGGREGATOR over the deterministic detection-engineering suite:

  - ``sigma_yara_lint``  — is each rule structurally valid? (per-rule errors/warnings)
  - ``detection_dedup``  — which rules are duplicates / subsumed / overlapping?
  - ``detection_coverage`` — which target ATT&CK techniques are UNCOVERED (blind
                             spots)? which rules carry no ATT&CK tag?

It runs all three over one rule set and folds the results into a single governance
report plus a conservative ``health_score`` (0..100) and a prioritized
``findings`` list an engineer can work top-down. It adds NO new judgement of its
own beyond composition — every sub-result is passed through faithfully, so the
report is exactly as sound (and as conservative) as the three tools it calls.

Provable core
-------------
DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same rule set in →
same report out. Reuses the three sibling tools by path (``tools/`` is a scripts
tree, not a package), which in turn share one Sigma parser, so all four agree.

Health score (transparent, conservative)
-----------------------------------------
Starts at 100 and deducts, capped, for each defect CLASS so one noisy class cannot
drive the score negative and the weighting is auditable:
  - invalid rules (lint errors) ....... up to -40  (structural breakage is worst)
  - uncovered target techniques ....... up to -30  (blind spots)
  - duplicate rule pairs .............. up to -15
  - untagged rules .................... up to -10  (un-attributable coverage)
  - lint warnings + invalid ATT&CK tags up to -5
  - non-actionable rules .............. up to -15  (claim coverage, cannot fire)
The per-class deduction is ``weight * min(1, count / basis)`` so it saturates; the
score is clamped to ``[0, 100]`` and ROUNDED (deterministic). It is a triage aid,
not a compliance verdict — the raw counts and per-rule detail are always included.

Input contract
--------------
event = {
    "rules": [<sigma yaml string OR parsed dict>, ...],   # required, non-empty
    "techniques": ["T1059", "T1190.001", ...],            # optional target list
}

Output contract (on success)
----------------------------
{
  "ok": True,
  "rule_count": N,
  "health_score": 0..100,
  "totals": {"invalid_rules", "rules_with_warnings", "duplicate_pairs",
             "subsumptions", "overlaps", "uncovered_techniques",
             "untagged_rules", "invalid_tags", "non_actionable_rules"},
  "lint": {"invalid": [{"rule", "errors"}], "warnings": [{"rule", "warnings"}]},
  "dedup": {<detection_dedup result minus ok>},
  "coverage": {<detection_coverage result minus ok>} | None,
  "findings": ["prioritized human-readable lines, worst first"],
  "summary": "one-liner",
}
On bad input: {"ok": False, "error": "validation_error", "message": "..."}

Egress & secrets posture
------------------------
ZERO egress, ZERO tokens, ZERO secrets. Pure Python; deterministic.
"""
from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, List, Optional, Tuple

_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _AuditError(ValueError):
    """Malformed request (bad input shape)."""


# --------------------------------------------------------------------------- #
# Load the sibling tools by path (tools/ is a flat scripts tree, not a package).#
# Each is loaded ONCE and reused across the audit.                            #
# --------------------------------------------------------------------------- #
def _load_tool(name: str):
    path = os.path.join(_TOOLS_DIR, name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"_audit_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Input validation                                                            #
# --------------------------------------------------------------------------- #
def _validate(event: Dict[str, Any]) -> Tuple[List[Any], Optional[List[str]]]:
    if not isinstance(event, dict):
        raise _AuditError("event must be a dict")
    rules = event.get("rules")
    if rules is None and "rule" in event:
        rules = [event["rule"]]
    if not isinstance(rules, list) or not rules:
        raise _AuditError("missing required non-empty list field 'rules'")
    techniques = event.get("techniques")
    if techniques is not None and not isinstance(techniques, list):
        raise _AuditError("'techniques' must be a list of technique ids")
    return rules, techniques


# --------------------------------------------------------------------------- #
# Health score — transparent, saturating, deterministic.                      #
# --------------------------------------------------------------------------- #
# (weight, basis): deduct weight * min(1, count/basis) so each class saturates.
_SCORE_WEIGHTS = {
    "invalid_rules": (40, 5),
    "uncovered_techniques": (30, 10),
    "duplicate_pairs": (15, 5),
    "untagged_rules": (10, 10),
    "lint_and_tag_noise": (5, 10),
    "fp_prone_rules": (10, 5),
    # A rule that CLAIMS an ATT&CK technique but can never fire (no detection
    # block / no condition / condition naming an undefined selection) is worse than
    # an untagged rule: an untagged rule under-reports its own coverage, while this
    # one makes the matrix show green over a real blind spot. Weighted alongside the
    # blind-spot class it manufactures, and saturating on a handful.
    "non_actionable_rules": (15, 5),
}


def _health_score(totals: Dict[str, int], coverage_ran: bool) -> int:
    score = 100.0
    score -= _deduct("invalid_rules", totals["invalid_rules"])
    if coverage_ran:
        score -= _deduct("uncovered_techniques", totals["uncovered_techniques"])
    score -= _deduct("duplicate_pairs", totals["duplicate_pairs"])
    score -= _deduct("untagged_rules", totals["untagged_rules"])
    score -= _deduct("lint_and_tag_noise",
                     totals["rules_with_warnings"] + totals["invalid_tags"])
    score -= _deduct("fp_prone_rules", totals.get("fp_prone_rules", 0))
    score -= _deduct("non_actionable_rules", totals.get("non_actionable_rules", 0))
    return max(0, min(100, round(score)))


def _deduct(key: str, count: int) -> float:
    weight, basis = _SCORE_WEIGHTS[key]
    if count <= 0:
        return 0.0
    return weight * min(1.0, count / basis)


# --------------------------------------------------------------------------- #
# Core aggregation                                                            #
# --------------------------------------------------------------------------- #
def _empty_dedup() -> Dict[str, Any]:
    """The dedup result shape for an empty analyzable set (no pairs possible)."""
    return {"ok": True, "rule_count": 0, "duplicates": [], "subsumptions": [],
            "overlaps": [], "not_analyzed": [], "summary": "0 analyzable rule(s)."}


def _empty_coverage(techniques: Optional[List[str]]) -> Dict[str, Any]:
    """The coverage result shape for an empty analyzable set: every target is a
    blind spot (no rule can cover it)."""
    uncovered = sorted({t.strip().upper() for t in techniques}) if techniques else []
    return {"ok": True, "rule_count": 0,
            "target_count": len(uncovered) if techniques is not None else None,
            "covered": [], "uncovered": uncovered, "untagged_rules": [],
            "invalid_tags": [], "non_actionable_rules": [],
            "coverage_ratio": (0.0 if techniques else None),
            "summary": "0 analyzable rule(s)."}


def _analyze(rules: List[Any], techniques: Optional[List[str]]) -> Dict[str, Any]:
    lint = _load_tool("sigma_yara_lint")
    dedup = _load_tool("detection_dedup")
    coverage = _load_tool("detection_coverage")

    # --- per-rule lint (sigma). Reuse dedup's rule-id derivation for stable ids
    #     that match the dedup/coverage reports. A rule string that does not parse
    #     is surfaced as a lint error, not a crash. We also RESILIENTLY separate
    #     rules dedup/coverage can accept (str/dict) from junk entries (int/None/…):
    #     one garbage entry must not blind the operator to the rest of the library,
    #     so a non-str/dict rule is recorded as an invalid rule and EXCLUDED from the
    #     batch handed to the dedup/coverage sub-tools (which reject the whole list
    #     on any non-str/dict member). ---
    invalid: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    fp_prone_list: List[Dict[str, Any]] = []
    analyzable: List[Any] = []
    for i, raw in enumerate(rules):
        rid, content = _rule_id_and_content(raw, i, dedup)
        if isinstance(raw, (str, dict)):
            analyzable.append(raw)
        else:
            # Not a rule the suite can parse at all — surface it, then skip it.
            invalid.append({"rule": rid,
                            "errors": [f"not a Sigma rule (got {type(raw).__name__}); "
                                       f"expected a YAML string or a dict"]})
            continue
        res = lint.handler({"rule_type": "sigma", "content": content}, None)
        if not res.get("ok"):
            invalid.append({"rule": rid, "errors": [res.get("message", "unlintable rule")]})
            continue
        if res.get("errors"):
            invalid.append({"rule": rid, "errors": res["errors"]})
        if res.get("warnings"):
            warnings.append({"rule": rid, "warnings": res["warnings"]})
        if res.get("fp_warnings"):
            fp_prone_list.append({"rule": rid, "fp_warnings": res["fp_warnings"]})

    # --- dedup + coverage over the ANALYZABLE subset (each is itself conservative).
    #     An empty analyzable set (every entry was junk) yields empty sub-reports
    #     rather than a sub-tool validation error. ---
    dedup_res = _empty_dedup() if not analyzable else dedup.handler({"rules": analyzable}, None)
    if not dedup_res.get("ok"):
        raise _AuditError(f"dedup sub-tool rejected input: {dedup_res.get('message')}")
    cov_event: Dict[str, Any] = {"rules": analyzable}
    if techniques is not None:
        cov_event["techniques"] = techniques
    cov_res = _empty_coverage(techniques) if not analyzable else coverage.handler(cov_event, None)
    if not cov_res.get("ok"):
        raise _AuditError(f"coverage sub-tool rejected input: {cov_res.get('message')}")
    coverage_ran = techniques is not None

    invalid.sort(key=lambda d: d["rule"])
    warnings.sort(key=lambda d: d["rule"])
    # FP-prone: rules with >=2 fp_warnings (the threshold for "will likely drown a SOC").
    fp_prone = [r for r in fp_prone_list if len(r.get("fp_warnings", [])) >= 2]
    fp_prone.sort(key=lambda d: d["rule"])

    totals = {
        "invalid_rules": len(invalid),
        "rules_with_warnings": len(warnings),
        "duplicate_pairs": len(dedup_res["duplicates"]),
        "subsumptions": len(dedup_res["subsumptions"]),
        "overlaps": len(dedup_res["overlaps"]),
        "uncovered_techniques": len(cov_res["uncovered"]),
        "untagged_rules": len(cov_res["untagged_rules"]),
        "invalid_tags": len(cov_res["invalid_tags"]),
        "fp_prone_rules": len(fp_prone),
        # Rules coverage EXCLUDED because they can never fire (see
        # detection_coverage's non_actionable_rules). `.get` keeps this tolerant of
        # an older coverage result shape.
        "non_actionable_rules": len(cov_res.get("non_actionable_rules") or []),
    }
    score = _health_score(totals, coverage_ran)

    findings = _prioritized_findings(totals, invalid, dedup_res, cov_res, coverage_ran, fp_prone)

    # Strip the redundant "ok" from the nested sub-results for a cleaner report.
    dedup_report = {k: v for k, v in dedup_res.items() if k != "ok"}
    cov_report = ({k: v for k, v in cov_res.items() if k != "ok"}
                  if coverage_ran else None)

    summary = (
        f"{len(rules)} rule(s): health {score}/100 — "
        f"{totals['invalid_rules']} invalid, {totals['duplicate_pairs']} dup pair(s), "
        f"{totals['uncovered_techniques']} uncovered technique(s), "
        f"{totals['untagged_rules']} untagged."
    )
    result: Dict[str, Any] = {
        "ok": True,
        "rule_count": len(rules),
        "health_score": score,
        "totals": totals,
        "lint": {"invalid": invalid, "warnings": warnings},
        "dedup": dedup_report,
        "coverage": cov_report,
        "findings": findings,
        "summary": summary,
    }
    if fp_prone:
        result["fp_prone"] = fp_prone
    return result


def _rule_id_and_content(raw: Any, index: int, dedup) -> Tuple[str, str]:
    """Return (stable_rule_id, sigma_text_for_lint) for one input rule.

    A dict rule is re-serialized to a trivial YAML for the linter via a minimal
    round-trip; a string rule is linted verbatim. The id uses dedup's own
    derivation so the three reports refer to the same rule by the same name."""
    if isinstance(raw, str):
        # Parse just enough to derive an id; lint the ORIGINAL text.
        try:
            parsed = dedup._parse_yaml(raw)
        except Exception:
            parsed = {}
        rid = dedup._rule_id(parsed if isinstance(parsed, dict) else {}, index)
        return rid, raw
    if isinstance(raw, dict):
        rid = dedup._rule_id(raw, index)
        return rid, _dict_to_sigma(raw)
    # Non-str/non-dict: give it a positional id and an empty body so the linter
    # reports a clean structural error rather than the audit crashing.
    return f"rule[#{index}]", ""


def _dict_to_sigma(rule: Dict[str, Any]) -> str:
    """Serialize a parsed rule dict to minimal Sigma YAML sufficient for LINTING
    (title/id/logsource/detection presence + condition). Deterministic; only the
    keys the linter inspects are emitted, values are rendered flat."""
    import json
    lines: List[str] = []
    for key in ("title", "id", "status", "level"):
        if key in rule and not isinstance(rule[key], (dict, list)):
            lines.append(f"{key}: {json.dumps(rule[key], ensure_ascii=False)}")
    ls = rule.get("logsource")
    if isinstance(ls, dict):
        lines.append("logsource:")
        for k, v in ls.items():
            if not isinstance(v, (dict, list)):
                lines.append(f"    {k}: {json.dumps(v, ensure_ascii=False)}")
    det = rule.get("detection")
    if isinstance(det, dict):
        lines.append("detection:")
        for sel_name, sel in det.items():
            if sel_name == "condition":
                continue
            lines.append(f"    {sel_name}:")
            if isinstance(sel, dict):
                for fk, fv in sel.items():
                    lines.append(f"        {fk}: {json.dumps(fv, ensure_ascii=False)}")
        cond = det.get("condition")
        if cond is not None:
            lines.append(f"    condition: {json.dumps(cond, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def _prioritized_findings(totals, invalid, dedup_res, cov_res, coverage_ran,
                          fp_prone=None) -> List[str]:
    """Build a worst-first, human-readable findings list. Deterministic order."""
    out: List[str] = []
    if invalid:
        out.append(f"[critical] {len(invalid)} rule(s) FAIL lint (structurally invalid): "
                   + ", ".join(d["rule"] for d in invalid[:10])
                   + (" …" if len(invalid) > 10 else ""))
    if coverage_ran and cov_res["uncovered"]:
        out.append(f"[high] {len(cov_res['uncovered'])} target technique(s) UNCOVERED "
                   f"(blind spots): " + ", ".join(cov_res["uncovered"][:15])
                   + (" …" if len(cov_res["uncovered"]) > 15 else ""))
    if fp_prone:
        out.append(f"[medium] {len(fp_prone)} rule(s) are FP-prone "
                   f"(>=2 noise heuristics triggered): "
                   + ", ".join(d["rule"] for d in fp_prone[:10])
                   + (" …" if len(fp_prone) > 10 else ""))
    for d in dedup_res["duplicates"]:
        out.append(f"[medium] duplicate rules: {d['a']} == {d['b']} (keep one)")
    for s in dedup_res["subsumptions"]:
        out.append(f"[medium] {s['subset']} is subsumed by {s['superset']} (review redundancy)")
    if cov_res["untagged_rules"]:
        out.append(f"[low] {len(cov_res['untagged_rules'])} rule(s) carry no ATT&CK tag: "
                   + ", ".join(cov_res["untagged_rules"][:10])
                   + (" …" if len(cov_res["untagged_rules"]) > 10 else ""))
    if cov_res["invalid_tags"]:
        out.append(f"[low] {len(cov_res['invalid_tags'])} invalid ATT&CK tag(s)")
    return out


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Run the full deterministic detection-library health check. Pure, offline.
    Never raises: a malformed request is a ``validation_error``. Adds no judgement
    beyond composing sigma_yara_lint + detection_dedup + detection_coverage, so the
    report is exactly as conservative as those three tools."""
    try:
        rules, techniques = _validate(event)
    except _AuditError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    try:
        return _analyze(rules, techniques)
    except _AuditError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}


if __name__ == "__main__":
    import json

    good = """
title: PowerShell Encoded Command
id: r-ps-001
logsource:
    product: windows
    category: process_creation
tags:
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""
    dup = """
title: PowerShell Encoded Command (copy)
id: r-ps-002
logsource:
    product: windows
    category: process_creation
tags:
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""
    broken = "title: broken\ndetection:\n    selection:\n        x: y\n"  # no logsource/condition
    print(json.dumps(handler(
        {"rules": [good, dup, broken], "techniques": ["T1059", "T1190", "T1046"]}, None,
    ), indent=2))
