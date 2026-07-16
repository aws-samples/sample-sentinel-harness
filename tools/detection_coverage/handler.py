"""detection_coverage — deterministic ATT&CK coverage / gap analysis for a Sigma set.

SecOps purpose
--------------
A detection team's most important question about its rule library is NOT "are these
rules well-formed" (that is ``sigma_yara_lint``) nor "are any redundant"
(``detection_dedup``) — it is: **"which adversary techniques can we NOT detect at
all?"** A single uncovered ATT&CK technique is a blind spot an attacker walks
through. This tool answers that deterministically.

Given a SET of Sigma rules (each optionally carrying ``tags: [attack.tXXXX, ...]``,
the standard Sigma ATT&CK convention) and a TARGET list of technique ids (e.g. a
threat-model's priority techniques, or an ATT&CK-Navigator layer), it reports:
  - ``covered``    — target techniques with at least one detecting rule;
  - ``uncovered``  — target techniques with NO rule (the blind spots — the point);
  - ``untagged_rules`` — rules that carry no ATT&CK tag at all (un-attributable
                     coverage, a governance gap);
  - ``invalid_tags`` — ``attack.*`` tags that are not a valid technique id;
  - ``coverage_ratio`` — covered / target (only when a target list is given).

With no target list, it produces the INVENTORY: every technique the rule set tags,
and which rules tag it (uncovered/ratio are then not applicable).

Sound sub-technique reasoning
-----------------------------
A rule tagged with a SUB-technique (``T1059.001`` PowerShell) DOES contribute
coverage to its PARENT (``T1059``) — detecting the specific behavior detects an
instance of the general one. The reverse is NOT sound: a rule tagged only with the
PARENT (``T1059``) does NOT let us claim the specific sub-technique ``T1059.001`` is
covered (the parent tag is broader than the sub). So:
  - a target PARENT ``T1059`` is covered by a rule tagging ``T1059`` OR any
    ``T1059.<sub>``;
  - a target SUB ``T1059.001`` is covered ONLY by a rule tagging exactly
    ``T1059.001``.
This is the same conservative direction as ``detection_dedup``: never over-claim
coverage, because a false "covered" hides a real blind spot.

Provable core
-------------
DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same inputs → same
report. Reuses the shared Sigma YAML parser so all detection tools agree.

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
  "target_count": M | None,
  "covered":   [{"technique": "T1059", "rules": [<id>, ...]}],
  "uncovered": ["T1499", ...],                # empty when no target list
  "untagged_rules": [<id>, ...],
  "invalid_tags": [{"rule": <id>, "tag": "attack.bogus"}],
  "coverage_ratio": 0.66 | None,
  "summary": "human-readable one-liner",
}
On bad input: {"ok": False, "error": "validation_error", "message": "..."}

Egress & secrets posture
------------------------
ZERO egress, ZERO tokens, ZERO secrets. Pure Python; deterministic.
"""
from __future__ import annotations

import importlib.util
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Reuse the shared Sigma YAML parser from the sibling sigma_yara_lint tool.    #
# --------------------------------------------------------------------------- #
def _load_yaml_parser():
    sibling = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_yara_lint", "handler.py",
    )
    spec = importlib.util.spec_from_file_location("_syl_for_coverage", sibling)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_yaml(text: str) -> Any:
    return _load_yaml_parser()._parse_yaml(text)


# A valid ATT&CK technique id: T#### optionally .### sub-technique.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# A Sigma ATT&CK tag: "attack.t1059.001" (case-insensitive). The non-technique
# attack.* tags (tactics like "attack.execution", "attack.g0016" groups) are NOT
# techniques and are ignored for coverage (not treated as invalid).
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_ATTACK_TACTIC_OR_GROUP_RE = re.compile(r"^attack\.(?![tT]\d)", re.IGNORECASE)


class _CoverageError(ValueError):
    """Malformed request (bad input shape)."""


# --------------------------------------------------------------------------- #
# Input validation                                                            #
# --------------------------------------------------------------------------- #
def _validate(event: Dict[str, Any]) -> Tuple[List[Any], Optional[List[str]]]:
    if not isinstance(event, dict):
        raise _CoverageError("event must be a dict")
    rules = event.get("rules")
    if rules is None and "rule" in event:
        rules = [event["rule"]]
    if not isinstance(rules, list) or not rules:
        raise _CoverageError("missing required non-empty list field 'rules'")

    techniques = event.get("techniques")
    if techniques is None:
        return rules, None
    if not isinstance(techniques, list):
        raise _CoverageError("'techniques' must be a list of technique ids")
    norm: List[str] = []
    for t in techniques:
        if not isinstance(t, str) or not _TECHNIQUE_RE.match(t.strip().upper()):
            raise _CoverageError(
                f"invalid target technique id {t!r}; expected e.g. 'T1059' or 'T1059.001'"
            )
        norm.append(t.strip().upper())
    # De-dupe while preserving first-seen order (determinism, no double-count).
    seen: set = set()
    deduped = [t for t in norm if not (t in seen or seen.add(t))]
    return rules, deduped


def _parse_rule(raw: Any, index: int) -> Dict[str, Any]:
    if isinstance(raw, str):
        if not raw.strip():
            raise _CoverageError(f"rules[{index}] is an empty string")
        try:
            parsed = _parse_yaml(raw)
        except Exception as exc:  # surface parse failure, don't swallow
            raise _CoverageError(f"rules[{index}] YAML parse error: {exc}") from exc
    elif isinstance(raw, dict):
        parsed = raw
    else:
        raise _CoverageError(f"rules[{index}] must be a YAML string or a dict")
    if not isinstance(parsed, dict):
        raise _CoverageError(f"rules[{index}] did not resolve to a mapping")
    return parsed


def _rule_id(parsed: Dict[str, Any], index: int) -> str:
    rid = parsed.get("id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    title = parsed.get("title")
    if isinstance(title, str) and title.strip():
        return f"{title.strip()} [#{index}]"
    return f"rule[#{index}]"


def _rule_techniques(parsed: Dict[str, Any], rid: str, invalid: List[Dict[str, str]]):
    """Extract the set of valid technique ids a rule tags, recording malformed
    ``attack.*`` technique-looking tags in ``invalid``. Non-technique ``attack.*``
    tags (tactics/groups/software) are ignored, not flagged."""
    tags = parsed.get("tags")
    if not isinstance(tags, list):
        return set()
    out: set = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        t = tag.strip()
        m = _ATTACK_TAG_RE.match(t)
        if m:
            out.add(m.group(1).upper())
            continue
        # An attack.* tag that looks like a technique ("attack.t123", "attack.t99999")
        # but is not a valid id is a real authoring error — flag it. A tactic/group
        # tag ("attack.execution", "attack.g0016") is legitimate and ignored.
        low = t.lower()
        if low.startswith("attack.t") and not _ATTACK_TACTIC_OR_GROUP_RE.match(t):
            invalid.append({"rule": rid, "tag": t})
    return out


# --------------------------------------------------------------------------- #
# Core analysis                                                               #
# --------------------------------------------------------------------------- #
def _covering_rules(target: str, per_rule: List[Tuple[str, set]]) -> List[str]:
    """Rule ids that cover ``target``. A SUB target is covered only by an exact
    tag; a PARENT target is covered by an exact tag OR any of its sub-techniques."""
    is_parent = "." not in target
    hits: List[str] = []
    for rid, techs in per_rule:
        if target in techs:
            hits.append(rid)
        elif is_parent and any(t.split(".")[0] == target for t in techs):
            hits.append(rid)
    return hits


def _analyze(rules: List[Any], techniques: Optional[List[str]]) -> Dict[str, Any]:
    invalid_tags: List[Dict[str, str]] = []
    per_rule: List[Tuple[str, set]] = []      # (rule_id, {techniques})
    untagged: List[str] = []

    for i, raw in enumerate(rules):
        parsed = _parse_rule(raw, i)
        rid = _rule_id(parsed, i)
        techs = _rule_techniques(parsed, rid, invalid_tags)
        per_rule.append((rid, techs))
        if not techs:
            untagged.append(rid)

    covered: List[Dict[str, Any]] = []
    uncovered: List[str] = []
    coverage_ratio: Optional[float] = None
    target_count: Optional[int] = None

    if techniques is not None:
        target_count = len(techniques)
        for target in techniques:
            hits = _covering_rules(target, per_rule)
            if hits:
                covered.append({"technique": target, "rules": sorted(hits)})
            else:
                uncovered.append(target)
        coverage_ratio = (
            round(len(covered) / target_count, 4) if target_count else None
        )
    else:
        # No target list → inventory every technique the rule set tags.
        inventory: Dict[str, List[str]] = {}
        for rid, techs in per_rule:
            for t in techs:
                inventory.setdefault(t, []).append(rid)
        covered = [{"technique": t, "rules": sorted(rids)}
                   for t, rids in inventory.items()]

    # Deterministic ordering of every output list.
    covered.sort(key=lambda c: c["technique"])
    uncovered.sort()
    untagged.sort()
    invalid_tags.sort(key=lambda d: (d["rule"], d["tag"]))

    if techniques is not None:
        summary = (
            f"{len(rules)} rule(s) vs {target_count} target technique(s): "
            f"{len(covered)} covered, {len(uncovered)} UNCOVERED "
            f"(ratio {coverage_ratio}); {len(untagged)} untagged rule(s), "
            f"{len(invalid_tags)} invalid tag(s)."
        )
    else:
        summary = (
            f"{len(rules)} rule(s) tag {len(covered)} distinct technique(s); "
            f"{len(untagged)} untagged rule(s), {len(invalid_tags)} invalid tag(s). "
            f"(no target list → inventory only)"
        )

    return {
        "ok": True,
        "rule_count": len(rules),
        "target_count": target_count,
        "covered": covered,
        "uncovered": uncovered,
        "untagged_rules": untagged,
        "invalid_tags": invalid_tags,
        "coverage_ratio": coverage_ratio,
        "summary": summary,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Report ATT&CK coverage / blind spots for a Sigma rule set. Pure,
    deterministic, offline. Never raises: a malformed request is a
    ``validation_error``. Coverage claims are CONSERVATIVE — a sub-technique tag
    covers its parent but never the reverse, so a false "covered" never hides a
    real blind spot."""
    try:
        rules, techniques = _validate(event)
    except _CoverageError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    try:
        return _analyze(rules, techniques)
    except _CoverageError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}


if __name__ == "__main__":
    import json

    ps = """
title: PowerShell Encoded Command
id: r-ps-001
logsource:
    product: windows
    category: process_creation
tags:
    - attack.execution
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""
    untagged = """
title: Suspicious LOLBin
id: r-lol-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\certutil.exe'
    condition: selection
"""
    print(json.dumps(handler(
        {"rules": [ps, untagged], "techniques": ["T1059", "T1046", "T1190"]}, None,
    ), indent=2))
