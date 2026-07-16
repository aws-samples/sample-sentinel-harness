"""detection_dedup — deterministic Sigma rule-set overlap / redundancy governance.

SecOps purpose
--------------
A mature detection library accretes hundreds of Sigma rules over years, authored
by many hands. Overlap creeps in: two rules that fire on the exact same events, a
narrow rule whose every hit is already caught by a broader one, rules that partly
overlap. That overlap costs alert-fatigue (duplicate alerts), review time, and
maintenance drag — but finding it by eye across a large corpus is infeasible.

This tool takes a SET of Sigma rules and deterministically reports, for the
same-logsource pairs it can PROVE a relationship for:
  - ``duplicates``     — identical detection logic (same match set);
  - ``subsumptions``   — rule A's match set is a proven SUBSET of rule B's (every
                         event A catches, B also catches — A may be redundant);
  - ``overlaps``       — same logsource + a shared predicate, neither subsumes;
and — the honest part — everything it CANNOT soundly analyze (complex conditions,
regex/list/numeric predicates) is surfaced in ``not_analyzed`` rather than
silently ignored. It NEVER claims a rule is redundant unless the subset relation
is provable, because a wrong "safe to delete" verdict deletes real coverage.

Provable core
-------------
DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same rule set in →
same report out. The subsumption logic is conservative set-containment reasoning
over normalized ``(field, modifier, value)`` predicates for the "single-selection
AND" rule shape (the overwhelming majority of Sigma rules); anything outside that
provable shape is declared not-analyzed, never guessed.

Subset reasoning (why it is SOUND, not heuristic)
-------------------------------------------------
For a rule whose condition is exactly its one selection, the rule fires iff ALL of
that selection's predicates match, so its match set is the INTERSECTION of the
per-predicate match sets. Rule A's match set ⊆ rule B's match set is proven when,
for every predicate ``qB`` of B, A has a same-field predicate ``pA`` whose match
set ⊆ ``qB``'s (``pA`` implies ``qB``). This is a SUFFICIENT condition: it may miss
some true subset relations (conservative) but never asserts a false one.

Input contract
--------------
event = {"rules": [<sigma yaml string OR parsed dict>, ...]}
    A single rule is accepted too (wrapped into a one-element set).

Output contract (on success)
----------------------------
{
  "ok": True,
  "rule_count": N,
  "duplicates":   [{"a": <id>, "b": <id>, "reason": "..."}],
  "subsumptions": [{"subset": <id>, "superset": <id>, "reason": "..."}],
  "overlaps":     [{"a": <id>, "b": <id>, "shared": ["field|mod=value", ...]}],
  "not_analyzed": [{"rule": <id>, "reason": "..."}],
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
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Reuse the shared Sigma YAML parser from the sibling sigma_yara_lint tool so  #
# all detection tools parse Sigma identically (tools/ is a scripts tree).      #
# --------------------------------------------------------------------------- #
def _load_yaml_parser():
    sibling = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_yara_lint", "handler.py",
    )
    spec = importlib.util.spec_from_file_location("_syl_for_dedup", sibling)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_yaml(text: str) -> Any:
    return _load_yaml_parser()._parse_yaml(text)


# The value-transform modifiers whose set-containment we can reason about soundly.
_ANALYZABLE_MODIFIERS = {"", "contains", "startswith", "endswith"}


class _DedupError(ValueError):
    """Malformed request (bad input shape)."""


# --------------------------------------------------------------------------- #
# Input validation + rule normalization                                       #
# --------------------------------------------------------------------------- #
def _validate(event: Dict[str, Any]) -> List[Any]:
    if not isinstance(event, dict):
        raise _DedupError("event must be a dict")
    rules = event.get("rules")
    if rules is None and "rule" in event:
        rules = [event["rule"]]
    if not isinstance(rules, list) or not rules:
        raise _DedupError("missing required non-empty list field 'rules'")
    return rules


def _parse_rule(raw: Any, index: int) -> Dict[str, Any]:
    """Parse one rule (yaml string or dict) into a mapping; raise on bad shape."""
    if isinstance(raw, str):
        if not raw.strip():
            raise _DedupError(f"rules[{index}] is an empty string")
        try:
            parsed = _parse_yaml(raw)
        except Exception as exc:  # surface parse failure, don't swallow
            raise _DedupError(f"rules[{index}] YAML parse error: {exc}") from exc
    elif isinstance(raw, dict):
        parsed = raw
    else:
        raise _DedupError(f"rules[{index}] must be a YAML string or a dict")
    if not isinstance(parsed, dict):
        raise _DedupError(f"rules[{index}] did not resolve to a mapping")
    return parsed


def _rule_id(parsed: Dict[str, Any], index: int) -> str:
    """Stable display id: prefer 'id', then 'title', else positional. Positional
    is suffixed so two untitled rules never collide into one id."""
    rid = parsed.get("id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    title = parsed.get("title")
    if isinstance(title, str) and title.strip():
        return f"{title.strip()} [#{index}]"
    return f"rule[#{index}]"


def _canonical_logsource(parsed: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    """Normalize logsource to a hashable, order-independent key of the fields that
    define the data stream (product/category/service). Absent logsource → empty."""
    ls = parsed.get("logsource")
    if not isinstance(ls, dict):
        return ()
    out = []
    for k in ("product", "category", "service"):
        v = ls.get(k)
        if v is not None:
            out.append((k, str(v).strip().lower()))
    return tuple(sorted(out))


# --------------------------------------------------------------------------- #
# Predicate model — a rule is "analyzable" iff its condition is exactly its one #
# selection and every predicate is a scalar value with an analyzable modifier. #
# --------------------------------------------------------------------------- #
# A predicate is (field_lower, value_modifier, value_lower).
Predicate = Tuple[str, str, str]


def _analyzable_predicates(parsed: Dict[str, Any]) -> Optional[List[Predicate]]:
    """Return the normalized predicate list for a single-selection AND rule, or
    ``None`` if the rule falls outside the provable shape (complex condition,
    multiple selections, list/regex/numeric/unknown-modifier value)."""
    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        return None
    selection_names = [k for k in detection if k != "condition"]
    if len(selection_names) != 1:
        return None  # multi-selection → condition-dependent, not simply provable
    cond = detection.get("condition")
    name = selection_names[0]
    # The condition must be exactly the one selection name (a pure AND of its keys).
    if not isinstance(cond, str) or cond.strip().lower() != name.strip().lower():
        return None
    selection = detection[name]
    if not isinstance(selection, dict) or not selection:
        return None

    preds: List[Predicate] = []
    for key, value in selection.items():
        # Any list/dict value (OR / |all AND / nested) is outside the sound scalar
        # model; a non-string scalar (int/bool/None) likewise. Bail → not analyzed.
        if not isinstance(value, str):
            return None
        parts = str(key).split("|")
        field = parts[0].strip().lower()
        modifiers = [p.strip().lower() for p in parts[1:] if p.strip()]
        # Pick the value-transform modifier; reject 're'/'all'/numeric/base64/cidr
        # and any unknown modifier as non-analyzable.
        value_modifier = ""
        for m in modifiers:
            if m in ("contains", "startswith", "endswith"):
                value_modifier = m
            else:
                return None  # 're', 'all', 'cidr', 'base64', numeric, unknown → bail
        preds.append((field, value_modifier, value.lower()))
    return preds


# --------------------------------------------------------------------------- #
# Sound set-containment between predicates on the SAME field                   #
# --------------------------------------------------------------------------- #
def _predicate_implies(p: Predicate, q: Predicate) -> bool:
    """True iff match-set(p) ⊆ match-set(q) is PROVABLE (same field assumed).

    p/q are (field, modifier, value); modifier ∈ {"", contains, startswith,
    endswith}. Comparison is on the already-lowercased values (Sigma is
    case-insensitive by default). Returns False whenever containment is not
    provable — never over-claims."""
    _, pm, pv = p
    _, qm, qv = q
    if qm == "":                       # q is exact-equality: only exact-equal p ⊆ q
        return pm == "" and pv == qv
    if qm == "contains":               # any of eq/contains/startswith/endswith(pv)
        return qv in pv                # ⊆ contains(qv) iff qv is a substring of pv
    if qm == "startswith":             # only eq / startswith can force a prefix
        return pm in ("", "startswith") and pv.startswith(qv)
    if qm == "endswith":               # only eq / endswith can force a suffix
        return pm in ("", "endswith") and pv.endswith(qv)
    return False


def _subset_of(a_preds: List[Predicate], b_preds: List[Predicate]) -> bool:
    """True iff match-set(A) ⊆ match-set(B) is provable for two analyzable rules.

    Sufficient condition: for EVERY predicate of B, A has a same-field predicate
    that implies it. Then match-set(A) ⊆ each such B-predicate's set, hence ⊆ their
    intersection = match-set(B). A predicate of B on a field A never constrains
    breaks the subset (A allows that field to be anything) → correctly returns
    False."""
    for qb in b_preds:
        if not any(pa[0] == qb[0] and _predicate_implies(pa, qb) for pa in a_preds):
            return False
    return True


def _pred_label(p: Predicate) -> str:
    field, mod, val = p
    return f"{field}|{mod}={val}" if mod else f"{field}={val}"


# --------------------------------------------------------------------------- #
# Core analysis                                                               #
# --------------------------------------------------------------------------- #
def _analyze(rules: List[Any]) -> Dict[str, Any]:
    parsed_rules: List[Dict[str, Any]] = []
    ids: List[str] = []
    logsources: List[Tuple] = []
    preds: List[Optional[List[Predicate]]] = []
    not_analyzed: List[Dict[str, str]] = []

    for i, raw in enumerate(rules):
        p = _parse_rule(raw, i)
        rid = _rule_id(p, i)
        parsed_rules.append(p)
        ids.append(rid)
        logsources.append(_canonical_logsource(p))
        pr = _analyzable_predicates(p)
        preds.append(pr)
        if pr is None:
            not_analyzed.append({
                "rule": rid,
                "reason": "outside the provable shape (needs a single selection, a "
                          "plain-AND condition, and scalar contains/startswith/"
                          "endswith/equals predicates) — no subset claim made.",
            })

    duplicates: List[Dict[str, str]] = []
    subsumptions: List[Dict[str, str]] = []
    overlaps: List[Dict[str, Any]] = []

    n = len(rules)
    for i in range(n):
        for j in range(i + 1, n):
            # Different data stream → the rules never see the same events; no
            # relationship is asserted across logsources.
            if logsources[i] != logsources[j]:
                continue
            pi, pj = preds[i], preds[j]
            if pi is None or pj is None:
                continue  # at least one rule is not analyzable (already recorded)
            i_sub_j = _subset_of(pi, pj)
            j_sub_i = _subset_of(pj, pi)
            if i_sub_j and j_sub_i:
                # A duplicate is SYMMETRIC — canonicalize the pair by sorted id so
                # the report is identical regardless of input order (determinism).
                da, db = sorted((ids[i], ids[j]))
                duplicates.append({
                    "a": da, "b": db,
                    "reason": "identical match set (each rule's events are exactly "
                              "the other's) — keep one.",
                })
            elif i_sub_j:
                subsumptions.append({
                    "subset": ids[i], "superset": ids[j],
                    "reason": f"every event {ids[i]!r} catches is also caught by "
                              f"{ids[j]!r} (broader) — review whether {ids[i]!r} is "
                              f"redundant.",
                })
            elif j_sub_i:
                subsumptions.append({
                    "subset": ids[j], "superset": ids[i],
                    "reason": f"every event {ids[j]!r} catches is also caught by "
                              f"{ids[i]!r} (broader) — review whether {ids[j]!r} is "
                              f"redundant.",
                })
            else:
                shared = sorted(
                    _pred_label(p) for p in set(pi) & set(pj)
                )
                if shared:
                    # Overlap is SYMMETRIC — canonicalize the pair id order.
                    oa, ob = sorted((ids[i], ids[j]))
                    overlaps.append({"a": oa, "b": ob, "shared": shared})

    # Deterministic ordering of every output list.
    duplicates.sort(key=lambda d: (d["a"], d["b"]))
    subsumptions.sort(key=lambda d: (d["subset"], d["superset"]))
    overlaps.sort(key=lambda d: (d["a"], d["b"]))
    not_analyzed.sort(key=lambda d: d["rule"])

    summary = (
        f"{n} rule(s): {len(duplicates)} duplicate pair(s), "
        f"{len(subsumptions)} subsumption(s), {len(overlaps)} overlap(s), "
        f"{len(not_analyzed)} not analyzed."
    )
    return {
        "ok": True,
        "rule_count": n,
        "duplicates": duplicates,
        "subsumptions": subsumptions,
        "overlaps": overlaps,
        "not_analyzed": not_analyzed,
        "summary": summary,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Report provable overlap/redundancy across a set of Sigma rules.

    Pure, deterministic, offline. Never raises: a malformed request is a
    ``validation_error``. The tool is CONSERVATIVE — it only asserts a
    duplicate/subsumption when the set-containment is provable, and surfaces every
    rule it could not soundly analyze in ``not_analyzed`` (never a silent skip)."""
    try:
        rules = _validate(event)
    except _DedupError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    try:
        return _analyze(rules)
    except _DedupError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}


if __name__ == "__main__":
    import json

    broad = """
title: PowerShell Encoded Command
id: broad-001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""
    narrow = """
title: PowerShell Encoded Command (powershell.exe only)
id: narrow-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""
    print(json.dumps(handler({"rules": [broad, narrow]}, None), indent=2))
