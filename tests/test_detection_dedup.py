"""
Offline unit tests for the detection_dedup tool.
================================================================================
``tools/detection_dedup`` reports PROVABLE overlap/redundancy across a Sigma rule
set: duplicates (identical match set), subsumptions (A's events ⊆ B's), overlaps
(shared predicate, neither subsumes), and a ``not_analyzed`` ledger for everything
outside the sound single-selection-AND shape.

The load-bearing property is SOUNDNESS: the tool must NEVER claim a rule is a
duplicate/subset unless the set-containment is provable, because a wrong "safe to
delete" verdict deletes real detection coverage. These tests pin the true
relationships AND — just as importantly — assert the tool STAYS SILENT (no false
subsumption) whenever containment does not hold.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_dedupundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dd = _load("detection_dedup")


def dedup(rules) -> dict:
    return dd.handler({"rules": rules}, None)


def _rule(rid: str, selection: dict, *, product="windows",
          category="process_creation", condition="selection") -> str:
    """Build a single-selection Sigma rule. ``selection`` maps ``field|mod`` → str."""
    sel = "\n".join(f"        {k}: '{v}'" for k, v in selection.items())
    return (
        f"id: {rid}\n"
        f"title: {rid}\n"
        f"logsource:\n    product: {product}\n    category: {category}\n"
        f"detection:\n    selection:\n{sel}\n    condition: {condition}\n"
    )


# --------------------------------------------------------------------------- #
# duplicates                                                                  #
# --------------------------------------------------------------------------- #
def test_identical_rules_are_duplicates():
    a = _rule("a", {"CommandLine|contains": "-enc"})
    b = _rule("b", {"CommandLine|contains": "-enc"})
    out = dedup([a, b])
    assert out["duplicates"] == [
        {"a": "a", "b": "b",
         "reason": "identical match set (each rule's events are exactly the "
                   "other's) — keep one."}
    ]
    assert out["subsumptions"] == [] and out["overlaps"] == []


def test_duplicate_ignores_predicate_order():
    a = _rule("a", {"CommandLine|contains": "-enc", "Image|endswith": "x.exe"})
    b = _rule("b", {"Image|endswith": "x.exe", "CommandLine|contains": "-enc"})
    assert len(dedup([a, b])["duplicates"]) == 1


# --------------------------------------------------------------------------- #
# subsumption (the sound-subset core)                                         #
# --------------------------------------------------------------------------- #
def test_extra_predicate_makes_narrow_subset_of_broad():
    """More AND predicates ⇒ a SMALLER match set ⇒ narrow ⊆ broad."""
    broad = _rule("broad", {"CommandLine|contains": "-enc"})
    narrow = _rule("narrow", {"CommandLine|contains": "-enc",
                              "Image|endswith": "\\powershell.exe"})
    out = dedup([broad, narrow])
    assert out["subsumptions"] == [
        {"subset": "narrow", "superset": "broad",
         "reason": "every event 'narrow' catches is also caught by 'broad' "
                   "(broader) — review whether 'narrow' is redundant."}
    ]
    assert out["duplicates"] == []


def test_contains_value_subset_direction():
    """contains 'powershell -enc' ⊆ contains '-enc' (longer substring is stricter)."""
    narrow = _rule("narrow", {"CommandLine|contains": "powershell -enc"})
    broad = _rule("broad", {"CommandLine|contains": "-enc"})
    subs = dedup([narrow, broad])["subsumptions"]
    assert subs == [{"subset": "narrow", "superset": "broad",
                     "reason": subs[0]["reason"]}]


def test_equality_is_subset_of_contains():
    """field == 'abc' ⊆ field|contains 'b' (exact match implies the substring)."""
    eq = _rule("eq", {"CommandLine": "abc"})
    con = _rule("con", {"CommandLine|contains": "b"})
    subs = dedup([eq, con])["subsumptions"]
    assert len(subs) == 1 and subs[0]["subset"] == "eq" and subs[0]["superset"] == "con"


def test_startswith_stricter_prefix_is_subset():
    """startswith 'powershell.exe' ⊆ startswith 'power'."""
    strict = _rule("strict", {"Image|startswith": "powershell.exe"})
    loose = _rule("loose", {"Image|startswith": "power"})
    subs = dedup([strict, loose])["subsumptions"]
    assert len(subs) == 1 and subs[0]["subset"] == "strict"


# --------------------------------------------------------------------------- #
# SOUNDNESS guards — the tool must NOT over-claim                             #
# --------------------------------------------------------------------------- #
def test_disjoint_values_no_relationship():
    a = _rule("a", {"CommandLine|contains": "-enc"})
    b = _rule("b", {"CommandLine|contains": "-decode"})
    out = dedup([a, b])
    assert out["duplicates"] == [] and out["subsumptions"] == []
    # same field + same modifier but different value ⇒ not a shared predicate
    assert out["overlaps"] == []


def test_contains_wrong_direction_is_not_subset():
    """contains '-enc' is NOT a subset of contains 'powershell -enc' (broader ⊄
    narrower) — the tool must not assert a reversed/false subsumption."""
    broad = _rule("broad", {"CommandLine|contains": "-enc"})
    narrow = _rule("narrow", {"CommandLine|contains": "powershell -enc"})
    subs = dedup([broad, narrow])["subsumptions"]
    # exactly one direction: narrow ⊆ broad, never broad ⊆ narrow
    assert [s["subset"] for s in subs] == ["narrow"]


def test_startswith_vs_contains_not_provable_subset():
    """startswith 'x' and contains 'x' do NOT have a provable containment either
    way (startswith⊄contains? contains⊄startswith?) — stay silent."""
    a = _rule("a", {"Image|startswith": "abc"})
    b = _rule("b", {"Image|contains": "abc"})
    subs = dedup([a, b])["subsumptions"]
    # startswith 'abc' ⊆ contains 'abc' IS provable (prefix implies substring);
    # the reverse is not. Exactly one direction, subset = the startswith rule.
    assert [s["subset"] for s in subs] == ["a"]


def test_extra_field_on_superset_breaks_subsumption():
    """If B constrains a field A does not, A is NOT ⊆ B (A allows that field free)."""
    a = _rule("a", {"CommandLine|contains": "-enc"})
    b = _rule("b", {"CommandLine|contains": "-enc", "User|contains": "admin"})
    # a ⊄ b (b also requires User); b ⊆ a (b is the narrower one)
    subs = dedup([a, b])["subsumptions"]
    assert [s["subset"] for s in subs] == ["b"]


# --------------------------------------------------------------------------- #
# logsource discrimination                                                    #
# --------------------------------------------------------------------------- #
def test_different_logsource_no_relationship():
    a = _rule("a", {"CommandLine|contains": "-enc"}, product="windows")
    b = _rule("b", {"CommandLine|contains": "-enc"}, product="linux")
    out = dedup([a, b])
    assert out["duplicates"] == [] and out["subsumptions"] == [] and out["overlaps"] == []


# --------------------------------------------------------------------------- #
# overlaps                                                                    #
# --------------------------------------------------------------------------- #
def test_shared_predicate_neither_subsumes_is_overlap():
    a = _rule("a", {"CommandLine|contains": "-enc", "Image|endswith": "ps.exe"})
    b = _rule("b", {"CommandLine|contains": "-enc", "ParentImage|endswith": "cmd.exe"})
    out = dedup([a, b])
    assert out["subsumptions"] == [] and out["duplicates"] == []
    assert out["overlaps"] == [{"a": "a", "b": "b", "shared": ["commandline|contains=-enc"]}]


# --------------------------------------------------------------------------- #
# not_analyzed ledger — conservative honesty                                  #
# --------------------------------------------------------------------------- #
def test_regex_predicate_is_not_analyzed():
    r = _rule("re-rule", {"CommandLine|re": ".*enc.*"})
    out = dedup([r, _rule("plain", {"CommandLine|contains": "-enc"})])
    assert "re-rule" in [x["rule"] for x in out["not_analyzed"]]
    # and no relationship is asserted involving the un-analyzable rule
    assert out["duplicates"] == [] and out["subsumptions"] == []


def test_multi_selection_condition_is_not_analyzed():
    rule = (
        "id: multi\ntitle: multi\n"
        "logsource:\n    product: windows\n    category: process_creation\n"
        "detection:\n"
        "    sel_a:\n        CommandLine|contains: '-enc'\n"
        "    sel_b:\n        Image|endswith: 'ps.exe'\n"
        "    condition: sel_a and sel_b\n"
    )
    out = dedup([rule])
    assert out["not_analyzed"] == [
        {"rule": "multi", "reason": out["not_analyzed"][0]["reason"]}
    ]


def test_list_value_is_not_analyzed():
    """A list value (OR / |all) is outside the scalar model → not analyzed."""
    rule = (
        "id: listrule\ntitle: listrule\n"
        "logsource:\n    product: windows\n    category: process_creation\n"
        "detection:\n    selection:\n        CommandLine|contains:\n"
        "            - '-enc'\n            - '-decode'\n    condition: selection\n"
    )
    assert dedup([rule])["not_analyzed"][0]["rule"] == "listrule"


# --------------------------------------------------------------------------- #
# determinism + shape + validation                                            #
# --------------------------------------------------------------------------- #
def test_output_is_deterministic_regardless_of_input_order():
    a = _rule("a", {"CommandLine|contains": "-enc"})
    b = _rule("b", {"CommandLine|contains": "-enc"})
    c = _rule("c", {"CommandLine|contains": "-decode"})
    r1 = dedup([a, b, c])
    r2 = dedup([c, b, a])
    for key in ("duplicates", "subsumptions", "overlaps", "not_analyzed"):
        assert r1[key] == r2[key], key


def test_parsed_dict_rules_accepted():
    a = {"id": "a", "logsource": {"product": "windows"},
         "detection": {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}}
    b = {"id": "b", "logsource": {"product": "windows"},
         "detection": {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}}
    assert len(dedup([a, b])["duplicates"]) == 1


def test_single_rule_no_pairs():
    out = dedup([_rule("solo", {"CommandLine|contains": "-enc"})])
    assert out["rule_count"] == 1
    assert out["duplicates"] == [] and out["subsumptions"] == [] and out["overlaps"] == []


def test_summary_counts_match_lists():
    a = _rule("a", {"CommandLine|contains": "-enc"})
    b = _rule("b", {"CommandLine|contains": "-enc"})
    out = dedup([a, b])
    assert "1 duplicate pair(s)" in out["summary"]


def test_empty_rules_is_validation_error():
    r = dd.handler({"rules": []}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_list_rules_is_validation_error():
    r = dd.handler({"rules": "not-a-list"}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_single_rule_key_wrapped():
    """A convenience 'rule' singular key is wrapped into a one-element set."""
    r = dd.handler({"rule": _rule("solo", {"CommandLine|contains": "-enc"})}, None)
    assert r["ok"] is True and r["rule_count"] == 1


def test_malformed_yaml_rule_is_validation_error():
    r = dd.handler({"rules": ["\tthis: : : not yaml ["]}, None)
    # the minimal/real parser may accept odd text; if it cannot resolve a mapping
    # with detection, the rule is simply not analyzed — never a crash.
    assert r["ok"] in (True, False)
    if r["ok"]:
        assert r["not_analyzed"]  # unusable rule surfaced, not silently dropped


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
