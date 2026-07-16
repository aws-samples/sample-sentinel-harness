"""
Offline unit tests for the detection_coverage tool.
================================================================================
``tools/detection_coverage`` reports ATT&CK coverage / blind spots for a Sigma
rule set: covered / UNCOVERED target techniques, untagged rules, and invalid tags.

The load-bearing properties:
  * SOUNDNESS of coverage direction — a sub-technique tag (T1059.001) covers its
    PARENT (T1059), but a parent tag NEVER covers a specific sub-technique. A false
    "covered" would hide a real blind spot, so the conservative direction is pinned
    in both directions.
  * The UNCOVERED list is the point of the tool — it must surface every target with
    no detecting rule.
  * Determinism — same inputs, same ordered report regardless of input order.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_covundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dc = _load("detection_coverage")


def cover(rules, techniques=None) -> dict:
    ev = {"rules": rules}
    if techniques is not None:
        ev["techniques"] = techniques
    return dc.handler(ev, None)


def _rule(rid: str, tags=None, *, product="windows") -> str:
    tagblock = ""
    if tags:
        lines = "\n".join(f"        - {t}" for t in tags)
        tagblock = f"tags:\n{lines}\n"
    return (
        f"id: {rid}\ntitle: {rid}\n"
        f"logsource:\n    product: {product}\n"
        f"{tagblock}"
        f"detection:\n    selection:\n        CommandLine|contains: 'x'\n    condition: selection\n"
    )


# --------------------------------------------------------------------------- #
# covered / uncovered                                                         #
# --------------------------------------------------------------------------- #
def test_exact_tag_covers_target():
    out = cover([_rule("r1", ["attack.t1059"])], ["T1059"])
    assert out["covered"] == [{"technique": "T1059", "rules": ["r1"]}]
    assert out["uncovered"] == []
    assert out["coverage_ratio"] == 1.0


def test_uncovered_target_is_reported():
    out = cover([_rule("r1", ["attack.t1059"])], ["T1059", "T1190", "T1046"])
    assert out["uncovered"] == ["T1046", "T1190"]
    assert out["coverage_ratio"] == round(1 / 3, 4)


def test_multiple_rules_cover_one_technique():
    out = cover([_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1059"])], ["T1059"])
    assert out["covered"][0]["rules"] == ["r1", "r2"]


# --------------------------------------------------------------------------- #
# SOUND sub-technique direction                                               #
# --------------------------------------------------------------------------- #
def test_sub_technique_tag_covers_parent_target():
    """A rule tagged T1059.001 detects an instance of T1059 → covers the parent."""
    out = cover([_rule("r1", ["attack.t1059.001"])], ["T1059"])
    assert out["covered"] == [{"technique": "T1059", "rules": ["r1"]}]
    assert out["uncovered"] == []


def test_parent_tag_does_not_cover_sub_technique_target():
    """A rule tagged only with the PARENT T1059 must NOT claim the specific
    sub-technique T1059.001 is covered (conservative — no false 'covered')."""
    out = cover([_rule("r1", ["attack.t1059"])], ["T1059.001"])
    assert out["covered"] == []
    assert out["uncovered"] == ["T1059.001"]


def test_sub_tag_covers_exact_sub_target():
    out = cover([_rule("r1", ["attack.t1059.001"])], ["T1059.001"])
    assert out["covered"] == [{"technique": "T1059.001", "rules": ["r1"]}]


def test_sibling_sub_does_not_cover_other_sub():
    """T1059.001 must not cover a sibling T1059.003."""
    out = cover([_rule("r1", ["attack.t1059.001"])], ["T1059.003"])
    assert out["uncovered"] == ["T1059.003"]


# --------------------------------------------------------------------------- #
# tag validity / untagged                                                     #
# --------------------------------------------------------------------------- #
def test_case_insensitive_tag():
    out = cover([_rule("r1", ["attack.T1059.001"])], ["T1059.001"])
    assert out["covered"][0]["rules"] == ["r1"]


def test_tactic_and_group_tags_are_ignored_not_invalid():
    """attack.execution (tactic) / attack.g0016 (group) are legitimate, not
    technique tags → ignored, never flagged invalid."""
    out = cover([_rule("r1", ["attack.execution", "attack.g0016", "attack.t1059"])], ["T1059"])
    assert out["invalid_tags"] == []
    assert out["covered"][0]["rules"] == ["r1"]


def test_malformed_technique_tag_is_flagged_invalid():
    out = cover([_rule("r1", ["attack.t99999", "attack.tXYZ"])])
    flagged = {d["tag"] for d in out["invalid_tags"]}
    assert "attack.t99999" in flagged


def test_untagged_rule_is_surfaced():
    out = cover([_rule("r1", None)], ["T1059"])
    assert out["untagged_rules"] == ["r1"]
    assert out["uncovered"] == ["T1059"]


# --------------------------------------------------------------------------- #
# inventory mode (no target list)                                             #
# --------------------------------------------------------------------------- #
def test_inventory_mode_lists_all_tagged_techniques():
    out = cover([_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1190"])])
    assert out["target_count"] is None
    assert out["coverage_ratio"] is None
    assert out["uncovered"] == []
    techs = {c["technique"] for c in out["covered"]}
    assert techs == {"T1059", "T1190"}


# --------------------------------------------------------------------------- #
# determinism + shape + validation                                            #
# --------------------------------------------------------------------------- #
def test_output_is_deterministic_regardless_of_input_order():
    rules = [_rule("r3", ["attack.t1046"]), _rule("r1", ["attack.t1059"]),
             _rule("r2", None)]
    targets = ["T1190", "T1059", "T1046"]
    r1 = cover(rules, targets)
    r2 = cover(list(reversed(rules)), list(reversed(targets)))
    for key in ("covered", "uncovered", "untagged_rules", "invalid_tags"):
        assert r1[key] == r2[key], key


def test_duplicate_target_deduped():
    out = cover([_rule("r1", ["attack.t1059"])], ["T1059", "T1059"])
    assert out["target_count"] == 1
    assert out["coverage_ratio"] == 1.0


def test_parsed_dict_rules_accepted():
    r = {"id": "r1", "logsource": {"product": "windows"}, "tags": ["attack.t1059"],
         "detection": {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}}
    assert cover([r], ["T1059"])["covered"][0]["rules"] == ["r1"]


def test_empty_rules_is_validation_error():
    r = dc.handler({"rules": []}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_invalid_target_technique_is_validation_error():
    r = dc.handler({"rules": [_rule("r1", ["attack.t1059"])], "techniques": ["not-a-tech"]}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_list_techniques_is_validation_error():
    r = dc.handler({"rules": [_rule("r1", ["attack.t1059"])], "techniques": "T1059"}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_summary_flags_uncovered_count():
    out = cover([_rule("r1", ["attack.t1059"])], ["T1059", "T1190"])
    assert "1 UNCOVERED" in out["summary"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
