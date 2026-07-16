"""
Offline unit tests for the detection_navigator tool.
================================================================================
``tools/detection_navigator`` renders detection_coverage output into a standard
MITRE ATT&CK Navigator layer JSON (v4.5).

Properties pinned here:
  * SCHEMA VALIDITY — the emitted layer carries every field the Navigator import
    expects (name/versions.layer/domain/gradient/techniques[]), and each technique
    row has techniqueID/score/color/comment/enabled.
  * FIDELITY — covered techniques map to green/score-100, uncovered to red/score-0,
    exactly mirroring what detection_coverage reports (the renderer adds no new
    judgement, incl. the conservative sub-technique direction).
  * DETERMINISM — same inputs → identical layer (techniques sorted by id).

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_navundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nav = _load("detection_navigator")
cov = _load("detection_coverage")


def navigate(rules, techniques=None, name=None) -> dict:
    ev = {"rules": rules}
    if techniques is not None:
        ev["techniques"] = techniques
    if name is not None:
        ev["name"] = name
    return nav.handler(ev, None)


def _rule(rid, tags=None, value="-enc", *, product="windows",
          category="process_creation") -> str:
    tagblock = ""
    if tags:
        tagblock = "tags:\n" + "".join(f"    - {t}\n" for t in tags)
    return (
        f"title: {rid}\nid: {rid}\n"
        f"logsource:\n    product: {product}\n    category: {category}\n"
        f"{tagblock}"
        f"detection:\n    selection:\n        CommandLine|contains: '{value}'\n"
        f"    condition: selection\n"
    )


def _rows_by_id(out):
    return {r["techniqueID"]: r for r in out["layer"]["techniques"]}


# --------------------------------------------------------------------------- #
# schema validity                                                             #
# --------------------------------------------------------------------------- #
def test_layer_has_required_navigator_fields():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059", "T1190"])
    layer = out["layer"]
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert "gradient" in layer and "techniques" in layer
    assert isinstance(layer["name"], str) and layer["name"]


def test_technique_rows_have_required_fields():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059", "T1190"])
    for row in out["layer"]["techniques"]:
        assert set(row) >= {"techniqueID", "score", "color", "comment", "enabled"}


def test_layer_is_json_serializable():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059"])
    json.loads(json.dumps(out["layer"]))  # round-trips as strict JSON


def test_custom_layer_name_used():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059"], name="Q3 Coverage")
    assert out["layer"]["name"] == "Q3 Coverage"


# --------------------------------------------------------------------------- #
# fidelity to detection_coverage                                              #
# --------------------------------------------------------------------------- #
def test_covered_green_uncovered_red():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059", "T1190", "T1046"])
    rows = _rows_by_id(out)
    assert rows["T1059"]["score"] == 100 and rows["T1059"]["color"] == "#1a9850"
    assert "r1" in rows["T1059"]["comment"]
    for gap in ("T1190", "T1046"):
        assert rows[gap]["score"] == 0 and rows[gap]["color"] == "#d73027"
        assert "blind spot" in rows[gap]["comment"]
    assert out["covered_count"] == 1 and out["uncovered_count"] == 2


def test_matches_coverage_tool_result():
    rules = [_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1190"], value="-x")]
    techniques = ["T1059", "T1190", "T1499"]
    out = navigate(rules, techniques)
    cov_res = cov.handler({"rules": rules, "techniques": techniques}, None)
    covered_ids = {c["technique"] for c in cov_res["covered"]}
    green = {r["techniqueID"] for r in out["layer"]["techniques"] if r["score"] == 100}
    red = {r["techniqueID"] for r in out["layer"]["techniques"] if r["score"] == 0}
    assert green == covered_ids
    assert red == set(cov_res["uncovered"])


def test_sub_technique_tag_covers_parent_row():
    """A rule tagged T1059.001 makes the target parent T1059 green (mirrors the
    coverage tool's conservative sub->parent direction)."""
    out = navigate([_rule("r1", ["attack.t1059.001"])], ["T1059"])
    assert _rows_by_id(out)["T1059"]["score"] == 100


def test_parent_tag_does_not_cover_sub_row():
    out = navigate([_rule("r1", ["attack.t1059"])], ["T1059.001"])
    assert _rows_by_id(out)["T1059.001"]["score"] == 0


def test_inventory_mode_all_green():
    """With no target list, the layer covers exactly the tagged techniques (all green)."""
    out = navigate([_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1190"], value="-x")])
    rows = _rows_by_id(out)
    assert set(rows) == {"T1059", "T1190"}
    assert all(r["score"] == 100 for r in rows.values())
    assert out["uncovered_count"] == 0


# --------------------------------------------------------------------------- #
# determinism + validation                                                    #
# --------------------------------------------------------------------------- #
def test_techniques_sorted_and_deterministic():
    rules = [_rule("r1", ["attack.t1059"])]
    techniques = ["T1190", "T1046", "T1059"]
    a = navigate(rules, techniques)
    b = navigate(list(rules), list(reversed(techniques)))
    ids = [r["techniqueID"] for r in a["layer"]["techniques"]]
    assert ids == sorted(ids)
    assert a["layer"]["techniques"] == b["layer"]["techniques"]


def test_empty_rules_is_validation_error():
    r = nav.handler({"rules": []}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_invalid_target_technique_is_validation_error():
    r = nav.handler({"rules": [_rule("r1", ["attack.t1059"])], "techniques": ["nope"]}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_empty_name_is_validation_error():
    r = nav.handler({"rules": [_rule("r1", ["attack.t1059"])], "name": "  "}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_single_rule_key_wrapped():
    r = nav.handler({"rule": _rule("solo", ["attack.t1059"]), "techniques": ["T1059"]}, None)
    assert r["ok"] is True and r["covered_count"] == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
