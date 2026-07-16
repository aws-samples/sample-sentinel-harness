"""detection_navigator — render Sigma coverage as an ATT&CK Navigator layer JSON.

SecOps purpose
--------------
``detection_coverage`` answers "which ATT&CK techniques can we NOT detect?" as
structured data. A SOC lead wants that as a PICTURE: the MITRE ATT&CK Navigator
(mitre-attack.github.io/attack-navigator) renders a technique heat-map from a
standard "layer" JSON. This tool turns the coverage analysis into exactly that
layer file — drag-drop it into Navigator and the matrix lights up green where a
rule exists and red where there is a blind spot.

It is a THIN, faithful renderer over ``detection_coverage``: it adds no coverage
judgement of its own (same conservative sub-technique semantics — a sub-tag covers
its parent, a parent tag never covers a specific sub-technique), it only maps that
result into the Navigator schema. Covered → score 100 (green); uncovered → score 0
(red); each technique row carries a ``comment`` naming the detecting rule(s) or
flagging the gap.

Provable core
-------------
DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same inputs → byte-for
-byte-stable layer JSON (techniques sorted by id). Reuses ``detection_coverage`` by
path (``tools/`` is a scripts tree), which reuses the shared Sigma parser.

Layer schema
------------
Emits ATT&CK Navigator layer format **v4.5** (``versions.layer`` = "4.5",
``versions.navigator`` = "4.9.1"): a top-level object with ``name``, ``domain``
("enterprise-attack"), ``description``, a ``gradient``, and a ``techniques`` list
of ``{techniqueID, score, color, comment, enabled}`` entries. This is the exact
shape the Navigator import accepts.

Input contract
--------------
event = {
    "rules": [<sigma yaml string OR parsed dict>, ...],   # required, non-empty
    "techniques": ["T1059", "T1190.001", ...],            # optional target list
    "name": "SentinelHarness Coverage",                   # optional layer name
}
If ``techniques`` is omitted, the layer covers exactly the techniques the rule set
tags (inventory mode) — every emitted row is then a covered (green) technique.

Output contract (on success)
----------------------------
{
  "ok": True,
  "layer": {<ATT&CK Navigator layer v4.5 object>},
  "covered_count": int,
  "uncovered_count": int,
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
from typing import Any, Dict, List, Optional

_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Navigator layer schema + palette constants.
_LAYER_VERSION = "4.5"
_NAVIGATOR_VERSION = "4.9.1"
_ATTACK_VERSION = "14"
_DOMAIN = "enterprise-attack"
_COLOR_COVERED = "#1a9850"     # green
_COLOR_UNCOVERED = "#d73027"   # red
_SCORE_COVERED = 100
_SCORE_UNCOVERED = 0


class _NavigatorError(ValueError):
    """Malformed request (bad input shape)."""


def _load_coverage():
    path = os.path.join(_TOOLS_DIR, "detection_coverage", "handler.py")
    spec = importlib.util.spec_from_file_location("_coverage_for_navigator", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _validate(event: Dict[str, Any]):
    if not isinstance(event, dict):
        raise _NavigatorError("event must be a dict")
    rules = event.get("rules")
    if rules is None and "rule" in event:
        rules = [event["rule"]]
    if not isinstance(rules, list) or not rules:
        raise _NavigatorError("missing required non-empty list field 'rules'")
    techniques = event.get("techniques")
    if techniques is not None and not isinstance(techniques, list):
        raise _NavigatorError("'techniques' must be a list of technique ids")
    name = event.get("name", "SentinelHarness Coverage")
    if not isinstance(name, str) or not name.strip():
        raise _NavigatorError("'name' must be a non-empty string")
    return rules, techniques, name.strip()


def _technique_row(technique_id: str, *, covered: bool, comment: str) -> Dict[str, Any]:
    """Build one Navigator ``techniques`` entry. The color is set explicitly (not
    left to the gradient) so a layer viewed without recomputing scores still shows
    the covered/uncovered split."""
    return {
        "techniqueID": technique_id,
        "score": _SCORE_COVERED if covered else _SCORE_UNCOVERED,
        "color": _COLOR_COVERED if covered else _COLOR_UNCOVERED,
        "comment": comment,
        "enabled": True,
    }


def _build_layer(name: str, covered: List[Dict[str, Any]], uncovered: List[str]) -> Dict[str, Any]:
    """Assemble the ATT&CK Navigator layer v4.5 object. ``techniques`` is sorted by
    id for byte-stable output."""
    rows: List[Dict[str, Any]] = []
    for c in covered:
        rule_list = ", ".join(c.get("rules", []))
        rows.append(_technique_row(
            c["technique"], covered=True,
            comment=f"covered by: {rule_list}" if rule_list else "covered",
        ))
    for tid in uncovered:
        rows.append(_technique_row(
            tid, covered=False, comment="NO detecting rule — blind spot",
        ))
    rows.sort(key=lambda r: r["techniqueID"])

    total = len(covered) + len(uncovered)
    pct = round(100 * len(covered) / total, 1) if total else 0.0
    return {
        "name": name,
        "versions": {
            "attack": _ATTACK_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer": _LAYER_VERSION,
        },
        "domain": _DOMAIN,
        "description": (
            f"sentinel-harness detection coverage: {len(covered)}/{total} technique(s) "
            f"covered ({pct}%), {len(uncovered)} blind spot(s). Deterministic export."
        ),
        "gradient": {
            "colors": [_COLOR_UNCOVERED, _COLOR_COVERED],
            "minValue": _SCORE_UNCOVERED,
            "maxValue": _SCORE_COVERED,
        },
        "legendItems": [
            {"label": "covered (>=1 rule)", "color": _COLOR_COVERED},
            {"label": "uncovered (blind spot)", "color": _COLOR_UNCOVERED},
        ],
        "sorting": 0,
        "hideDisabled": False,
        "techniques": rows,
    }


def _analyze(rules: List[Any], techniques: Optional[List[str]], name: str) -> Dict[str, Any]:
    coverage = _load_coverage()
    cov_event: Dict[str, Any] = {"rules": rules}
    if techniques is not None:
        cov_event["techniques"] = techniques
    cov = coverage.handler(cov_event, None)
    if not cov.get("ok"):
        # Surface the sub-tool's own validation reason (bad rule shape, etc.).
        raise _NavigatorError(f"coverage sub-tool rejected input: {cov.get('message')}")

    covered = cov["covered"]
    uncovered = cov["uncovered"]
    layer = _build_layer(name, covered, uncovered)
    return {
        "ok": True,
        "layer": layer,
        "covered_count": len(covered),
        "uncovered_count": len(uncovered),
        "summary": (
            f"{len(layer['techniques'])} technique(s) in layer: "
            f"{len(covered)} covered (green), {len(uncovered)} uncovered (red)."
        ),
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Render a Sigma rule set's ATT&CK coverage as a Navigator layer JSON. Pure,
    deterministic, offline. Never raises: a malformed request is a
    ``validation_error``. A thin faithful renderer over ``detection_coverage`` — it
    inherits that tool's conservative coverage semantics and adds no new judgement."""
    try:
        rules, techniques, name = _validate(event)
    except _NavigatorError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    try:
        return _analyze(rules, techniques, name)
    except _NavigatorError as exc:
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
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""
    out = handler({"rules": [ps], "techniques": ["T1059", "T1046", "T1190"],
                   "name": "Demo Coverage"}, None)
    print(json.dumps(out, indent=2))
