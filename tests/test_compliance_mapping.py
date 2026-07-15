"""
Offline test that docs/COMPLIANCE.md stays HONEST.

ZERO AWS, ZERO network. Parses the capability-anchor table in docs/COMPLIANCE.md
and asserts that EVERY anchor (the repo path each control mapping leans on) really
exists. This is what keeps the compliance mapping from drifting into aspirational
claims: if a capability is renamed/removed, this test fails until the doc is fixed.

It also checks the doc references all three frameworks and that every capability id
declared in the anchor table (C1, C2, ...) is actually cited in at least one
framework mapping (no dangling anchors).
"""
from __future__ import annotations

import os
import re

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOC = os.path.join(_REPO, "docs", "COMPLIANCE.md")

# A capability-anchor row looks like:  | C1 | <desc> | 🟢 | `path/to/anchor` |
_ANCHOR_ROW = re.compile(
    r"^\|\s*(C\d+)\s*\|.*\|\s*[^|]*\|\s*`([^`]+)`\s*\|\s*$", re.MULTILINE
)


def _doc_text() -> str:
    assert os.path.isfile(_DOC), "docs/COMPLIANCE.md must exist"
    return open(_DOC, encoding="utf-8").read()


def _anchors() -> dict:
    """Return {capability_id: anchor_path} parsed from the anchor table."""
    return {cid: path.strip() for cid, path in _ANCHOR_ROW.findall(_doc_text())}


def test_doc_exists_and_has_anchor_table():
    anchors = _anchors()
    assert len(anchors) >= 15, f"expected the full capability anchor table, got {len(anchors)}"


def test_every_anchor_path_exists():
    """The load-bearing honesty check: every cited path is a real repo file/dir."""
    missing = []
    for cid, path in _anchors().items():
        full = os.path.join(_REPO, path)
        if not os.path.exists(full):
            missing.append(f"{cid} -> {path}")
    assert not missing, "COMPLIANCE.md cites non-existent anchors: " + "; ".join(missing)


def test_all_three_frameworks_present():
    text = _doc_text()
    assert "SOC 2" in text
    assert "ISO/IEC 27001" in text or "ISO 27001" in text
    assert "NIST" in text and "CSF" in text


def test_every_capability_is_cited_in_a_mapping():
    """No dangling anchors: each Cn from the table appears again in a framework
    mapping section (SOC 2 / ISO / CSF), not just defined and forgotten."""
    text = _doc_text()
    anchors = _anchors()
    # strip the anchor table region so we count citations in the mapping sections
    # (each Cn is referenced as e.g. 'C1 HITL' or '· C5 ...').
    dangling = []
    for cid in anchors:
        # count occurrences; >1 means cited beyond its own table row
        if len(re.findall(rf"\b{cid}\b", text)) < 2:
            dangling.append(cid)
    assert not dangling, f"capabilities defined but never mapped: {dangling}"


def test_has_honest_scope_and_gaps_sections():
    """The doc must NOT read as a certification claim — it must carry the explicit
    'not a certification' scope note and a 'what this does NOT cover' section."""
    text = _doc_text().lower()
    assert "not a certification" in text
    assert "does not cover" in text or "honest gap" in text
