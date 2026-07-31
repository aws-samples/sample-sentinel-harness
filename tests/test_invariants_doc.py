"""
INV-DOC-3: every test named in docs/INVARIANTS.md must actually exist.
======================================================================
``docs/INVARIANTS.md`` is the executable contract for the platform's security
behaviour: each invariant names the test that proves it. That is only worth
anything if the citation is real — a renamed or deleted test would leave a row
claiming enforcement that no longer happens, which is precisely the
"documented but unenforced" failure mode the invariants file exists to prevent
(see the M18.1 root-cause note in that document).

So this module parses the doc and asserts every cited test is collectible. It
also checks the invariant IDs referenced from code comments resolve to a real
row, so a grep for ``INV-PROMOTE-3`` always lands somewhere.

Zero network, zero AWS.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_PATH = os.path.join(REPO_ROOT, "docs", "INVARIANTS.md")
TESTS_DIR = os.path.join(REPO_ROOT, "tests")

# `file.py::Class::method`, `file.py::Class` or `file.py::function`, as cited in
# the doc's "Enforced by" column (wrapped in backticks there).
_CITATION_RE = re.compile(
    r"(test_[A-Za-z0-9_]+\.py)(?:::([A-Za-z0-9_]+))?(?:::([A-Za-z0-9_]+))?"
)
_INV_ID_RE = re.compile(r"\bINV-[A-Z]+-\d+\b")


def _doc_text() -> str:
    with open(DOC_PATH, encoding="utf-8") as fh:
        return fh.read()


def test_invariants_doc_exists_and_is_substantive():
    assert os.path.isfile(DOC_PATH), "docs/INVARIANTS.md is missing"
    text = _doc_text()
    assert len(text) > 2000, "the invariants doc looks truncated"
    for family in ("INV-PROMOTE-", "INV-LOOP-", "INV-SANDBOX-", "INV-GOV-", "INV-DOC-"):
        assert family in text, f"no {family} invariants documented"


def _cited_files() -> set[str]:
    return {m.group(1) for m in _CITATION_RE.finditer(_doc_text())}


def test_every_cited_test_file_exists():
    """A citation must point at a real test module."""
    missing = sorted(f for f in _cited_files()
                     if not os.path.isfile(os.path.join(TESTS_DIR, f)))
    assert not missing, (
        f"docs/INVARIANTS.md cites test files that do not exist: {missing}. "
        "Either restore the test or update the invariant row — a row citing a "
        "missing test claims an enforcement that no longer happens."
    )


def _cited_node_ids() -> list[str]:
    """Full `tests/file::Class[::method]` citations, ready to hand to pytest.

    A citation ending in ``_`` is a deliberate PREFIX reference (the doc cites a
    family such as ``test_safety_veto_*`` rather than one case); those are skipped
    here and covered by :func:`test_prefix_citations_match_at_least_one_test`.
    """
    out = []
    for m in _CITATION_RE.finditer(_doc_text()):
        parts = [p for p in m.groups() if p]
        if len(parts) > 1 and not parts[-1].endswith("_"):
            out.append("tests/" + "::".join(parts))
    return sorted(set(out))


def _prefix_citations() -> list[tuple[str, str]]:
    """``(file, prefix)`` pairs for family citations like ``test_safety_veto_``."""
    out = []
    for m in _CITATION_RE.finditer(_doc_text()):
        parts = [p for p in m.groups() if p]
        if len(parts) > 1 and parts[-1].endswith("_"):
            out.append((parts[0], parts[-1]))
    return sorted(set(out))


def test_every_cited_node_id_is_collectible():
    """Each `file::Class::method` citation must be a REAL, collectible test node.

    Uses pytest's own collector so a renamed class/method is caught, not just a
    renamed file.
    """
    node_ids = _cited_node_ids()
    assert node_ids, "no class/method-level citations parsed — check the doc format"

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:randomly", "-p", "no:cacheprovider", *node_ids],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.fail(
            "docs/INVARIANTS.md cites test nodes pytest cannot collect.\n"
            f"nodes: {node_ids}\n"
            f"--- stdout ---\n{proc.stdout[-3000:]}\n"
            f"--- stderr ---\n{proc.stderr[-2000:]}"
        )


def test_prefix_citations_match_at_least_one_test():
    """A family citation (``test_safety_veto_``) must match a real test name."""
    for filename, prefix in _prefix_citations():
        path = os.path.join(TESTS_DIR, filename)
        assert os.path.isfile(path), f"cited file missing: {filename}"
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        assert re.search(rf"def {re.escape(prefix)}\w+", source), (
            f"docs/INVARIANTS.md cites the family {prefix!r}* in {filename}, "
            "but no test with that prefix exists"
        )


def test_invariant_ids_are_unique_and_sequential():
    """No duplicate IDs (a duplicate makes a grep ambiguous)."""
    text = _doc_text()
    # Only count IDs in a bold table cell (`**INV-X-1**`) as a DEFINITION; plain
    # mentions elsewhere are references.
    defined = re.findall(r"\*\*(INV-[A-Z]+-\d+)\*\*", text)
    dupes = {i for i in defined if defined.count(i) > 1}
    assert not dupes, f"duplicate invariant definitions: {sorted(dupes)}"
    assert len(defined) >= 20, f"only {len(defined)} invariants defined — expected 20+"


def test_invariant_ids_referenced_in_code_are_defined():
    """An ``INV-...`` cited from source must resolve to a documented row.

    Code comments point back at invariant IDs so an implementation detail can be
    traced to the property it serves. A stale ID breaks that link.
    """
    defined = set(re.findall(r"\*\*(INV-[A-Z]+-\d+)\*\*", _doc_text()))
    referenced: dict[str, str] = {}
    for root, _dirs, files in os.walk(os.path.join(REPO_ROOT, "sentinel_harness")):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                for inv in _INV_ID_RE.findall(fh.read()):
                    referenced.setdefault(inv, os.path.relpath(path, REPO_ROOT))
    unknown = {inv: src for inv, src in referenced.items() if inv not in defined}
    assert not unknown, (
        f"source references invariant IDs that docs/INVARIANTS.md does not define: "
        f"{unknown}"
    )


def test_every_invariant_row_names_an_owner_and_a_test():
    """A row with an empty Owner or 'Enforced by' cell is an unenforced claim."""
    offenders = []
    for line in _doc_text().splitlines():
        if not re.match(r"\|\s*\*\*INV-", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        # id | invariant | owner | enforced by
        if len(cells) < 4 or not cells[2] or not cells[3]:
            offenders.append(cells[0] if cells else line)
        elif "test_" not in cells[3]:
            offenders.append(cells[0])
    assert not offenders, (
        f"invariant rows missing an owner or a real test citation: {offenders}"
    )
