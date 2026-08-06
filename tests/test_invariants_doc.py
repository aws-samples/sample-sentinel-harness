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
    # Repository-scoped: some cited nodes live in modules that skip at COLLECTION time
    # outside a git checkout (the CI-config guards — see tests/repo_infra.py), and pytest
    # cannot collect a node inside a skipped module. Verifying citations is a maintainer's
    # job on the repo, not a downstream packager's on an sdist.
    from repo_infra import require_git_checkout
    require_git_checkout("test_every_cited_node_id_is_collectible")

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


def _defined_invariant_ids() -> list[str]:
    """Every invariant ID DEFINED by a table row, in document order.

    A definition is the bold ID in the FIRST cell of a table row — i.e. a line
    starting with ``| **INV-...**``. The previous regex scanned the whole document
    for ``**INV-X-1**`` anywhere, so bolding an ID in explanatory prose registered a
    second "definition" and tripped the duplicate check. The docstring already said
    "only count IDs in a bold table CELL"; the code did not implement that — the
    exact claim-without-a-mechanism gap round 16 audits, here in the guard itself.
    """
    return re.findall(r"^\|\s*\*\*(INV-[A-Z]+-\d+)\*\*", _doc_text(), re.MULTILINE)


def test_invariant_ids_are_unique_and_sequential():
    """No duplicate IDs (a duplicate makes a grep ambiguous)."""
    defined = _defined_invariant_ids()
    dupes = {i for i in defined if defined.count(i) > 1}
    assert not dupes, f"duplicate invariant definitions: {sorted(dupes)}"
    assert len(defined) >= 20, f"only {len(defined)} invariants defined — expected 20+"


def test_prose_may_reference_an_invariant_without_redefining_it():
    """Regression for the guard above: discussing `**INV-X-1**` in prose is normal
    (the file explains several invariants at length) and must not read as a second
    definition."""
    text = _doc_text()
    # There IS at least one bold prose mention — otherwise this test is vacuous.
    all_bold = re.findall(r"\*\*(INV-[A-Z]+-\d+)\*\*", text)
    row_defined = _defined_invariant_ids()
    assert len(all_bold) > len(row_defined), (
        "no bold prose mention of an invariant found; this guard is untested "
        "(and the duplicate check it protects would go unexercised)"
    )


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
        # Split on UNESCAPED pipes only: an invariant description may contain a
        # literal `\|` (e.g. a Sigma `field|base64` modifier), which is NOT a
        # column separator. A naive split("|") would shard that row into extra
        # cells and mis-flag it.
        cells = [c.strip().replace(r"\|", "|")
                 for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        # id | invariant | owner | enforced by
        if len(cells) < 4 or not cells[2] or not cells[3]:
            offenders.append(cells[0] if cells else line)
        elif "test_" not in cells[3]:
            offenders.append(cells[0])
    assert not offenders, (
        f"invariant rows missing an owner or a real test citation: {offenders}"
    )

# --------------------------------------------------------------------------- #
# Numeric claims in the invariant rows (INV-DOC-7)                            #
# --------------------------------------------------------------------------- #
_HISTORICAL_MARKER = "AT THE TIME"

# Countable things an invariant row may quantify, each with a way to measure it NOW.
_COUNTABLE = {
    "harnesses": lambda: sum(
        1 for name in os.listdir(os.path.join(REPO_ROOT, "harnesses"))
        if os.path.isfile(os.path.join(REPO_ROOT, "harnesses", name, "harness.yaml"))
    ),
    "evidence": lambda: len(
        [p for p in os.listdir(os.path.join(REPO_ROOT, "evidence")) if p.endswith(".json")]
    ),
    # NOTE: "test files" is deliberately NOT in this map. The only `N test files` figure in the
    # whole document is INV-PKG-3's historical 162, which the AT-THE-TIME exemption skips — so an
    # entry here would be dead configuration that no assertion could ever exercise. Discovered by
    # mutating `repo_infra.count_test_files` and seeing only test_docs_drift.py react; the
    # unreactive side was correct, not broken. That count IS shared between the two guards via
    # `repo_infra.count_test_files`, which is what stops them disagreeing about tests/smoke/.
    "specialists": lambda: sum(
        1 for name in os.listdir(os.path.join(REPO_ROOT, "specialists"))
        if os.path.isfile(os.path.join(REPO_ROOT, "specialists", name, "agent_a2a.py"))
    ),
}


def _invariant_rows() -> list:
    return [line for line in _doc_text().splitlines() if line.startswith("| **INV-")]


def test_every_current_state_count_in_an_invariant_row_is_accurate():
    """A number in an invariant row is a checkable claim, and two had already drifted.

    INV-TEST-2 said "across 169 files" while the suite had 170 — wrong within two rounds of being
    written, because the suite grows and the number did not. (Fixed by restating it as coverage:
    "every test module", which cannot drift.)

    This checks the remaining countable claims. It deliberately does NOT flag numbers marked
    `AT THE TIME`: INV-PKG-3 records that the sdist "carried all 162 test files AT THE TIME", a
    historical measurement of a defect. Forcing that to track the current count would make the
    guard demand the falsification of a record — the same trap the CHANGELOG guard hit when a bulk
    rename rewrote released entries, and the reason the docs-drift guard distinguishes
    present-tense claims from changelog lines.

    A guard that cannot tell a claim from a record pressures you into rewriting history for green.
    """
    offenders = []
    for row in _invariant_rows():
        invariant = re.match(r"\| \*\*(INV-[A-Z0-9-]+)\*\*", row)
        name = invariant.group(1) if invariant else "?"
        for noun, measure in _COUNTABLE.items():
            for match in re.finditer(rf"\b(\d{{1,4}})\s+{re.escape(noun)}\b", row):
                # Historical figures are exempt, but only when explicitly marked. Guessing from
                # verb tense would be unreliable and would let a stale claim hide behind "carried".
                trailing = row[match.end(): match.end() + 90]
                if _HISTORICAL_MARKER in trailing:
                    continue
                actual = measure()
                if int(match.group(1)) != actual:
                    offenders.append(
                        f"{name}: says {match.group(0)!r}, actual {actual}"
                    )
    assert not offenders, (
        "invariant row(s) quote a stale count:\n  " + "\n  ".join(offenders)
        + f"\n\nEither update the number, restate it as coverage (\"every test module\") so it "
        f"cannot drift, or — if it records a past measurement — mark it "
        f"{_HISTORICAL_MARKER!r} so this guard leaves it alone."
    )


def test_the_countable_measurements_are_non_trivial():
    """Positive control. Each measurement above must return a plausible number; a lambda returning
    0 (a renamed directory, say) would make every comparison pass or fail for the wrong reason."""
    for noun, measure in _COUNTABLE.items():
        value = measure()
        assert value >= 4, f"measuring {noun!r} returned {value} — this check is now blind"


def test_the_historical_exemption_marks_a_real_number():
    """Guard the exemption without coupling it to the measurement map.

    My first version required the marked row to contain a number DISAGREEING with a current
    measurement. That broke the moment I removed the dead `"test files"` entry from `_COUNTABLE`,
    because nothing in the map covers INV-PKG-3's figure any more — the guard and the map had
    become coupled in a way neither needed.

    What has to hold is simpler and independent: the marker must sit just after a number, so it
    exempts something rather than decorating prose. A marker on a row with no figure would be a
    dead branch — the "lint-exempt directory = never-cleaned directory" rule applied to a test's
    own escape hatch.
    """
    marked = [row for row in _invariant_rows() if _HISTORICAL_MARKER in row]
    assert marked, (
        f"no invariant row carries the {_HISTORICAL_MARKER!r} marker any more. If the historical "
        "count was removed, delete this test and the exemption; if the marker was dropped by "
        "accident, the count guard will start reporting a recorded measurement as drift."
    )
    for row in marked:
        index = row.index(_HISTORICAL_MARKER)
        window = row[max(0, index - 60):index]
        assert re.search(r"\d", window), (
            f"the {_HISTORICAL_MARKER!r} marker appears with no number before it, so it exempts "
            f"nothing:\n  ...{window}[{_HISTORICAL_MARKER}]..."
        )
