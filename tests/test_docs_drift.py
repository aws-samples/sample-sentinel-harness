"""
Docs-drift guard for the pdoc-rendered API reference.
=====================================================
The API site (``.github/workflows/docs.yml`` → pdoc → GitHub Pages) is only as good
as the docstrings it renders. This test fails the build when a PUBLIC symbol exported
from ``sentinel_harness`` has no docstring, so the reference site can never silently
degrade into a wall of undocumented names.

Scope + rationale:
- Only ``sentinel_harness.__all__``-style exports are checked (the names a user
  imports and the ones pdoc surfaces first) — internal helpers are out of scope.
- Constants / simple data values (str, int, float, bool, frozenset, dict, tuple,
  module objects) are skipped: a docstring on a plain value is neither idiomatic nor
  renderable. Only callables (functions) and classes must be documented.
- ZERO AWS / network: this reads the already-imported module object, nothing else.
"""
from __future__ import annotations

import inspect
import os

# Hermetic import — never resolve a real region/role/creds.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import sentinel_harness as sh  # noqa: E402


def _public_names() -> list[str]:
    """Public exports: names bound on the package that don't start with '_'."""
    return [n for n in dir(sh) if not n.startswith("_")]


def test_public_callables_and_classes_have_docstrings():
    """Every exported function/class must carry a non-empty docstring (feeds pdoc)."""
    undocumented = []
    for name in _public_names():
        obj = getattr(sh, name)
        if inspect.isfunction(obj) or inspect.isclass(obj):
            doc = inspect.getdoc(obj)
            if not (doc and doc.strip()):
                undocumented.append(name)
    assert not undocumented, (
        "public API exports missing a docstring (the pdoc site would render them "
        f"blank): {sorted(undocumented)}"
    )


def test_package_has_module_docstring():
    """The package itself must have a top-level docstring (pdoc's landing page)."""
    assert (sh.__doc__ or "").strip(), "sentinel_harness package is missing its module docstring"


def test_public_surface_is_nonempty():
    """Guard against an __init__ regression that stops re-exporting the public API."""
    names = _public_names()
    # A floor, not an exact count (the surface only grows): core entry points present.
    for expected in ("create_harness", "invoke", "create_gateway", "regression_guard"):
        assert expected in names, f"expected public export {expected!r} missing from sentinel_harness"
    assert len(names) >= 40, f"public surface unexpectedly small ({len(names)} names) — export regression?"


# ========================================================================== #
# INV-DOC-2 — quoted counts must match reality (and each other)              #
# ========================================================================== #
# WHY: a security reference is judged on whether its claims are checkable. Before
# this guard the README asserted BOTH "2365 offline tests" (badge) and "2352
# offline tests pass" (status matrix) while the suite actually collected 2493 —
# three different numbers, one of them in a shields.io badge a reader takes at
# face value. Numbers in prose rot silently; only a test keeps them honest.
#
# SCOPE (deliberately narrow): only claims about the CURRENT state are checked.
# ROADMAP entries that record a milestone's historical delta ("suite 2126 → 2352")
# are a changelog, not a claim about today, so they are excluded by matching only
# the specific present-tense phrasings below.
import re          # noqa: E402
import subprocess  # noqa: E402
import sys         # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tolerance for the test count: the suite grows with every feature, and a docs
# update should not be required for a +5 test PR. A drift beyond this means the
# docs are quoting a materially stale number (the pre-M18 drift was 141).
_TEST_COUNT_TOLERANCE = 60


def _collected_test_count() -> int:
    """Ask pytest how many tests actually exist (collection only — nothing runs)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:randomly", "-p", "no:cacheprovider", "tests/"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    match = re.search(r"(\d+) tests collected", proc.stdout)
    assert match, f"could not parse a collection count from pytest:\n{proc.stdout[-1500:]}"
    return int(match.group(1))


def _read(rel_path: str) -> str:
    with open(os.path.join(REPO_ROOT, rel_path), encoding="utf-8") as fh:
        return fh.read()


# Present-tense claims about the size of the offline suite, per file.
_TEST_COUNT_CLAIM_RES = (
    re.compile(r"offline%20tests-(\d{3,5})%20passing"),   # README shields.io badge
    re.compile(r"\*\*(\d{3,5}) offline tests pass\*\*"),
    re.compile(r"\*\*(\d{3,5}) offline passing\*\*"),
    re.compile(r"(\d{3,5})-test offline suite"),
    re.compile(r"all (\d{3,5}) offline tests green"),
    re.compile(r"→ (\d{3,5}) passing"),
    re.compile(r"`make test` → (\d{3,5}) offline tests green"),
    re.compile(r"^- \*\*Scale\.\*\* (\d{3,5}) offline tests pass", re.M),
    re.compile(r"offline unit \+ config tests \((\d{3,5})\)"),
    # site/index.html — the public landing page. Both its <meta description> (what search
    # engines and social cards quote) and its body prose state the suite size.
    #
    # These two are deliberately NARROW. My first attempt used a bare
    # `(\d{3,5}) offline tests`, which also matched ROADMAP's HISTORICAL changelog lines
    # ("2126 → 2352 offline passing", "installs 0.4.0 from PyPI; suite 2365 passed") and
    # reported them as drift. Those record what was true at the time and must not be
    # rewritten — the same reason this change leaves the old tool name in CHANGELOG's
    # released sections. A count guard has to distinguish a present-tense CLAIM from a
    # record of the past, or it pressures you into falsifying history to get green.
    re.compile(r"(\d{3,5}) tests, \d+ defects fixed"),      # <meta description>
    re.compile(r"tl-desc\">(\d{3,5}) offline tests green"),  # landing-page timeline entry
)

# `site/index.html` is a HAND-WRITTEN, git-tracked page published to GitHub Pages — the most
# public claim this project makes, and the last one to get checked. It sat at "2352 tests"
# while the suite had 3843: off by 1480, in the <meta description> a search result quotes.
# The count guard covered README and docs/ and stopped there, so the drift lived in the one
# file no maintainer opens. Adding it here is cheap; noticing it was not.
_DOC_FILES = ("README.md", "docs/ROADMAP.md", "docs/FIDELITY-REPORT.md",
              "docs/TESTING.md", "site/index.html")


def _quoted_test_counts() -> dict[str, list[int]]:
    """Every present-tense suite-size claim, keyed by file."""
    found: dict[str, list[int]] = {}
    for rel in _DOC_FILES:
        path = os.path.join(REPO_ROOT, rel)
        if not os.path.isfile(path):
            continue
        text = _read(rel)
        hits = [int(m.group(1)) for rx in _TEST_COUNT_CLAIM_RES
                for m in rx.finditer(text)]
        if hits:
            found[rel] = hits
    return found


def test_quoted_counts_match_reality():
    """INV-DOC-2: every present-tense suite-size claim tracks the real suite.

    Enforces docs/INVARIANTS.md INV-DOC-2. Fails with the exact file, the quoted
    number and the real one, so fixing it is mechanical.
    """
    actual = _collected_test_count()
    quoted = _quoted_test_counts()
    assert quoted, (
        "no suite-size claims found in the docs — either the phrasing changed "
        "(update _TEST_COUNT_CLAIM_RES) or the claims were removed"
    )
    stale = {
        rel: [n for n in nums if abs(n - actual) > _TEST_COUNT_TOLERANCE]
        for rel, nums in quoted.items()
    }
    stale = {rel: nums for rel, nums in stale.items() if nums}
    assert not stale, (
        f"docs quote a stale offline-test count (suite really collects {actual}, "
        f"tolerance ±{_TEST_COUNT_TOLERANCE}): {stale}. Update the number — a "
        "security reference is judged on whether its claims are checkable."
    )


def test_quoted_test_FILE_counts_match_reality():
    """INV-DOC-2, second number: the count of test FILES, not just of tests.

    The guard above tracked "3806 offline tests" and caught every drift in it. Meanwhile
    "across **137** test files" — in the SAME SENTENCE of `docs/FIDELITY-REPORT.md`, and in
    a ROADMAP table row — had drifted to a real 157 and nothing noticed, because the
    regexes only ever captured the test count.

    That is this repo's most-recorded shape once more, at the level of a CLAIM rather than a
    code path: a guard written for one number in a sentence leaves the other numbers in that
    sentence unguarded. A stale file count understates the suite by 13%, and a reference
    whose checkable claims are wrong is judged on exactly that.
    """
    # A DEDICATED tolerance, not `_TEST_COUNT_TOLERANCE`. My first version reused it and the
    # mutation "revert 157 back to 137" SURVIVED: ±60 is 1.6% of ~3800 tests (sensible) but
    # ±38% of 157 files, so the check accepted almost any number while reporting green. A
    # tolerance is calibrated to a MAGNITUDE; borrowing one across two magnitudes in the same
    # file yields a guard that runs and verifies nothing. Files are added a handful at a time,
    # so ±3 is generous and still catches real drift.
    _FILE_COUNT_TOLERANCE = 3
    # Shared measurement: this used `os.listdir` (169) while test_invariants_doc.py used
    # `os.walk` (170, counting tests/smoke/). Both passed because they checked different
    # documents — one fact, two implementations, which is how a doc update satisfies one guard
    # and contradicts the other.
    from repo_infra import count_test_files

    actual = count_test_files()
    patterns = (
        re.compile(r"across (\d{2,4}) test files"),
        re.compile(r"\|\s*`tests/`\s*\|\s*(\d{2,4}) files"),
    )
    quoted: dict[str, list[int]] = {}
    for rel in _DOC_FILES:
        if not os.path.isfile(os.path.join(REPO_ROOT, rel)):
            continue
        text = _read(rel)
        hits = [int(m.group(1)) for rx in patterns for m in rx.finditer(text)]
        if hits:
            quoted[rel] = hits

    # Positive control: a scan that matches nothing proves nothing. If the phrasing
    # changed, this must fail loudly rather than vacuously pass.
    assert quoted, (
        "no test-FILE-count claims found in the docs. Either the phrasing changed "
        "(update the patterns above) or the claims were removed — but this guard silently "
        "matching nothing is how the 137-vs-157 drift survived in the first place."
    )
    stale = {rel: [n for n in nums if abs(n - actual) > _FILE_COUNT_TOLERANCE]
             for rel, nums in quoted.items()}
    stale = {rel: nums for rel, nums in stale.items() if nums}
    assert not stale, (
        f"docs quote a stale test-FILE count (tests/ really has {actual} test_*.py files, "
        f"tolerance ±{_FILE_COUNT_TOLERANCE}): {stale}."
    )


def test_quoted_test_counts_do_not_contradict_each_other():
    """Two files (or two lines) must never assert DIFFERENT current sizes.

    The pre-M18 README claimed 2365 in its badge and 2352 in its status matrix.
    Both were wrong, but the contradiction alone is the tell — a reader cannot
    know which to trust.
    """
    quoted = _quoted_test_counts()
    all_values = {n for nums in quoted.values() for n in nums}
    assert len(all_values) <= 1, (
        f"the docs assert conflicting offline-test counts: {quoted}. "
        "Pick one number and use it everywhere."
    )


def test_per_round_acceptance_records_are_not_all_the_same_number():
    """INV-DOC-4 (round 19): a historical record must record HISTORY.

    `docs/ROADMAP.md` carries a per-round acceptance line for each audit round, of the
    form "suite 2493 -> **3522** offline passing". The left number is that round's
    starting size and differs per round, correctly. The right number is what the suite
    was WHEN THAT ROUND CLOSED — so five consecutive rounds cannot all end at the same
    size, because each of them added tests.

    They did. All five read the same value, because every count update was applied with
    an undiscriminating find-and-replace over the file, which rewrote eight rounds of
    acceptance records to today's number each time. Nothing caught it: the present-tense
    checks above deliberately ignore these lines, and a wrong-but-consistent number reads
    as fine.

    This does not try to reconstruct the true historical values — they are not recoverable
    from the doc. It fails when a NEW blanket rewrite flattens them further, and it is
    satisfied by any record where the closing sizes actually differ.
    """
    text = _read("docs/ROADMAP.md")
    # "suite 2493 -> **3522**" / "Suite 2590 -> **3522**" / "2730 -> **3522** collected"
    rx = re.compile(r"[Ss]uite (\d{3,5}) → \*\*(\d{3,5})\*\*")
    records = [(int(m.group(1)), int(m.group(2))) for m in rx.finditer(text)]
    assert len(records) >= 4, (
        f"only found {len(records)} per-round acceptance records in ROADMAP.md; the "
        "phrasing changed and this check is now blind"
    )
    starts = [s for s, _ in records]
    ends = [e for _, e in records]
    assert len(set(starts)) == len(starts), (
        f"two rounds claim the same STARTING suite size: {starts}. A round starts where "
        "the previous one ended, so these must all differ."
    )
    # The real assertion: a monotonically growing suite cannot close at one size for
    # every round. One repeat is a plausible no-net-change round; all of them is a
    # blanket rewrite.
    most_common = max(set(ends), key=ends.count)
    assert ends.count(most_common) < len(ends), (
        f"every per-round acceptance record closes at {most_common}: {ends}. Each round "
        "added tests, so these cannot all be equal — a blanket find-and-replace over "
        "the file has overwritten the history with the current number. Update only the "
        "lines that assert the CURRENT suite size; the per-round records are history."
    )


def test_quoted_tool_count_matches_reality():
    """The tool count is quoted a lot ("20 tools") and is trivially checkable."""
    actual = len([d for d in os.listdir(os.path.join(REPO_ROOT, "tools"))
                  if os.path.isdir(os.path.join(REPO_ROOT, "tools", d))])
    claims: dict[str, list[int]] = {}
    rx = re.compile(r"(\d{1,3}) tools\b")
    for rel in _DOC_FILES:
        path = os.path.join(REPO_ROOT, rel)
        if not os.path.isfile(path):
            continue
        hits = [int(m.group(1)) for m in rx.finditer(_read(rel))]
        # A "7-tool detection suite" style sub-count is a different claim; only
        # flag numbers that are clearly meant as the FULL tool count.
        hits = [n for n in hits if n >= 10]
        if hits:
            claims[rel] = hits
    wrong = {rel: [n for n in nums if n != actual] for rel, nums in claims.items()}
    wrong = {rel: nums for rel, nums in wrong.items() if nums}
    assert not wrong, (
        f"docs quote a wrong tool count (tools/ really has {actual}): {wrong}"
    )


def test_quoted_evidence_count_matches_reality():
    """Evidence artifacts are the repo's proof surface; the count must be real."""
    evidence_dir = os.path.join(REPO_ROOT, "evidence")
    actual = len([f for f in os.listdir(evidence_dir) if f.endswith(".json")])
    rx = re.compile(r"(\d{1,3}) evidence (?:JSON )?(?:artifacts|sets)")
    wrong: dict[str, list[int]] = {}
    for rel in _DOC_FILES:
        path = os.path.join(REPO_ROOT, rel)
        if not os.path.isfile(path):
            continue
        hits = [int(m.group(1)) for m in rx.finditer(_read(rel))]
        bad = [n for n in hits if n > actual]   # over-claiming is the real sin
        if bad:
            wrong[rel] = bad
    assert not wrong, (
        f"docs over-claim the evidence count (evidence/ really has {actual} JSON "
        f"artifacts): {wrong}"
    )

# --------------------------------------------------------------------------- #
# Counts in the public docs and the landing page (INV-DOC-9)                  #
# --------------------------------------------------------------------------- #
# Files that state facts to a reader. `site/index.html` is included deliberately: it is
# hand-written, git-tracked and published to GitHub Pages, and its claims are HTML-encoded, so the
# markdown-oriented patterns above never reached it. INV-DOC-8 is the record of the same blindness
# for URL-encoded README badges — one fact, several encodings.
_PUBLIC_DOCS = ("README.md", "docs/COMPARISON.md", "docs/FIDELITY-REPORT.md",
                "docs/ROADMAP.md", "site/index.html")

# Nouns whose TOTAL is measurable from the tree.
_TOTALS = {
    "scenarios": lambda: len([
        p for p in os.listdir(os.path.join(REPO_ROOT, "scenarios"))
        if p.startswith("scenario_") and p.endswith(".py")
    ]),
    "evidence artifacts": lambda: len([
        p for p in os.listdir(os.path.join(REPO_ROOT, "evidence")) if p.endswith(".json")
    ]),
    "evidence JSON artifacts": lambda: len([
        p for p in os.listdir(os.path.join(REPO_ROOT, "evidence")) if p.endswith(".json")
    ]),
    "tools": lambda: len([
        d for d in os.listdir(os.path.join(REPO_ROOT, "tools"))
        if os.path.isfile(os.path.join(REPO_ROOT, "tools", d, "handler.py"))
    ]),
}

# SUBSET claims: a smaller number that is correct because it counts part of the whole. Each maps to
# the exact members, so the claim is verified rather than merely excused.
#
# Without this the guard would demand "7-tool detection suite" become "20-tool", which is the
# failure mode INV-DOC-7 records for historical figures, in a different costume: a guard that
# cannot tell a subset from a total pressures you into making a correct sentence wrong.
_SUBSETS = {
    "7-tool": (
        "sigma_yara_lint", "detection_translate", "detection_dedup", "detection_coverage",
        "detection_audit", "detection_navigator", "detection_baseline",
    ),
    "suite (7 tools": (
        "sigma_yara_lint", "detection_translate", "detection_dedup", "detection_coverage",
        "detection_audit", "detection_navigator", "detection_baseline",
    ),
    # The landing page words it differently again ("7 deterministic tools"), which my first
    # marker list missed — a fourth phrasing of the same subset. Every new wording is another
    # spelling that must be enumerated, which is the cost of prose stating facts.
    "7 deterministic tools": (
        "sigma_yara_lint", "detection_translate", "detection_dedup", "detection_coverage",
        "detection_audit", "detection_navigator", "detection_baseline",
    ),
    "Suite (7 tools": (
        "sigma_yara_lint", "detection_translate", "detection_dedup", "detection_coverage",
        "detection_audit", "detection_navigator", "detection_baseline",
    ),
}


def test_every_total_count_in_the_public_docs_is_accurate():
    """Totals stated to a reader must match the tree.

    Found by auditing: `docs/COMPARISON.md` said "2365 tests, 21 scenarios, 36 evidence artifacts"
    — all three long stale, the test count by 1600 — because its phrasing ("Numbers above (...)")
    matched none of the present-tense patterns the older guards look for.
    `docs/FIDELITY-REPORT.md` was off by one on two counts, and `site/index.html` claimed
    "21 offline scenarios" for a command that runs a narrated tour touching 9.

    Subset claims are checked separately below, not exempted.
    """
    offenders = []
    for relative in _PUBLIC_DOCS:
        path = os.path.join(REPO_ROOT, relative)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for noun, measure in _TOTALS.items():
            # An ADJECTIVE may sit between the number and the noun: `21 offline scenarios`,
            # `38 evidence JSON artifacts`. My first pattern required them adjacent and so missed
            # the site's "21 offline scenarios" entirely — the mutation reinstating that exact
            # defect SURVIVED. Same lesson as INV-DOC-8's URL-encoded badges: a guard scoped to one
            # SPELLING of a claim leaves the other spellings unguarded.
            #
            # Bounded to two intervening words: wide enough for the real phrasings, narrow enough
            # that `20 tools ... 9 skills` cannot be read as "20 skills".
            pattern = rf"\b(\d{{1,4}})\s+(?:[a-z]+\s+){{0,2}}{re.escape(noun)}\b"
            for match in re.finditer(pattern, text):
                if any(marker in text[max(0, match.start() - 30):match.end()]
                       for marker in _SUBSETS):
                    continue  # a subset claim; verified by the test below
                actual = measure()
                if int(match.group(1)) != actual:
                    offenders.append(f"{relative}: {match.group(0)!r} (actual {actual})")
    assert not offenders, (
        "public doc(s) state a stale total:\n  " + "\n  ".join(offenders)
        + "\n\nThese are the numbers a reader takes at face value."
    )


def test_every_subset_claim_names_members_that_all_exist():
    """A subset claim is verified, not excused.

    "7-tool detection suite" is CORRECT — it counts part of the 20 tools — so the total guard must
    skip it. But skipping is not enough: the claim has to be true. This checks the arithmetic (the
    stated number equals the member count) and that every named member is a real tool on disk.

    I nearly mis-fixed this: guessing the membership from name prefixes gave 8 (it wrongly included
    `sigma_match`, which is the matching engine rather than a suite member). README enumerates the
    seven explicitly; the authoritative list belongs here, not in a prefix heuristic.
    """
    tools_dir = os.path.join(REPO_ROOT, "tools")
    for marker, members in _SUBSETS.items():
        stated = int(re.search(r"(\d+)", marker).group(1))
        assert stated == len(members), (
            f"subset marker {marker!r} claims {stated} but names {len(members)} members: {members}"
        )
        missing = [m for m in members
                   if not os.path.isfile(os.path.join(tools_dir, m, "handler.py"))]
        assert not missing, (
            f"subset {marker!r} names tool(s) that do not exist: {missing}"
        )


def test_the_subset_markers_are_actually_present_in_the_docs():
    """Positive control for the exemption.

    An exemption nobody exercises is either unnecessary or silently broken — the same rule as
    INV-DOC-7's historical marker. If no doc contains a subset marker, the skip branch above is
    dead and the membership check has nothing to protect.
    """
    # EVERY marker must still appear somewhere, not just one of them. My first version asserted
    # only that the list was non-empty, and the mutation "reword ROADMAP's `suite (7 tools`"
    # SURVIVED because two other markers were still present — one claim going stale while
    # unrelated ones kept the assertion satisfied. Identical to the `or` across two badge
    # spellings one round earlier: a check on the union of independent facts pins none of them.
    missing = []
    for marker in sorted(_SUBSETS):
        present = False
        for relative in _PUBLIC_DOCS:
            path = os.path.join(REPO_ROOT, relative)
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as fh:
                if marker in fh.read():
                    present = True
                    break
        if not present:
            missing.append(marker)
    assert not missing, (
        f"subset marker(s) {missing} appear in no public doc. Either the claim was reworded — "
        "update _SUBSETS — or the exemption for it is now dead code that would let a stale subset "
        "count through unexamined."
    )


def test_the_landing_page_is_covered_by_this_scan():
    """`site/index.html` is the most public artifact here and the last one to get checked.

    Asserted explicitly because it is easy to drop from a list of "docs" — it is not markdown, its
    claims are HTML-encoded, and the older guards' patterns never matched it. That is exactly how
    "21 offline scenarios" survived next to a command that runs a 9-scenario tour.
    """
    assert "site/index.html" in _PUBLIC_DOCS
    path = os.path.join(REPO_ROOT, "site", "index.html")
    assert os.path.isfile(path), "site/index.html is missing"
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # It must contain at least one measurable claim, or including it proves nothing.
    hits = sum(len(re.findall(rf"\b\d{{1,4}}\s+{re.escape(noun)}\b", text))
               for noun in _TOTALS)
    assert hits >= 1, (
        "site/index.html states no measurable count any more, so including it in this scan is "
        "vacuous. Either it was rewritten (fine — simplify this test) or the phrasing changed."
    )
