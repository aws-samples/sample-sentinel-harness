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
)

_DOC_FILES = ("README.md", "docs/ROADMAP.md", "docs/FIDELITY-REPORT.md",
              "docs/TESTING.md")


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
