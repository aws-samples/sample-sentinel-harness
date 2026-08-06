"""
The per-file coverage table must track reality.
==============================================
`tests/README-coverage.md` explains, file by file, which coverage gaps exist and why they
are acceptable. That makes it a document a reviewer trusts to decide where effort should
go — and nothing was checking it.

A sixth sweep re-measured it. **Five of its seven rows were wrong by 16 to 61 points, and
every one UNDERSTATED the real coverage:**

    tools/sigma_match/handler.py              doc 65%   real 98%   (+33)
    longrunning/bas-runner/bas_cases.py       doc 84%   real 100%  (+16)
    longrunning/detonation/bedrock_entrypoint doc 35%   real 96%   (+61)
    specialists/attack-mapper/agent_a2a.py    doc 80%   real 100%  (+20)
    specialists/threat-hunt/agent_a2a.py      doc 81%   real 100%  (+19)

The direction is the interesting part. This was not random rot: coverage kept improving and
the table never followed. Its header still said "591 passed" while the suite had grown to
3725. A document that makes the project look WORSE than it is misdirects effort exactly as
much as one that flatters it — a reader would have spent a round re-testing
`detonation/bedrock_entrypoint.py`, which is already at 96%.

Same shape as INV-DOC-2 (quoted counts must match reality), one level down: from "how many
tests are there" to "how well is each file covered".

How this test gets its numbers
------------------------------
It reads `coverage.json` if a recent one is present, and otherwise SKIPS with instructions
rather than running a 3-minute coverage pass inside a unit test. `make ci` already produces
the data, so the checking path exists where it belongs. A skip is honest here; silently
passing without measuring would be the failure mode this whole file exists to prevent.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

import pytest

import child_pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "tests" / "README-coverage.md"
COVERAGE_DATA = REPO_ROOT / ".coverage"

# How far a documented figure may sit from the measured one. Coverage moves a little with
# the pytest-randomly seed (a couple of path-loaded modules land differently), so a tight
# bound would be flaky. 5 points is wide enough to absorb that and far narrower than the
# 16-61 point drift this test was written for.
_TOLERANCE_POINTS = 5

# A coverage.json older than this is a stale artifact from an unrelated run.
_MAX_DATA_AGE_SECONDS = 24 * 3600

# INV-DOC-5. When set, a missing/stale data file is an ERROR, not a skip.
#
# These three assertions are the only thing keeping `tests/README-coverage.md` honest (they
# were written after five of its rows were found wrong by 16-61 points). They ran on
# maintainer laptops — where `make ci` has already produced `.coverage` — and SKIPPED in CI
# on every single run, because CI's `coverage run -m pytest tests` only writes the data file
# when it EXITS. So during the test step there is no data, and the guard that keeps the
# coverage doc honest was never verified in the one place that gates merges.
#
# Measured, not assumed: replicating CI's exact invocation locally reproduces `SKIPPED [3]`.
#
# ci.yml now runs this module as a separate step AFTER `coverage report`, with this variable
# set. Without the variable the fix would be silent-failure-prone in the usual way — a later
# change to the data-file path would restore the no-op and the step would still pass green.
# `~/.claude/rules/degradation-and-guards.md`: "检查失败" and "检查通过" must not look alike.
_REQUIRE_DATA_ENV = "SENTINEL_REQUIRE_COVERAGE_DATA"


# The badge shows the aggregate TOTAL, which is stable: measured 91.907 under three different
# pytest-randomly seeds. So it gets its own tight bound rather than the per-file tolerance above.
_BADGE_TOLERANCE_POINTS = 1


def _unavailable(reason: str) -> None:
    """Skip locally, FAIL where the caller declared the data must exist."""
    if os.environ.get(_REQUIRE_DATA_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        raise AssertionError(
            f"{_REQUIRE_DATA_ENV}=1 but the coverage data is unusable: {reason} "
            "This runs as a dedicated CI step after `coverage report`, so the data file "
            "must exist here. Skipping would mean the documented coverage figures go "
            "unverified in CI — which is exactly the defect this flag exists to prevent."
        )
    pytest.skip(reason)


def _coverage_json() -> dict:
    """Measured coverage, from the existing .coverage data file.

    Generates coverage.json from `.coverage` (cheap — it is a report, not a re-run). Absent
    or stale data skips locally and FAILS when `SENTINEL_REQUIRE_COVERAGE_DATA=1`.
    """
    if not COVERAGE_DATA.is_file():
        _unavailable(
            "no .coverage data file. Run `make ci` (or "
            "`coverage run -m pytest tests`) first; this test verifies the documented "
            "per-file figures against that run rather than re-measuring inside a unit test."
        )
    age = time.time() - COVERAGE_DATA.stat().st_mtime
    if age > _MAX_DATA_AGE_SECONDS:
        _unavailable(
            f"the .coverage data file is {age / 3600:.1f}h old — too stale to check the "
            "documented figures against. Re-run `make ci`."
        )
    launcher = _coverage_launcher()
    out = REPO_ROOT / ".coverage-doc-check.json"
    try:
        # `--fail-under=0` is load-bearing. Without it, `coverage json` exits 2 when the
        # measured total is below `.coveragerc`'s `fail_under = 88` — so a partial coverage
        # run (one test file, say) makes the exit code mean "coverage is low" while this
        # code reads it as "the renderer is broken". Caught by a positive control that
        # failed for the RIGHT outcome and the WRONG reason. Rendering JSON and enforcing a
        # floor are separate questions; `make ci` owns the floor.
        result = subprocess.run(
            [*launcher, "json", "-o", str(out), "-q", "--fail-under=0"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        )
        # NOT a skip. The data file exists and is fresh, so failing to render it means the
        # renderer is broken — and a guard that skips when its own tooling breaks reports
        # "skipped" where it means "never checked". Three times while writing this file I
        # read a skip as success; the distinction has to be enforced, not remembered.
        assert result.returncode == 0 and out.is_file(), (
            f"a fresh .coverage exists but `coverage json` failed via {launcher!r}: "
            f"rc={result.returncode} stdout={result.stdout.strip()[:200]!r} "
            f"stderr={result.stderr.strip()[:200]!r}"
        )
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)


def _coverage_launcher() -> list[str]:
    """An argv prefix that can run `coverage`, resolved rather than assumed.

    The first version hardcoded `["python", "-m", "coverage", ...]`, which fails here:
    `coverage` is not installed in the project venv, only in the isolated environment
    `make ci` builds with `uv run --with coverage`. That is the SIXTH time a hardcoded
    interpreter/tool launcher has broken in this repo — the reason `tests/child_pytest.py`
    exists at all.

    Tried in order: the parent interpreter (right whenever the suite was itself launched
    with coverage available), then `uv run --with coverage`, then a bare `coverage`.
    """
    import sys

    candidates: list[list[str]] = [
        [sys.executable, "-m", "coverage"],
        ["uv", "run", "--no-project", "--with", "coverage", "python", "-m", "coverage"],
        ["coverage"],
    ]
    for candidate in candidates:
        try:
            probe = subprocess.run([*candidate, "--version"], cwd=REPO_ROOT,
                                   capture_output=True, text=True, timeout=180)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0 and "coverage" in (probe.stdout + probe.stderr).lower():
            return candidate
    # Same treatment as a missing data file: an unresolvable launcher is a genuine
    # environment gap locally, but in CI it means the check silently did not happen. I read
    # this particular skip as a success three times before it became an assertion.
    _unavailable(
        "no way to run `coverage` was found (tried the parent interpreter, "
        "`uv run --with coverage`, and a bare `coverage`), so the documented figures "
        "cannot be verified here. This is a genuine environment gap, not a pass."
    )
    raise AssertionError("unreachable")  # _unavailable always raises or skips


def _documented_rows() -> list[tuple[str, int]]:
    """Every `| \\`path\\` | NN% |` row in the doc's per-file table."""
    text = DOC.read_text(encoding="utf-8")
    return [(p, int(pct))
            for p, pct in re.findall(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)%", text, re.M)]


def test_the_table_parses():
    """Guard the guard. Every assertion below iterates the parsed rows, so a regex that
    stops matching would make this whole module vacuously green."""
    rows = _documented_rows()
    assert len(rows) >= 7, (
        f"only parsed {len(rows)} per-file coverage rows from {DOC.name}; the table format "
        "changed and this check is now blind"
    )
    for path, pct in rows:
        assert 0 <= pct <= 100, f"{path}: implausible coverage {pct}%"


def test_every_documented_file_exists():
    """A row naming a deleted or moved file is a stale claim."""
    missing = [p for p, _ in _documented_rows() if not (REPO_ROOT / p).is_file()]
    assert not missing, (
        f"the coverage table names file(s) that do not exist: {missing}"
    )


def test_no_documented_figure_has_drifted():
    """The point of the file. Each documented percentage must be within tolerance of the
    measured one."""
    cov = _coverage_json()
    measured = {p: f["summary"]["percent_covered"] for p, f in cov["files"].items()}
    drifted = []
    unmeasured = []
    for path, claimed in _documented_rows():
        hits = [v for p, v in measured.items() if p.endswith(path)]
        if not hits:
            unmeasured.append(path)
            continue
        real = hits[0]
        if abs(real - claimed) > _TOLERANCE_POINTS:
            drifted.append((path, claimed, round(real, 1)))
    assert not drifted, (
        "documented coverage has drifted from measured (doc% -> real%):\n  "
        + "\n  ".join(f"{p}: {c}% -> {r}%" for p, c, r in drifted)
        + f"\n\nTolerance is {_TOLERANCE_POINTS} points. Update the table in "
          f"{DOC.name}. A figure that understates coverage misdirects effort just as much "
          "as one that overstates it — five rows were once low by 16-61 points and a "
          "reader would have re-tested a file already at 96%."
    )
    assert not unmeasured, (
        f"documented file(s) absent from the coverage data: {unmeasured}. Either they are "
        "no longer matched by the .coveragerc include globs, or the path in the doc is "
        "wrong — both make the row unverifiable."
    )


def test_the_quoted_total_matches_measured():
    """The whole-repo TOTAL line in the doc."""
    cov = _coverage_json()
    real = cov["totals"]["percent_covered"]
    text = DOC.read_text(encoding="utf-8")
    match = re.search(r"include globs:\s*\*\*(\d+)%\*\*", text)
    assert match, (
        "could not find the quoted whole-repo TOTAL in the doc — the phrasing changed and "
        "this check is blind"
    )
    claimed = int(match.group(1))
    assert abs(real - claimed) <= _TOLERANCE_POINTS, (
        f"the doc quotes a whole-repo total of {claimed}% but the measured total is "
        f"{real:.1f}%"
    )


def test_third_party_code_is_not_measured():
    """The `*/tools/*` include glob once matched `site-packages/mcp/server/fastmcp/tools/`
    — 96 statements of a third-party library, 46 uncovered — which pulled the reported
    figure down and made the 88 floor looser than it looked, since the denominator carried
    code this repo neither owns nor should test."""
    cov = _coverage_json()
    foreign = sorted(p for p in cov["files"]
                     if "site-packages" in p or "/.venv/" in p or "/node_modules/" in p)
    assert not foreign, (
        f"coverage is measuring third-party code: {foreign[:5]}. The `omit` rules in "
        ".coveragerc must exclude site-packages / .venv / node_modules, or the quality "
        "gate is computed over a denominator that includes somebody else's library."
    )


def test_the_stated_suite_size_is_current():
    """The table's header quotes the suite size it was measured against. A stale one is how
    a reader learns to distrust the whole document — it said '591 passed' while the suite
    had grown to 3725."""
    text = DOC.read_text(encoding="utf-8")
    match = re.search(r"\((\d[\d,]*)\s+passed", text)
    assert match, "the doc no longer states the suite size it was measured against"
    claimed = int(match.group(1).replace(",", ""))
    # Through the shared launcher, not a hardcoded `python` — see _coverage_launcher.
    launcher = child_pytest.resolve_launcher()
    result = subprocess.run(
        [*launcher, "tests", "--collect-only", "-q",
         "-p", "no:randomly", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
    )
    found = re.search(r"(\d+)\s+tests? collected", result.stdout)
    assert found, (
        "could not read the collected test count — the child pytest did not report one, "
        f"so this check never ran: rc={result.returncode} "
        f"out={result.stdout[-300:]!r}"
    )
    actual = int(found.group(1))
    # Generous: the doc quotes a PASSED count and this is a COLLECTED count, and the suite
    # grows every round. This catches an order-of-magnitude staleness, not a few tests.
    assert abs(actual - claimed) <= max(60, actual * 0.05), (
        f"the coverage doc says it was measured against {claimed} passing tests, but the "
        f"suite now collects {actual}. Re-measure and update the header — a figure from a "
        "different era makes every row below it suspect."
    )

# --------------------------------------------------------------------------- #
# The README badges (INV-DOC-8)                                               #
# --------------------------------------------------------------------------- #
# TOML reader. `tomllib` is stdlib only on 3.11+, so 3.10 uses the marker-gated `tomli` from the
# `test` extra — the pattern already used by test_ci_installs_the_test_extra.py and
# test_sdist_contents.py. My first version of the badge guards did a bare `import tomllib` inside
# two test bodies, which passed on 3.11/3.12/3.13 and failed on 3.10 only. CI's version matrix
# caught it; a second implementation of a problem this repo had already solved.
#
# Not a silent skip: `tomli` IS installed on CI's 3.10 (verified — zero tomli-related skips in that
# job), so the guard runs on every Python in the matrix.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    tomllib = pytest.importorskip(
        "tomli", reason="TOML parsing on 3.10 needs the `tomli` marker-gated dep")


README = REPO_ROOT / "README.md"


def _badge_value(label: str) -> str | None:
    """The value segment of a shields.io badge, e.g. `coverage-92%25-1D8102` -> `92%25`."""
    text = README.read_text(encoding="utf-8")
    match = re.search(rf"img\.shields\.io/badge/{re.escape(label)}-([^-\"]+)-", text)
    return match.group(1) if match else None


def test_the_coverage_badge_matches_measured_coverage():
    """The badge is the first number a reader sees, and it had drifted to 90% against a real 92%.

    Worse than stale on its own: `tests/README-coverage.md` said 92% in the same repo, so the two
    documents contradicted each other and the WRONG one was the shields.io badge a reader takes at
    face value.

    It survived every counting guard because the value is URL-encoded — `coverage-90%25` contains no
    bare `90%`, so no regex looking for a percentage matched it. A guard scoped to one spelling of a
    fact leaves the other spellings unguarded, which is the shape this repo records most.

    Deliberately in THIS module rather than a new one: the badge and the table are two statements of
    one measurement, so they must share `_coverage_json` — a third implementation is how they came
    to disagree.
    """
    raw = _badge_value("coverage")
    assert raw, "the README coverage badge is gone or its markup changed"
    claimed = int(re.sub(r"%25|%", "", raw))

    measured = _coverage_json()["totals"]["percent_covered"]
    # A DEDICATED tolerance, not `_TOLERANCE_POINTS`. That one is 5 because PER-FILE coverage moves
    # with the pytest-randomly seed. The badge states the aggregate TOTAL over 8643 statements, and
    # measured across three seeds it does not move at all (91.907 every time), so 5 points is far
    # too loose: it swallowed the very drift this guard was written for — the mutation "revert the
    # badge to 90%" SURVIVED, because |90-92| < 5.
    #
    # A tolerance is calibrated to a magnitude. Borrowing one across two magnitudes yields a check
    # that runs and verifies nothing — the same mistake as reusing a +/-60 test-count tolerance for
    # a 157-file count. 1 point absorbs rounding of the displayed integer and nothing else.
    assert abs(claimed - measured) <= _BADGE_TOLERANCE_POINTS, (
        f"the README coverage badge claims {claimed}% but the measured total is "
        f"{measured:.1f}% (tolerance +/-{_BADGE_TOLERANCE_POINTS}). Update the badge — it is the first "
        f"number a reader sees, and tests/README-coverage.md states the real figure, so a stale "
        f"badge makes the two documents contradict each other."
    )


def test_the_version_badge_matches_the_package_version():
    """Same class, different fact: the badge said 0.4.0 while the package was 0.5.1.

    A version badge a full minor release behind misrepresents what a reader would install, and
    nothing checked it — `test_docs_drift.py` guards test counts and evidence counts, not this.
    """
    raw = _badge_value("version")
    assert raw, "the README version badge is gone or its markup changed"

    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]
    assert raw == declared, (
        f"the README version badge says {raw!r} but pyproject.toml declares {declared!r}."
    )

    # And that the package agrees with its own metadata, so the badge is not merely consistent
    # with a wrong pyproject.
    import sentinel_harness

    assert sentinel_harness.__version__ == declared, (
        f"sentinel_harness.__version__ is {sentinel_harness.__version__!r} but pyproject declares "
        f"{declared!r} — the badge would be right about the wrong thing."
    )


def test_the_python_badge_matches_requires_python():
    """The support claim a reader checks before installing.

    Cheap, and it closes the set of README badges that state a machine-checkable fact: version,
    coverage, python, and the test count (guarded by `test_docs_drift.py`). The rest are prose.
    """
    raw = _badge_value("python")
    assert raw, "the README python badge is gone or its markup changed"
    claimed = re.sub(r"%2B", "+", raw)  # shields.io encodes '+'

    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        requires = tomllib.load(fh)["project"]["requires-python"]
    floor = re.search(r"(\d+\.\d+)", requires)
    assert floor, f"cannot parse a version floor from requires-python={requires!r}"
    assert claimed.startswith(floor.group(1)), (
        f"the README python badge says {claimed!r} but requires-python is {requires!r}."
    )


def test_every_badge_this_module_checks_still_exists():
    """Positive control. Each test above returns early-ish if the markup changed; without this, a
    README rewrite that dropped the badges would leave three tests passing on `None` handling
    rather than on facts."""
    for label in ("coverage", "version", "python"):
        assert _badge_value(label) is not None, (
            f"the {label!r} badge is no longer parseable from README.md, so the guard for it is "
            "checking nothing. Either the badge was removed (delete its test) or the markup "
            "changed (update `_badge_value`)."
        )
