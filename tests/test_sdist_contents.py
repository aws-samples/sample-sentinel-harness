"""INV-PKG-3 — the sdist ships the trees its bundled test suite reads.

The sdist is published to PyPI beside the wheel, and it is the artifact downstream packagers
work from — conda-forge, Debian, Fedora all unpack it and run the bundled suite to validate the
build. Measured, following exactly that workflow:

    pip install <sdist> && cd <unpacked> && pytest tests/
    -> 43 errors during collection
       12x scenarios/  7x specialists/  3x longrunning/  2x demo/  1x sentinel_inference_gateway/
       FileNotFoundError

There was no `MANIFEST.in`, so nobody had ever DECIDED what the sdist contains. setuptools'
defaults pull in `tests/` automatically, so it shipped all 162 test files and none of the trees
they read — the worst of the two coherent options:

- omit the tests entirely (the sdist is then a minimal build input), or
- ship tests that RUN (the sdist must then carry their fixtures).

Shipping tests that cannot run means a packager either skips them — losing the verification the
bundled suite exists to provide — or files "this package is broken". Nothing caught it because
`release.yml`'s smoke test installs `dist/*.whl` only, and no test had ever opened the tarball.

Two lessons recorded in the fix
-------------------------------
1. **The failures under-reported the problem.** The 43 errors named 5 trees; an exhaustive scan
   of `REPO_ROOT / "<name>"` references across `tests/` found **19**. pytest stops collecting a
   module at its first error, so later trees were never reached. Fixing only what failed would
   have left the next `pip install sdist && pytest` broken somewhere new. This test re-derives
   the list from source so the two cannot drift.

2. **`.github/` stays out, and the guards that read it became repository-scoped.** Shipping CI
   config in an sdist would make a packager's build depend on our workflows. Instead
   `tests/repo_infra.py` defines ONE asymmetric rule — inside a git checkout a missing workflow
   is a FAILURE, outside one it is a skip — because the alternative (each guard skipping when
   its file is missing) is the silent no-op the last four rounds were spent removing.

ZERO network, ZERO AWS: builds an sdist locally and reads the tarball.
"""
from __future__ import annotations

import collections
import os
import re
import shutil
import subprocess
import sys
import tarfile

import pytest

from pristine_tree import pristine_copy

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO_ROOT, "MANIFEST.in")

# Trees a test may reference that are deliberately NOT in the sdist, with the reason.
_DELIBERATELY_ABSENT = {
    # CI configuration is not source. The guards reading it skip outside a checkout —
    # see tests/repo_infra.py and INV-PKG-3's docstring.
    ".github",
    # Build/publish output. INV-PKG-2 records a stale build/lib/ shipping a DELETED tool into a
    # wheel; it must not reach the sdist either.
    "build",
    "dist",
    # The published landing page is a website artifact, not source needed to build or test.
    "site",
    # Not directories — these came from the reference scan as string literals.
    "litellm", "ls-files",
}


def _referenced_trees() -> collections.Counter:
    """Top-level names the test suite reads via `REPO_ROOT / "<name>"`.

    Derived from source, NOT from the observed failures — the failures under-reported the set
    5-to-19 because pytest abandons a module after its first collection error.
    """
    patterns = (
        re.compile(r'REPO_ROOT,\s*"([A-Za-z_][A-Za-z_0-9-]*)"'),
        re.compile(r'REPO_ROOT\s*/\s*"([A-Za-z_][A-Za-z_0-9-]*)"'),
        re.compile(r'_REPO,\s*"([A-Za-z_][A-Za-z_0-9-]*)"'),
    )
    hits: collections.Counter = collections.Counter()
    tests_dir = os.path.join(REPO_ROOT, "tests")
    for root, _dirs, files in os.walk(tests_dir):
        if "__pycache__" in root:
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            with open(os.path.join(root, name), encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            for pattern in patterns:
                for match in pattern.finditer(text):
                    hits[match.group(1)] += 1
    return hits


@pytest.fixture(scope="module")
def sdist_names(tmp_path_factory) -> set:
    """Top-level entries inside a freshly built sdist."""
    launcher = None
    for candidate, probe in (
        (["uv", "build"], ["uv", "build", "--help"]),
        ([sys.executable, "-m", "build"], [sys.executable, "-m", "build", "--version"]),
    ):
        if shutil.which(candidate[0]) is None and candidate[0] != sys.executable:
            continue
        try:
            # Probe the CAPABILITY, not its host: `python --version` says nothing about
            # whether `python -m build` works. That mistake cost a CI round (INV-PKG-2).
            result = subprocess.run(probe, cwd=REPO_ROOT, capture_output=True, text=True,
                                    timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            launcher = candidate
            break

    if launcher is None:
        if os.environ.get("CI", "").strip().lower() in ("1", "true", "yes", "on"):
            raise AssertionError(
                "no sdist builder found (tried `uv build`, `python -m build`) but CI=1. "
                "ci.yml must install `build`; without one INV-PKG-3 is unverified where "
                "merges are gated."
            )
        pytest.skip("no way to build an sdist was found")

    # Built from a PRISTINE COPY, not in place. This module used `cwd=REPO_ROOT`, and its two
    # sibling guards did not — an asymmetry with two measured consequences:
    #
    #   1. It inherited the staleness it exists to detect. With a ghost handler planted in
    #      `build/lib/tools/`, `test_wheel_contents.py` FAILED (caught it) while this module
    #      reported `6 passed`. Same shape as INV-PKG-2, whose fix is quoted in the wheel
    #      guard's own docstring — written in the same round as this file.
    #   2. It left a `sentinel_harness.egg-info/` in the working tree. That path is gitignored,
    #      so `git status` stayed clean: a test silently mutating the repository it tests.
    #
    # The sdist ARTIFACT was never wrong — `MANIFEST.in`'s `prune build` keeps a stale staging
    # tree out of the tarball (verified: 20 handlers, no ghost). The defect was the guard's
    # method and its side effect.
    src = pristine_copy(tmp_path_factory.mktemp("src"))
    out = tmp_path_factory.mktemp("sdist")
    argv = ([*launcher, "--sdist", "-o", str(out)] if launcher[0] == "uv"
            else [*launcher, "--sdist", "--outdir", str(out), src])
    proc = subprocess.run(argv, cwd=src, capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, f"sdist build failed:\n{(proc.stdout + proc.stderr)[-2000:]}"

    tarballs = list(out.glob("*.tar.gz"))
    assert len(tarballs) == 1, f"expected one sdist, got {[t.name for t in tarballs]}"
    with tarfile.open(tarballs[0]) as tf:
        members = tf.getnames()
    # Strip the `<name>-<version>/` prefix and keep the first path component.
    return {n.split("/")[1] for n in members if n.count("/") >= 1 and n.split("/")[1]}


def test_the_scan_found_references(sdist_names):
    """Positive control, twice over: the reference scan and the tarball must both be
    non-trivial. Comparing two empty sets succeeds, which is how a packaging guard becomes
    decoration."""
    refs = _referenced_trees()
    assert len(refs) >= 15, f"reference scan found only {len(refs)} trees: {sorted(refs)}"
    assert len(sdist_names) >= 20, f"sdist has only {len(sdist_names)} entries: {sorted(sdist_names)}"


def test_every_tree_the_tests_read_is_in_the_sdist(sdist_names):
    """The defect.

    A tree referenced by the bundled tests but absent from the sdist means the suite cannot run
    where it is shipped — 43 collection errors, measured.
    """
    referenced = {
        name for name in _referenced_trees()
        if name not in _DELIBERATELY_ABSENT
        and os.path.isdir(os.path.join(REPO_ROOT, name))
    }
    missing = sorted(referenced - sdist_names)
    assert not missing, (
        f"the sdist ships tests that read {missing}, but not those trees. A downstream "
        f"packager running the bundled suite (conda-forge, Debian and Fedora all do) gets "
        f"FileNotFoundError.\n\n"
        f"Add a `recursive-include` line to MANIFEST.in, or — if the tree genuinely should not "
        f"ship — add it to _DELIBERATELY_ABSENT here WITH the reason, so the decision is "
        f"recorded rather than implied by omission."
    )


def test_the_deliberately_absent_list_is_accurate(sdist_names):
    """Guard the exemptions. An entry claiming a tree is excluded, while it actually ships, is a
    stale exemption — the "lint-exempt directory = never-cleaned directory" rule applied to a
    test's own allowlist."""
    real_dirs = {name for name in _DELIBERATELY_ABSENT
                 if os.path.isdir(os.path.join(REPO_ROOT, name))}
    wrongly_shipped = sorted(real_dirs & sdist_names)
    assert not wrongly_shipped, (
        f"_DELIBERATELY_ABSENT claims {wrongly_shipped} stay out of the sdist, but they are in "
        f"it. Either MANIFEST.in gained an include it should not have, or the exemption is "
        f"stale — a wrong exemption is worse than none, because it argues for a constraint that "
        f"is not in force."
    )


def test_ci_configuration_is_not_shipped(sdist_names):
    """`.github/` must stay out, asserted so a well-meaning "make the tests pass in the sdist"
    change does not ship it.

    The correct fix for those failures was to scope the guards (tests/repo_infra.py), not to
    ship the workflows: an sdist carrying CI config makes a packager's build depend on our
    pipeline and invites bug reports about a CI they cannot run.
    """
    assert ".github" not in sdist_names, (
        "the sdist now ships .github/. CI configuration is not source — the guards that read "
        "it are repository-scoped via tests/repo_infra.py instead."
    )


def test_manifest_exists_and_is_a_decision():
    """The root cause was the ABSENCE of a manifest, so its presence is the fix.

    Without `MANIFEST.in`, sdist contents are whatever setuptools' defaults happen to be — and
    those defaults include `tests/` while excluding the data the tests read, which is precisely
    the inconsistent state that shipped.
    """
    assert os.path.isfile(MANIFEST), (
        "MANIFEST.in is gone. Without it setuptools' sdist defaults apply, which ship tests/ "
        "but none of the trees the tests read — 43 collection errors, measured."
    )
    with open(MANIFEST, encoding="utf-8") as fh:
        text = fh.read()
    for required in ("recursive-include tests", "recursive-include scenarios",
                     "recursive-include specialists", "prune build"):
        assert required in text, f"MANIFEST.in lost its `{required}` rule"


def test_the_lockfile_and_security_policy_ship():
    """Two specific files that must be in the sdist, for reasons a generic rule would miss.

    `SECURITY.md` is cited by COMPLIANCE.md's control table (C15) — my first draft of
    MANIFEST.in omitted it and `test_compliance_mapping` failed inside the sdist. `uv.lock` is
    what lets a packager reproduce the exact environment the suite was verified against.

    Read from MANIFEST.in rather than the built tarball so this stays fast; the tarball-level
    check is `test_every_tree_the_tests_read_is_in_the_sdist`.
    """
    with open(MANIFEST, encoding="utf-8") as fh:
        text = fh.read()
    for name in ("SECURITY.md", "uv.lock", "CONTRIBUTING.md"):
        assert re.search(rf"^include {re.escape(name)}$", text, re.M), (
            f"MANIFEST.in no longer includes {name}."
        )
