"""Locating repo infrastructure (`.github/`) from a test, with ONE rule about its absence.

Several guards assert things about CI configuration: that `ci.yml` installs the `test` extra
(INV-CI-1), that it runs the coverage-doc guard as its own step (INV-DOC-5), that a real-stack
job exists (INV-PKG-1), that `release.yml` builds from a fresh checkout (INV-PKG-2), that the
TypeScript pin and its dependabot ignore agree (INV-IAC).

All of them read `.github/`, and `.github/` is **deliberately not in the sdist** — it is CI
configuration, not source. So running the sdist's bundled test suite (which
`tests/test_sdist_contents.py` now requires to work, and which every downstream packager does)
produced 14 failures that mean nothing: a conda-forge maintainer does not maintain our CI.

The naive fix — ship `.github/` in the sdist — is wrong: it would make a packager's build
artifacts depend on our workflow files, and would invite "fix the CI config" bug reports from
people who cannot run our CI.

The other naive fix is worse: make each guard skip when the file is missing. That is the exact
trap the last four rounds were spent undoing (INV-CI-1, INV-DOC-5, INV-PKG-1, INV-PKG-2): a
guard that skips where it matters has verified nothing, and reports green either way.

So the rule is defined ONCE, here, and it is asymmetric:

    inside a git checkout   -> `.github/` MUST exist; its absence is a FAILURE
    outside one (an sdist)  -> skip, with a reason naming why

"Inside a checkout" is detected by the presence of `.git`, not by an env var a caller could get
wrong, and not by the absence of `.github` itself (which would be circular — the thing being
tested deciding whether to test it).
"""
from __future__ import annotations

import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GITHUB_DIR = os.path.join(REPO_ROOT, ".github")


def is_git_checkout() -> bool:
    """True when running from a git working tree (as opposed to an unpacked sdist).

    `.git` may be a directory (normal clone) or a file (worktree / submodule), so both count.
    """
    dot_git = os.path.join(REPO_ROOT, ".git")
    return os.path.isdir(dot_git) or os.path.isfile(dot_git)


def require_workflow(*parts: str) -> str:
    """Absolute path to a file under `.github/`, or skip/fail per the rule above.

    In a checkout a missing workflow is a FAILURE — that is the case where these guards are
    load-bearing, and where "the file moved" must not read as "nothing to check". In an
    unpacked sdist it is an honest skip.
    """
    path = os.path.join(GITHUB_DIR, *parts)
    if os.path.isfile(path):
        return path

    relative = os.path.join(".github", *parts)
    if is_git_checkout():
        raise AssertionError(
            f"{relative} does not exist, but this IS a git checkout (.git present), so the "
            f"guards that read it are load-bearing here. Either the workflow was renamed — "
            f"update the guard and the workflow together — or it was deleted, which is the "
            f"defect. This must never degrade to a skip inside a checkout: INV-CI-1, "
            f"INV-DOC-5, INV-PKG-1 and INV-PKG-2 are all records of a check that silently "
            f"stopped running."
        )
    # `allow_module_level=True` is REQUIRED, not defensive. Three of the five callers invoke
    # this at module scope (`CI_YML = require_workflow(...)`), and a bare `pytest.skip()` during
    # collection is an ERROR, not a skip — pytest says so explicitly:
    #   "Using pytest.skip outside of a test will skip the entire module. If that's your
    #    intention, pass allow_module_level=True."
    # Without it the sdist run produced 3 collection ERRORS instead of 3 clean skips, i.e. the
    # helper written to stop meaningless failures produced meaningless failures of its own.
    # Harmless inside a test function too: the flag only widens where a skip is permitted.
    pytest.skip(
        f"{relative} is absent and this is not a git checkout — an unpacked sdist, which "
        f"deliberately excludes .github/ (CI config is not source). This guard only applies "
        f"to the repository itself.",
        allow_module_level=True,
    )
    raise AssertionError("unreachable")  # pragma: no cover - pytest.skip raises


def require_git_checkout(what: str) -> None:
    """Skip (outside a checkout) or proceed (inside one) for guards that need git metadata.

    Some guards enumerate files with `git ls-files` — deliberately, so that git-ignored build
    output cannot pollute the scan. In an unpacked sdist there is no `.git`, so the enumeration
    returns nothing and every assertion built on it either fails or, worse, passes vacuously.

    `tests/test_repo_identity.py` shows why this needs a real skip rather than a tolerant
    fallback: its own `test_the_sanity_of_this_guard` requires the scan to see >100 files
    including `site/index.html` and `.github/ISSUE_TEMPLATE/config.yml` — neither of which is in
    the sdist by design. The guard is inherently repository-scoped. Making it "work" in an sdist
    would mean weakening the sanity check, i.e. removing the positive control that makes its
    negative results meaningful.

    Same asymmetry as `require_workflow`: silent no-op inside a checkout is forbidden.
    """
    if is_git_checkout():
        return
    pytest.skip(
        f"{what} requires git metadata (`git ls-files`) and repository-only paths such as "
        f"site/ and .github/, which an unpacked sdist deliberately omits. This guard is "
        f"repository-scoped by design — see tests/repo_infra.py.",
        allow_module_level=True,
    )

def count_test_files() -> int:
    """THE test-file count, so the docs guards cannot disagree about it.

    Two guards measured this two ways and both passed, because they checked different documents:
    `test_docs_drift.py` used `os.listdir` (top level only -> 169) and
    `test_invariants_doc.py` used `os.walk` (recursive -> 170). The difference is
    `tests/smoke/test_m4_acceptance.py`.

    Recursive is the honest answer: pytest collects it, so it IS a test file. One definition, so a
    future doc update cannot satisfy one guard while contradicting the other — the "same fact,
    two implementations" shape this repo records more than any other.
    """
    tests_dir = os.path.join(REPO_ROOT, "tests")
    return sum(
        1
        for _root, _dirs, files in os.walk(tests_dir)
        for name in files
        if name.startswith("test_") and name.endswith(".py")
    )
