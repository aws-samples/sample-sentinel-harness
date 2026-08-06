"""One way to build a distribution artifact from a pristine copy of the repo.

Three modules needed this and grew three answers. `test_wheel_contents.py` and
`test_installed_cli_e2e.py` each carried a `shutil.copytree` with a **byte-identical** twelve-entry
ignore list; `test_sdist_contents.py` built **in place** with `cwd=REPO_ROOT`.

That third one mattered. Measured, with a ghost handler planted in `build/lib/tools/`:

    wheel guard  (pristine copy, build/ excluded)   -> FAILED, caught the ghost
    sdist guard  (in-place build)                   -> 6 passed, saw nothing

The sdist guard inherited the very staleness it exists to detect — and the wheel guard's own
docstring, written in the same round, spells out why in-place building is wrong. "A fix applied to
one call site is not an invariant", this time landing on two adjacent modules of mine.

The in-place build also left a `sentinel_harness.egg-info/` behind in the working tree. It is
gitignored, so `git status` stayed clean and the pollution was silent — a test that mutates the
repository it is testing, invisibly.

(The sdist ARTIFACT was never affected: `MANIFEST.in`'s `prune build` keeps a stale staging tree
out of the tarball — verified, 20 handlers and no ghost. The defect was in the guard's method and
in the side effect, not in what ships.)

Everything that builds an artifact from source in this suite goes through `pristine_copy` so the
exclusion list has ONE definition. If it drifts, all three guards drift together — which is the
point.
"""
from __future__ import annotations

import os
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Excluded from the copy. Build/vendor output and local state only — never source.
#
# `build` and `dist` are the load-bearing entries: INV-PKG-2 records a stale `build/lib/` putting a
# DELETED tool back into a wheel, so a guard that copies them in cannot see the defect it exists
# for. The rest keep the copy fast and free of machine-specific state.
_IGNORED = (
    ".git",
    "build",
    "dist",
    "*.egg-info",
    "__pycache__",
    ".venv",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
    "cdk.out",
    ".terraform",
    "htmlcov",
    ".coverage",
)


def pristine_copy(destination) -> str:
    """Copy the repo to `destination` minus build output, and return the copied root.

    `destination` is a path (typically from `tmp_path_factory.mktemp`). A plain `copytree` of the
    working tree rather than `git archive`, deliberately: this must reflect what WOULD be shipped
    from the current source, including uncommitted edits, which is what a contributor running the
    suite wants to know.
    """
    target = os.path.join(str(destination), "repo")
    shutil.copytree(REPO_ROOT, target, ignore=shutil.ignore_patterns(*_IGNORED))
    return target


def ignored_patterns() -> tuple:
    """The exclusion list, for tests that assert its contents."""
    return _IGNORED
