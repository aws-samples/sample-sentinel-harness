"""
The ONE way a test launches a child pytest.
==========================================
Three structural guards prove themselves end-to-end by writing a real defect into the
tree, running the suite as a CHILD PROCESS, and asserting the failure names the file.
That pattern is the only thing that distinguishes "the guard fires" from "the guard's
predicate is correct in isolation" — round 18 shipped three guards whose unit controls
passed while the guards were blind.

But the child launcher itself has now been wrong three times, each fix curing the
symptom rather than the cause:

    round 18  ["python", "-m", "pytest", ...]        -> no pytest on PATH's python;
                                                        empty output read as "it fired"
    round 18  [sys.executable, "-m", "pytest", ...]  -> correct ONLY when the parent is
                                                        pytest. Under `uv run python`,
                                                        sys.executable is
                                                        .venv/bin/python3, which has no
                                                        pytest.
    round 19  ["uv", "run", "pytest", ...]           -> correct only where `uv` is
                                                        installed. CI has no uv:
                                                        FileNotFoundError on all four
                                                        Python versions.

The cause underneath all three: **a child that cannot start exits non-zero, and a
non-zero exit is exactly what "the guard fired" looks like.** Swapping launchers cannot
fix that; the launcher has to be resolved and then VERIFIED before its exit code is
allowed to mean anything.

So this module does two things, once, for all three call sites:

1. Resolves a launcher that actually works in THIS process's environment, trying the
   parent's own interpreter first (`sys.executable -m pytest` — right whenever the parent
   is pytest, which it is) and falling back to `uv run pytest` only if that fails.
2. Distinguishes the three outcomes a caller must never conflate: the suite passed, the
   suite failed, or **the child never ran**. A caller asserting "the guard fired" gets an
   explicit error for the third case instead of a false positive.

The resolution is cached per process: probing costs one subprocess, and three guards
would otherwise pay for it repeatedly.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from typing import List, NamedTuple, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# A real pytest summary line. Its ABSENCE is the tell that the child never got as far as
# collecting anything, whatever the exit code says.
_SUMMARY_RE = re.compile(r"\d+ (?:passed|failed|error|skipped|deselected)")

_CANDIDATES: tuple[List[str], ...] = (
    # The parent's own interpreter. Correct whenever the parent is pytest — which it is,
    # since this module is only imported from tests — and needs nothing on PATH.
    [sys.executable, "-m", "pytest"],
    # A uv-managed environment where the parent somehow is not pytest.
    ["uv", "run", "pytest"],
    # Last resort: whatever pytest is on PATH.
    ["pytest"],
)

_resolved: Optional[List[str]] = None


class ChildNeverRan(RuntimeError):
    """The child process did not reach the point of collecting tests.

    Raised rather than returned so a caller cannot mistake it for a test failure. This
    is the failure mode that made three separate guards look healthy while proving
    nothing.
    """


class ChildResult(NamedTuple):
    returncode: int
    output: str

    @property
    def suite_failed(self) -> bool:
        return self.returncode != 0


def _probe(launcher: List[str]) -> bool:
    """True if this launcher can start pytest at all."""
    try:
        result = subprocess.run(
            [*launcher, "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and "pytest" in (result.stdout + result.stderr).lower()


def resolve_launcher() -> List[str]:
    """The argv prefix that runs pytest in this environment. Cached per process."""
    global _resolved
    if _resolved is not None:
        return _resolved
    for candidate in _CANDIDATES:
        if _probe(candidate):
            _resolved = candidate
            return _resolved
    raise ChildNeverRan(
        "no way to launch a child pytest was found. Tried: "
        + "; ".join(" ".join(c) for c in _CANDIDATES)
        + ". Every end-to-end guard control depends on this, so they cannot be trusted "
        "until it is fixed — do NOT skip them, since a skipped control is the same as a "
        "blind one."
    )


def run_child_suite(
    test_file: str,
    *,
    deselect: tuple[str, ...] = (),
    timeout: float = 600,
) -> ChildResult:
    """Run ONE test file as a child process and return (returncode, combined output).

    ``deselect`` entries are node ids passed to ``--deselect``; a control that re-runs
    its own file must deselect itself or it recurses forever.

    Raises :class:`ChildNeverRan` when the child produced no pytest summary — the case
    that must never be read as "the guard fired".
    """
    launcher = resolve_launcher()
    argv = [*launcher, f"tests/{test_file}", "-q", "--no-header",
            "-p", "no:randomly", "-p", "no:cacheprovider"]
    for node_id in deselect:
        argv += ["--deselect", node_id]
    try:
        completed = subprocess.run(
            argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ChildNeverRan(
            f"the child launcher {launcher!r} vanished between probe and run: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ChildNeverRan(
            f"the child suite did not finish within {timeout}s, so its exit status "
            f"cannot be interpreted: {exc}"
        ) from exc
    output = (completed.stdout or "") + (completed.stderr or "")
    if "No module named pytest" in output:
        raise ChildNeverRan(
            f"the child has no pytest (launcher {launcher!r}), so its non-zero exit "
            f"means nothing:\n{output[-400:]}"
        )
    if not _SUMMARY_RE.search(output):
        raise ChildNeverRan(
            f"the child produced no pytest summary (launcher {launcher!r}, exit "
            f"{completed.returncode}), so it never collected anything and its exit "
            f"status cannot be read as a verdict:\n{output[-400:]}"
        )
    return ChildResult(completed.returncode, output)


# --------------------------------------------------------------------------- #
# The same problem for a plain PYTHON script                                   #
# --------------------------------------------------------------------------- #
# `tests/test_scenarios_execute.py` runs `scenarios/*.py` in a subprocess. It first
# hardcoded ["uv", "run", "python", ...] and died on CI with returncode 255, because CI
# has no `uv` — the FIFTH time this launcher mistake has been made in this repo, and the
# first time inside a test written AFTER the module built to prevent it.
#
# The lesson that keeps not sticking: a helper only prevents the recurrence for the call
# shape it actually exports. `child_pytest` exported "run pytest" and nothing else, so the
# next author (me) needing "run a python script" copied the pattern instead of reusing the
# resolution. Hence this sibling.
_PY_CANDIDATES: tuple[List[str], ...] = (
    # The parent's own interpreter — correct in CI, in a venv, and under `uv run`, and
    # needs nothing on PATH.
    [sys.executable],
    # A uv-managed environment where sys.executable somehow cannot import the package.
    ["uv", "run", "python"],
    ["python3"],
)

_resolved_py: Optional[List[str]] = None


def _probe_python(launcher: List[str]) -> bool:
    """True if this launcher can run python AND import the package under test.

    Importing `sentinel_harness` is part of the probe on purpose: a bare `python3` on PATH
    may exist while having none of the dependencies, and a launcher that starts but cannot
    import turns every scenario into a false failure.
    """
    try:
        result = subprocess.run(
            [*launcher, "-c", "import sentinel_harness"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def resolve_python_launcher() -> List[str]:
    """The argv prefix that runs a repo python script in this environment. Cached."""
    global _resolved_py
    if _resolved_py is not None:
        return _resolved_py
    for candidate in _PY_CANDIDATES:
        if _probe_python(candidate):
            _resolved_py = candidate
            return _resolved_py
    raise ChildNeverRan(
        "no way to launch a child python that can import sentinel_harness was found. "
        "Tried: " + "; ".join(" ".join(c) for c in _PY_CANDIDATES)
    )


def run_python_script(
    relpath: str,
    *,
    env: Optional[dict] = None,
    timeout: float = 600,
) -> subprocess.CompletedProcess:
    """Run a repo-relative python script in a subprocess and return the completed process.

    Raises :class:`ChildNeverRan` when the launcher itself could not start, so "the child
    never ran" can never be mistaken for "the script failed" — the distinction that made
    three separate guards look healthy while proving nothing.
    """
    launcher = resolve_python_launcher()
    run_env = dict(env) if env is not None else None
    try:
        return subprocess.run(
            [*launcher, relpath],
            cwd=REPO_ROOT, capture_output=True, text=True,
            timeout=timeout, env=run_env,
        )
    except FileNotFoundError as exc:
        raise ChildNeverRan(
            f"the python launcher {launcher!r} vanished between probe and run: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ChildNeverRan(
            f"{relpath} did not finish within {timeout}s, so its exit status cannot be "
            f"interpreted: {exc}"
        ) from exc
