"""INV-DOC-5 — the coverage-doc guard actually RUNS in CI, and cannot skip there.

`tests/test_coverage_doc.py` re-measures every figure in `tests/README-coverage.md` against
real coverage data. It exists because five of that table's rows were once wrong by 16 to 61
points, every one understating the truth.

**It never ran in CI.** CI's test step is `coverage run -m pytest tests`, and `coverage`
writes `.coverage` only when it EXITS — so while the suite is running there is no data file,
and those three assertions called `pytest.skip`. They executed on maintainer laptops (where
`make ci` had already produced the file) and skipped on every CI run. The guard that keeps
the coverage doc honest was only ever verified on the machine of the person who might have
let it drift.

Measured, not inferred: replicating CI's exact invocation locally reproduces `SKIPPED [3]`.

This is INV-CI-1's shape a second time — a check that silently no-ops precisely where it
matters — which is why the fix is two-part and both parts are asserted here:

1. `ci.yml` runs the module as a dedicated step AFTER `coverage report`, when the data exists.
2. That step sets `SENTINEL_REQUIRE_COVERAGE_DATA=1`, under which absent/stale data RAISES
   instead of skipping. Without part 2, a later change to the data-file path would quietly
   restore the no-op and the new step would still report green — fixing the symptom while
   leaving the failure mode intact.

Why a separate file: `test_coverage_doc.py` is the thing under test here. A guard living
inside the module it guards shares its fate — if that module stopped being collected, an
in-file assertion would vanish with it, while this one keeps failing.

ZERO network, ZERO AWS.
"""
from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a CORE dependency; absence is a bug")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI_YML = os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")
GUARD_MODULE = os.path.join(REPO_ROOT, "tests", "test_coverage_doc.py")
REQUIRE_ENV = "SENTINEL_REQUIRE_COVERAGE_DATA"


def _ci() -> dict:
    with open(CI_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _test_job_steps() -> list:
    doc = _ci()
    job = doc["jobs"]["test"]
    steps = job.get("steps") or []
    assert steps, "the `test` job has no steps"
    return steps


def _step_running_the_guard() -> dict:
    """The step that invokes tests/test_coverage_doc.py explicitly."""
    for step in _test_job_steps():
        run = step.get("run") or ""
        if "test_coverage_doc.py" in run:
            return step
    raise AssertionError(
        "no step in ci.yml's `test` job runs tests/test_coverage_doc.py explicitly. "
        "It cannot rely on the main `coverage run -m pytest tests` step: that step has not "
        "written `.coverage` yet, so the module's assertions SKIP. This is exactly the "
        "defect INV-DOC-5 records — re-add the dedicated step after `coverage report`."
    )


def test_ci_runs_the_coverage_doc_guard_as_its_own_step():
    """Part 1 of the fix: the step exists at all."""
    step = _step_running_the_guard()
    assert "pytest" in (step.get("run") or ""), (
        f"the step naming test_coverage_doc.py does not invoke pytest: {step.get('run')!r}"
    )


def test_that_step_forbids_skipping():
    """Part 2, and the half that keeps the fix from decaying.

    A dedicated step that is still allowed to skip is a step that reports green while
    checking nothing — the same failure wearing a different hat.
    """
    step = _step_running_the_guard()
    env = step.get("env") or {}
    assert REQUIRE_ENV in env, (
        f"the coverage-doc step does not set {REQUIRE_ENV}, so a missing or stale "
        f".coverage would make it SKIP and still pass. Step env: {sorted(env)}"
    )
    value = str(env[REQUIRE_ENV]).strip().lower()
    assert value in ("1", "true", "yes", "on"), (
        f"{REQUIRE_ENV} is set to {env[REQUIRE_ENV]!r}, which the helper does not treat as "
        "truthy — the skip would still be allowed. Use \"1\"."
    )


def test_the_guard_step_comes_after_the_coverage_gate():
    """Ordering is load-bearing, not cosmetic.

    `.coverage` exists only once `coverage run` has exited. Placed before the main test step,
    this would read a STALE file from an earlier job (or none at all) — verifying the doc
    against numbers that are not this run's.
    """
    steps = _test_job_steps()
    names = [(s.get("name") or "") for s in steps]
    runs = [(s.get("run") or "") for s in steps]

    guard_idx = next(i for i, r in enumerate(runs) if "test_coverage_doc.py" in r)
    measure_idx = next(i for i, r in enumerate(runs)
                       if "coverage run" in r and "pytest" in r)
    assert guard_idx > measure_idx, (
        f"the coverage-doc step (index {guard_idx}, {names[guard_idx]!r}) runs BEFORE the "
        f"measuring step (index {measure_idx}, {names[measure_idx]!r}). `.coverage` does not "
        "exist yet at that point, so it would verify the doc against stale or absent data."
    )


def test_the_helper_honours_the_env_var():
    """The PREMISE, checked against the code rather than trusted.

    A workflow that sets a variable no code reads is theatre. This asserts the module really
    branches on it — the guard-the-guard rule, applied to my own fix.
    """
    with open(GUARD_MODULE, encoding="utf-8") as fh:
        source = fh.read()
    assert REQUIRE_ENV in source, (
        f"tests/test_coverage_doc.py never mentions {REQUIRE_ENV}, so ci.yml sets a variable "
        "nothing reads and the skip is still reachable in CI."
    )
    assert re.search(r"raise AssertionError", source), (
        "the module reads the env var but never raises, so the 'must not skip' contract is "
        "unenforced."
    )
    # And that the skip is routed through ONE helper rather than open-coded per call site —
    # "a fix applied to one call site is not an invariant", the shape this repo records most.
    assert source.count("pytest.skip(") <= 1, (
        "there is more than one bare `pytest.skip(` in test_coverage_doc.py. Every "
        "unavailable-data path must go through `_unavailable()`, or one of them will keep "
        "skipping in CI while the others fail."
    )


@pytest.mark.parametrize("truthy", ["1", "true", "YES", "on"])
def test_the_truthy_parsing_accepts_the_usual_spellings(truthy):
    """CONTROL for the flag itself. `bool("false")` is True in Python, and this repo has
    recorded that trap (INV-COERCE) three times — so the parsing is asserted, not assumed."""
    import importlib

    spec = importlib.util.spec_from_file_location("coverage_doc_probe", GUARD_MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    os.environ[REQUIRE_ENV] = truthy
    try:
        with pytest.raises(AssertionError):
            mod._unavailable("probe reason")
    finally:
        os.environ.pop(REQUIRE_ENV, None)


@pytest.mark.parametrize("falsey", ["0", "false", "no", "", "off"])
def test_a_falsey_flag_still_skips(falsey):
    """The other half: a developer with `SENTINEL_REQUIRE_COVERAGE_DATA=0` must get the
    friendly skip, not a failure. Over-strictness gets routed around."""
    import importlib

    spec = importlib.util.spec_from_file_location("coverage_doc_probe2", GUARD_MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    os.environ[REQUIRE_ENV] = falsey
    try:
        with pytest.raises(BaseException) as exc:
            mod._unavailable("probe reason")
        assert exc.typename in ("Skipped", "OutcomeException"), (
            f"a falsey {REQUIRE_ENV}={falsey!r} raised {exc.typename} instead of skipping"
        )
    finally:
        os.environ.pop(REQUIRE_ENV, None)
