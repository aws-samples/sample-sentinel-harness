"""INV-CI-1 — CI installs the whole `test` extra, so no test layer skips silently.
==================================================================================
`.github/workflows/ci.yml` used to install its test dependencies as a hand-copied list:

    pip install -e .
    pip install pytest pytest-randomly coverage ruff==0.15.20 hypothesis

That is five of the `test` extra's nine entries. The two it omitted were **`mcp`** and
**`anyio[trio]`**, and `tests/test_mcp_protocol.py` opens with a module-level
`importorskip("mcp")`. So on every CI run the ENTIRE MCP protocol E2E layer skipped —
7 tests that exercise the one surface an untrusted MCP peer reaches — and CI reported green.

Reproduced, not inferred. A throwaway uv project pinned to exactly CI's dependency list
showed `mcp: ABSENT`, `anyio: ABSENT`, and `test_mcp_protocol.py` collapsing to
`1 skipped`. Local runs reported 6 skips and CI reported 12; **nothing compared the two
numbers**, which is the whole reason this survived. A skip is the one test outcome that
looks identical whether the code is fine, the test is broken, or the test never existed.

The fix is not "add mcp to the list" — that leaves the second source of truth in place, and
the next dependency added to `[test]` would silently fail to reach CI the same way. CI now
installs `-e ".[test]"`, which cannot drift from `pyproject.toml` because it IS
`pyproject.toml`. `ruff` stays separate and pinned so the lint verdict is byte-identical
between pre-commit, `make ci` and CI.

Why this file is a test and not a comment
-----------------------------------------
The defect was invisible for the same reason it was cheap to introduce: nobody reads a
workflow's install step while reviewing a Python change. These assertions run in the suite
that every change already has to pass.

ZERO network, ZERO AWS — this parses two YAML files and one TOML file.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    tomllib = pytest.importorskip(
        "tomli", reason="TOML parsing on 3.10 needs the `tomli` marker-gated dep")

yaml = pytest.importorskip("yaml", reason="pyyaml is a CORE dependency; absence is a bug")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Resolved through the shared helper: a missing workflow FAILS inside a checkout and skips
# in an unpacked sdist (which excludes .github/ on purpose). See tests/repo_infra.py.
from repo_infra import require_workflow  # noqa: E402

CI_YML = require_workflow("workflows", "ci.yml")
RELEASE_YML = require_workflow("workflows", "release.yml")
PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")

# Distribution name -> import name, for the entries whose two names differ.
_IMPORT_NAME = {
    "pytest-randomly": "pytest_randomly",
    "pytest-anyio": "pytest_anyio",
    "anyio": "anyio",
}


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _test_extra() -> list:
    """The `test` extra's requirement strings, from pyproject.toml."""
    data = tomllib.loads(_read(PYPROJECT))
    extras = data["project"].get("optional-dependencies", {})
    assert "test" in extras, (
        f"pyproject.toml has no `test` extra; found {sorted(extras)}. If it was renamed, "
        "this file and both workflows must be updated together."
    )
    return extras["test"]


def _dist_name(requirement: str) -> str:
    """`anyio[trio]>=4.0` -> `anyio`; `tomli>=2.0; python_version<'3.11'` -> `tomli`."""
    return re.split(r"[<>=!;\[\s]", requirement.strip(), maxsplit=1)[0]


def _install_steps(workflow_path: str) -> str:
    """Concatenated `run:` bodies of every step that runs pip."""
    doc = yaml.safe_load(_read(workflow_path))
    bodies = []
    for job in doc.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            run = step.get("run") or ""
            if "pip install" in run:
                bodies.append(run)
    assert bodies, f"{workflow_path} has no pip install step at all"
    return "\n".join(bodies)


# --------------------------------------------------------------------------- #
# The defect itself                                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("workflow", [CI_YML, RELEASE_YML],
                         ids=["ci.yml", "release.yml"])
def test_the_workflow_installs_the_test_extra(workflow):
    """Both workflows must install `.[test]`, not a hand-copied subset.

    `release.yml` matters as much as `ci.yml`: the release gate is the last place a
    silently narrowed test run should go unnoticed.
    """
    body = _install_steps(workflow)
    assert re.search(r"pip install\s+-e\s+[\"']?\.\[test\]", body), (
        f"{os.path.basename(workflow)} does not install the `test` extra. A hand-copied "
        "dependency list is a second source of truth that nothing reconciles — the last "
        "one omitted `mcp` and `anyio`, and the whole MCP protocol E2E layer skipped in "
        f"CI while reporting green.\n\ninstall steps:\n{body}"
    )


@pytest.mark.parametrize("workflow", [CI_YML, RELEASE_YML],
                         ids=["ci.yml", "release.yml"])
def test_every_test_extra_dep_is_importable_in_the_installed_env(workflow):
    """CONTROL, and the assertion that actually bites.

    The check above is textual — it proves the workflow *says* `[test]`. This one proves
    the extra's contents are really importable in the environment running this suite. If
    the extra listed a package that does not exist, or one whose import name we got wrong,
    the textual check would still pass while tests skipped exactly as before.

    Skipped rather than failed when a dep is genuinely absent, because a contributor
    running a bare `pip install -e . && pytest` should get a clear instruction, not a
    mysterious red. CI has no such excuse: the workflow's own install step ends with an
    explicit `python -c "import mcp, anyio, ..."` that fails the job loudly.
    """
    del workflow  # the parametrisation only exists to name both files in the report
    missing = []
    for requirement in _test_extra():
        dist = _dist_name(requirement)
        if ";" in requirement and "python_version" in requirement:
            continue  # marker-gated (tomli on 3.10 only) — not expected everywhere
        module = _IMPORT_NAME.get(dist, dist.replace("-", "_"))
        if importlib_find(module) is None:
            missing.append(f"{dist} (import {module})")
    if missing:
        pytest.skip(
            "the `test` extra is not fully installed here: " + ", ".join(missing)
            + " — run `pip install -e '.[test]'`. CI installs it and asserts the imports."
        )
    assert not missing


def importlib_find(module: str):
    import importlib.util
    try:
        return importlib.util.find_spec(module)
    except (ImportError, ValueError):  # namespace / broken parent package
        return None


def test_ci_fails_loudly_if_an_optional_dep_is_absent():
    """The install step must END with an import check.

    Without it, a resolver hiccup that drops `mcp` degrades to "12 skipped" — the exact
    failure mode this file exists for, re-entering through a different door. The rule from
    `~/.claude/rules/degradation-and-guards.md`: "检查失败" and "检查通过" must not look
    the same.
    """
    body = _install_steps(CI_YML)
    assert re.search(r"python -c .{0,80}import mcp", body), (
        "ci.yml's install step has no post-install import assertion, so a dependency that "
        f"fails to install would surface as a SKIP, not a failure:\n{body}"
    )


def test_ruff_stays_pinned_outside_the_extra():
    """CONTROL for the fix's shape.

    Moving to `[test]` must not sweep `ruff` in with it. The lint verdict has to be
    byte-identical between pre-commit, `make ci` and CI, which requires an exact pin that
    a `>=` range in an extra cannot give. If a future change adds ruff to the extra, this
    is where the trade-off gets re-argued.
    """
    body = _install_steps(CI_YML)
    assert re.search(r"pip install ruff==\d+\.\d+", body), (
        f"ruff is no longer installed at an exact pin in ci.yml:\n{body}"
    )
    assert not any(_dist_name(r) == "ruff" for r in _test_extra()), (
        "ruff was added to the `test` extra. It is deliberately pinned separately so the "
        "lint verdict cannot differ between local and CI — see the comment in ci.yml."
    )


# --------------------------------------------------------------------------- #
# The general case: the convention that broke, turned into a check            #
# --------------------------------------------------------------------------- #
def test_every_async_test_file_pins_a_backend():
    """Any file using `pytest.mark.anyio` must define its own `anyio_backend` fixture.

    This is the OTHER half of the same round. `tests/test_mcp_protocol.py` did two things
    to make its async tests work — a module-level `importorskip("mcp")` and a local
    `anyio_backend` fixture returning "asyncio" — and when I wrote a new async test file
    beside it I carried neither. The symptom is not a helpful "fixture not found": pytest
    reports `async def functions are not natively supported` and FAILS.

    Two reasons the fixture must be local rather than inherited from anyio's plugin:
    anyio's own `anyio_backend` is parametrised over every installed backend, so async
    tests would silently run twice (asyncio AND trio); and a file that pins it states which
    event loop its assertions were actually verified under.

    "A fix applied to one call site is not an invariant" — the shape this repo has recorded
    more than any other, here landing on a TESTING CONVENTION. That is exactly the kind of
    thing that needs a check rather than a comment, because nobody greps for conventions.
    """
    tests_dir = os.path.join(REPO_ROOT, "tests")
    offenders = []
    checked = []
    for name in sorted(os.listdir(tests_dir)):
        if not name.startswith("test_") or not name.endswith(".py"):
            continue
        source = _read(os.path.join(tests_dir, name))
        if "pytest.mark.anyio" not in source:
            continue
        checked.append(name)
        if "def anyio_backend(" not in source:
            offenders.append(name)

    # Positive control: a scan that finds nothing is indistinguishable from a broken scan.
    assert checked, (
        "this guard found NO async test files at all, so it proved nothing. Either the "
        "async tests were renamed/removed (update this guard) or the detection is broken."
    )
    assert not offenders, (
        f"async test file(s) using pytest.mark.anyio without their own `anyio_backend` "
        f"fixture: {offenders}. Add `@pytest.fixture def anyio_backend(): return "
        f'"asyncio"` — otherwise pytest fails with "async def functions are not natively '
        f'supported", which reads like a missing plugin rather than a missing fixture. '
        f"(scanned {len(checked)} async file(s): {checked})"
    )
