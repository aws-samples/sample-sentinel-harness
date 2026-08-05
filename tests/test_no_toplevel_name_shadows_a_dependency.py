"""INV-PKG-1 — no top-level directory shadows an installed dependency's import name.

The repo shipped a top-level `litellm/` directory containing `litellm/gateway/`, and `litellm`
is also a **PyPI package this project's own specialist containers install**
(`strands-agents[a2a,litellm]==1.9.1`). There was no `litellm/__init__.py`, so it resolved as
a *namespace* package — and a regular package always wins over a namespace package.

Consequence, reproduced rather than reasoned about:

    no litellm installed   litellm.gateway -> OK  (namespace pkg, our directory)
    litellm installed      litellm.gateway -> ModuleNotFoundError

The gateway's whole purpose is to be the one audited chokepoint a **specialist** points at for
inference — and every specialist container installs the real `litellm`. So the module could not
be imported in the only environment it was built for, and its README's
`from litellm.gateway import InferenceGateway` was an example that fails for anyone who
follows it.

Why nothing caught it
---------------------
`litellm` is declared in **no extra** — not `test`, not `mcp`, nowhere. So the five
`importorskip("litellm")` / `importorskip("strands")` tests skipped in *every* environment,
local and CI alike. This is one step worse than INV-CI-1 (where the dep was declared but CI
installed a hand-copied subset): here the dependency was never installable by the suite at
all, so the tests could not run anywhere.

The skip was not hiding a stale test. It was hiding a namespace collision that breaks the
module in production — the same lesson as INV-MCP-5, reached by a different route: **a test
that never runs cannot report a broken contract.**

Fixed by moving the package to `sentinel_inference_gateway/`, a name carrying the project
prefix precisely because the root cause was an unprefixed top-level name colliding with PyPI.

ZERO network, ZERO AWS: this reads the filesystem and one requirements file.
"""
from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that are not importable Python package names, so they cannot shadow anything:
# hyphens/dots are illegal in an import name, and these are data/infra trees.
_NOT_IMPORT_NAMES = re.compile(r"[-.]")

# Build/vendor output and non-package trees. `site` is on this list for a REASON worth
# recording, because it looks alarming: it collides with the stdlib `site` module, which the
# interpreter imports automatically at STARTUP — a far worse collision than the `litellm` one
# if it were real. Measured instead of assumed: `site/` holds only `index.html`, no `.py` file
# at all, so it never becomes even a namespace package and `import site` still resolves to the
# stdlib (verified with `sys.path[0] == ''` from the repo root, the worst case). If a `.py`
# file is ever added under `site/`, `test_no_python_files_under_the_site_directory` below fails
# — the shadowing only starts mattering at that moment.
_IGNORED = {
    "__pycache__", "build", "site", "dist", "node_modules", "venv",
    "sentinel_harness.egg-info",
}

# Import names of third-party packages this project installs ANYWHERE: its own extras, and the
# per-specialist container requirements. A top-level directory matching one of these shadows it.
#
# Deliberately includes the CONTAINER requirements, not just pyproject's. The collision that
# motivated this file was invisible from pyproject alone: `litellm` appears there in no form —
# it arrives via `strands-agents[a2a,litellm]` in each specialist's requirements.txt. A guard
# reading only pyproject would have reported all-clear on the exact defect it exists to catch.
_KNOWN_DEPENDENCY_IMPORT_NAMES = {
    # from pyproject (core + extras)
    "boto3", "botocore", "yaml", "pytest", "hypothesis", "coverage", "mcp", "anyio",
    "trio", "tomli",
    # from specialists/*/requirements.txt
    "strands", "litellm", "bedrock_agentcore", "fastapi", "uvicorn", "starlette",
    "httpx", "pydantic", "a2a",
}


def _toplevel_package_dirs() -> set:
    """Top-level directories whose names are legal Python import names."""
    found = set()
    for name in os.listdir(REPO_ROOT):
        if name.startswith(".") or name in _IGNORED:
            continue
        if not os.path.isdir(os.path.join(REPO_ROOT, name)):
            continue
        if _NOT_IMPORT_NAMES.search(name):
            continue  # `iac-cdk`, `iac-terraform` — not importable, cannot shadow
        found.add(name)
    return found


def test_the_scan_sees_the_repo_layout():
    """Positive control. Every assertion below is a set difference; if this came back empty
    they would all hold vacuously and the module would be decoration."""
    dirs = _toplevel_package_dirs()
    assert len(dirs) >= 8, (
        f"only found {len(dirs)} importable top-level directories: {sorted(dirs)}. The layout "
        "changed and this guard is now blind."
    )
    # And that the sentinel directory this guard was written for is actually present.
    assert "sentinel_harness" in dirs, sorted(dirs)


def test_no_toplevel_directory_shadows_a_dependency():
    """The defect itself.

    A top-level directory whose name matches an installed distribution's import name shadows
    it — or gets shadowed BY it, which is the direction that bit here, because a regular
    package outranks a namespace package.
    """
    collisions = sorted(_toplevel_package_dirs() & _KNOWN_DEPENDENCY_IMPORT_NAMES)
    assert not collisions, (
        f"top-level directory/directories collide with an installed dependency's import "
        f"name: {collisions}.\n\n"
        "Whichever is a REGULAR package (has __init__.py) wins; a namespace package always "
        "loses. `litellm/gateway/` was reachable locally and vanished the moment the real "
        "`litellm` was installed — which every specialist container does, so the module was "
        "broken in the only environment it targeted.\n\n"
        "Rename with a project prefix (see `sentinel_inference_gateway/`)."
    )


def test_every_toplevel_package_dir_is_a_regular_package_or_not_importable():
    """The mechanism, not just the one instance.

    A directory intended as a Python package must carry `__init__.py`. Relying on namespace-
    package resolution is what made the collision silent AND environment-dependent: it worked
    on a laptop and failed in a container, the hardest failure to reason about.

    Directories that are plainly data/config trees are exempt — they are never imported.
    """
    data_trees = {
        "assets", "demo", "deploy", "docs", "eval", "evidence", "harnesses", "intake",
        "mockdata", "registry", "rules", "skills", "specialists", "longrunning",
        "scenarios", "tests", "tools", "iac", "litellm",
    }
    offenders = []
    for name in sorted(_toplevel_package_dirs() - data_trees):
        init = os.path.join(REPO_ROOT, name, "__init__.py")
        if not os.path.isfile(init):
            offenders.append(name)
    assert not offenders, (
        f"top-level importable directory/directories with no __init__.py: {offenders}. "
        "They resolve as NAMESPACE packages, which any installed regular package of the same "
        "name silently outranks. Add `__init__.py` (or move the tree under an existing "
        "package)."
    )


def test_the_gateway_is_importable_under_its_new_name():
    """Regression: the module the collision broke must import, and expose its API.

    Deliberately a real import rather than a path check — the defect was that
    `importlib.import_module` failed while the files sat right there on disk.
    """
    import importlib

    mod = importlib.import_module("sentinel_inference_gateway")
    assert hasattr(mod, "InferenceGateway"), (
        f"sentinel_inference_gateway exposes no InferenceGateway: {dir(mod)}"
    )
    assert hasattr(mod, "complete"), "the module-level `complete` convenience is missing"
    # A REGULAR package now — the property whose absence made the old location losable.
    assert getattr(mod, "__file__", None), (
        "sentinel_inference_gateway resolved as a namespace package (no __file__), so an "
        "installed package of the same name could shadow it again."
    )


def test_the_old_colliding_path_is_gone():
    """The rename must not leave the shadowed copy behind.

    Two copies would be worse than the original defect: local runs would keep importing the
    old path and the collision would stay invisible in exactly the environment that tests it.
    """
    stale = os.path.join(REPO_ROOT, "litellm")
    assert not os.path.exists(stale), (
        f"{stale} still exists. It shadows/gets shadowed by the real `litellm` package; the "
        "gateway now lives in sentinel_inference_gateway/."
    )


@pytest.mark.parametrize("specialist", ["cve-intel", "attack-mapper", "threat-hunt",
                                        "adversarial-reviewer"])
def test_the_container_requirements_still_pull_litellm(specialist):
    """The PREMISE of this whole guard, asserted rather than assumed.

    The collision only matters because the containers really do install `litellm`. If they
    stopped, this file's reasoning would be stale — and a guard whose premise has quietly
    expired is worse than none, because it argues for a constraint nobody can justify.
    """
    path = os.path.join(REPO_ROOT, "specialists", specialist, "requirements.txt")
    assert os.path.isfile(path), f"{specialist} has no requirements.txt"
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    # COMMENTS ARE STRIPPED FIRST, and that is the point. My first version was
    # `assert "litellm" in text`, and mutation-testing showed "drop the litellm extra from
    # strands-agents" SURVIVING — the file carries a comment explaining what the a2a + litellm
    # extras do, so the substring was still present after the dependency itself was gone.
    # Substring matching standing in for structural judgement: the defect class this repo has
    # recorded more than any other, here inside a guard I had just written to catch another one.
    requirements = [ln.split("#", 1)[0].strip() for ln in lines]
    requirements = [ln for ln in requirements if ln]

    installing = [ln for ln in requirements if "litellm" in ln]
    assert installing, (
        f"{specialist}/requirements.txt has no REQUIREMENT line pulling litellm "
        f"(comments ignored). Actual requirements: {requirements}\n"
        "If the specialists no longer install it, the shadowing risk for that name is gone — "
        "update _KNOWN_DEPENDENCY_IMPORT_NAMES and this file's rationale together."
    )

# --------------------------------------------------------------------------- #
# The CI job that makes these tests runnable at all                           #
# --------------------------------------------------------------------------- #
def _ci_jobs() -> dict:
    yaml_mod = pytest.importorskip("yaml")
    path = os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")
    with open(path, encoding="utf-8") as fh:
        return yaml_mod.safe_load(fh)["jobs"]


def test_ci_has_a_job_that_installs_the_real_stack():
    """Without this job, `importorskip("strands")` skips in CI exactly as it always did.

    The fix for INV-PKG-1 is two halves: move the colliding package (done above), and make the
    tests that would have caught it actually RUN. Guarding only the first half would leave the
    next shadowing bug just as invisible.
    """
    jobs = _ci_jobs()
    matching = [
        name for name, job in jobs.items()
        if any("strands-agents" in (s.get("run") or "") for s in job.get("steps") or [])
    ]
    assert matching, (
        f"no CI job installs the real specialist stack. Jobs: {sorted(jobs)}. Without one, the "
        "ten importorskip('strands'/'litellm') calls skip in every environment — which is how "
        "the litellm namespace collision survived undetected."
    )


def test_that_job_pins_the_same_version_the_containers_pin():
    """A job testing a DIFFERENT version than ships is worse than none: it would report green
    against a stack no deployment uses, and this repo has already recorded the cost of that
    (INV-MCP-5 — `mcp>=1.0` unbounded, CI resolved 2.0, production could not start)."""
    jobs = _ci_jobs()
    runs = " ".join(
        s.get("run") or ""
        for job in jobs.values() for s in job.get("steps") or []
    )
    ci_pins = set(re.findall(r"strands-agents\[[^\]]*\]==([0-9][0-9.]*)", runs))
    assert ci_pins, f"no pinned strands-agents install found in ci.yml: {runs[:300]}"

    container_pins = set()
    for specialist in ("cve-intel", "attack-mapper", "threat-hunt", "adversarial-reviewer"):
        path = os.path.join(REPO_ROOT, "specialists", specialist, "requirements.txt")
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                m = re.match(r"strands-agents\[[^\]]*\]==([0-9][0-9.]*)", line)
                if m:
                    container_pins.add(m.group(1))
    assert container_pins, "no specialist requirements.txt pins strands-agents"
    assert ci_pins == container_pins, (
        f"CI installs strands-agents {sorted(ci_pins)} but the containers pin "
        f"{sorted(container_pins)}. The job would validate a stack that never ships."
    )


def test_that_job_treats_a_skip_as_a_failure():
    """The half that keeps the fix from decaying.

    If the heavy deps fail to resolve, every test in that job reports "skipped" and the job
    goes green — restoring the exact condition that hid the collision. INV-DOC-5 recorded the
    same trap one round earlier: a dedicated step still allowed to skip is the same failure
    wearing a different hat.
    """
    jobs = _ci_jobs()
    for name, job in jobs.items():
        steps = job.get("steps") or []
        if not any("strands-agents" in (s.get("run") or "") for s in steps):
            continue
        body = " ".join(s.get("run") or "" for s in steps)
        assert "skipped" in body and "exit 1" in body, (
            f"job {name!r} installs the real stack but does not fail on a SKIP. If strands or "
            "litellm silently fail to resolve, every test skips and the job reports green — "
            f"verifying nothing. Step bodies:\n{body[:500]}"
        )
        return
    pytest.fail("no real-stack job found (the previous test should have caught this)")

def test_no_python_files_under_the_site_directory():
    """`site/` is exempted from the shadowing scan, so the exemption needs its own guard.

    `site` is the stdlib module the interpreter imports at STARTUP to set up `sys.path` and
    site-packages. Today `site/` is a published landing page containing only `index.html`, so
    it cannot shadow anything — a directory with no `.py` file is not even a namespace package.
    Verified from the repo root with `sys.path[0] == ''`: `import site` still resolves to the
    stdlib.

    But that safety is a property of the directory's CONTENTS, not of its name. The moment
    someone adds a `.py` file there, the exemption in `_IGNORED` becomes a hole in a guard
    whose whole subject is name shadowing — and the failure would appear at interpreter
    startup, before any test could report it.

    This is the "lint-excluded directory = never-cleaned directory" rule from the project's
    degradation rules, applied to a test exemption: an exemption without its own check is a
    permanent blind spot.
    """
    site_dir = os.path.join(REPO_ROOT, "site")
    if not os.path.isdir(site_dir):
        pytest.skip("no site/ directory in this checkout")

    python_files = []
    for root, _dirs, files in os.walk(site_dir):
        python_files.extend(os.path.join(root, f) for f in files if f.endswith(".py"))

    assert not python_files, (
        f"site/ now contains Python file(s): {python_files}. `site` is the STDLIB module the "
        "interpreter imports automatically at startup, so a top-level `site/` package can "
        "shadow it and break the interpreter before any test runs. Either move these files or "
        "rename the directory (and remove `site` from _IGNORED above)."
    )
