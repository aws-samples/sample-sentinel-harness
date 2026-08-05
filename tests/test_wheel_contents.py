"""INV-PKG-2 — the built wheel contains exactly the tools that exist on disk.

A wheel built locally shipped **21 tool handlers** while `tools/` held 20, and the extra one
was `tools/whitelist_optimizer/` — a directory **deleted** in the previous round's
inclusive-language rename. Reproduced end to end: installing that wheel put the deleted
handler back on disk.

Root cause: setuptools stages the package tree into `build/lib/` and copies FROM there. It
never prunes entries whose source has been removed, so `build/lib/tools/` held BOTH
`allowlist_optimizer/` (new) and `whitelist_optimizer/` (deleted) and the wheel got both.
`make clean` did not remove `build/`, so the stale copy survived every clean and every rebuild.

Why this is a security defect and not untidiness
-----------------------------------------------
The ghost tool is not exposed by MCP today, and the reason is worth stating: INV-MCP-1's
governance gate requires a registry entry, and a deleted tool has none. **That gate caught it**
— defence in depth working as intended.

The danger is still real:

- `SENTINEL_MCP_ALLOW_PENDING=1` (the documented dev escape hatch) bypasses the gate, and
  would expose code nobody maintains or patches any more.
- Generally: **any deleted tool comes back this way.** If a tool were removed *because* of a
  vulnerability, the removal silently would not take effect in the artifact.

Why nothing caught it
---------------------
`test_packaging.py` checks the packaging CONFIG — that `find.include` covers the right trees,
that `namespaces` is on, that the registry is declared as package data. Every assertion reads
`pyproject.toml`. None of them build anything, so none could see that the artifact disagreed
with the source tree.

INV-MCP-2 guards the same coupling in the OTHER direction — "is the registry present in the
wheel?" — after the wheel was found to omit `registry/`. This is "does the wheel contain things
that should not be there?", and the asymmetry is why one was guarded and the other was not.

Cost: this module BUILDS a wheel, which takes a few seconds. That is why it is one module with
a session-scoped fixture rather than a check bolted onto `test_packaging.py`.

ZERO network (the build resolves nothing — `uv build` uses the local backend), ZERO AWS.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a CORE dependency; absence is a bug")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")


def _build_launcher() -> list:
    """An argv prefix that can build a wheel, PROBED for the capability it will actually use.

    Seventh occurrence in this repo of a hardcoded/mis-probed tool launcher, and my first
    version here repeated the mistake in a new way: it probed `candidate[:1] --version`, i.e.
    `python --version` for the `python -m build` candidate. That always succeeds, so the
    function returned a launcher whose `build` module was not installed — CI failed on all four
    Pythons with `No module named build` while the local run was green (uv is installed here,
    so the first candidate won and the broken fallback was never exercised).

    **A probe must exercise the capability, not its host.** `python --version` says nothing
    about whether `python -m build` works. Each candidate is now invoked in the same form it
    will be used, and its output is checked.
    """
    candidates = [
        (["uv", "build"], ["uv", "build", "--help"]),
        ([sys.executable, "-m", "build"], [sys.executable, "-m", "build", "--version"]),
    ]
    for launcher, probe_argv in candidates:
        if shutil.which(launcher[0]) is None and launcher[0] != sys.executable:
            continue
        try:
            probe = subprocess.run(probe_argv, cwd=REPO_ROOT, capture_output=True,
                                   text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return launcher
    return []


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory) -> str:
    """Build a wheel into a temp dir and return its path.

    Built from a **pristine copy** of the tree, not from the repo itself. Two reasons, both
    learned the hard way:

    1. Building in-place would create/refresh `build/` and `*.egg-info` in the working tree as
       a side effect of running the tests — a test that mutates the repo it is testing.
    2. More importantly, this test must measure what the SOURCE says, not what a stale local
       `build/lib/` says. If it built in-place it would inherit the very staleness it exists to
       detect, and would have passed on the defect that motivated it.
    """
    launcher = _build_launcher()
    if not launcher:
        # Skip locally, FAIL in CI. Same treatment as INV-DOC-5's coverage data: a packaging
        # guard that skips where merges are gated has verified nothing, and would have reported
        # green on the very defect it exists to catch. ci.yml installs `build` and asserts the
        # import, so reaching this branch there means the install regressed.
        if os.environ.get("CI", "").strip().lower() in ("1", "true", "yes", "on"):
            raise AssertionError(
                "no wheel builder found (tried `uv build`, `python -m build`) but CI=1. "
                "ci.yml must `pip install build`; without a builder these assertions cannot "
                "run, and INV-PKG-2 would be unverified in the one place that gates merges."
            )
        pytest.skip("no way to build a wheel was found (tried `uv build`, `python -m build`)")

    src = tmp_path_factory.mktemp("src") / "repo"
    # copytree with an ignore list rather than `git archive`: this must work in a dirty tree
    # too, since the point is to check what WOULD be shipped from the current source.
    shutil.copytree(
        REPO_ROOT, src,
        ignore=shutil.ignore_patterns(
            ".git", "build", "dist", "*.egg-info", "__pycache__", ".venv", "node_modules",
            ".pytest_cache", ".ruff_cache", ".hypothesis", "cdk.out", ".terraform",
        ),
    )
    out = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run([*launcher, "--wheel", "-o", str(out)] if launcher[0] == "uv"
                          else [*launcher, "--wheel", "--outdir", str(out), str(src)],
                          cwd=src, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, (
        f"wheel build failed:\n{(proc.stdout + proc.stderr)[-2000:]}"
    )
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {[w.name for w in wheels]}"
    return str(wheels[0])


def _wheel_handlers(wheel: str) -> set:
    with zipfile.ZipFile(wheel) as zf:
        return {
            name.split("/")[1]
            for name in zf.namelist()
            if name.startswith("tools/") and name.endswith("/handler.py")
        }


def _disk_handlers() -> set:
    return {
        name for name in os.listdir(TOOLS_DIR)
        if os.path.isfile(os.path.join(TOOLS_DIR, name, "handler.py"))
    }


def test_the_build_produced_something_measurable(built_wheel):
    """Positive control. Every assertion below is a set comparison; two empty sets are equal,
    so a build that produced an empty wheel would make this module vacuously green."""
    handlers = _wheel_handlers(built_wheel)
    assert len(handlers) >= 15, (
        f"the wheel contains only {len(handlers)} tool handlers: {sorted(handlers)}. Either "
        "packaging broke or this check is now blind."
    )


def test_the_wheel_ships_no_tool_that_is_absent_from_the_source_tree(built_wheel):
    """The defect. A wheel carrying a DELETED handler puts dead code back on disk.

    Not exposed by MCP today (INV-MCP-1's governance gate needs a registry entry, and a deleted
    tool has none) — but `SENTINEL_MCP_ALLOW_PENDING=1` bypasses that gate, and a tool removed
    because of a vulnerability would silently keep shipping.
    """
    ghosts = sorted(_wheel_handlers(built_wheel) - _disk_handlers())
    assert not ghosts, (
        f"the wheel ships tool handler(s) that no longer exist in tools/: {ghosts}.\n\n"
        "setuptools stages into build/lib/ and copies FROM it without pruning deleted "
        "entries, so a stale build/ resurrects removed modules. Run `make clean` (which now "
        "removes build/) or `make dist`, which builds from a clean tree.\n\n"
        "Measured once already: after the whitelist_optimizer -> allowlist_optimizer rename a "
        "local wheel carried 21 handlers including the deleted one, and installing it put that "
        "code back on disk."
    )


def test_every_tool_on_disk_reaches_the_wheel(built_wheel):
    """The other direction, and the reason `find.include` has `tools*`.

    A tool missing from the wheel fails at RUNTIME with `tool handler not found` for anyone who
    installed rather than cloned — the packaging failure mode INV-MCP-2 records.
    """
    missing = sorted(_disk_handlers() - _wheel_handlers(built_wheel))
    assert not missing, (
        f"tool(s) present in tools/ but absent from the wheel: {missing}. An installed user "
        "would get `tool handler not found` at runtime."
    )


def test_the_wheel_agrees_with_the_registry(built_wheel):
    """Cross-check against governance, not just against the filesystem.

    The two checks above compare the wheel with `tools/`. This compares it with the registry,
    which is what actually decides whether a tool may run. A wheel and a registry that disagree
    is how a tool becomes exposed-but-unapproved or approved-but-missing.
    """
    with open(os.path.join(REPO_ROOT, "registry", "tools.yaml"), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    entries = data if isinstance(data, list) else data.get("tools", data)
    registry_names = {e["name"] for e in entries if isinstance(e, dict) and "name" in e}
    assert len(registry_names) >= 15, f"parsed only {len(registry_names)} registry entries"

    in_wheel = _wheel_handlers(built_wheel)
    unknown = sorted(in_wheel - registry_names)
    assert not unknown, (
        f"the wheel ships handler(s) the registry does not name: {unknown}. Every shipped tool "
        "must carry a governance decision — even `status: pending` — so that nothing runs, or "
        "can be made to run with SENTINEL_MCP_ALLOW_PENDING=1, without one."
    )


def test_the_packaged_registry_copy_is_present_and_current(built_wheel):
    """INV-MCP-2, re-checked against the ARTIFACT rather than against pyproject.

    `test_packaging.py` asserts the registry is *declared* as package data and that the two
    source copies match. Neither statement proves the file reached the wheel — and the original
    INV-MCP-2 defect was precisely a wheel that omitted `registry/`, making
    `pip install && sentinel-mcp` fail open from any directory outside a checkout.
    """
    with zipfile.ZipFile(built_wheel) as zf:
        names = zf.namelist()
        packaged = [n for n in names if n.endswith("data/tools.yaml")]
        assert packaged, (
            f"the wheel ships no sentinel_harness/data/tools.yaml. Without it an installed "
            f"sentinel-mcp cannot read the registry. YAML files present: "
            f"{[n for n in names if n.endswith('.yaml')]}"
        )
        shipped = yaml.safe_load(zf.read(packaged[0]))

    with open(os.path.join(REPO_ROOT, "registry", "tools.yaml"), encoding="utf-8") as fh:
        source = yaml.safe_load(fh)

    def _names(doc):
        entries = doc if isinstance(doc, list) else doc.get("tools", doc)
        return {e["name"] for e in entries if isinstance(e, dict) and "name" in e}

    assert _names(shipped) == _names(source), (
        f"the registry inside the wheel names different tools than registry/tools.yaml.\n"
        f"  only in wheel : {sorted(_names(shipped) - _names(source))}\n"
        f"  only in source: {sorted(_names(source) - _names(shipped))}"
    )


def test_make_clean_removes_the_build_directory():
    """The fix's other half, asserted so it cannot quietly regress.

    `make clean` did not remove `build/`, which is why the stale staging tree survived
    indefinitely. A cleaner that leaves the one directory responsible for stale artifacts is
    the "lint-exempt directory = never-cleaned directory" rule in a different costume.
    """
    with open(os.path.join(REPO_ROOT, "Makefile"), encoding="utf-8") as fh:
        makefile = fh.read()

    clean_body = makefile.split("\nclean:", 1)
    assert len(clean_body) == 2, "the Makefile has no `clean` target"
    # Up to the next target definition at column 0.
    body = clean_body[1].split("\n\n", 1)[0]
    body_lines = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    body_text = "\n".join(body_lines)
    assert "build/" in body_text, (
        f"`make clean` does not remove build/. setuptools copies from build/lib/ without "
        f"pruning deleted modules, so a rename or removal keeps shipping until that directory "
        f"is cleared. clean body:\n{body_text}"
    )

# --------------------------------------------------------------------------- #
# The IN-PLACE build path — the one people actually use                       #
# --------------------------------------------------------------------------- #
def test_no_stale_build_staging_tree_contradicts_the_source():
    """The check that catches the ORIGINAL defect, which the wheel test above does NOT.

    This is worth spelling out, because I got it wrong first. The `built_wheel` fixture builds
    from a pristine copy with `build/` excluded — good for asking "is the SOURCE packaged
    correctly?", and **blind to the actual defect**, which lives in a stale staging tree. I
    confirmed the blindness rather than assuming it: with a ghost handler planted in
    `build/lib/tools/`, that fixture reported 6 passed while an in-place `uv build` in the same
    working tree produced a wheel with 21 handlers including the ghost.

    A guard that verifies an idealised build instead of the build that actually happens is the
    same class of error as verifying a helper instead of the wired-up path. So this assertion
    inspects `build/lib/` directly — no build required, so it is fast and runs in every suite.

    Deliberately NOT fixed by making the fixture build in-place: that would mutate the working
    tree as a side effect of running tests, and would refresh `build/` so a later run inherits
    whatever this run staged. Two assertions, two questions.
    """
    staged_tools = os.path.join(REPO_ROOT, "build", "lib", "tools")
    if not os.path.isdir(staged_tools):
        # No staging tree: nothing can be stale. This is the state `make clean` leaves and the
        # state CI is always in (fresh checkout), so it is the common case, not a skip-worthy
        # gap.
        return

    staged = {
        name for name in os.listdir(staged_tools)
        if os.path.isfile(os.path.join(staged_tools, name, "handler.py"))
    }
    ghosts = sorted(staged - _disk_handlers())
    assert not ghosts, (
        f"build/lib/tools/ still stages handler(s) deleted from tools/: {ghosts}.\n\n"
        "setuptools copies FROM this tree without pruning removed entries, so an in-place "
        "`uv build` / `python -m build` would ship them — verified: a wheel built this way "
        "carried 21 handlers instead of 20, and installing it put the deleted code back on "
        "disk.\n\n"
        "Run `make clean` (which now removes build/) or `make dist`."
    )


def test_the_release_workflow_builds_from_a_fresh_checkout():
    """Why the PUBLISHED artifacts were never affected — asserted, not assumed.

    I nearly reported this defect as shipping to PyPI. It does not: the release job runs on a
    fresh `actions/checkout`, which has no `build/`, so its wheel is clean. Stating that
    accurately matters as much as finding the bug — the real blast radius was "a locally built
    wheel differs from the released one", which is dangerous in a different way: it is the
    artifact a maintainer inspects by hand.

    If the release workflow ever gained a cache or a self-hosted runner with a persistent
    workspace, that assumption breaks — which is what this test watches for.
    """
    path = os.path.join(REPO_ROOT, ".github", "workflows", "release.yml")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    build_jobs = {
        name: job for name, job in doc["jobs"].items()
        if any("build" in (s.get("run") or "") for s in job.get("steps") or [])
    }
    assert build_jobs, f"no job in release.yml runs a build: {sorted(doc['jobs'])}"

    for name, job in build_jobs.items():
        steps = job.get("steps") or []
        assert any("actions/checkout" in (s.get("uses") or "") for s in steps), (
            f"release job {name!r} builds without a fresh checkout step, so it could reuse a "
            "stale build/ staging tree and ship deleted modules."
        )
        # A restore-cache of the workspace would reintroduce exactly the staleness this file is
        # about. Caching pip/uv downloads is fine; caching the tree is not.
        for step in steps:
            uses = step.get("uses") or ""
            if "actions/cache" not in uses:
                continue
            cached = str(step.get("with", {}).get("path", ""))
            assert "build" not in cached, (
                f"release job {name!r} restores a cache covering {cached!r}, which can "
                "resurrect a stale build/lib/ staging tree in the published artifact."
            )
