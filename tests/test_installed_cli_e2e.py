"""INV-PKG-4 — the documented CLI works from an INSTALLED wheel, outside any checkout.

Every packaging guard before this one inspected an artifact: is the tool handler in the wheel,
is the registry in the wheel, does the sdist carry the trees its tests read. All necessary, and
all blind to the same thing — **a file being present in the wheel does not mean the command
works**.

That gap hid a real defect. `sentinel export <name>` is the documented no-lock-in escape hatch
(README.md, docs/QUICKSTART.md, docs/COMPARISON.md). Reproduced by installing the wheel into a
throwaway environment and running it from a directory unrelated to any checkout:

    sentinel export alert-triage
    -> error: could not resolve harness 'alert-triage' — pass a path to a harness.yaml or a
       name under <site-packages>/harnesses/<name>/harness.yaml

The resolver was right. `_REPO_ROOT` is the parent of `sentinel_harness/`, which on an installed
wheel *is* site-packages, so it looked in the correct place and said so. The DATA was missing:
`packages.find.include` listed `sentinel_harness*`, `intake*`, `tools*`, `mockdata*` — and not
`harnesses*`. All 8 shipped harnesses were unreachable for anyone who installed rather than
cloned.

INV-MCP-2 fixed exactly this shape for `registry/`. `harnesses/` was left out of that fix, so
this is "a fix applied to one call site is not an invariant" landing on a packaging include
list — which is why this file tests the *documented surface* rather than one name.

What this layer adds over `test_wheel_contents.py`
--------------------------------------------------
That module asks "is X in the tarball?". This one asks "does the command a user was told to run
actually run?", in a venv with only the wheel and its declared dependencies — no repo on
`sys.path`, no `PYTHONPATH`, no CWD-relative data.

Two findings that only this framing produces:

- The 6-of-8 harnesses that "failed" after the packaging fix were **not** a defect: they refuse
  because `${SENTINEL_GATEWAY_ARN}` and friends are unset, which is the 12-factor config check
  doing its job — an explicit refusal, not a silent degradation. With the vars set, 8/8 export
  108-143 lines of Strands code. Asserting the refusal is part of the contract here.
- Exit codes were already correct (1 on failure). I initially misread them as 0 because `$?` in
  my probe had been clobbered by a pipe through `head`. Verified properly before claiming a
  defect; the shell was wrong, not the CLI.

Cost: ~4s per session (one `uv run --with <wheel>`), gated behind a builder probe.
ZERO network beyond the local wheel install, ZERO AWS.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from pristine_tree import pristine_copy

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESSES_DIR = os.path.join(REPO_ROOT, "harnesses")

# The 12-factor placeholders several shipped harnesses reference. Set for the calls that are
# expected to succeed; deliberately UNSET for the refusal test.
_TWELVE_FACTOR_ENV = {
    "SENTINEL_GATEWAY_ARN": "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test",
    "SENTINEL_GATEWAY_URL": "https://gw.example.internal/mcp",
    "SENTINEL_MEMORY_ID": "mem-test-000",
}

_BASE_ENV = {
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/test",
    "SENTINEL_REGION": "us-east-1",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
}


def _disk_harnesses() -> list:
    return sorted(
        name for name in os.listdir(HARNESSES_DIR)
        if os.path.isfile(os.path.join(HARNESSES_DIR, name, "harness.yaml"))
    )


@pytest.fixture(scope="module")
def installed_wheel(tmp_path_factory) -> str:
    """Build a wheel from a pristine copy of the tree and return its path.

    Copied rather than built in place so the run does not create/refresh `build/` in the
    working tree — and so a stale local `build/lib/` cannot feed this test the very staleness
    INV-PKG-2 is about.
    """
    if shutil.which("uv") is None:
        if os.environ.get("CI", "").strip().lower() in ("1", "true", "yes", "on"):
            raise AssertionError(
                "uv is not available but CI=1. This layer needs `uv run --with <wheel>` to "
                "install into an isolated environment; without it INV-PKG-4 is unverified "
                "where merges are gated."
            )
        pytest.skip("uv is required to install a wheel into an isolated environment")

    # Shared helper: the exclusion list has ONE definition (tests/pristine_tree.py). It was
    # duplicated verbatim here and in test_installed_cli_e2e.py, while test_sdist_contents.py
    # built IN PLACE and was therefore blind to a stale build/ — with a ghost handler planted
    # in build/lib/tools/, this module caught it and that one reported 6 passed.
    src = pristine_copy(tmp_path_factory.mktemp("src"))
    out = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run(["uv", "build", "--wheel", "-o", str(out)],
                          cwd=src, capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, f"wheel build failed:\n{(proc.stdout + proc.stderr)[-2000:]}"
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {[w.name for w in wheels]}"
    return str(wheels[0])


def _run_installed(wheel: str, argv: list, *, cwd: str, extra_env: dict | None = None):
    """Run `sentinel <argv>` from an environment containing ONLY the wheel + its deps.

    `--no-project` and an explicitly built env matter: without them uv would pick up this
    repository's own project and put the checkout on `sys.path`, which is exactly the
    condition that hides installed-only defects.
    """
    env = {
        # A minimal environment: no PYTHONPATH, no inherited SENTINEL_* beyond what we set.
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        **_BASE_ENV,
        **(extra_env or {}),
    }
    for name in ("VIRTUAL_ENV", "PYTHONPATH", "UV_PROJECT_ENVIRONMENT"):
        env.pop(name, None)
    return subprocess.run(
        ["uv", "run", "--no-project", "--with", wheel, "sentinel", *argv],
        cwd=cwd, capture_output=True, text=True, timeout=600, env=env,
    )


def test_the_console_script_runs_at_all(installed_wheel, tmp_path):
    """Positive control for this whole module. If `sentinel --help` cannot run in the isolated
    environment, every assertion below would fail for an uninteresting reason and the module
    would be reporting on its own harness rather than on the package."""
    proc = _run_installed(installed_wheel, ["--help"], cwd=str(tmp_path))
    assert proc.returncode == 0, f"`sentinel --help` failed:\n{proc.stdout}\n{proc.stderr}"
    assert "usage: sentinel" in proc.stdout, proc.stdout


@pytest.mark.parametrize("harness", _disk_harnesses())
def test_every_documented_harness_exports_from_an_installed_wheel(
    installed_wheel, tmp_path, harness
):
    """The defect, as a regression test, for EVERY harness rather than the one I happened to try.

    Run from `tmp_path` — a directory with no `harnesses/`, no repo, nothing on `sys.path` but
    the installed wheel. That is the only configuration in which this defect is visible.
    """
    proc = _run_installed(installed_wheel, ["export", harness], cwd=str(tmp_path),
                          extra_env=_TWELVE_FACTOR_ENV)
    assert proc.returncode == 0, (
        f"`sentinel export {harness}` failed on an installed wheel (rc={proc.returncode}).\n"
        f"stdout: {proc.stdout[-600:]}\nstderr: {proc.stderr[-900:]}\n\n"
        "This is the documented no-lock-in escape hatch. If the error names a "
        "site-packages/harnesses path, `harnesses*` is missing from "
        "[tool.setuptools.packages.find].include."
    )
    # And that it produced real code, not an empty file: `rc=0` with no output would satisfy a
    # returncode-only assertion while shipping nothing.
    assert len(proc.stdout.splitlines()) >= 50, (
        f"export produced only {len(proc.stdout.splitlines())} lines for {harness}:\n"
        f"{proc.stdout[:400]}"
    )
    assert "Agent(" in proc.stdout, (
        f"the exported code for {harness} contains no Strands `Agent(` construction — it is "
        f"not runnable starter code:\n{proc.stdout[:600]}"
    )


def test_an_unset_twelve_factor_variable_is_REFUSED_not_defaulted(installed_wheel, tmp_path):
    """CONTROL, and a contract in its own right.

    Six of the eight harnesses reference `${SENTINEL_GATEWAY_ARN}` and similar. With those
    unset, `export` must FAIL with a message naming the variable — not silently emit code with
    an empty ARN, which would produce an agent that fails later, somewhere else, for a reason
    nobody can trace.

    This is why the 6-of-8 "failures" seen while verifying the packaging fix were not a defect:
    they were this check working. Asserting it here means a future change that "helpfully"
    defaults the value gets caught.
    """
    proc = _run_installed(installed_wheel, ["export", "alert-triage"], cwd=str(tmp_path))
    assert proc.returncode != 0, (
        "`sentinel export alert-triage` SUCCEEDED with no SENTINEL_GATEWAY_ARN set. A missing "
        "12-factor variable must be refused, not defaulted — an exported agent carrying an "
        "empty ARN fails later and elsewhere.\n" + proc.stdout[:500]
    )
    combined = proc.stdout + proc.stderr
    assert "SENTINEL_GATEWAY_ARN" in combined, (
        f"the refusal does not name the missing variable, so the operator cannot act on it:\n"
        f"{combined[-600:]}"
    )


def test_the_mcp_server_starts_governed_from_an_installed_wheel(installed_wheel, tmp_path):
    """INV-MCP-1 + INV-MCP-2 end to end on the installed path.

    The registry made it into the wheel (guarded by `test_wheel_contents.py`), but that is a
    tarball assertion. This one calls `_discover_tools()` in the isolated environment: the
    governance gate must find the packaged registry and expose the approved subset, rather than
    raising `GovernanceUnavailable` or — the original INV-MCP-1 defect — failing open.
    """
    code = (
        "import json;"
        "from sentinel_harness.mcp_server import _discover_tools, _load_approved_set;"
        "print(json.dumps({'exposed': sorted(_discover_tools()),"
        " 'approved': len(_load_approved_set())}))"
    )
    env = {
        "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **_BASE_ENV,
    }
    proc = subprocess.run(
        ["uv", "run", "--no-project", "--with", installed_wheel, "python", "-c", code],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=600, env=env,
    )
    assert proc.returncode == 0, (
        f"tool discovery failed on an installed wheel — the packaged registry is unreadable "
        f"from outside a checkout, which is INV-MCP-2's defect.\n{proc.stderr[-900:]}"
    )
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data["approved"] >= 15, f"only {data['approved']} approved tools resolved: {data}"
    assert len(data["exposed"]) >= 15, f"only {len(data['exposed'])} tools exposed: {data}"
    # Governance must still EXCLUDE what it excludes — a wheel that exposes more than a
    # checkout would be a fail-open, the exact INV-MCP-1 shape.
    assert "web_search" not in data["exposed"], (
        "`web_search` is registry-pending and must not be exposed; the installed path is "
        "failing open (INV-MCP-1)."
    )


def test_the_cli_does_not_depend_on_the_current_directory(installed_wheel, tmp_path):
    """`sentinel detection --help` and `sentinel mcp --help` must work anywhere.

    A subcommand whose *parser* construction touches CWD-relative data would fail here while
    passing in a checkout — the same class as the harness defect, one level earlier.
    """
    for subcommand in ("detection", "mcp", "export", "run-scenario"):
        proc = _run_installed(installed_wheel, [subcommand, "--help"], cwd=str(tmp_path))
        assert proc.returncode == 0, (
            f"`sentinel {subcommand} --help` failed from {tmp_path} on an installed wheel:\n"
            f"{proc.stderr[-600:]}"
        )
        assert f"usage: sentinel {subcommand}" in proc.stdout, proc.stdout[:300]


def test_the_version_reported_matches_the_package_metadata(installed_wheel, tmp_path):
    """A cheap consistency check on the installed artifact: `__version__` and the distribution
    metadata must agree, or `sentinel --version`-style output misidentifies what is running."""
    code = (
        "import sentinel_harness, importlib.metadata as md;"
        "print(sentinel_harness.__version__, md.version('sentinel-harness'))"
    )
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **_BASE_ENV}
    proc = subprocess.run(
        ["uv", "run", "--no-project", "--with", installed_wheel, "python", "-c", code],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=600, env=env,
    )
    assert proc.returncode == 0, proc.stderr[-600:]
    attr, meta = proc.stdout.split()
    assert attr == meta, (
        f"sentinel_harness.__version__ is {attr!r} but the installed distribution reports "
        f"{meta!r} — the artifact misreports its own version."
    )

# --------------------------------------------------------------------------- #
# The documented commands, executed exactly as written                        #
# --------------------------------------------------------------------------- #
_QUICKSTART = os.path.join(REPO_ROOT, "docs", "QUICKSTART.md")


def _documented_export_commands() -> list:
    """`sentinel export ...` lines from docs/QUICKSTART.md's fenced blocks."""
    with open(_QUICKSTART, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    found = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("sentinel export "):
            continue
        # Drop shell redirection: the assertion is about resolution, not about the shell.
        found.append(stripped.split(">")[0].strip())
    return found


def test_the_documented_export_commands_are_executable(installed_wheel, tmp_path):
    """QUICKSTART taught `sentinel export harnesses/alert-triage/harness.yaml` — a RELATIVE
    path that exists only inside a checkout. A reader who ran `pip install sentinel-harness`
    has no `harnesses/` directory in their CWD, so the documented command could not work for
    them even after the packaging fix.

    Documentation that cannot be followed is a defect of the same kind as a missing file: it
    fails for the reader, silently for us. So the doc now teaches the NAME form first (works
    anywhere) and the path form as the in-checkout variant, and this test runs whatever the doc
    currently says.

    Path-form commands are executed from the repo root — that is the context the doc gives them
    — while name-form commands run from `tmp_path`, where nothing but the installed wheel can
    satisfy them.
    """
    commands = _documented_export_commands()
    # Positive control: a doc whose fenced blocks stopped matching would make this vacuous.
    assert len(commands) >= 2, (
        f"parsed only {len(commands)} `sentinel export` commands from QUICKSTART.md: "
        f"{commands}. Either the doc changed shape or this parser is now blind."
    )

    name_forms = [c for c in commands if "/" not in c]
    path_forms = [c for c in commands if "/" in c]

    # The assertion is about ORDER, not mere presence, and that distinction cost a mutation.
    # My first version was `assert name_forms` — "the doc mentions a name form somewhere". The
    # mutation "revert the doc to teaching only the relative path" SURVIVED it, because a
    # second `sentinel export alert-triage` appears further down in the 12-factor example. One
    # documentation regression was masked by an unrelated line elsewhere on the page.
    #
    # A reader follows the page top-down and runs the FIRST command they see. So the contract is
    # that the first documented form must work without a checkout — an existence check stood in
    # for a structural one, the defect class this repo has recorded more than any other.
    assert commands[0] in name_forms, (
        f"the FIRST documented export command is {commands[0]!r}, a path form. A reader who "
        f"ran `pip install sentinel-harness` has no harnesses/ directory in their CWD, so the "
        f"first thing the doc tells them to run cannot work. Teach the name form first.\n"
        f"all commands, in page order: {commands}"
    )

    for command in name_forms:
        argv = command.split()[1:]
        proc = _run_installed(installed_wheel, argv, cwd=str(tmp_path),
                              extra_env=_TWELVE_FACTOR_ENV)
        assert proc.returncode == 0, (
            f"documented command `{command}` failed from a directory with no checkout "
            f"(rc={proc.returncode}):\n{proc.stderr[-700:]}"
        )

    for command in path_forms:
        argv = command.split()[1:]
        proc = _run_installed(installed_wheel, argv, cwd=REPO_ROOT,
                              extra_env=_TWELVE_FACTOR_ENV)
        assert proc.returncode == 0, (
            f"documented command `{command}` failed from the repo root "
            f"(rc={proc.returncode}):\n{proc.stderr[-700:]}"
        )


def test_the_doc_states_the_twelve_factor_requirement():
    """The refusal is correct behaviour, so it has to be documented, or it reads as a bug.

    Six of eight harnesses refuse without `${SENTINEL_*}` set. A reader who follows QUICKSTART
    and hits that refusal with no forewarning reasonably concludes the export is broken — and
    the most likely "fix" they would ask for is defaulting the value, which is exactly what
    must not happen.
    """
    with open(_QUICKSTART, encoding="utf-8") as fh:
        text = fh.read()
    assert "SENTINEL_GATEWAY_ARN" in text, (
        "QUICKSTART.md does not mention the 12-factor variables the shipped harnesses "
        "reference, so the documented export appears to fail for no reason."
    )
    assert "refuse" in text.lower() or "non-zero" in text, (
        "QUICKSTART.md does not say that a missing variable is REFUSED. Without that, the "
        "refusal reads as a defect rather than as the contract."
    )
