"""INV-MCP-5 — the `mcp` upper bound exists because the code needs the 1.x decorator API.

`pyproject.toml` declared `mcp>=1.0` with **no upper bound**, and mcp 2.0.0 is a breaking
rewrite of the low-level server API `sentinel_harness/mcp_server.py` is built on:

    mcp 1.28.1   Server("x").list_tools   -> present
    mcp 2.0.0    Server("x").list_tools   -> AttributeError

`create_server()` registers its two handlers with `@server.list_tools()` and
`@server.call_tool()`. Verified against a real 2.0.0 install, it raises

    AttributeError: 'Server' object has no attribute 'list_tools'

so `pip install sentinel-harness[mcp] && sentinel mcp serve` could not start at all. That
is a user-facing, install-time break against the CURRENT PyPI release of `mcp` — the
version a new user gets by default.

What hid it, and the lesson
---------------------------
CI never installed `mcp`: it hand-copied a partial dependency list instead of installing the
`test` extra (INV-CI-1). So every test that would have caught this SKIPPED, on every run,
while CI reported green. The silent skip was not concealing a stale test — it was concealing
a **broken published dependency contract**. That is the strongest case in this repo for the
rule that a skip must never be read as a pass.

The second lesson is about my own verification. I first checked compatibility by confirming
`from mcp.server import Server` still resolves on 2.0.0, and concluded production code was
fine. It resolves — and the API behind it is gone. **An import check is not a compatibility
check**; it proves a module attribute exists, not that the surface has the same shape. The
assertion below therefore CALLS the decorator surface rather than importing it.

ZERO network, ZERO AWS.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 only
    tomllib = pytest.importorskip("tomli", reason="TOML reader on 3.10")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")

# The decorator factories `mcp_server.create_server` calls on the `Server` object. These are
# exactly what mcp 2.0.0 removed.
_REQUIRED_SERVER_DECORATORS = ("list_tools", "call_tool")


def _pyproject() -> dict:
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def _mcp_requirements() -> dict:
    """Every `mcp` requirement string, keyed by the extra that declares it."""
    extras = _pyproject()["project"].get("optional-dependencies", {})
    found = {}
    for extra, reqs in extras.items():
        for req in reqs:
            if re.match(r"^mcp\b", req.strip()):
                found[extra] = req.strip()
    return found


def test_the_code_still_depends_on_the_1x_decorator_api():
    """The PREMISE of the upper bound, checked by CALLING the surface.

    If a future change ports `mcp_server.py` to 2.0's request-handler API, this test fails
    and points at the bound — so the pin gets lifted deliberately rather than lingering as
    a stale constraint nobody dares touch. A pin whose reason is only in a comment becomes
    permanent.
    """
    pytest.importorskip("mcp", reason="needs the `test` extra: pip install -e '.[test]'")
    from mcp.server import Server

    server = Server("bound-probe")
    missing = [n for n in _REQUIRED_SERVER_DECORATORS if not hasattr(server, n)]
    assert not missing, (
        f"the installed `mcp` has no {missing} on `Server`, but "
        "sentinel_harness/mcp_server.py registers its handlers with those decorators. "
        "Either the installed version violates the declared upper bound, or the code was "
        "ported and this guard + the bound in pyproject.toml need updating together."
    )

    # And that the production module really uses them — otherwise the check above passes
    # while the bound protects nothing.
    with open(os.path.join(REPO_ROOT, "sentinel_harness", "mcp_server.py"),
              encoding="utf-8") as fh:
        source = fh.read()
    for name in _REQUIRED_SERVER_DECORATORS:
        assert f"@server.{name}()" in source, (
            f"mcp_server.py no longer uses @server.{name}(). If it was ported to mcp 2.x's "
            "API, LIFT the `<2` bound in pyproject.toml — a pin that outlives its reason "
            "blocks users from upgrading for nothing."
        )


@pytest.mark.parametrize("extra", ["mcp", "test"])
def test_the_mcp_requirement_is_upper_bounded(extra):
    """Both the `mcp` extra (what users install) and `test` (what CI installs) must cap it.

    The user-facing one matters most: an unbounded range means the next `pip install
    sentinel-harness[mcp]` silently picks up a version whose API this code does not speak,
    and the failure surfaces as an AttributeError at server startup rather than as a
    resolver conflict at install time. Capping turns a runtime crash into a dependency
    error, which is the diagnosable one.
    """
    reqs = _mcp_requirements()
    assert extra in reqs, (
        f"the `{extra}` extra no longer declares an `mcp` requirement: {reqs}"
    )
    req = reqs[extra]
    assert re.search(r"<\s*2", req), (
        f"the `{extra}` extra declares {req!r} with no upper bound. mcp 2.0.0 removed "
        "`Server.list_tools` / `Server.call_tool`, so an unbounded range means "
        "`pip install sentinel-harness[mcp]` installs a version where `sentinel mcp serve` "
        "cannot start. See the comment in pyproject.toml for how to lift it."
    )


def test_both_extras_agree_on_the_bound():
    """CONTROL: the two declarations must not drift apart.

    If `test` capped it and `mcp` did not, CI would test 1.x while users got 2.x — the
    worst arrangement, because the suite would be green and broken at the same time. That is
    a variant of exactly what happened here.
    """
    reqs = _mcp_requirements()
    specs = {extra: req for extra, req in reqs.items() if extra in ("mcp", "test")}
    normalised = {re.sub(r"\s+", "", req) for req in specs.values()}
    assert len(normalised) == 1, (
        f"the `mcp` and `test` extras declare DIFFERENT mcp ranges: {specs}. CI would then "
        "exercise a different version than users install."
    )


def test_the_installed_version_satisfies_the_declared_bound():
    """The bound is only worth anything if the environment running this suite obeys it.

    Without this, a stale local venv could hold a version the bound forbids and the suite
    would validate behaviour no user will ever get.
    """
    pytest.importorskip("mcp")
    import importlib.metadata as md

    installed = md.version("mcp")
    major = int(installed.split(".")[0])
    assert major < 2, (
        f"mcp {installed} is installed, but pyproject.toml caps it below 2.0 because "
        "`Server.list_tools` / `Server.call_tool` were removed in 2.0. This environment is "
        "not testing what users get — reinstall with `pip install -e '.[test]'`."
    )
