"""Packaging tripwire — the wheel must ship every tree the CLI/MCP server needs.

v0.4.0 shipped a broken wheel: ``[tool.setuptools] packages = ["sentinel_harness",
"intake"]`` silently dropped ``sentinel_harness.connectors`` (an explicit package
list does NOT imply subpackages) and the whole ``tools/`` + ``mockdata/`` trees —
so ``sentinel detection audit`` and ``sentinel mcp serve`` failed for every
pip-installed user with ``tool handler not found`` / ``No module named 'mockdata'``.

These tests read pyproject.toml as data (no build, no network) and fail if the
packaging config regresses to a shape that drops any required tree. A full
build-and-import proof lives in the release quality gate (the wheel smoke test).
"""
from __future__ import annotations

import os
import sys

import pytest

# TOML reader. `tomllib` is stdlib from 3.11; on 3.10 — which `requires-python = ">=3.10"`
# declares as supported — the standard backport `tomli` provides the identical API.
#
# This used to be `tomllib = None` on 3.10, and the fixture skipped. The consequence was
# that EVERY test reading pyproject.toml — 7 of this file's 12, including the INV-MCP-2
# packaging guard added in round 20 — was inert on the project's own minimum version. CI
# covers 3.11+ so the guard still had teeth there, but a guard that evaporates on the
# floor version is a guard with a documented hole in it.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover — py3.10 path, exercised in the 3.10 CI leg
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(_REPO_ROOT, "pyproject.toml")

# Every top-level tree the runtime discovers at import- or call-time. Dropping any
# of these from the wheel breaks a shipped command for pip-installed users:
#   sentinel_harness — the library (find() must include SUBpackages, e.g. connectors)
#   intake           — imported by the M1 meta-agent path
#   tools            — cli._load_tool_handler + mcp_server._discover_tools load
#                      tools/<name>/handler.py relative to the package parent
#   mockdata         — imported by enrich_ioc / ops_query / siem_query handlers
REQUIRED_TREES = ["sentinel_harness", "intake", "tools", "mockdata"]


@pytest.fixture(scope="module")
def pyproject() -> dict:
    if tomllib is None:
        pytest.skip("tomllib requires Python 3.11+ (config shape is version-independent)")
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def test_packaging_uses_find_not_explicit_list(pyproject: dict) -> None:
    """An explicit packages list is the failure mode that shipped the broken wheel
    (it silently drops subpackages). Require the find() directive."""
    setuptools_cfg = pyproject.get("tool", {}).get("setuptools", {})
    packages = setuptools_cfg.get("packages")
    assert isinstance(packages, dict) and "find" in packages, (
        "pyproject [tool.setuptools] packages must use the packages.find directive, "
        "not an explicit list — an explicit list drops subpackages (shipped broken "
        f"in 0.4.0); got {packages!r}"
    )


@pytest.mark.parametrize("tree", REQUIRED_TREES)
def test_find_include_covers_required_tree(pyproject: dict, tree: str) -> None:
    find_cfg = (
        pyproject.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    )
    include = find_cfg.get("include", [])
    assert any(
        pat == tree or pat == f"{tree}*" or pat.startswith(f"{tree}.")
        for pat in include
    ), (
        f"pyproject packages.find.include must cover {tree!r} — the wheel breaks a "
        f"shipped command without it (see module docstring). include={include}"
    )


def test_find_namespaces_enabled(pyproject: dict) -> None:
    """tools/<name>/ dirs have no __init__.py — they only ship with namespaces=true."""
    find_cfg = (
        pyproject.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    )
    assert find_cfg.get("namespaces") is True, (
        "packages.find.namespaces must be true: tools/ is a flat handler tree with "
        "no __init__.py files and is silently dropped without namespace discovery"
    )


@pytest.mark.parametrize("tree", REQUIRED_TREES)
def test_required_tree_exists(tree: str) -> None:
    assert os.path.isdir(os.path.join(_REPO_ROOT, tree)), f"{tree}/ missing from repo"


# --------------------------------------------------------------- INV-MCP-2: data files
def test_registry_yaml_is_declared_as_package_data(pyproject: dict) -> None:
    """The governance registry must ship in the wheel as package DATA.

    `packages.find` above ships CODE (`.py`), not a `.yaml`. Round 20: the wheel shipped
    no `registry/` at all, so a pip-installed `sentinel-mcp` could not read the registry
    and — combined with the pre-fix fail-open gate — served every tool ungoverned. A
    dropped data file fails SILENTLY and permissively, unlike the dropped `connectors`
    subpackage this file already guards, which failed loudly. So it needs its own guard.
    """
    pkg_data = pyproject.get("tool", {}).get("setuptools", {}).get("package-data", {})
    patterns = pkg_data.get("sentinel_harness", [])
    assert any("yaml" in p for p in patterns), (
        "pyproject [tool.setuptools.package-data] must ship sentinel_harness/data/*.yaml "
        f"— the governance registry is not code and packages.find will not carry it. "
        f"Got package-data.sentinel_harness={patterns!r}"
    )


def test_packaged_registry_copy_exists_and_matches_source() -> None:
    """The packaged copy must exist AND be identical to the canonical `registry/`.

    Two copies can drift — the INV-EGRESS-3 lesson. This is the tripwire that they have
    not. When they must differ, this test is where the reason gets recorded.
    """
    canonical = os.path.join(_REPO_ROOT, "registry", "tools.yaml")
    packaged = os.path.join(_REPO_ROOT, "sentinel_harness", "data", "tools.yaml")
    assert os.path.isfile(packaged), (
        "sentinel_harness/data/tools.yaml is missing — the wheel will ship no registry"
    )
    with open(canonical, encoding="utf-8") as a, open(packaged, encoding="utf-8") as b:
        assert a.read() == b.read(), (
            "registry/tools.yaml and the packaged sentinel_harness/data/tools.yaml have "
            "drifted — regenerate the packaged copy (cp registry/tools.yaml "
            "sentinel_harness/data/tools.yaml) or record why they must differ"
        )
