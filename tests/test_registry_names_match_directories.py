"""INV-REGISTRY-5 — a registry tool name must equal its `tools/` directory name.

`mcp_server._discover_tools` walks `tools/`, takes each **directory name** as the tool name,
and tests membership against the registry's approved set:

    if tool_name not in approved and not allow_pending:
        continue

So a registry entry whose `name` does not match its directory makes the tool vanish —
**silently**. Reproduced before writing this file:

    baseline                          17 tools exposed
    rename the registry entry only    16 tools exposed
                                      old name: absent
                                      new name: absent
                                      NO error, NO warning

The tool is not reported missing, mis-named, or pending. It is simply gone, and `list_tools`
serves a shorter list that looks perfectly healthy.

Why the existing guards did not catch it
----------------------------------------
`test_registry.py` is thorough about two other pairings — registry-vs-code-factory
(`governance_check`) and the two shipped YAML copies staying in sync — but **nothing** checked
registry-name-vs-directory-name. Three couplings, two guarded. That is the asymmetry heuristic
this repo keeps finding defects with.

Relationship to INV-MCP-1
-------------------------
INV-MCP-1 fixed the case where the registry cannot be READ (it used to fail open and expose
every tool; it now raises). This is the adjacent case: the registry reads fine and the *names*
disagree. That one now fails loud, this one still failed silent — the same gate, the other
input.

Why it was written when it was
-----------------------------
The tool now called `allowlist_optimizer` used to carry a name that violates the project's
inclusive-language rule. Renaming it touched a directory, BOTH shipped registry copies and 38
files — and without this guard, getting any one of them wrong would have deleted a tool from
the MCP surface while every test still passed. So the guard came first and the rename second:
it was verified to catch the desync (3 of these assertions fire) before being relied on.

ZERO network, ZERO AWS.
"""
from __future__ import annotations

import os

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a CORE dependency; absence is a bug")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

# Both shipped copies. `registry/tools.yaml` is what a checkout uses; the `sentinel_harness/
# data/` copy is what the wheel ships (INV-MCP-2 — the wheel used to omit it entirely, so
# `pip install && sentinel-mcp` failed open from any directory).
REGISTRY_COPIES = (
    os.path.join(REPO_ROOT, "registry", "tools.yaml"),
    os.path.join(REPO_ROOT, "sentinel_harness", "data", "tools.yaml"),
)


def _entries(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if isinstance(data, dict):
        data = data.get("tools", data)
    assert isinstance(data, list), f"{path}: expected a list of tool entries, got {type(data)}"
    return data


def _registry_names(path: str) -> set:
    return {e["name"] for e in _entries(path) if isinstance(e, dict) and "name" in e}


def _directory_names() -> set:
    return {
        name for name in os.listdir(TOOLS_DIR)
        if os.path.isfile(os.path.join(TOOLS_DIR, name, "handler.py"))
    }


def test_the_scan_finds_tools_at_all():
    """Positive control. Every assertion below compares two sets; if either came back empty
    the comparisons would hold vacuously and this module would be decoration."""
    dirs = _directory_names()
    assert len(dirs) >= 15, (
        f"only found {len(dirs)} tool directories under {TOOLS_DIR} — the layout changed and "
        "these comparisons are now blind"
    )
    for path in REGISTRY_COPIES:
        names = _registry_names(path)
        assert len(names) >= 15, f"{path}: only parsed {len(names)} entries"


@pytest.mark.parametrize("registry", REGISTRY_COPIES,
                         ids=["registry/tools.yaml", "sentinel_harness/data/tools.yaml"])
def test_every_registry_name_has_a_matching_directory(registry):
    """The failure that is otherwise silent.

    A registry entry with no matching directory is not an error anywhere in the system: the
    discovery loop iterates DIRECTORIES, so an unmatched registry name is never looked up. It
    simply never becomes a tool.
    """
    orphans = sorted(_registry_names(registry) - _directory_names())
    assert not orphans, (
        f"{os.path.relpath(registry, REPO_ROOT)} names tool(s) with no "
        f"tools/<name>/handler.py: {orphans}. `mcp_server._discover_tools` keys off the "
        "DIRECTORY name, so such an entry never becomes a tool — and nothing reports it. "
        "Reproduced: renaming one registry entry dropped the exposed tool count from 17 to "
        "16 with no error at all. If this is a deliberate rename, rename the directory too "
        "(and the other registry copy)."
    )


@pytest.mark.parametrize("registry", REGISTRY_COPIES,
                         ids=["registry/tools.yaml", "sentinel_harness/data/tools.yaml"])
def test_every_tool_directory_has_a_registry_entry(registry):
    """The other direction: an ungoverned directory.

    Less dangerous (governance excludes it by default, which is the safe answer) but still
    wrong — a tool nobody approved sitting in the tree looks like an oversight in whichever
    direction it is read, and `SENTINEL_MCP_ALLOW_PENDING=1` would expose it.
    """
    ungoverned = sorted(_directory_names() - _registry_names(registry))
    assert not ungoverned, (
        f"tools/ contains handler(s) absent from "
        f"{os.path.relpath(registry, REPO_ROOT)}: {ungoverned}. Add a registry entry (even "
        "`status: pending`) so the governance decision is explicit rather than implied by "
        "omission."
    )


def test_the_two_registry_copies_agree_on_names():
    """The wheel copy and the checkout copy must name the same tools.

    If they drifted, a checkout would expose one set and an installed wheel another — and the
    suite, which runs from a checkout, would be green either way. INV-MCP-2 is the record of
    the wheel's registry going wrong unnoticed.
    """
    a, b = (_registry_names(p) for p in REGISTRY_COPIES)
    assert a == b, (
        f"the two shipped registry copies name different tools.\n"
        f"  only in registry/tools.yaml:            {sorted(a - b)}\n"
        f"  only in sentinel_harness/data/tools.yaml: {sorted(b - a)}\n"
        "A checkout and an installed wheel would expose different tool sets."
    )


def test_the_mcp_surface_matches_the_approved_set():
    """END TO END: what `_discover_tools` actually exposes, not what the files say.

    The assertions above compare text. This one runs the real discovery path, so a mismatch
    introduced anywhere between the YAML and the exposed surface is caught even if the
    filename comparisons happen to line up.

    Control-plane tools are excluded by default (they can spend money / mutate AWS), so they
    are subtracted rather than expected.
    """
    from sentinel_harness.mcp_server import (
        _CONTROL_PLANE_TOOLS, _discover_tools, _load_approved_set,
    )

    exposed = set(_discover_tools())
    approved = set(_load_approved_set())
    expected = (approved & _directory_names()) - set(_CONTROL_PLANE_TOOLS)

    assert exposed == expected, (
        f"the MCP surface does not match the approved-and-implemented set.\n"
        f"  approved but NOT exposed: {sorted(expected - exposed)}\n"
        f"  exposed but NOT expected: {sorted(exposed - expected)}\n"
        "A tool silently dropping off this surface is the defect INV-REGISTRY-5 exists for."
    )
    # Positive control on the end-to-end path too: an empty surface would satisfy an
    # equality check against an equally empty expectation.
    assert len(exposed) >= 15, f"only {len(exposed)} tools exposed: {sorted(exposed)}"
