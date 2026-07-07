"""
Offline governance tests for the tool/skill registry (Layer-3 dual-gate)
========================================================================
These tests make ZERO AWS calls and require no credentials. They exercise the
core governance invariant: a tool is *live* only if it is in BOTH the
declarative registry (approved) AND the code ``TOOL_FACTORY_MAP``. We assert
the three cases explicitly — in-registry-only, in-code-only, in-both — plus
resolution and YAML loading of the shipped ``registry/tools.yaml``.
"""
from __future__ import annotations

import os

import pytest

from sentinel_harness.registry import (  # noqa: E402
    GovernanceReport,
    RegistryError,
    ToolEntry,
    ToolRegistry,
    load_registry,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_YAML = os.path.join(REPO_ROOT, "registry", "tools.yaml")


def _factory(name: str):
    """A trivial deterministic tool-config builder (stands in for core.tool_*)."""
    return lambda: {"type": "test_tool", "name": name}


# --------------------------------------------------------------------------- #
# ToolEntry validation                                                        #
# --------------------------------------------------------------------------- #
def test_tool_entry_defaults_pending():
    e = ToolEntry(name="t", owner="team")
    assert e.status == "pending"
    assert e.description == ""
    assert e.metadata == {}


def test_tool_entry_requires_name_and_owner():
    with pytest.raises(RegistryError):
        ToolEntry(name="", owner="team")
    with pytest.raises(RegistryError):
        ToolEntry(name="t", owner="")


def test_tool_entry_rejects_bad_status():
    with pytest.raises(RegistryError, match="invalid status"):
        ToolEntry(name="t", owner="team", status="live")


# --------------------------------------------------------------------------- #
# Dual-gate governance: the three cases                                       #
# --------------------------------------------------------------------------- #
def test_in_both_is_live():
    """Approved in registry AND implemented in code -> live + resolvable."""
    reg = ToolRegistry({"sigma_yara_lint": _factory("sigma_yara_lint")})
    reg.add_entry(ToolEntry(name="sigma_yara_lint", owner="det-eng", status="approved"))
    rep = reg.governance_check()
    assert rep.live == ["sigma_yara_lint"]
    assert rep.approved_missing_impl == []
    assert rep.impl_missing_registry == []
    assert rep.ok is True
    assert reg.list_live() == ["sigma_yara_lint"]
    assert reg.resolve("sigma_yara_lint") == {"type": "test_tool", "name": "sigma_yara_lint"}


def test_in_registry_only_is_not_live():
    """Approved in registry but NO code factory -> drift, not live, resolve raises."""
    reg = ToolRegistry()  # empty factory map
    reg.add_entry(ToolEntry(name="nvd_lookup", owner="vuln", status="approved"))
    rep = reg.governance_check()
    assert rep.live == []
    assert rep.approved_missing_impl == ["nvd_lookup"]
    assert rep.impl_missing_registry == []
    assert rep.ok is False
    assert reg.list_live() == []
    with pytest.raises(RegistryError, match="no code implementation"):
        reg.resolve("nvd_lookup")


def test_in_code_only_is_not_live():
    """Code factory exists but the name is NOT in the registry -> shadow capability."""
    reg = ToolRegistry({"rogue_tool": _factory("rogue_tool")})
    rep = reg.governance_check()
    assert rep.live == []
    assert rep.impl_missing_registry == ["rogue_tool"]
    assert rep.approved_missing_impl == []
    assert rep.ok is False
    assert reg.list_live() == []
    with pytest.raises(RegistryError, match="not in the registry"):
        reg.resolve("rogue_tool")


def test_pending_in_both_is_not_live():
    """Present on both sides but status=pending -> not live, resolve refuses."""
    reg = ToolRegistry({"web_search": _factory("web_search")})
    reg.add_entry(ToolEntry(name="web_search", owner="ti", status="pending"))
    rep = reg.governance_check()
    assert rep.live == []
    assert rep.pending == ["web_search"]
    assert rep.ok is True  # pending is not drift; it is an intentional state
    with pytest.raises(RegistryError, match="not approved"):
        reg.resolve("web_search")


def test_deprecated_is_not_resolvable():
    reg = ToolRegistry({"old_tool": _factory("old_tool")})
    reg.add_entry(ToolEntry(name="old_tool", owner="ti", status="deprecated"))
    assert reg.list_live() == []
    with pytest.raises(RegistryError, match="not approved"):
        reg.resolve("old_tool")


def test_resolve_unknown_raises():
    reg = ToolRegistry()
    with pytest.raises(RegistryError, match="not in the registry"):
        reg.resolve("does_not_exist")


# --------------------------------------------------------------------------- #
# register() code-side API                                                    #
# --------------------------------------------------------------------------- #
def test_register_adds_factory_and_enables_live():
    reg = ToolRegistry()
    reg.add_entry(ToolEntry(name="attack_lookup", owner="ti", status="approved"))
    assert reg.list_live() == []  # no impl yet
    reg.register("attack_lookup", _factory("attack_lookup"))
    assert reg.list_live() == ["attack_lookup"]


def test_register_rejects_non_callable():
    reg = ToolRegistry()
    with pytest.raises(RegistryError, match="callable"):
        reg.register("x", "not-callable")  # type: ignore[arg-type]


def test_register_rejects_empty_name():
    reg = ToolRegistry()
    with pytest.raises(RegistryError):
        reg.register("", _factory("x"))


# --------------------------------------------------------------------------- #
# load_dict shapes                                                            #
# --------------------------------------------------------------------------- #
def test_load_dict_list_shape():
    reg = ToolRegistry().load_dict({
        "tools": [
            {"name": "a", "owner": "t1", "status": "approved", "description": "d", "extra": 1},
            {"name": "b", "owner": "t2"},
        ]
    })
    ea = reg.get_entry("a")
    assert ea.owner == "t1" and ea.status == "approved" and ea.description == "d"
    assert ea.metadata == {"extra": 1}  # unknown keys preserved
    assert reg.get_entry("b").status == "pending"


def test_load_dict_mapping_shape():
    reg = ToolRegistry().load_dict({"a": {"owner": "t1", "status": "approved"}})
    assert reg.get_entry("a").status == "approved"


def test_load_dict_rejects_non_mapping():
    with pytest.raises(RegistryError):
        ToolRegistry().load_dict(["not", "a", "mapping"])  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Shipped registry/tools.yaml                                                 #
# --------------------------------------------------------------------------- #
def test_shipped_yaml_loads_and_lists_real_tools():
    reg = ToolRegistry().load_yaml(TOOLS_YAML)
    names = set(reg.entries())
    assert {"sigma_yara_lint", "nvd_lookup", "epss_kev", "attack_lookup", "web_search"} <= names
    # web_search is intentionally pending in the shipped file.
    assert reg.get_entry("web_search").status == "pending"
    assert reg.get_entry("sigma_yara_lint").status == "approved"
    # Every entry has an owner and a non-empty description (no personal names).
    for e in reg.entries().values():
        assert e.owner and e.description
        assert "@" not in e.owner  # team alias/label, not an email/person


def test_load_registry_with_shipped_yaml_dual_gate():
    """Wire the shipped YAML to a factory map covering only the 4 approved tools
    that have code; web_search is pending so it is never live regardless."""
    factory_map = {n: _factory(n) for n in
                   ("sigma_yara_lint", "nvd_lookup", "epss_kev", "attack_lookup",
                    "harness_ops", "run_evaluation", "sigma_match", "asset_lookup",
                    "siem_query", "enrich_ioc", "create_ticket", "whitelist_optimizer")}
    reg = load_registry(factory_map, TOOLS_YAML)
    rep = reg.governance_check()
    # harness_ops (M1) + run_evaluation (M2) + sigma_match/asset_lookup (M3) +
    # siem_query/enrich_ioc/create_ticket (M5) + whitelist_optimizer (M6) are approved +
    # code-mapped, so live (list_live is sorted).
    assert reg.list_live() == ["asset_lookup", "attack_lookup", "create_ticket", "enrich_ioc",
                               "epss_kev", "harness_ops", "nvd_lookup", "run_evaluation",
                               "siem_query", "sigma_match", "sigma_yara_lint", "whitelist_optimizer"]
    assert rep.approved_missing_impl == []       # all approved tools implemented
    assert rep.impl_missing_registry == []       # no shadow code
    assert rep.pending == []                      # web_search has no factory here
    assert rep.ok is True


def test_shipped_yaml_flags_missing_impl_as_drift():
    """If SecOps approves a tool with no code factory, governance_check flags it."""
    reg = load_registry({}, TOOLS_YAML)  # zero code factories
    rep = reg.governance_check()
    assert set(rep.approved_missing_impl) == {
        "sigma_yara_lint", "nvd_lookup", "epss_kev", "attack_lookup",
        "harness_ops", "run_evaluation", "sigma_match", "asset_lookup",
        "siem_query", "enrich_ioc", "create_ticket", "whitelist_optimizer"
    }
    assert rep.ok is False


def test_load_yaml_missing_file_raises():
    with pytest.raises(RegistryError, match="not found"):
        ToolRegistry().load_yaml("/nonexistent/registry.yaml")


def test_governance_report_type():
    assert isinstance(ToolRegistry().governance_check(), GovernanceReport)
