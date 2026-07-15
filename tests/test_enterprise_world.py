"""
Offline tests for mockdata.enterprise — the DEEP attack-path world.

ZERO AWS, ZERO network, fast, deterministic. Asserts the enterprise world is:
- populated and multi-tier (dozens of hosts across five subnets),
- internally consistent (every trust-edge endpoint is a real host),
- public-hygiene clean (RFC-1918 internal / RFC-5737 doc IPs, no secrets),
- shaped EXACTLY as the real ``build_attack_paths`` reasoner consumes — and, in a
  live integration check, the reasoner finds the three PLANTED chains and does
  NOT over-claim from the patched bastion / isolated hosts.

The integration test loads the real reasoner the same namespace-safe way its own
suite does, so this pins the world↔reasoner contract, not a re-implementation.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import re

from mockdata import enterprise

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_reasoner():
    """Load specialists/attack-mapper/agent_a2a.py under a unique name (namespace-safe)."""
    path = os.path.join(_REPO, "specialists", "attack-mapper", "agent_a2a.py")
    spec = importlib.util.spec_from_file_location("attack_mapper_agent_undertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# populated + deterministic                                                   #
# --------------------------------------------------------------------------- #
def test_load_enterprise_is_deterministic():
    assert enterprise.load_enterprise() == enterprise.load_enterprise()


def test_load_returns_independent_copies():
    a = enterprise.load_enterprise()
    a["hosts"][0]["id"] = "MUTATED"
    assert enterprise.load_enterprise()["hosts"][0]["id"] != "MUTATED"


def test_world_is_deep():
    stats = enterprise.stats()
    assert stats["hosts"] >= 40, "the deep world should carry dozens of hosts"
    assert stats["internet_exposed"] >= 5
    assert stats["entry_nodes"] >= 3, "several valid attack entry points"
    assert stats["trust_edges"] >= 10
    assert stats["crown_jewels"] >= 3


def test_five_tiers_present():
    subnets = {h["subnet"] for h in enterprise.load_enterprise()["hosts"]}
    assert {enterprise.DMZ, enterprise.APP, enterprise.DATA,
            enterprise.CORP, enterprise.MGMT}.issubset(subnets)


# --------------------------------------------------------------------------- #
# internal consistency                                                        #
# --------------------------------------------------------------------------- #
def test_every_edge_endpoint_is_a_real_host():
    world = enterprise.load_enterprise()
    ids = {h["id"] for h in world["hosts"]}
    for e in world["trust_edges"]:
        assert e["src"] in ids, f"edge src {e['src']} unknown"
        assert e["dst"] in ids, f"edge dst {e['dst']} unknown"
        assert e.get("kind"), f"edge {e} missing kind"


def test_host_ids_unique():
    ids = [h["id"] for h in enterprise.load_enterprise()["hosts"]]
    assert len(ids) == len(set(ids)), "duplicate host ids"


def test_every_host_has_required_shape():
    for h in enterprise.load_enterprise()["hosts"]:
        assert isinstance(h["id"], str) and h["id"]
        assert isinstance(h["internet_exposed"], bool)
        assert isinstance(h["services"], list) and h["services"]
        for s in h["services"]:
            assert {"port", "proto", "name", "known_vuln", "cve_id"} <= set(s)
            assert isinstance(s["known_vuln"], bool)


def test_crown_jewels_are_critical():
    world = enterprise.load_enterprise()
    crit = {h["id"] for h in world["hosts"] if h["criticality"] == "critical"}
    assert set(enterprise.crown_jewels()) == crit
    assert {"db-01", "dc-01", "secrets-01"}.issubset(crit)


# --------------------------------------------------------------------------- #
# public hygiene                                                              #
# --------------------------------------------------------------------------- #
def test_internal_subnets_are_rfc1918():
    for h in enterprise.load_enterprise()["hosts"]:
        net = ipaddress.ip_network(h["subnet"], strict=False)
        assert net.is_private, f"{h['id']} subnet {h['subnet']} is not RFC-1918"


def test_no_secrets_or_real_accounts_in_source():
    src = open(os.path.join(_REPO, "mockdata", "enterprise.py"), encoding="utf-8").read()
    for acct in re.findall(r"\b\d{12}\b", src):
        assert acct == "000000000000", f"non-placeholder account id: {acct}"
    for tok in ("AKIA", "ghp_", "xoxb-", "sk-"):
        assert tok not in src, f"secret-looking prefix {tok!r} in source"


# --------------------------------------------------------------------------- #
# exposure_surface query shapes                                               #
# --------------------------------------------------------------------------- #
def test_surface_wildcard_returns_all():
    surf = enterprise.exposure_surface("*")
    assert len(surf["hosts"]) == enterprise.stats()["hosts"]
    assert len(surf["trust_edges"]) == enterprise.stats()["trust_edges"]


def test_surface_by_host_id():
    surf = enterprise.exposure_surface("web-01")
    assert [h["id"] for h in surf["hosts"]] == ["web-01"]
    # only edges whose src is web-01 come along
    assert all(e["src"] == "web-01" for e in surf["trust_edges"])
    assert any(e["dst"] == "app-01" for e in surf["trust_edges"])


def test_surface_by_subnet():
    surf = enterprise.exposure_surface(enterprise.DATA)
    ids = {h["id"] for h in surf["hosts"]}
    assert "db-01" in ids and "web-01" not in ids


def test_surface_unknown_query_is_empty_not_error():
    surf = enterprise.exposure_surface("nonexistent-host")
    assert surf["hosts"] == [] and surf["trust_edges"] == []


# --------------------------------------------------------------------------- #
# INTEGRATION: the real reasoner finds the planted chains, no over-claim      #
# --------------------------------------------------------------------------- #
def test_reasoner_finds_the_three_planted_chains():
    m = _load_reasoner()
    chains = m.build_attack_paths(enterprise.exposure_surface("*"))
    assert isinstance(chains, list) and chains

    # collect multi-hop chains (len(path) >= 3) by their (entry -> ... -> final)
    reached = {c["path"][-1] for c in chains if len(c["path"]) >= 3}
    # Chain 1: crown-jewel db, Chain 2: domain controller, Chain 3: secrets store
    assert "db-01" in reached, "crown-jewel db chain not found"
    assert "dc-01" in reached, "domain-controller chain not found"
    assert "secrets-01" in reached, "secrets-store chain not found"


def test_reasoner_entries_match_exposed_vuln_hosts():
    m = _load_reasoner()
    chains = m.build_attack_paths(enterprise.exposure_surface("*"))
    entries = {c["entry"] for c in chains}
    # exactly the three internet-exposed known-vuln hosts are entries
    assert entries == {"web-01", "proxy-01", "vpn-01"}
    # the patched bastion is NEVER an entry (exposed but no known_vuln)
    assert "bastion-01" not in entries


def test_reasoner_does_not_overclaim_from_patched_bastion():
    """bastion-01 -> web-02 (flat_network) leads nowhere vulnerable; no chain may
    originate at the patched bastion."""
    m = _load_reasoner()
    chains = m.build_attack_paths(enterprise.exposure_surface("*"))
    for c in chains:
        assert c["path"][0] != "bastion-01", "over-claimed a chain from the patched bastion"
