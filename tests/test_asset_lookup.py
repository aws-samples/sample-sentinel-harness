"""
Offline tests for the asset_lookup exposure-surface tool
========================================================
Dedicated tests for ``tools/asset_lookup/handler.py`` — the deterministic,
OFFLINE exposure-surface tool the attack-mapper reasoner consumes. ZERO AWS,
ZERO network, no real sleep. The handler is deterministic by design, so the
offline paths need no mocking; only the live (``ASSET_LOOKUP_LIVE=1``) branch
is steered via env / monkeypatch, and even then it performs no I/O (the live
client is an M5 stub that raises).

This file is a good citizen about ``sys.modules``: the tool ships a module
literally named ``handler`` (as do sibling tools), so importing it by bare
name would collide in ``sys.modules`` when the whole suite runs. We load it
from an explicit file path under a UNIQUE module name and NEVER register the
bare ``handler`` name — mirroring tests/test_attack_mapper.py — so this file
cannot poison any other tool test regardless of collection order.
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "asset_lookup")
HANDLER_PATH = os.path.join(ASSET_TOOL_DIR, "handler.py")


def _load_module(unique_name: str, path: str):
    """Import a standalone .py file under a unique name without polluting the
    bare module namespace shared by sibling tools."""
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Register under the UNIQUE name only, never as bare "handler".
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


# A unique name distinct from the one test_attack_mapper.py uses
# ("asset_lookup_handler"), so both files can co-exist in one pytest run.
asset_handler = _load_module("asset_lookup_handler_dedicated", HANDLER_PATH)


# --------------------------------------------------------------------------- #
# Wildcard query returns the full offline surface                             #
# --------------------------------------------------------------------------- #
def test_wildcard_returns_full_offline_surface():
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["query"] == "*"
    surface = res["surface"]
    host_ids = {h["id"] for h in surface["hosts"]}
    # The whole known fixture surface — all four hosts.
    assert host_ids == {"web-01", "app-01", "db-01", "bastion-01"}
    # Output ordering is stable (sorted by host id).
    assert [h["id"] for h in surface["hosts"]] == sorted(host_ids)


def test_wildcard_surface_carries_known_vuln_and_cve_fields():
    """The exposure surface must expose the known-vuln / CVE fields the
    reasoner keys off — assert the REAL fixture values, not just presence."""
    res = asset_handler.handler({"query": "*"}, None)
    hosts = {h["id"]: h for h in res["surface"]["hosts"]}

    # web-01 carries the one known-vulnerable, internet-exposed service.
    web = hosts["web-01"]
    assert web["internet_exposed"] is True
    https = next(s for s in web["services"] if s["port"] == 443)
    assert https["known_vuln"] is True
    assert https["cve_id"] == "CVE-2021-44228"
    assert https["proto"] == "tcp" and https["name"] == "https"
    # web-01's ssh service is patched.
    ssh = next(s for s in web["services"] if s["port"] == 22)
    assert ssh["known_vuln"] is False and ssh["cve_id"] is None

    # bastion-01 is internet-exposed but fully patched (negative case).
    bastion = hosts["bastion-01"]
    assert bastion["internet_exposed"] is True
    assert all(s["known_vuln"] is False for s in bastion["services"])
    assert all(s["cve_id"] is None for s in bastion["services"])

    # Interior tiers are not internet-exposed and patched.
    for internal_id in ("app-01", "db-01"):
        h = hosts[internal_id]
        assert h["internet_exposed"] is False
        assert all(s["known_vuln"] is False for s in h["services"])


def test_wildcard_surface_carries_trust_edges():
    """Trust edges are the pivot chain the reasoner turns into an attack path."""
    res = asset_handler.handler({"query": "*"}, None)
    edges = res["surface"]["trust_edges"]
    edge_tuples = {(e["src"], e["dst"], e["kind"]) for e in edges}
    assert ("web-01", "app-01", "ssh_key_reuse") in edge_tuples
    assert ("app-01", "db-01", "shared_admin_cred") in edge_tuples
    assert ("bastion-01", "web-01", "flat_network") in edge_tuples
    for e in edges:
        assert set(e) == {"src", "dst", "kind"}


# --------------------------------------------------------------------------- #
# Specific host / subnet queries                                              #
# --------------------------------------------------------------------------- #
def test_single_host_query_returns_only_that_host():
    res = asset_handler.handler({"query": "app-01"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    ids = {h["id"] for h in res["surface"]["hosts"]}
    assert ids == {"app-01"}
    # An edge is kept only when its SOURCE is in scope; app-01 -> db-01 stays,
    # web-01 -> app-01 (src out of scope) does not.
    kinds = {(e["src"], e["dst"]) for e in res["surface"]["trust_edges"]}
    assert kinds == {("app-01", "db-01")}


def test_subnet_query_matches_hosts_in_that_subnet():
    res = asset_handler.handler({"query": "10.0.0.0/24"}, None)
    assert res["ok"] is True
    ids = {h["id"] for h in res["surface"]["hosts"]}
    # web-01 and bastion-01 both live in 10.0.0.0/24.
    assert ids == {"web-01", "bastion-01"}


def test_broad_subnet_query_matches_all_tiers():
    res = asset_handler.handler({"query": "10.0.0.0/16"}, None)
    ids = {h["id"] for h in res["surface"]["hosts"]}
    assert {"web-01", "app-01", "db-01", "bastion-01"} <= ids


def test_bare_ip_query_is_routed_through_the_network_branch():
    """A bare IP (no ``/``) is still a network query, NOT a host-id lookup — so
    it goes through the subnet-match branch (exercises _looks_like_ip / line
    243). A bare IP parses as a /32 network, and none of the fixture /24 subnets
    is a subnet-of a /32, so the surface is empty; the point is that the query
    is routed as a network (never a fabricated host-id hit) and yields ok=True."""
    assert asset_handler._looks_like_ip("10.0.2.0") is True
    assert asset_handler._looks_like_ip("web-01") is False
    res = asset_handler.handler({"query": "10.0.2.0"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    # /32 bare IP is not a supernet of any fixture /24 -> empty, not an error.
    assert res["surface"]["hosts"] == []
    assert res["surface"]["trust_edges"] == []


def test_unknown_host_returns_empty_surface():
    res = asset_handler.handler({"query": "ghost-99"}, None)
    assert res["ok"] is True
    assert res["surface"]["hosts"] == []
    assert res["surface"]["trust_edges"] == []


# --------------------------------------------------------------------------- #
# Input validation errors                                                     #
# --------------------------------------------------------------------------- #
def test_missing_query_is_validation_error():
    res = asset_handler.handler({}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad_query", ["", "   ", "\t\n"])
def test_blank_or_empty_query_is_validation_error(bad_query):
    res = asset_handler.handler({"query": bad_query}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad_query", [123, None, 1.5, ["*"], {"q": 1}])
def test_non_string_query_is_validation_error(bad_query):
    res = asset_handler.handler({"query": bad_query}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    res = asset_handler.handler("not-a-dict", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


def test_invalid_subnet_is_validation_error():
    res = asset_handler.handler({"query": "10.0.0.0/99"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "invalid subnet" in res["message"]


def test_bad_host_id_characters_is_validation_error():
    res = asset_handler.handler({"query": "bad host!"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "invalid asset id" in res["message"]


def test_over_long_query_is_validation_error():
    """A query longer than the max token length is rejected (line 192)."""
    too_long = "a" * (asset_handler._MAX_QUERY_LEN + 1)
    res = asset_handler.handler({"query": too_long}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "too long" in res["message"]
    # A query exactly at the limit is still accepted (boundary), even if it
    # matches no host.
    at_limit = "a" * asset_handler._MAX_QUERY_LEN
    ok = asset_handler.handler({"query": at_limit}, None)
    assert ok["ok"] is True and ok["surface"]["hosts"] == []


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_offline_surface_is_deterministic():
    a = asset_handler.handler({"query": "*"}, None)
    b = asset_handler.handler({"query": "*"}, None)
    assert a == b
    # Edges returned are copies — mutating the result must not corrupt the
    # module-level fixture for the next caller.
    a["surface"]["trust_edges"][0]["kind"] = "TAMPERED"
    c = asset_handler.handler({"query": "*"}, None)
    assert all(e["kind"] != "TAMPERED" for e in c["surface"]["trust_edges"])


# --------------------------------------------------------------------------- #
# Live (ASSET_LOOKUP_LIVE) branch behavior — still ZERO network               #
# --------------------------------------------------------------------------- #
def test_default_is_offline_stub_no_network(monkeypatch):
    """With ASSET_LOOKUP_LIVE unset the tool serves the offline stub and never
    reaches the live client (which would raise)."""
    monkeypatch.delenv("ASSET_LOOKUP_LIVE", raising=False)

    def _boom(query):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached in offline mode")

    monkeypatch.setattr(asset_handler, "_fetch_live", _boom)
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "stub"


@pytest.mark.parametrize("val", ["0", "true", "yes", "", "01"])
def test_live_flag_only_activates_on_exact_1(monkeypatch, val):
    """Only ASSET_LOOKUP_LIVE == "1" flips to live; anything else stays offline."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", val)
    monkeypatch.setattr(
        asset_handler,
        "_fetch_live",
        lambda q: (_ for _ in ()).throw(AssertionError("should stay offline")),
    )
    res = asset_handler.handler({"query": "*"}, None)
    assert res["source"] == "stub"


def test_live_without_backend_url_surfaces_upstream_error(monkeypatch):
    """Opting into live with no ASSET_LOOKUP_URL must surface an explicit
    upstream_error (RuntimeError branch in _fetch_live), never fall back."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.delenv("ASSET_LOOKUP_URL", raising=False)
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "ASSET_LOOKUP_URL is not set" in res["message"]


def test_live_with_unreachable_backend_surfaces_upstream_error(monkeypatch):
    """With a backend URL configured the live client makes a REAL urllib call;
    an unreachable backend (connection refused on a closed loopback port) is
    surfaced as upstream_error, never a fabricated surface and never a silent
    fixture fallback. ZERO external network: 127.0.0.1:1 is a closed local port.
    Full request-shape / success-path / auth-header coverage lives in the
    dedicated tests/test_asset_lookup_live.py mock-server suite."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", "http://127.0.0.1:1/asset")
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # We do NOT fall back to the stub surface on a live failure.
    assert "surface" not in res


def test_fetch_live_raises_on_unreachable_backend(monkeypatch):
    """Directly exercise _fetch_live's transport-failure branch (URLError ->
    RuntimeError). 127.0.0.1:1 is a closed local port: connection refused, no
    external network."""
    monkeypatch.setenv("ASSET_LOOKUP_URL", "http://127.0.0.1:1/asset")
    with pytest.raises(RuntimeError, match="backend request failed"):
        asset_handler._fetch_live("*")


def test_fetch_live_without_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("ASSET_LOOKUP_URL", raising=False)
    with pytest.raises(RuntimeError, match="ASSET_LOOKUP_URL is not set"):
        asset_handler._fetch_live("*")


def test_live_success_path_sets_source_live(monkeypatch):
    """When a live client IS wired (future M5), the handler wraps its surface
    with source='live' (exercises the source='live' assignment). We stub
    _fetch_live to return a surface — still ZERO network."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    fake_surface = {"hosts": [], "trust_edges": []}
    monkeypatch.setattr(asset_handler, "_fetch_live", lambda q: fake_surface)
    res = asset_handler.handler({"query": "10.0.0.0/24"}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["query"] == "10.0.0.0/24"
    assert res["surface"] == fake_surface


# --------------------------------------------------------------------------- #
# __main__ entrypoint (lines 311-313)                                         #
# --------------------------------------------------------------------------- #
def test_main_entrypoint_prints_wildcard_surface(capsys, monkeypatch):
    """Running the module as __main__ prints the wildcard surface as JSON."""
    import json

    monkeypatch.delenv("ASSET_LOOKUP_LIVE", raising=False)
    runpy.run_path(HANDLER_PATH, run_name="__main__")
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True
    assert parsed["source"] == "stub"
    assert {h["id"] for h in parsed["surface"]["hosts"]} == {
        "web-01", "app-01", "db-01", "bastion-01"
    }


# --------------------------------------------------------------------------- #
# House rule: no hardcoded secrets or real account ids in the source          #
# --------------------------------------------------------------------------- #
def test_source_has_no_hardcoded_secrets_or_account_ids():
    import re

    src = open(HANDLER_PATH, encoding="utf-8").read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src
