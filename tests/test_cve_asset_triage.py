"""
Offline tests for the M5 CVE-triage-AGAINST-ASSET E2E
=====================================================
Exercises ``scenarios/scenario_cve_asset_triage.py`` — the POC that triages a
CVE against the mock asset surface (nvd_lookup -> epss_kev -> asset_lookup ->
deterministic ``triage()`` join -> HITL gate). ZERO AWS, ZERO network, no sleep,
fast.

The scenario + its three tools are deterministic mocks, so nothing needs
mocking: the pure run yields the same verdict every time. We load the scenario
by an explicit file path under a UNIQUE module name (never bare ``handler`` / a
name a sibling test could collide with), mirroring how the tools' own tests
import them. Importing the scenario module must make ZERO AWS/network calls —
asserted implicitly by the fact that these tests run offline with only a
placeholder role ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SCENARIO_PATH = os.path.join(
    REPO_ROOT, "scenarios", "scenario_cve_asset_triage.py"
)


def _load_scenario():
    """Load the scenario module under a unique name (import-safe, offline)."""
    unique = "scenario_cve_asset_triage__test"
    spec = importlib.util.spec_from_file_location(unique, SCENARIO_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


cat = _load_scenario()


# --------------------------------------------------------------------------
# The pure end-to-end run: closed=True, Log4Shell maps to web-01.
# --------------------------------------------------------------------------
def test_pure_run_closes_true():
    verdict = cat.run_pure()["verdict"]
    assert verdict["closed"] is True
    assert verdict["cve_id"] == "CVE-2021-44228"
    assert verdict["has_cvss"] is True
    assert verdict["in_kev"] is True
    assert verdict["hitl_gate_required"] is True
    assert verdict["blast_radius_computed"] is True


def test_log4shell_affects_web01():
    """Default CVE (Log4Shell) intersects the fleet at web-01, exposing the CVE."""
    verdict = cat.run_pure()["verdict"]
    assert "web-01" in verdict["affected_hosts"]
    # web-01 is internet-exposed AND Log4Shell is in KEV -> worst-quadrant action.
    assert verdict["recommended_action"] == "patch_now_exposed_and_exploited"


def test_pure_run_is_deterministic():
    """Same POC run -> identical verdict (no clock, no randomness)."""
    v1 = cat.run_pure()["verdict"]
    v2 = cat.run_pure()["verdict"]
    assert v1 == v2


# --------------------------------------------------------------------------
# triage(): the deterministic, unit-testable core.
# --------------------------------------------------------------------------
_LOG4SHELL_CVE = {
    "id": "CVE-2021-44228",
    "cvss_v3_score": 10.0,
    "cvss_v3_severity": "CRITICAL",
}
_LOG4SHELL_EPSS = {
    "epss": 0.975,
    "epss_percentile": 0.999,
    "in_kev": True,
    "kev_date_added": "2021-12-10",
    "kev_due_date": "2021-12-24",
}
_FLEET_SURFACE = {
    "hosts": [
        {
            "id": "web-01",
            "internet_exposed": True,
            "services": [
                {"port": 443, "name": "https", "known_vuln": True,
                 "cve_id": "CVE-2021-44228"},
                {"port": 22, "name": "ssh", "known_vuln": False, "cve_id": None},
            ],
        },
        {
            "id": "app-01",
            "internet_exposed": False,
            "services": [
                {"port": 8080, "name": "http-app", "known_vuln": False,
                 "cve_id": None},
            ],
        },
        {
            "id": "db-01",
            "internet_exposed": False,
            "services": [
                {"port": 5432, "name": "postgres", "known_vuln": False,
                 "cve_id": None},
            ],
        },
    ],
    "trust_edges": [
        {"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"},
        {"src": "app-01", "dst": "db-01", "kind": "shared_admin_cred"},
    ],
}


def test_triage_joins_log4shell_to_web01():
    v = cat.triage("CVE-2021-44228", _LOG4SHELL_CVE, _LOG4SHELL_EPSS, _FLEET_SURFACE)
    assert v["affected_hosts"] == ["web-01"]
    assert v["severity"] == "CRITICAL"
    assert v["cvss"] == 10.0
    assert v["exploited_in_wild"] is True
    assert v["blast_radius"]["affected_count"] == 1
    assert v["blast_radius"]["internet_exposed_hit"] is True
    # Trust-edge pivot OUT of the affected host is the extended blast radius.
    assert v["blast_radius"]["reachable_hosts"] == ["app-01"]
    assert v["recommended_action"] == "patch_now_exposed_and_exploited"


def test_triage_cve_affecting_no_host_is_empty_not_crash():
    """A CVE that matches no mock host -> empty affected_hosts, benign action."""
    other_cve = {"id": "CVE-2018-1000006", "cvss_v3_score": 8.8,
                 "cvss_v3_severity": "HIGH"}
    other_epss = {"epss": 0.42, "in_kev": False}
    v = cat.triage("CVE-2018-1000006", other_cve, other_epss, _FLEET_SURFACE)
    assert v["affected_hosts"] == []
    assert v["blast_radius"]["affected_count"] == 0
    assert v["blast_radius"]["reachable_hosts"] == []
    assert v["recommended_action"] == "no_action_not_exposed"


def test_triage_case_insensitive_cve_id():
    """Lower-case cve id still joins (normalized to upper before matching)."""
    v = cat.triage("cve-2021-44228", _LOG4SHELL_CVE, _LOG4SHELL_EPSS, _FLEET_SURFACE)
    assert v["cve_id"] == "CVE-2021-44228"
    assert v["affected_hosts"] == ["web-01"]


def test_triage_missing_nvd_and_epss_does_not_crash():
    """No NVD/EPSS data (None) -> severity/cvss None, still a coherent verdict."""
    v = cat.triage("CVE-2021-44228", None, None, _FLEET_SURFACE)
    assert v["severity"] is None
    assert v["cvss"] is None
    assert v["exploited_in_wild"] is False
    # Exposed but not KEV-confirmed -> prioritize (not the worst quadrant).
    assert v["affected_hosts"] == ["web-01"]
    assert v["recommended_action"] == "prioritize_patch"


def test_triage_none_surface_is_empty_not_crash():
    """No asset surface at all -> empty affected_hosts, benign action."""
    v = cat.triage("CVE-2021-44228", _LOG4SHELL_CVE, _LOG4SHELL_EPSS, None)
    assert v["affected_hosts"] == []
    assert v["recommended_action"] == "no_action_not_exposed"


def test_triage_requires_cve_id():
    import pytest

    with pytest.raises(ValueError):
        cat.triage("", _LOG4SHELL_CVE, _LOG4SHELL_EPSS, _FLEET_SURFACE)


def test_hitl_gate_always_required():
    """No remediation is auto-applied: the HITL gate is always required."""
    v = cat.triage("CVE-2021-44228", _LOG4SHELL_CVE, _LOG4SHELL_EPSS, _FLEET_SURFACE)
    assert cat.hitl_gate_required(v) is True
    benign = cat.triage("CVE-2018-1000006",
                        {"cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH"},
                        {"in_kev": False}, _FLEET_SURFACE)
    assert cat.hitl_gate_required(benign) is True
