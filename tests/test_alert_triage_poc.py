"""
Offline tests for the M5 end-to-end alert-triage POC
====================================================
Exercises ``scenarios/scenario_alert_triage_poc.py`` — the POC that triages a
mock alert across all four data planes (siem_query -> enrich_ioc -> asset_lookup
-> correlate -> create_ticket). ZERO AWS, ZERO network, no sleep, fast.

The scenario + its four tools are deterministic mocks, so nothing needs mocking:
the pure run yields the same verdict every time. We load the scenario by an
explicit file path under a UNIQUE module name (never bare ``handler`` / a name a
sibling test could collide with), mirroring how the tools' own tests import them.
Importing the scenario module must make ZERO AWS/network calls — that is asserted
implicitly by the fact that these tests run offline with only a placeholder role
ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SCENARIO_PATH = os.path.join(
    REPO_ROOT, "scenarios", "scenario_alert_triage_poc.py"
)


def _load_scenario():
    """Load the scenario module under a unique name (import-safe, offline)."""
    unique = "scenario_alert_triage_poc__test"
    spec = importlib.util.spec_from_file_location(unique, SCENARIO_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


poc = _load_scenario()


# --------------------------------------------------------------------------
# The pure end-to-end run: closed=True with all five booleans True.
# --------------------------------------------------------------------------
def test_pure_run_closes_with_all_booleans_true():
    verdict = poc.run_pure()["verdict"]
    for key in (
        "siem_hit",
        "ioc_malicious",
        "asset_vulnerable",
        "correlated_true_positive",
        "ticket_created",
        "closed",
    ):
        assert verdict[key] is True, f"expected {key} True, got {verdict[key]!r}"


def test_pure_run_is_deterministic():
    """Same POC run -> identical verdict (no clock, no randomness)."""
    v1 = poc.run_pure()["verdict"]
    v2 = poc.run_pure()["verdict"]
    assert v1 == v2


# --------------------------------------------------------------------------
# correlate(): the Log4Shell case is a true_positive; a benign event is not.
# --------------------------------------------------------------------------
_LOG4SHELL_EVENT = {
    "alert_id": "alert-1001",
    "ts": "2026-06-28T14:03:11Z",
    "severity": "critical",
    "rule_name": "Log4Shell JNDI Exploit Attempt",
    "host": "web-01",
    "src_ip": "203.0.113.66",
    "dst_ip": "192.0.2.10",
    "technique": "T1190",
    "false_positive": False,
}
_MALICIOUS_IOC = {
    "type": "ip",
    "known": True,
    "threat_category": "c2",
    "confidence": "high",
    "related_hosts": ["web-01"],
    "verdict": "malicious",
}
_WEB01_SURFACE = {
    "hosts": [
        {
            "id": "web-01",
            "internet_exposed": True,
            "services": [
                {"port": 443, "name": "https", "known_vuln": True,
                 "cve_id": "CVE-2021-44228"},
                {"port": 22, "name": "ssh", "known_vuln": False, "cve_id": None},
            ],
        }
    ],
    "trust_edges": [{"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"}],
}


def test_correlate_marks_log4shell_true_positive():
    v = poc.correlate(_LOG4SHELL_EVENT, _MALICIOUS_IOC, _WEB01_SURFACE)
    assert v["verdict"] == "true_positive"
    assert v["confidence"] == "high"
    assert v["recommended_action"] == "contain_host_and_open_incident"
    # Blast radius carries the Log4Shell CVE and the downstream pivot.
    assert v["blast_radius"]["vulnerable"] is True
    assert "CVE-2021-44228" in v["blast_radius"]["cves"]
    assert v["blast_radius"]["reachable_hosts"] == ["app-01"]
    assert v["signals"] == {
        "ioc_malicious": True,
        "asset_vulnerable": True,
        "not_false_positive": True,
    }


def test_correlate_benign_false_positive_not_true_positive():
    """An allowlisted-CDN false positive is dismissed, never a true_positive."""
    benign_event = {
        "alert_id": "alert-1010",
        "severity": "info",
        "rule_name": "Known-Good CDN Traffic",
        "host": "web-01",
        "src_ip": "192.0.2.10",
        "technique": "T1071",
        "false_positive": True,
    }
    benign_ioc = {
        "type": "ip", "known": False, "threat_category": None,
        "confidence": None, "related_hosts": [], "verdict": "unknown",
    }
    v = poc.correlate(benign_event, benign_ioc, _WEB01_SURFACE)
    assert v["verdict"] != "true_positive"
    assert v["verdict"] == "false_positive"
    assert v["recommended_action"] == "dismiss"


def test_correlate_clean_ip_downgrades_to_inconclusive():
    """A real (non-FP) alert whose IOC is NOT malicious is not a true_positive."""
    event = dict(_LOG4SHELL_EVENT)
    clean_ioc = {"verdict": "benign", "known": True, "related_hosts": []}
    v = poc.correlate(event, clean_ioc, _WEB01_SURFACE)
    assert v["verdict"] == "inconclusive"
    assert v["verdict"] != "true_positive"
    assert v["recommended_action"] == "escalate_for_manual_review"


def test_correlate_patched_host_not_true_positive():
    """Malicious IOC but a host with no known-vuln service -> not true_positive."""
    patched_surface = {
        "hosts": [
            {"id": "web-01", "services": [
                {"port": 22, "name": "ssh", "known_vuln": False, "cve_id": None}]}
        ],
        "trust_edges": [],
    }
    v = poc.correlate(_LOG4SHELL_EVENT, _MALICIOUS_IOC, patched_surface)
    assert v["verdict"] != "true_positive"
    assert v["blast_radius"]["vulnerable"] is False


def test_correlate_requires_alert_id():
    import pytest

    with pytest.raises(ValueError):
        poc.correlate({"host": "web-01"}, None, None)
