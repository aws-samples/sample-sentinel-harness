"""Offline tests for the mockdata SecOps world (single source of truth).

ZERO AWS, ZERO network, fast, deterministic. This asserts the world is:
  * deterministic (same load -> same data; copies are independent),
  * internally consistent (every alert host/ip references a real host or IOC),
  * cross-linked (the Log4Shell alert -> a C2 IOC -> web-01 -> CVE-2021-44228),
  * well-formed (all IPs in RFC 5737 doc ranges; SHA-256 hashes are 64-hex).

Like the sibling tool tests, we load the package by an explicit file path under
a UNIQUE module name so this file cannot collide with any other test's
``sys.modules`` entries regardless of collection order.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCKDATA_DIR = os.path.join(REPO_ROOT, "mockdata")

# RFC 5737 documentation ranges — the ONLY IP space allowed in the mock world.
_DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_DOMAIN_SUFFIXES = (".example.test", ".example.com")


def _load_package(unique_name: str, pkg_dir: str):
    """Load the mockdata package by path under a UNIQUE name.

    We register the unique name so relative imports inside the package
    (``from .world import ...``) resolve, without ever claiming the bare
    ``mockdata`` name that a production import might expect.
    """
    init_path = os.path.join(pkg_dir, "__init__.py")
    spec = importlib.util.spec_from_file_location(
        unique_name, init_path, submodule_search_locations=[pkg_dir]
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {init_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


mockdata = _load_package("mockdata_under_test", MOCKDATA_DIR)


def _is_doc_ip(value: str) -> bool:
    addr = ipaddress.ip_address(value)
    return any(addr in net for net in _DOC_NETS)


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_load_world_is_deterministic():
    assert mockdata.load_world() == mockdata.load_world()


def test_load_world_returns_independent_copies():
    """Mutating one result must not leak into the shared source."""
    w1 = mockdata.load_world()
    w1["hosts"][0]["id"] = "MUTATED"
    w2 = mockdata.load_world()
    assert w2["hosts"][0]["id"] != "MUTATED"


def test_accessors_match_load_world():
    world = mockdata.load_world()
    assert mockdata.hosts() == world["hosts"]
    assert mockdata.alerts() == world["alerts"]
    assert mockdata.iocs() == world["iocs"]
    assert mockdata.tickets_seed() == world["tickets"]


# --------------------------------------------------------------------------- #
# Shape / non-empty                                                           #
# --------------------------------------------------------------------------- #
def test_world_is_populated():
    assert len(mockdata.hosts()) >= 6
    assert 8 <= len(mockdata.iocs()) <= 12
    assert 10 <= len(mockdata.alerts()) <= 15
    assert len(mockdata.tickets_seed()) >= 2


def test_canonical_hosts_reused_from_asset_plane():
    ids = {h["id"] for h in mockdata.hosts()}
    assert {"web-01", "app-01", "db-01", "bastion-01"}.issubset(ids)
    # The extra hosts named in the task.
    assert {"win-ws-07", "dc-01"}.issubset(ids)


def test_web01_carries_log4shell_cve():
    web01 = next(h for h in mockdata.hosts() if h["id"] == "web-01")
    assert web01["known_vuln"] is True
    assert web01["cve"] == "CVE-2021-44228"


# --------------------------------------------------------------------------- #
# Well-formedness: IPs in doc ranges, hashes valid, domains reserved          #
# --------------------------------------------------------------------------- #
def test_all_host_ips_are_doc_range():
    for h in mockdata.hosts():
        assert _is_doc_ip(h["ip"]), f"host {h['id']} ip {h['ip']} not doc-range"


def test_all_ioc_artifacts_well_formed():
    for ioc in mockdata.iocs():
        t, v = ioc["type"], ioc["value"]
        if t == "ip":
            assert _is_doc_ip(v), f"{ioc['id']} ip {v} not doc-range"
        elif t == "domain":
            assert v.endswith(_ALLOWED_DOMAIN_SUFFIXES), f"{ioc['id']} domain {v}"
        elif t == "sha256":
            assert _SHA256_RE.match(v), f"{ioc['id']} hash {v} not 64-hex"
        else:  # pragma: no cover - guards against a new unhandled type
            raise AssertionError(f"unexpected ioc type {t!r}")
        # Required metadata present.
        for field in ("first_seen", "threat_category", "confidence", "relates_to"):
            assert ioc.get(field) is not None, f"{ioc['id']} missing {field}"


def test_all_alert_ips_are_doc_range_when_present():
    for a in mockdata.alerts():
        for ip in (a.get("src_ip"), a.get("dst_ip")):
            if ip is not None:
                assert _is_doc_ip(ip), f"{a['alert_id']} ip {ip} not doc-range"


def test_ioc_relates_to_real_hosts():
    host_ids = {h["id"] for h in mockdata.hosts()}
    for ioc in mockdata.iocs():
        for hid in ioc["relates_to"]:
            assert hid in host_ids, f"{ioc['id']} relates_to unknown host {hid}"


# --------------------------------------------------------------------------- #
# Internal consistency: alerts reference real hosts / real IOCs               #
# --------------------------------------------------------------------------- #
def test_every_alert_host_is_a_real_host():
    host_ids = {h["id"] for h in mockdata.hosts()}
    for a in mockdata.alerts():
        assert a["host"] in host_ids, f"{a['alert_id']} host {a['host']} unknown"


def test_every_alert_ip_references_a_host_or_ioc():
    """Each alert src/dst IP must be a known host IP or a known IOC value."""
    host_ips = {h["ip"] for h in mockdata.hosts()}
    ioc_values = {i["value"] for i in mockdata.iocs()}
    known = host_ips | ioc_values
    for a in mockdata.alerts():
        for ip in (a.get("src_ip"), a.get("dst_ip")):
            if ip is not None:
                assert ip in known, f"{a['alert_id']} ip {ip} references nothing"


def test_alerts_have_attack_technique_and_required_fields():
    for a in mockdata.alerts():
        for field in ("alert_id", "ts", "severity", "rule_name", "raw_summary"):
            assert a.get(field), f"{a['alert_id']} missing {field}"
        assert re.match(r"^T\d{4}", a["technique"]), f"{a['alert_id']} bad ATT&CK"


def test_has_both_true_positive_and_benign_events():
    alerts = mockdata.alerts()
    assert any(a.get("false_positive") for a in alerts), "no benign/FP event"
    assert any(a["severity"] in ("critical", "high") for a in alerts), "no TP-ish"


# --------------------------------------------------------------------------- #
# The headline cross-link: Log4Shell alert -> C2 IOC -> web-01 -> CVE         #
# --------------------------------------------------------------------------- #
def test_log4shell_alert_links_c2_ioc_and_web01_with_cve():
    alerts = {a["alert_id"]: a for a in mockdata.alerts()}
    iocs_by_value = {i["value"]: i for i in mockdata.iocs()}
    hosts = {h["id"]: h for h in mockdata.hosts()}

    # 1) The Log4Shell alert exists and targets web-01.
    log4shell = alerts["alert-1001"]
    assert "log4shell" in log4shell["rule_name"].lower()
    assert log4shell["technique"] == "T1190"
    assert log4shell["host"] == "web-01"

    # 2) Its src_ip is a C2 IOC.
    c2 = iocs_by_value[log4shell["src_ip"]]
    assert c2["threat_category"] == "c2"
    assert c2["confidence"] == "high"

    # 3) That C2 IOC relates to web-01.
    assert "web-01" in c2["relates_to"]

    # 4) web-01 carries CVE-2021-44228 (Log4Shell) — chain closes to the asset.
    assert hosts["web-01"]["cve"] == "CVE-2021-44228"


def test_ticket_sequence_is_monotonic_and_seeded():
    world = mockdata.load_world()
    seed = world["tickets"]
    seq = world["ticket_sequence"]
    assert seq["prefix"] == "SEC-"
    # Next id is strictly greater than every seeded id's number.
    seeded_nums = [int(t["ticket_id"].split("-")[1]) for t in seed]
    assert seq["next"] > max(seeded_nums)
    # A seed ticket ties back to the Log4Shell alert.
    assert any("alert-1001" in t.get("related_alert_ids", []) for t in seed)
