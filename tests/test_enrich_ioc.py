"""
Offline tests for the enrich_ioc IOC-reputation tool
====================================================
Dedicated tests for ``tools/enrich_ioc/handler.py`` — the deterministic,
OFFLINE IOC reputation/enrichment tool that alert triage consumes. ZERO AWS,
ZERO network, no real sleep. The handler is deterministic by design (it reads
the shared ``mockdata.world``), so the offline paths need no mocking; only the
live (``ENRICH_IOC_LIVE=1``) branch is steered via env / monkeypatch, and even
then it performs no I/O (the live client is a stub that raises).

This file is a good citizen about ``sys.modules``: the tool ships a module
literally named ``handler`` (as do sibling tools), so importing it by bare name
would collide in ``sys.modules`` when the whole suite runs. We load it from an
explicit file path under a UNIQUE module name and NEVER register the bare
``handler`` name — mirroring tests/test_asset_lookup.py — so this file cannot
poison any other tool test regardless of collection order.
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENRICH_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "enrich_ioc")
HANDLER_PATH = os.path.join(ENRICH_TOOL_DIR, "handler.py")

# The handler imports ``mockdata.world``; make the repo root importable.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


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


enrich = _load_module("enrich_ioc_handler_dedicated", HANDLER_PATH)

# Well-known fixture indicators (must match mockdata/world.py).
C2_IP = "203.0.113.66"            # ioc-c2-01, relates_to web-01, high conf
SCANNER_IP = "203.0.113.9"        # ioc-scan-01, scanner category
TOR_IP = "203.0.113.201"          # ioc-tor-exit-01, anonymizer, low conf
BENIGN_DOMAIN = "assets.example.com"       # ioc-benign-cdn-01, benign
PHISH_DOMAIN = "login-portal.example.test"  # ioc-phish-domain-01, phishing high
MAL_HASH = "a" * 63 + "1"         # ioc-mal-hash-01, malware high
DOC_IP_UNKNOWN = "192.0.2.99"     # valid doc IP, NOT in the mock set


# --------------------------------------------------------------------------- #
# The Log4Shell spine: C2 IP -> malicious + related web-01                     #
# --------------------------------------------------------------------------- #
def test_c2_ip_resolves_malicious_related_web01():
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True and res["source"] == "stub"
    rec = res["results"][C2_IP]
    assert rec["type"] == "ip"
    assert rec["known"] is True
    assert rec["threat_category"] == "c2"
    assert rec["confidence"] == "high"
    assert rec["verdict"] == "malicious"
    assert "web-01" in rec["related_hosts"]
    assert rec["first_seen"] == "2026-06-28T00:00:00Z"


# --------------------------------------------------------------------------- #
# A benign / documentation IP -> unknown or benign, never a false malicious    #
# --------------------------------------------------------------------------- #
def test_benign_cdn_domain_resolves_benign():
    res = enrich.handler({"indicator": BENIGN_DOMAIN}, None)
    rec = res["results"][BENIGN_DOMAIN]
    assert rec["type"] == "domain"
    assert rec["known"] is True
    assert rec["threat_category"] == "benign"
    assert rec["verdict"] == "benign"


def test_doc_ip_not_in_set_is_unknown():
    """A valid RFC 5737 doc IP that is NOT in the mock set: known:false /
    verdict:unknown, still classified as an ip — never a crash, never a false
    malicious."""
    res = enrich.handler({"indicator": DOC_IP_UNKNOWN}, None)
    rec = res["results"][DOC_IP_UNKNOWN]
    assert rec["type"] == "ip"
    assert rec["known"] is False
    assert rec["verdict"] == "unknown"
    assert rec["threat_category"] is None
    assert rec["confidence"] is None
    assert rec["first_seen"] is None
    assert rec["related_hosts"] == []


# --------------------------------------------------------------------------- #
# A domain and a sha256 each classify and resolve                              #
# --------------------------------------------------------------------------- #
def test_phishing_domain_classifies_and_resolves():
    res = enrich.handler({"indicator": PHISH_DOMAIN}, None)
    rec = res["results"][PHISH_DOMAIN]
    assert rec["type"] == "domain"
    assert rec["known"] is True
    assert rec["threat_category"] == "phishing"
    assert rec["confidence"] == "high"
    assert rec["verdict"] == "malicious"
    assert "win-ws-07" in rec["related_hosts"]


def test_malware_hash_classifies_and_resolves():
    res = enrich.handler({"indicator": MAL_HASH}, None)
    rec = res["results"][MAL_HASH]
    assert rec["type"] == "sha256"
    assert rec["known"] is True
    assert rec["threat_category"] == "malware"
    assert rec["verdict"] == "malicious"
    assert "win-ws-07" in rec["related_hosts"]


def test_scanner_and_tor_are_capped_at_suspicious():
    """Low-signal categories never auto-escalate to malicious, regardless of
    confidence: a scanner (medium) and a Tor exit (low) are both suspicious."""
    scan = enrich.handler({"indicator": SCANNER_IP}, None)["results"][SCANNER_IP]
    assert scan["known"] is True and scan["threat_category"] == "scanner"
    assert scan["verdict"] == "suspicious"

    tor = enrich.handler({"indicator": TOR_IP}, None)["results"][TOR_IP]
    assert tor["known"] is True and tor["threat_category"] == "anonymizer"
    assert tor["verdict"] == "suspicious"


# --------------------------------------------------------------------------- #
# Batch mode                                                                   #
# --------------------------------------------------------------------------- #
def test_batch_mode_enriches_each_indicator():
    batch = [C2_IP, BENIGN_DOMAIN, MAL_HASH, DOC_IP_UNKNOWN]
    res = enrich.handler({"indicators": batch}, None)
    assert res["ok"] is True and res["source"] == "stub"
    results = res["results"]
    assert set(results) == set(batch)
    assert results[C2_IP]["verdict"] == "malicious"
    assert results[BENIGN_DOMAIN]["verdict"] == "benign"
    assert results[MAL_HASH]["verdict"] == "malicious"
    assert results[DOC_IP_UNKNOWN]["verdict"] == "unknown"


def test_batch_with_mixed_types_classifies_each():
    res = enrich.handler({"indicators": [C2_IP, PHISH_DOMAIN, MAL_HASH]}, None)
    r = res["results"]
    assert r[C2_IP]["type"] == "ip"
    assert r[PHISH_DOMAIN]["type"] == "domain"
    assert r[MAL_HASH]["type"] == "sha256"


def test_unknown_indicator_returns_known_false():
    """An indicator classifiable but absent from the mock set -> known:false."""
    unknown_domain = "totally-unknown.example.com"
    res = enrich.handler({"indicator": unknown_domain}, None)
    rec = res["results"][unknown_domain]
    assert rec["known"] is False
    assert rec["verdict"] == "unknown"
    assert rec["type"] == "domain"


# --------------------------------------------------------------------------- #
# Validation errors (malformed input)                                          #
# --------------------------------------------------------------------------- #
def test_missing_both_fields_is_validation_error():
    res = enrich.handler({}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_both_fields_is_validation_error():
    res = enrich.handler({"indicator": C2_IP, "indicators": [C2_IP]}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_blank_indicator_is_validation_error(bad):
    res = enrich.handler({"indicator": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad", [123, None, 1.5, ["x"], {"k": 1}])
def test_non_string_indicator_is_validation_error(bad):
    res = enrich.handler({"indicator": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    res = enrich.handler("nope", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("junk", ["not an ioc!", "http://x", "1234", "g" * 64])
def test_unrecognizable_shape_is_validation_error(junk):
    """Junk that is neither ip/domain/sha256 (incl. a 64-char non-hex string) is
    a validation_error, never a silent known:false unknown."""
    res = enrich.handler({"indicator": junk}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_indicators_not_a_list_is_validation_error():
    res = enrich.handler({"indicators": C2_IP}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_empty_batch_is_validation_error():
    res = enrich.handler({"indicators": []}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_over_long_batch_is_validation_error():
    too_many = [C2_IP] * (enrich._MAX_BATCH + 1)
    res = enrich.handler({"indicators": too_many}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_over_long_indicator_is_validation_error():
    too_long = "a" * (enrich._MAX_INDICATOR_LEN + 1)
    res = enrich.handler({"indicator": too_long}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_one_bad_indicator_in_batch_fails_whole_batch():
    """A malformed member makes the whole call a validation_error (we validate
    up front, never partially enrich)."""
    res = enrich.handler({"indicators": [C2_IP, "junk!!"]}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Classification helper (direct)                                               #
# --------------------------------------------------------------------------- #
def test_classify_helper_distinguishes_types():
    assert enrich._classify(C2_IP) == "ip"
    assert enrich._classify("2001:db8::1") == "ip"  # IPv6 doc range
    assert enrich._classify(BENIGN_DOMAIN) == "domain"
    assert enrich._classify(MAL_HASH) == "sha256"
    with pytest.raises(ValueError):
        enrich._classify("not valid")


# --------------------------------------------------------------------------- #
# Determinism / no source mutation                                            #
# --------------------------------------------------------------------------- #
def test_offline_results_are_deterministic():
    a = enrich.handler({"indicator": C2_IP}, None)
    b = enrich.handler({"indicator": C2_IP}, None)
    assert a == b
    # Mutating the result must not corrupt the shared mock world for the next
    # caller (load_world hands out a deep copy; related_hosts is a fresh list).
    a["results"][C2_IP]["related_hosts"].append("TAMPERED")
    c = enrich.handler({"indicator": C2_IP}, None)
    assert "TAMPERED" not in c["results"][C2_IP]["related_hosts"]


def test_duplicate_in_batch_collapses_to_one_entry():
    res = enrich.handler({"indicators": [C2_IP, C2_IP]}, None)
    assert list(res["results"]) == [C2_IP]


# --------------------------------------------------------------------------- #
# Live (ENRICH_IOC_LIVE) branch — still ZERO network                          #
# --------------------------------------------------------------------------- #
def test_default_is_offline_stub(monkeypatch):
    monkeypatch.delenv("ENRICH_IOC_LIVE", raising=False)

    def _boom(inds):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached in offline mode")

    monkeypatch.setattr(enrich, "_fetch_live", _boom)
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True and res["source"] == "stub"


@pytest.mark.parametrize("val", ["0", "true", "yes", "", "01"])
def test_live_flag_only_activates_on_exact_1(monkeypatch, val):
    monkeypatch.setenv("ENRICH_IOC_LIVE", val)
    monkeypatch.setattr(
        enrich,
        "_fetch_live",
        lambda inds: (_ for _ in ()).throw(AssertionError("should stay offline")),
    )
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["source"] == "stub"


def test_live_without_backend_url_surfaces_upstream_error(monkeypatch):
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.delenv("ENRICH_IOC_URL", raising=False)
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "ENRICH_IOC_URL is not set" in res["message"]


def test_live_with_unreachable_backend_surfaces_upstream_error(monkeypatch):
    """With a real client wired, an unreachable backend (connection refused on
    a closed loopback port) is an ``upstream_error`` — never a crash and never
    a silent fall-back to the mock world. ZERO external network: the target is
    127.0.0.1 on a port nothing is listening on. The full live client is
    exercised against an in-process mock server in tests/test_enrich_ioc_live.py.
    """
    import socket

    # Grab an ephemeral port, then close it so the connect is refused.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", f"http://127.0.0.1:{closed_port}/api")
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"


def test_fetch_live_unreachable_backend_raises_runtime(monkeypatch):
    """Calling the real client directly against a refused loopback connection
    raises ``RuntimeError`` (mapped to ``upstream_error`` by the handler) — not
    a bare, unhandled socket exception. ZERO external network."""
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setenv("ENRICH_IOC_URL", f"http://127.0.0.1:{closed_port}/api")
    with pytest.raises(RuntimeError, match="request failed"):
        enrich._fetch_live([C2_IP])


def test_fetch_live_without_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("ENRICH_IOC_URL", raising=False)
    with pytest.raises(RuntimeError, match="ENRICH_IOC_URL is not set"):
        enrich._fetch_live([C2_IP])


def test_live_success_path_sets_source_live(monkeypatch):
    """When a live client IS wired (future), the handler wraps its results with
    source='live'. We stub _fetch_live to return a canned map — ZERO network."""
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    fake = {C2_IP: {"type": "ip", "known": True, "verdict": "malicious"}}
    monkeypatch.setattr(enrich, "_fetch_live", lambda inds: fake)
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["results"] == fake


# --------------------------------------------------------------------------- #
# __main__ entrypoint                                                         #
# --------------------------------------------------------------------------- #
def test_main_entrypoint_prints_results(capsys, monkeypatch):
    import json

    monkeypatch.delenv("ENRICH_IOC_LIVE", raising=False)
    runpy.run_path(HANDLER_PATH, run_name="__main__")
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True and parsed["source"] == "stub"
    assert parsed["results"][C2_IP]["verdict"] == "malicious"


# --------------------------------------------------------------------------- #
# House rule: no hardcoded secrets or real account ids in the source          #
# --------------------------------------------------------------------------- #
def test_source_has_no_hardcoded_secrets_or_account_ids():
    import re

    src = open(HANDLER_PATH, encoding="utf-8").read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src
