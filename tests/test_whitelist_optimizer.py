"""
Offline unit tests for the whitelist_optimizer tool handler
===========================================================
``tools/whitelist_optimizer`` is the *real, deterministic, LLM-free* core of
the M6 feedback loop: it turns a cohort of confirmed false-positive alerts
into a safe Sigma-style suppression/whitelist clause so a noisy detection rule
stops firing on known-good traffic — WITHOUT going blind to real threats.

Because a bad whitelist could silently suppress a true detection, every branch
matters: correct common-discriminator extraction (CDN domain, backup process,
tight CIDR), correct suppressed_count, the true-positive guard (a mixed set
must NOT be suppressed), the "no safe whitelist" refusal (no overfitting), and
malformed-input validation.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. The tool is pure Python by
design, so every case runs fully offline with no mocking.
"""
from __future__ import annotations

import importlib.util
import os

# The tool handlers live under tools/<name>/handler.py — a scripts tree, not an
# installed package. Load the module directly by a UNIQUE path-based name so
# the tests don't depend on tools/ being importable or collide with siblings.
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "whitelist_optimizer", "handler.py",
)
_spec = importlib.util.spec_from_file_location("whitelist_optimizer_handler", _HANDLER_PATH)
wl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wl)


def optimize(event) -> dict:
    return wl.handler(event, None)


# --------------------------------------------------------------------------- #
# FPs sharing a CDN domain -> a domain whitelist that suppresses them          #
# --------------------------------------------------------------------------- #
def test_cdn_domain_whitelist_suppresses_all():
    ev = {
        "rule_name": "Malware Beacon to C2 Domain",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com", "host": "web-01"},
            {"alert_id": "a2", "dst_domain": "assets.example.com", "host": "web-02"},
            {"alert_id": "a3", "dst_domain": "assets.example.com", "host": "web-03"},
        ],
    }
    r = optimize(ev)
    assert r["ok"] is True
    assert r["source"] == "stub"
    assert r["rule_name"] == "Malware Beacon to C2 Domain"
    assert r["whitelist"] is not None
    assert r["whitelist"]["fields"] == {"dst_domain": "assets.example.com"}
    assert r["whitelist"]["match_type"] in ("domain_exact", "domain_suffix")
    assert r["suppressed_count"] == 3
    assert "filter_known_good" in r["sigma_filter_yaml"]
    assert "not filter_known_good" in r["sigma_filter_yaml"]
    assert "dst_domain" in r["sigma_filter_yaml"]


def test_cdn_domain_suffix_when_subdomains_differ():
    # Different subdomains under one parent -> a safe suffix whitelist.
    ev = {
        "rule_name": "Suspicious Outbound HTTP",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "img.assets.example.com"},
            {"alert_id": "a2", "dst_domain": "js.assets.example.com"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"]["match_type"] == "domain_suffix"
    assert r["whitelist"]["fields"] == {"dst_domain": "assets.example.com"}
    assert r["suppressed_count"] == 2
    assert "dst_domain|endswith: 'assets.example.com'" in r["sigma_filter_yaml"]


def test_domain_suffix_of_only_tld_is_rejected():
    # Sharing only ".com" must NOT become a whitelist on the whole TLD.
    ev = {
        "rule_name": "Outbound HTTP",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "alpha.com"},
            {"alert_id": "a2", "dst_domain": "beta.com"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"] is None
    assert r["verdict"] == "no_safe_whitelist"
    assert r["suppressed_count"] == 0


# --------------------------------------------------------------------------- #
# FPs sharing a backup process -> a process whitelist                          #
# --------------------------------------------------------------------------- #
def test_backup_process_whitelist():
    ev = {
        "rule_name": "EDR Suspicious Binary",
        "fp_events": [
            {"alert_id": "a1", "process_name": "backup.exe", "host": "db-01"},
            {"alert_id": "a2", "process_name": "backup.exe", "host": "db-02"},
        ],
    }
    r = optimize(ev)
    assert r["ok"] is True
    assert r["whitelist"]["fields"] == {"process_name": "backup.exe"}
    assert r["whitelist"]["match_type"] == "exact"
    assert r["suppressed_count"] == 2
    assert "process_name: 'backup.exe'" in r["sigma_filter_yaml"]


def test_process_whitelist_is_case_insensitive_count():
    ev = {
        "rule_name": "EDR Suspicious Binary",
        "fp_events": [
            {"alert_id": "a1", "process_name": "Backup.EXE"},
            {"alert_id": "a2", "process_name": "backup.exe"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"]["match_type"] == "exact"
    assert r["suppressed_count"] == 2


# --------------------------------------------------------------------------- #
# FPs sharing a tight src_ip CIDR -> a CIDR whitelist                          #
# --------------------------------------------------------------------------- #
def test_shared_cidr_whitelist():
    ev = {
        "rule_name": "Port Scan Detected",
        "fp_events": [
            {"alert_id": "a1", "src_ip": "192.0.2.10"},
            {"alert_id": "a2", "src_ip": "192.0.2.11"},
            {"alert_id": "a3", "src_ip": "192.0.2.12"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"]["match_type"] in ("cidr", "exact")
    assert r["whitelist"]["fields"].get("src_ip") is not None
    assert r["suppressed_count"] == 3
    assert "src_ip" in r["sigma_filter_yaml"]


def test_identical_ip_is_exact_match():
    ev = {
        "rule_name": "Port Scan Detected",
        "fp_events": [
            {"alert_id": "a1", "src_ip": "192.0.2.10"},
            {"alert_id": "a2", "src_ip": "192.0.2.10"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"]["match_type"] == "exact"
    assert r["whitelist"]["fields"] == {"src_ip": "192.0.2.10"}
    assert r["suppressed_count"] == 2


def test_overbroad_ip_range_is_rejected():
    # Addresses spanning a /8 must not collapse into a whitelist on 10.0.0.0/8.
    ev = {
        "rule_name": "Port Scan Detected",
        "fp_events": [
            {"alert_id": "a1", "src_ip": "10.0.0.1"},
            {"alert_id": "a2", "src_ip": "10.255.255.254"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"] is None
    assert r["verdict"] == "no_safe_whitelist"


# --------------------------------------------------------------------------- #
# FPs with NO common field -> "no safe whitelist" (does not overfit)           #
# --------------------------------------------------------------------------- #
def test_no_common_field_refuses_whitelist():
    ev = {
        "rule_name": "Grab Bag Rule",
        "fp_events": [
            {"alert_id": "a1", "src_ip": "203.0.113.9", "host": "web-01"},
            {"alert_id": "a2", "process_name": "svchost.exe", "user": "svc-a"},
            {"alert_id": "a3", "dst_domain": "totally-different.example.test"},
        ],
    }
    r = optimize(ev)
    assert r["ok"] is True
    assert r["whitelist"] is None
    assert r["verdict"] == "no_safe_whitelist"
    assert r["suppressed_count"] == 0
    assert "no common" in r["rationale"].lower()


# --------------------------------------------------------------------------- #
# Mixed set including a TP -> whitelist must NOT suppress the TP                #
# --------------------------------------------------------------------------- #
def test_whitelist_must_not_suppress_provided_tp_example():
    # FPs all share the CDN domain; a real detection on a DIFFERENT domain is
    # passed as a TP example. The chosen whitelist must not catch it.
    ev = {
        "rule_name": "Malware Beacon to C2 Domain",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com", "src_ip": "192.0.2.10"},
            {"alert_id": "a2", "dst_domain": "assets.example.com", "src_ip": "192.0.2.11"},
        ],
        "tp_examples": [
            {"alert_id": "t1", "dst_domain": "cdn-update.example.test", "src_ip": "198.51.100.7"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"] is not None
    assert r["whitelist"]["fields"] == {"dst_domain": "assets.example.com"}
    # Prove the emitted clause does not match the true-positive.
    field = "dst_domain"
    mt = r["whitelist"]["match_type"]
    val = r["whitelist"]["fields"][field]
    assert wl._clause_matches(ev["tp_examples"][0], field, mt, val) is False
    assert r["suppressed_count"] == 2


def test_tp_forces_refusal_when_only_shared_field_hits_tp():
    # The ONLY common discriminator (dst_domain) also matches the TP, so there
    # is no safe whitelist — refuse rather than blind the rule.
    ev = {
        "rule_name": "Beacon Rule",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "shared.example.test"},
            {"alert_id": "a2", "dst_domain": "shared.example.test"},
        ],
        "tp_examples": [
            {"alert_id": "t1", "dst_domain": "shared.example.test"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"] is None
    assert r["verdict"] == "no_safe_whitelist"
    assert "true-positive" in r["rationale"].lower()


def test_inline_true_positive_flag_is_treated_as_guard():
    # A "mixed set" where one fp_event is actually dispositioned true_positive.
    ev = {
        "rule_name": "Beacon Rule",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com"},
            {"alert_id": "a2", "dst_domain": "assets.example.com"},
            {"alert_id": "t1", "dst_domain": "cdn-update.example.test",
             "disposition": "true_positive"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"]["fields"] == {"dst_domain": "assets.example.com"}
    # Only the 2 real FPs are suppressed; the inline TP is excluded.
    assert r["suppressed_count"] == 2
    assert wl._clause_matches(
        {"dst_domain": "cdn-update.example.test"},
        "dst_domain",
        r["whitelist"]["match_type"],
        r["whitelist"]["fields"]["dst_domain"],
    ) is False


# --------------------------------------------------------------------------- #
# suppressed_count reflects only events the clause actually matches            #
# --------------------------------------------------------------------------- #
def test_suppressed_count_partial_when_field_absent_in_some():
    # process_name is the shared exact field for the two that have it, but a
    # third FP has a different process, so it can't be the discriminator; the
    # tool should instead find NO common field across all three -> refusal.
    ev = {
        "rule_name": "EDR Suspicious Binary",
        "fp_events": [
            {"alert_id": "a1", "process_name": "backup.exe"},
            {"alert_id": "a2", "process_name": "backup.exe"},
            {"alert_id": "a3", "process_name": "other.exe"},
        ],
    }
    r = optimize(ev)
    assert r["whitelist"] is None
    assert r["verdict"] == "no_safe_whitelist"


# --------------------------------------------------------------------------- #
# existing_rule condition is merged into the emitted snippet                    #
# --------------------------------------------------------------------------- #
def test_existing_rule_condition_is_merged():
    ev = {
        "rule_name": "Beacon Rule",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com"},
            {"alert_id": "a2", "dst_domain": "assets.example.com"},
        ],
        "existing_rule": {
            "detection": {
                "selection": {"dst_domain|contains": "example"},
                "condition": "selection",
            }
        },
    }
    r = optimize(ev)
    assert "condition: selection and not filter_known_good" in r["sigma_filter_yaml"]


def test_existing_rule_compound_condition_is_parenthesized():
    ev = {
        "rule_name": "Beacon Rule",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com"},
            {"alert_id": "a2", "dst_domain": "assets.example.com"},
        ],
        "existing_rule": {
            "detection": {
                "sel_a": {"a": 1},
                "sel_b": {"b": 2},
                "condition": "sel_a and sel_b",
            }
        },
    }
    r = optimize(ev)
    assert "(sel_a and sel_b) and not filter_known_good" in r["sigma_filter_yaml"]


# --------------------------------------------------------------------------- #
# Validation errors                                                            #
# --------------------------------------------------------------------------- #
def test_missing_rule_name_is_validation_error():
    r = optimize({"fp_events": [{"dst_domain": "assets.example.com"}]})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "rule_name" in r["message"]


def test_empty_fp_events_is_validation_error():
    r = optimize({"rule_name": "R", "fp_events": []})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "fp_events" in r["message"]


def test_missing_fp_events_is_validation_error():
    r = optimize({"rule_name": "R"})
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    r = optimize("not a dict")
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_non_dict_fp_event_is_validation_error():
    r = optimize({"rule_name": "R", "fp_events": ["nope"]})
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_bad_existing_rule_type_is_validation_error():
    r = optimize({
        "rule_name": "R",
        "fp_events": [{"dst_domain": "assets.example.com"}],
        "existing_rule": 12345,
    })
    assert r["ok"] is False
    assert r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Determinism                                                                  #
# --------------------------------------------------------------------------- #
def test_deterministic_same_input_same_output():
    ev = {
        "rule_name": "Beacon Rule",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "assets.example.com"},
            {"alert_id": "a2", "dst_domain": "assets.example.com"},
        ],
    }
    assert optimize(ev) == optimize(ev)
