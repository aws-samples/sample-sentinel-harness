"""
Offline tests for the siem_query read-only SIEM tool
====================================================
Dedicated tests for ``tools/siem_query/handler.py`` — the deterministic,
OFFLINE, read-only query surface over the fictional ``mockdata`` world. ZERO
AWS, ZERO network, no sleep. The handler is deterministic by design, so the
offline paths need no mocking; only the live (``SIEM_QUERY_LIVE=1``) branch is
steered via env, and even then it performs no I/O (the live client raises).

``sys.modules`` hygiene: the tool ships a module literally named ``handler`` (as
do sibling tools), so importing it by bare name would collide when the whole
suite runs. We load it from an explicit file path under a UNIQUE module name and
NEVER register the bare ``handler`` name — mirroring tests/test_asset_lookup.py.
We also ensure REPO_ROOT is importable so the handler's ``import mockdata``
resolves against the real world module (no fixtures duplicated here).
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The handler does ``import mockdata`` — make the repo root importable so it
# resolves against the single-source-of-truth world package.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SIEM_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "siem_query")
HANDLER_PATH = os.path.join(SIEM_TOOL_DIR, "handler.py")


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


# A unique name so this file cannot poison any other tool test.
siem_handler = _load_module("siem_query_handler_dedicated", HANDLER_PATH)

import mockdata  # noqa: E402  (imported after sys.path is set up above)

# All alert ids in the fixture world, for subset assertions.
_ALL_ALERT_IDS = {a["alert_id"] for a in mockdata.load_world()["alerts"]}


def _ids(res):
    return {e["alert_id"] for e in res["events"]}


# --------------------------------------------------------------------------- #
# Wildcard: the whole stream                                                  #
# --------------------------------------------------------------------------- #
def test_wildcard_returns_all_events():
    res = siem_handler.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["count"] == len(_ALL_ALERT_IDS)
    assert _ids(res) == _ALL_ALERT_IDS
    # Sorted by timestamp then alert_id — output ordering is stable.
    tss = [(e["ts"], e["alert_id"]) for e in res["events"]]
    assert tss == sorted(tss)


def test_events_are_normalized_shape():
    res = siem_handler.handler({"query": "*"}, None)
    for e in res["events"]:
        assert set(e) == {
            "alert_id", "ts", "severity", "rule_name", "host",
            "src_ip", "dst_ip", "technique", "summary", "false_positive",
        }
        assert isinstance(e["false_positive"], bool)
        # raw_summary is projected to summary (never surfaced as raw_summary).
        assert isinstance(e["summary"], str)


# --------------------------------------------------------------------------- #
# Filter by host                                                              #
# --------------------------------------------------------------------------- #
def test_filter_by_host_returns_only_that_hosts_events():
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    assert res["count"] >= 1
    assert all(e["host"] == "web-01" for e in res["events"])
    assert res["count"] == len(res["events"])


def test_filter_by_host_is_a_true_subset():
    web = _ids(siem_handler.handler({"host": "web-01"}, None))
    bastion = _ids(siem_handler.handler({"host": "bastion-01"}, None))
    # Different hosts -> disjoint event sets, both non-empty, both subsets.
    assert web and bastion
    assert web.isdisjoint(bastion)
    assert web <= _ALL_ALERT_IDS and bastion <= _ALL_ALERT_IDS


# --------------------------------------------------------------------------- #
# Filter by technique                                                         #
# --------------------------------------------------------------------------- #
def test_filter_by_technique():
    res = siem_handler.handler({"technique": "T1190"}, None)
    assert res["ok"] is True
    assert all(e["technique"] == "T1190" for e in res["events"])
    assert res["count"] >= 1


def test_technique_is_case_insensitive():
    upper = _ids(siem_handler.handler({"technique": "T1190"}, None))
    lower = _ids(siem_handler.handler({"technique": "t1190"}, None))
    assert upper == lower and upper


# --------------------------------------------------------------------------- #
# The Log4Shell cross-link invariant                                          #
# --------------------------------------------------------------------------- #
def test_log4shell_alert_findable_by_host_and_by_technique():
    """alert-1001 (Log4Shell / T1190 on web-01) is the cross-plane spine: it
    MUST be discoverable both by host web-01 AND by technique T1190, carrying
    the C2 src_ip that ties to the IOC/asset planes."""
    by_host = siem_handler.handler({"host": "web-01"}, None)
    by_tech = siem_handler.handler({"technique": "T1190"}, None)
    assert "alert-1001" in _ids(by_host)
    assert "alert-1001" in _ids(by_tech)

    log4shell = next(e for e in by_host["events"] if e["alert_id"] == "alert-1001")
    assert log4shell["host"] == "web-01"
    assert log4shell["technique"] == "T1190"
    assert log4shell["severity"] == "critical"
    assert log4shell["src_ip"] == "203.0.113.66"  # the C2 IOC value


# --------------------------------------------------------------------------- #
# Filter by severity                                                          #
# --------------------------------------------------------------------------- #
def test_filter_by_severity():
    res = siem_handler.handler({"severity": "high"}, None)
    assert res["ok"] is True
    assert res["count"] >= 1
    assert all(e["severity"] == "high" for e in res["events"])


def test_severity_bands_partition_expected_counts():
    world_alerts = mockdata.load_world()["alerts"]
    for band in ("critical", "high", "medium", "low", "info"):
        expected = sum(1 for a in world_alerts if a["severity"] == band)
        res = siem_handler.handler({"severity": band}, None)
        assert res["count"] == expected


# --------------------------------------------------------------------------- #
# Filter by alert_id                                                          #
# --------------------------------------------------------------------------- #
def test_filter_by_alert_id_returns_single_event():
    res = siem_handler.handler({"alert_id": "alert-1006"}, None)
    assert res["ok"] is True
    assert res["count"] == 1
    assert res["events"][0]["alert_id"] == "alert-1006"
    assert res["events"][0]["host"] == "bastion-01"


# --------------------------------------------------------------------------- #
# Filter by since (time filter)                                               #
# --------------------------------------------------------------------------- #
def test_filter_by_since_returns_only_events_at_or_after():
    since = "2026-06-30T00:00:00Z"
    res = siem_handler.handler({"since": since}, None)
    assert res["ok"] is True
    assert res["count"] >= 1
    assert all(e["ts"] >= since for e in res["events"])
    # Cross-check against the raw world: exactly the on/after set.
    expected = {
        a["alert_id"]
        for a in mockdata.load_world()["alerts"]
        if a["ts"] >= since
    }
    assert _ids(res) == expected


def test_since_boundary_is_inclusive():
    # alert-1001 fires at exactly 2026-06-28T14:03:11Z; querying that instant
    # must include it (>= is inclusive).
    res = siem_handler.handler({"since": "2026-06-28T14:03:11Z"}, None)
    assert "alert-1001" in _ids(res)


def test_since_far_future_returns_empty_not_error():
    res = siem_handler.handler({"since": "2099-01-01T00:00:00Z"}, None)
    assert res["ok"] is True
    assert res["count"] == 0 and res["events"] == []


# --------------------------------------------------------------------------- #
# Unknown value -> empty, NOT an error                                        #
# --------------------------------------------------------------------------- #
def test_unknown_host_returns_empty_list_not_error():
    res = siem_handler.handler({"host": "ghost-99"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["count"] == 0
    assert res["events"] == []


def test_unknown_technique_and_severity_return_empty():
    for sel in ({"technique": "T9999"}, {"severity": "purple"},
                {"alert_id": "alert-9999"}):
        res = siem_handler.handler(sel, None)
        assert res["ok"] is True and res["count"] == 0 and res["events"] == []


# --------------------------------------------------------------------------- #
# Malformed input -> validation_error                                         #
# --------------------------------------------------------------------------- #
def test_empty_event_is_validation_error():
    res = siem_handler.handler({}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_unknown_selector_key_is_validation_error():
    res = siem_handler.handler({"hostname": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_more_than_one_selector_is_validation_error():
    res = siem_handler.handler({"host": "web-01", "technique": "T1190"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_blank_value_is_validation_error(bad):
    res = siem_handler.handler({"host": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad", [123, None, 1.5, ["web-01"], {"q": 1}])
def test_non_string_value_is_validation_error(bad):
    res = siem_handler.handler({"host": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    res = siem_handler.handler("not-a-dict", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


def test_over_long_value_is_validation_error():
    too_long = "a" * (siem_handler._MAX_VALUE_LEN + 1)
    res = siem_handler.handler({"host": too_long}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "too long" in res["message"]


def test_unsupported_query_value_is_validation_error():
    """The wildcard selector only supports '*'; a literal value is a client
    error (validation_error), not an upstream failure."""
    res = siem_handler.handler({"query": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Determinism & read-only guarantee                                           #
# --------------------------------------------------------------------------- #
def test_same_query_same_result():
    a = siem_handler.handler({"query": "*"}, None)
    b = siem_handler.handler({"query": "*"}, None)
    assert a == b


def test_result_mutation_does_not_corrupt_source():
    a = siem_handler.handler({"host": "web-01"}, None)
    a["events"][0]["severity"] = "TAMPERED"
    b = siem_handler.handler({"host": "web-01"}, None)
    assert all(e["severity"] != "TAMPERED" for e in b["events"])


# --------------------------------------------------------------------------- #
# Live (SIEM_QUERY_LIVE) branch — still ZERO network                          #
# --------------------------------------------------------------------------- #
def test_default_is_offline_stub(monkeypatch):
    monkeypatch.delenv("SIEM_QUERY_LIVE", raising=False)

    def _boom(k, v):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached offline")

    monkeypatch.setattr(siem_handler, "_fetch_live", _boom)
    res = siem_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "stub"


@pytest.mark.parametrize("val", ["0", "true", "yes", "", "01"])
def test_live_flag_only_activates_on_exact_1(monkeypatch, val):
    monkeypatch.setenv("SIEM_QUERY_LIVE", val)
    monkeypatch.setattr(
        siem_handler,
        "_fetch_live",
        lambda k, v: (_ for _ in ()).throw(AssertionError("should stay offline")),
    )
    res = siem_handler.handler({"query": "*"}, None)
    assert res["source"] == "stub"


def test_live_without_backend_url_surfaces_upstream_error(monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.delenv("SIEM_QUERY_URL", raising=False)
    res = siem_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "SIEM_QUERY_URL is not set" in res["message"]


def test_live_with_backend_url_surfaces_not_implemented(monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.setenv("SIEM_QUERY_URL", "https://siem.example.internal/api")
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "not wired yet" in res["message"]
    assert "siem.example.internal" in res["message"]


def test_fetch_live_without_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("SIEM_QUERY_URL", raising=False)
    with pytest.raises(RuntimeError, match="SIEM_QUERY_URL is not set"):
        siem_handler._fetch_live("query", "*")


def test_live_success_path_sets_source_live(monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    fake_events = [{"alert_id": "x", "ts": "2026-01-01T00:00:00Z"}]
    monkeypatch.setattr(siem_handler, "_fetch_live", lambda k, v: fake_events)
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["count"] == 1
    assert res["events"] == fake_events


# --------------------------------------------------------------------------- #
# __main__ entrypoint                                                         #
# --------------------------------------------------------------------------- #
def test_main_entrypoint_runs(capsys, monkeypatch):
    monkeypatch.delenv("SIEM_QUERY_LIVE", raising=False)
    runpy.run_path(HANDLER_PATH, run_name="__main__")
    out = capsys.readouterr().out
    # Two JSON blobs are printed (by-host, by-technique); both contain 1001.
    assert "alert-1001" in out
    assert '"ok": true' in out or '"ok":true' in out


# --------------------------------------------------------------------------- #
# House rule: no hardcoded secrets or real account ids in the source          #
# --------------------------------------------------------------------------- #
def test_source_has_no_hardcoded_secrets_or_account_ids():
    import re

    src = open(HANDLER_PATH, encoding="utf-8").read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src
