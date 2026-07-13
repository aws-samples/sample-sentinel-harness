"""
Offline unit tests for the reference tool handlers
==================================================
``tools/{nvd_lookup,epss_kev,attack_lookup,web_search}`` are offline-safe *reference
stubs*: they return deterministic fixtures unless a ``*_LIVE=1`` env var opts into a
real network call. These tests pin the input-validation contract, the stub payload
shape, and the egress posture (default path makes no network call) — all fully
offline. The live branches are intentionally NOT exercised (they require network and
are opt-in); we only assert the default is offline.

HARD RULE: ZERO network. We never set the ``*_LIVE`` env vars, so no handler leaves
the process.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_TOOLS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
)


def _load(tool_name: str):
    """Load tools/<tool_name>/handler.py by path (tools/ is a scripts tree)."""
    path = os.path.join(_TOOLS_DIR, tool_name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{tool_name}_handler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nvd = _load("nvd_lookup")
epss = _load("epss_kev")
attack = _load("attack_lookup")
web = _load("web_search")


# --------------------------------------------------------------------------- #
# nvd_lookup                                                                  #
# --------------------------------------------------------------------------- #
def test_nvd_known_cve_returns_stub():
    r = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert r["ok"] is True
    assert r["source"] == "stub"          # default is offline
    assert r["cve"]["cvss_v3_severity"] == "CRITICAL"
    assert r["cve"]["id"] == "CVE-2021-44228"


def test_nvd_lowercase_id_is_normalized():
    r = nvd.handler({"cve_id": "cve-2021-44228"}, None)
    assert r["ok"] is True
    assert r["cve"]["id"] == "CVE-2021-44228"


def test_nvd_unknown_cve_is_not_found_offline():
    r = nvd.handler({"cve_id": "CVE-2099-99999"}, None)
    assert r["ok"] is False
    assert r["error"] == "not_found"


@pytest.mark.parametrize("bad", ["", "not-a-cve", "CVE-21-44228", "44228"])
def test_nvd_bad_id_is_validation_error(bad):
    r = nvd.handler({"cve_id": bad}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# epss_kev                                                                    #
# --------------------------------------------------------------------------- #
def test_epss_single_and_batch_shape():
    r = epss.handler({"cve_ids": ["CVE-2021-44228", "CVE-2018-1000006"]}, None)
    assert r["ok"] is True and r["source"] == "stub"
    res = r["results"]
    assert res["CVE-2021-44228"]["in_kev"] is True         # in the KEV stub
    assert res["CVE-2018-1000006"]["in_kev"] is False       # not in KEV stub
    assert 0.0 <= res["CVE-2021-44228"]["epss"] <= 1.0


def test_epss_accepts_single_cve_id_key():
    r = epss.handler({"cve_id": "CVE-2021-44228"}, None)
    assert r["ok"] is True
    assert "CVE-2021-44228" in r["results"]


def test_epss_dedupes_and_uppercases():
    r = epss.handler({"cve_ids": ["cve-2021-44228", "CVE-2021-44228"]}, None)
    assert r["ok"] is True
    assert list(r["results"].keys()) == ["CVE-2021-44228"]  # de-duplicated


def test_epss_unknown_cve_yields_null_metrics_not_error():
    r = epss.handler({"cve_id": "CVE-2020-11111"}, None)
    assert r["ok"] is True
    entry = r["results"]["CVE-2020-11111"]
    assert entry["epss"] is None and entry["in_kev"] is False


@pytest.mark.parametrize("event", [{}, {"cve_ids": "not-a-list"}, {"cve_ids": []},
                                   {"cve_ids": ["bogus"]}])
def test_epss_bad_input_is_validation_error(event):
    r = epss.handler(event, None)
    assert r["ok"] is False and r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# attack_lookup                                                               #
# --------------------------------------------------------------------------- #
def test_attack_technique_and_subtechnique():
    parent = attack.handler({"technique_id": "T1059"}, None)
    assert parent["ok"] is True and parent["technique"]["is_subtechnique"] is False
    sub = attack.handler({"technique_id": "t1059.001"}, None)  # lowercase normalizes
    assert sub["ok"] is True
    assert sub["technique"]["id"] == "T1059.001"
    assert sub["technique"]["is_subtechnique"] is True


def test_attack_unknown_technique_not_found_offline():
    r = attack.handler({"technique_id": "T9999"}, None)
    assert r["ok"] is False and r["error"] == "not_found"


@pytest.mark.parametrize("bad", ["", "1059", "TX059", "T105a"])
def test_attack_bad_id_is_validation_error(bad):
    r = attack.handler({"technique_id": bad}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# web_search (egress-controlled, text-only)                                   #
# --------------------------------------------------------------------------- #
def test_web_search_returns_text_only_stub():
    r = web.handler({"query": "Log4Shell advisory"}, None)
    assert r["ok"] is True and r["source"] == "stub"
    assert len(r["results"]) == 5                # _DEFAULT_RESULTS
    assert all({"title", "url", "snippet"} <= set(item) for item in r["results"])
    # Egress posture is explicit in the contract note.
    assert "no page bodies" in r["note"]


def test_web_search_respects_max_results():
    r = web.handler({"query": "x", "max_results": 3}, None)
    assert r["ok"] is True and len(r["results"]) == 3


@pytest.mark.parametrize("event", [
    {},                                   # no query
    {"query": "   "},                     # blank query
    {"query": "x", "max_results": 0},     # below range
    {"query": "x", "max_results": 99},    # above range
    {"query": "x", "max_results": True},  # bool is not a valid int here
])
def test_web_search_bad_input_is_validation_error(event):
    r = web.handler(event, None)
    assert r["ok"] is False and r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Egress posture: no handler makes a network call on the default path         #
# --------------------------------------------------------------------------- #
def test_no_live_env_means_offline_source():
    """With no *_LIVE env var set, every tool reports source=stub/offline — the
    zero-egress default that makes these safe to run in CI."""
    for env in ("NVD_LIVE", "EPSS_KEV_LIVE", "ATTACK_LIVE", "WEB_SEARCH_LIVE"):
        assert os.environ.get(env) != "1"
    assert nvd.handler({"cve_id": "CVE-2021-44228"}, None)["source"] == "stub"
    assert epss.handler({"cve_id": "CVE-2021-44228"}, None)["source"] == "stub"
    assert attack.handler({"technique_id": "T1059"}, None)["source"] == "stub"
    assert web.handler({"query": "x"}, None)["source"] == "stub"
