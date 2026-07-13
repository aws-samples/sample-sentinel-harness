"""
Offline SSRF/egress-hardening tests for the live-backend tool clients.

These make ZERO network calls: they only exercise the pre-request URL guard that
runs BEFORE any socket is opened, so a hostile/misconfigured ``*_LIVE`` URL is
rejected deterministically (mapped to ``upstream_error`` / a raised error — never
a silent fixture fallback). Covered: a ``file://`` scheme and the cloud-metadata
IP ``169.254.169.254`` must both be refused; and with ``*_LIVE`` unset the tool
still returns ``source="stub"`` (the offline mock path is untouched).

``sys.modules`` hygiene: each tool ships a module literally named ``handler``; we
load every one under a UNIQUE name so collection order can never clobber them.
"""
from __future__ import annotations

import importlib.util
import os
import socket
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


siem = _load("siem_query_handler_ssrf", "tools/siem_query/handler.py")
enrich = _load("enrich_ioc_handler_ssrf", "tools/enrich_ioc/handler.py")
nvd = _load("nvd_lookup_handler_ssrf", "tools/nvd_lookup/handler.py")
ops = _load("ops_query_handler_ssrf", "tools/ops_query/handler.py")
asset = _load("asset_lookup_handler_ssrf", "tools/asset_lookup/handler.py")
web_search = _load("web_search_handler_ssrf", "tools/web_search/handler.py")


@pytest.fixture()
def no_network(monkeypatch):
    """Arm a hard guard: if any test actually opens a socket, fail loudly."""
    def _boom(*a, **k):  # pragma: no cover - only fires on a real regression
        raise AssertionError("SSRF guard test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", _boom, raising=False)
    monkeypatch.setattr(socket.socket, "connect_ex", _boom, raising=False)
    monkeypatch.setattr(socket, "create_connection", _boom, raising=False)


# --------------------------------------------------------------------------- #
# siem_query — operator-supplied SIEM_QUERY_URL is the real SSRF surface        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",                          # non-HTTP scheme
    "http://169.254.169.254/latest/meta-data/",    # cloud metadata (the key SSRF)
    "gopher://evil.example.test/",                 # non-HTTP scheme
    "http://0.0.0.0/",                             # unspecified address
    "ftp://internal.example.test/",                # non-HTTP scheme
])
def test_siem_query_rejects_dangerous_url(monkeypatch, no_network, bad_url):
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.setenv("SIEM_QUERY_URL", bad_url)
    res = siem.handler({"host": "web-01"}, None)
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    # never leaks events / never silently returns stub data on a blocked URL
    assert "events" not in res or not res.get("events")


def test_siem_query_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("SIEM_QUERY_LIVE", raising=False)
    res = siem.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


def test_siem_assert_safe_url_allows_plain_https():
    # A routable https host with a DNS name is allowed (DNS egress is the network
    # policy's job); the guard must not raise on the normal case.
    siem._assert_safe_url("https://siem.example.internal/api/search")


def test_siem_assert_safe_url_allows_loopback():
    # Loopback is a legitimate self-hosted / on-box backend (and what the mock
    # server in the live tests binds to) — the guard must allow it, blocking only
    # the metadata/link-local/unspecified ranges.
    siem._assert_safe_url("http://127.0.0.1:8899/query")


# --------------------------------------------------------------------------- #
# enrich_ioc — same guard (already shipped); confirm it holds                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",
    "http://169.254.169.254/",
])
def test_enrich_ioc_rejects_dangerous_url(monkeypatch, bad_url):
    """The guard must REFUSE a dangerous URL — and prove it by asserting urlopen is
    NEVER reached. A previous version only checked error=='upstream_error', which a
    connection failure also produces, so it passed even if the guard was not wired
    (the metadata IP is unroutable in CI). This spy makes the guard's rejection the
    ONLY way the test can pass, so an unwired guard can never regress silently."""
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", bad_url)

    reached = {"urlopen": False}

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        reached["urlopen"] = True
        raise AssertionError(
            f"SSRF guard did not fire: urlopen was reached for {bad_url!r}"
        )

    monkeypatch.setattr(enrich.urllib.request, "urlopen", _boom)
    res = enrich.handler({"indicator": "203.0.113.66"}, None)
    assert reached["urlopen"] is False, "urlopen must not be reached for a blocked URL"
    assert res["ok"] is False
    assert res["error"] == "upstream_error"


def test_enrich_ioc_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("ENRICH_IOC_LIVE", raising=False)
    res = enrich.handler({"indicator": "203.0.113.66"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


# --------------------------------------------------------------------------- #
# nvd_lookup — fixed NVD host; defend in depth against a malformed CVE id        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_cve", [
    "CVE-2021-44228 OR 1=1",
    "../../etc/passwd",
    "CVE-2021-44228&extra=1",
    "not-a-cve",
    "",
])
def test_nvd_rejects_malformed_cve_id(monkeypatch, no_network, bad_cve):
    monkeypatch.setenv("NVD_LIVE", "1")
    res = nvd.handler({"cve_id": bad_cve}, None)
    # malformed id must not reach the network; handler surfaces an error/absent hit
    assert res.get("ok") is False or not res.get("found", False)


def test_nvd_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("NVD_LIVE", raising=False)
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res.get("ok") is True
    assert res.get("source") == "stub"


# --------------------------------------------------------------------------- #
# ops_query — operator-supplied OPS_QUERY_URL is the real SSRF surface         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",                          # non-HTTP scheme
    "http://169.254.169.254/latest/meta-data/",    # cloud metadata (the key SSRF)
    "gopher://evil.example.test/",                 # non-HTTP scheme
    "http://0.0.0.0/",                             # unspecified address
    "ftp://internal.example.test/",                # non-HTTP scheme
])
def test_ops_query_rejects_dangerous_url(monkeypatch, bad_url):
    """The guard must REFUSE a dangerous URL and prove it by asserting urlopen is
    NEVER reached. A spy raises AssertionError if called, so the guard's pre-request
    rejection is the ONLY way the test can pass — an unwired guard can never regress
    silently."""
    monkeypatch.setenv("OPS_QUERY_LIVE", "1")
    monkeypatch.setenv("OPS_QUERY_URL", bad_url)

    reached = {"urlopen": False}

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        reached["urlopen"] = True
        raise AssertionError(
            f"SSRF guard did not fire: urlopen was reached for {bad_url!r}"
        )

    monkeypatch.setattr(ops.urllib.request, "urlopen", _boom)
    res = ops.handler({"query": "*"}, None)
    assert reached["urlopen"] is False, "urlopen must not be reached for a blocked URL"
    assert res["ok"] is False
    assert res["error"] == "upstream_error"


def test_ops_query_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("OPS_QUERY_LIVE", raising=False)
    res = ops.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


def test_ops_assert_safe_url_allows_plain_https():
    # A routable https host with a DNS name is allowed (DNS egress is the network
    # policy's job); the guard must not raise on the normal case.
    ops._assert_safe_url("https://ops-backend.example.internal/api/query")


def test_ops_assert_safe_url_allows_loopback():
    # Loopback is a legitimate self-hosted / on-box backend (and what the mock
    # server in the live tests binds to) — the guard must allow it, blocking only
    # the metadata/link-local/unspecified ranges.
    ops._assert_safe_url("http://127.0.0.1:9001/query")


# --------------------------------------------------------------------------- #
# asset_lookup — operator-supplied ASSET_LOOKUP_URL is the real SSRF surface  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",                          # non-HTTP scheme
    "http://169.254.169.254/latest/meta-data/",    # cloud metadata (the key SSRF)
    "gopher://evil.example.test/",                 # non-HTTP scheme
    "http://0.0.0.0/",                             # unspecified address
    "ftp://internal.example.test/",                # non-HTTP scheme
])
def test_asset_lookup_rejects_dangerous_url(monkeypatch, bad_url):
    """The guard must REFUSE a dangerous URL and prove it by asserting urlopen is
    NEVER reached. A spy raises AssertionError if called, so the guard's pre-request
    rejection is the ONLY way the test can pass — an unwired guard can never regress
    silently."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", bad_url)

    reached = {"urlopen": False}

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        reached["urlopen"] = True
        raise AssertionError(
            f"SSRF guard did not fire: urlopen was reached for {bad_url!r}"
        )

    monkeypatch.setattr(asset.urllib.request, "urlopen", _boom)
    res = asset.handler({"query": "*"}, None)
    assert reached["urlopen"] is False, "urlopen must not be reached for a blocked URL"
    assert res["ok"] is False
    assert res["error"] == "upstream_error"


def test_asset_lookup_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("ASSET_LOOKUP_LIVE", raising=False)
    res = asset.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


def test_asset_assert_safe_url_allows_plain_https():
    # A routable https host with a DNS name is allowed (DNS egress is the network
    # policy's job); the guard must not raise on the normal case.
    asset._assert_safe_url("https://assets.example.internal/api/lookup")


def test_asset_assert_safe_url_allows_loopback():
    # Loopback is a legitimate self-hosted / on-box backend (and what the mock
    # server in the live tests binds to) — the guard must allow it, blocking only
    # the metadata/link-local/unspecified ranges.
    asset._assert_safe_url("http://127.0.0.1:8910/asset")


# --------------------------------------------------------------------------- #
# web_search — operator-supplied WEB_SEARCH_ENDPOINT is the real SSRF surface #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",                          # non-HTTP scheme
    "http://169.254.169.254/latest/meta-data/",    # cloud metadata (the key SSRF)
    "gopher://evil.example.test/",                 # non-HTTP scheme
    "http://0.0.0.0/",                             # unspecified address
    "ftp://internal.example.test/",                # non-HTTP scheme
])
def test_web_search_rejects_dangerous_url(monkeypatch, bad_url):
    """The guard must REFUSE a dangerous URL and prove it by asserting urlopen is
    NEVER reached. A spy raises AssertionError if called, so the guard's pre-request
    rejection is the ONLY way the test can pass — an unwired guard can never regress
    silently."""
    monkeypatch.setenv("WEB_SEARCH_LIVE", "1")
    monkeypatch.setenv("WEB_SEARCH_ENDPOINT", bad_url)

    reached = {"urlopen": False}

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        reached["urlopen"] = True
        raise AssertionError(
            f"SSRF guard did not fire: urlopen was reached for {bad_url!r}"
        )

    monkeypatch.setattr(web_search.urllib.request, "urlopen", _boom)
    res = web_search.handler({"query": "beacon c2"}, None)
    assert reached["urlopen"] is False, "urlopen must not be reached for a blocked URL"
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    assert "results" not in res


def test_web_search_stub_when_live_unset(monkeypatch):
    monkeypatch.delenv("WEB_SEARCH_LIVE", raising=False)
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


def test_web_search_assert_safe_url_allows_plain_https():
    # A routable https host with a DNS name is allowed (DNS egress is the network
    # policy's job); the guard must not raise on the normal case.
    web_search._assert_safe_url("https://search.example.internal/api/search")


def test_web_search_assert_safe_url_allows_loopback():
    # Loopback is a legitimate self-hosted / on-box backend (and what the mock
    # server in the live tests binds to) — the guard must allow it, blocking only
    # the metadata/link-local/unspecified ranges.
    web_search._assert_safe_url("http://127.0.0.1:8080/search")
