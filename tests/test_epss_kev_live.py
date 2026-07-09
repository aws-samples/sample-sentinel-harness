"""
Offline live-client tests for the epss_kev tool (EPSS_KEV_LIVE=1)
=================================================================
Exercises the REAL live path of ``tools/epss_kev/handler.py`` — the stdlib
``urllib.request`` client reached when ``EPSS_KEV_LIVE=1`` that queries the
public EPSS API and the CISA KEV feed — against an **in-process MOCK
http.server** bound to ``127.0.0.1:0`` (an ephemeral port).

HONESTY: neither the FIRST.org EPSS host nor the CISA KEV host is ever
contacted. The tool hardcodes both URLs, so we monkeypatch
``urllib.request.urlopen`` to REWRITE each request's netloc onto our single
loopback mock while preserving the path + query; the mock dispatches on the
path (``/data/v1/epss`` vs the KEV feed path) so both upstream calls are
served locally. A ``source="live"`` result here means "the real client parsed
replies from our local mock", NOT that any real feed was queried. ZERO external
network I/O.

These tests prove the live client's request SHAPE (two GETs; EPSS batched via
``?cve=`` comma list), its response PARSING (EPSS ``data`` rows + KEV
``vulnerabilities`` rows -> merged normalized result), its ERROR HANDLING
(HTTP 500 / malformed JSON / connection-refused -> upstream_error), and the
BYTE-CAP guard (an over-limit body raises) — never a silent fixture fallback.

``sys.modules`` hygiene: the tool ships a module literally named ``handler``, so
we load it from an explicit path under a UNIQUE module name and never register
the bare ``handler`` name (mirrors tests/test_siem_query_live.py).
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "epss_kev", "handler.py")


def _load_module(unique_name: str, path: str):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # UNIQUE name only, never bare "handler"
    spec.loader.exec_module(module)
    return module


epss_kev = _load_module("epss_kev_handler_live_dedicated", HANDLER_PATH)

CVE_LOG4SHELL = "CVE-2021-44228"   # in both EPSS + KEV canned replies
CVE_EPSS_ONLY = "CVE-2018-1000006"  # in EPSS only -> in_kev must be False

_EPSS_REPLY = {
    "data": [
        {"cve": CVE_LOG4SHELL, "epss": "0.975000", "percentile": "0.999000"},
        {"cve": CVE_EPSS_ONLY, "epss": "0.420000", "percentile": "0.910000"},
    ]
}
_KEV_REPLY = {
    "vulnerabilities": [
        {
            "cveID": CVE_LOG4SHELL,
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
        }
    ]
}

_RESULT_KEYS = {
    "epss", "epss_percentile", "in_kev", "kev_date_added", "kev_due_date",
}


# --------------------------------------------------------------------------- #
# In-process MOCK http.server (127.0.0.1). Serves BOTH upstreams by path.     #
# --------------------------------------------------------------------------- #
_STATE = {
    "mode": "ok",         # ok | http_500 | bad_json
    "epss_path": None,    # captured EPSS request path (incl. query)
    "kev_hit": False,
}


class _MockEpssKevHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        is_epss = "/data/v1/epss" in self.path
        if is_epss:
            _STATE["epss_path"] = self.path
        else:
            _STATE["kev_hit"] = True

        if _STATE["mode"] == "http_500":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "boom"}')
            return
        if _STATE["mode"] == "bad_json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"this is not json {{{")
            return

        reply = _EPSS_REPLY if is_epss else _KEV_REPLY
        body = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _install_redirect(monkeypatch, netloc: str) -> None:
    """Rewrite both hardcoded upstream URLs onto our single loopback mock,
    preserving path + query so the mock can dispatch on the path. ZERO external
    network."""
    real_urlopen = urllib.request.urlopen

    def _fake(req, *args, **kwargs):
        parts = urlsplit(req.full_url)
        req.full_url = urlunsplit(("http", netloc, parts.path, parts.query, ""))
        return real_urlopen(req, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", _fake)


@pytest.fixture()
def mock_backend(monkeypatch):
    _STATE.update(mode="ok", epss_path=None, kev_hit=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockEpssKevHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("EPSS_KEV_LIVE", "1")
    _install_redirect(monkeypatch, f"{host}:{port}")
    try:
        yield f"{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Success: EPSS + KEV replies -> merged normalized result, source="live"      #
# --------------------------------------------------------------------------- #
def test_live_success_merges_epss_and_kev(mock_backend):
    res = epss_kev.handler(
        {"cve_ids": [CVE_LOG4SHELL, CVE_EPSS_ONLY]}, None
    )
    assert res["ok"] is True
    assert res["source"] == "live"
    assert set(res["results"]) == {CVE_LOG4SHELL, CVE_EPSS_ONLY}

    log4 = res["results"][CVE_LOG4SHELL]
    assert set(log4) == _RESULT_KEYS
    assert log4["epss"] == 0.975  # string coerced to float
    assert log4["epss_percentile"] == 0.999
    assert log4["in_kev"] is True
    assert log4["kev_date_added"] == "2021-12-10"
    assert log4["kev_due_date"] == "2021-12-24"

    # In EPSS only: scores present, but KEV status false and dates None.
    epss_only = res["results"][CVE_EPSS_ONLY]
    assert epss_only["epss"] == 0.42
    assert epss_only["in_kev"] is False
    assert epss_only["kev_date_added"] is None
    assert epss_only["kev_due_date"] is None


def test_live_sends_batched_epss_query_and_hits_kev(mock_backend):
    epss_kev.handler({"cve_ids": [CVE_LOG4SHELL, CVE_EPSS_ONLY]}, None)
    # EPSS supports comma-separated batch queries.
    assert _STATE["epss_path"] is not None
    assert f"cve={CVE_LOG4SHELL},{CVE_EPSS_ONLY}" in _STATE["epss_path"]
    assert _STATE["kev_hit"] is True


def test_live_cve_absent_from_both_feeds_degrades_to_empty(mock_backend):
    # A well-formed CVE that neither feed returns: scores None, in_kev False.
    unknown = "CVE-2020-0001"
    res = epss_kev.handler({"cve_id": unknown}, None)
    assert res["ok"] is True and res["source"] == "live"
    rec = res["results"][unknown]
    assert rec["epss"] is None
    assert rec["epss_percentile"] is None
    assert rec["in_kev"] is False


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused -> upstream_error       #
# --------------------------------------------------------------------------- #
def test_live_http_500_yields_upstream_error_no_fallback(mock_backend):
    _STATE["mode"] = "http_500"
    res = epss_kev.handler({"cve_id": CVE_LOG4SHELL}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # No silent stub fallback: CVE-2021-44228 exists offline, must NOT be served.
    assert "results" not in res


def test_live_malformed_json_yields_upstream_error(mock_backend):
    _STATE["mode"] = "bad_json"
    res = epss_kev.handler({"cve_id": CVE_LOG4SHELL}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "results" not in res


def test_live_connection_refused_yields_upstream_error(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    refused_port = s.getsockname()[1]
    s.close()

    monkeypatch.setenv("EPSS_KEV_LIVE", "1")
    _install_redirect(monkeypatch, f"127.0.0.1:{refused_port}")
    res = epss_kev.handler({"cve_id": CVE_LOG4SHELL}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "results" not in res


# --------------------------------------------------------------------------- #
# Byte-cap: an over-limit body RAISES rather than buffering unboundedly        #
# --------------------------------------------------------------------------- #
class _OversizedResp:
    """``read(n)`` always returns exactly ``n`` bytes, so the client's
    ``read(_MAX + 1)`` yields ``_MAX + 1`` bytes and trips the cap regardless of
    its numeric value. Cap-agnostic and allocation-light."""

    def read(self, amt=-1):
        return b"\x00" * (amt if amt and amt > 0 else 0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_live_oversized_body_raises_and_maps_to_upstream_error(monkeypatch):
    monkeypatch.setenv("EPSS_KEV_LIVE", "1")
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _OversizedResp()
    )
    res = epss_kev.handler({"cve_id": CVE_LOG4SHELL}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "exceeds" in res["message"]
    assert "results" not in res


# --------------------------------------------------------------------------- #
# Live opt-out: EPSS_KEV_LIVE unset -> offline stub (source="stub")           #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_returns_stub(monkeypatch):
    monkeypatch.delenv("EPSS_KEV_LIVE", raising=False)

    def _boom(*a, **k):  # pragma: no cover - must never run offline
        raise AssertionError("live backend must not be reached when flag unset")

    monkeypatch.setattr(epss_kev, "_enrich_live", _boom)
    res = epss_kev.handler({"cve_id": CVE_LOG4SHELL}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["results"][CVE_LOG4SHELL]["in_kev"] is True
