"""
Offline live-client tests for the nvd_lookup tool (NVD_LIVE=1)
=============================================================
Exercises the REAL live path of ``tools/nvd_lookup/handler.py`` — the stdlib
``urllib.request`` client reached when ``NVD_LIVE=1`` that queries the NVD CVE
2.0 API — against an **in-process MOCK http.server** bound to ``127.0.0.1:0``
(an ephemeral port).

HONESTY: no real NVD host is ever contacted. The tool hardcodes the NVD base
URL, so we monkeypatch ``urllib.request.urlopen`` to REWRITE the request netloc
onto our loopback mock while preserving the path, query, and headers the real
client set. A ``source="nvd"`` result here means "the real client parsed a reply
from our local mock", NOT that NVD was queried. There is ZERO external network
I/O: every request stays on the loopback interface.

These tests prove the live client's request SHAPE (GET, ``?cveId=`` query,
optional ``apiKey`` header from ``NVD_API_KEY``), its response PARSING (NVD 2.0
envelope -> normalized compact CVE), its ERROR HANDLING (HTTP 500 / malformed
JSON / connection-refused -> upstream_error, empty vulnerabilities -> not_found),
and the BYTE-CAP guard (an over-limit body raises) — never a silent fixture
fallback, and the API key is never echoed into the response.

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

HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "nvd_lookup", "handler.py")


def _load_module(unique_name: str, path: str):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # UNIQUE name only, never bare "handler"
    spec.loader.exec_module(module)
    return module


nvd = _load_module("nvd_lookup_handler_live_dedicated", HANDLER_PATH)


# An NVD 2.0 response exercising normalization: English description selected
# over other languages, cvssMetricV31 preferred, CWE ids de-duplicated + sorted
# and non-CWE weakness values dropped, references url-projected.
_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:39:23.157",
                "descriptions": [
                    {"lang": "es", "value": "descripcion en espanol"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI (Log4Shell)."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-917"}, {"value": "CWE-20"}]},
                    {"description": [{"value": "CWE-917"}, {"value": "NVD-CWE-Other"}]},
                ],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
                    {"source": "no-url-here"},
                ],
            }
        }
    ]
}

_CVE_KEYS = {
    "id", "published", "last_modified", "description",
    "cvss_v3_score", "cvss_v3_severity", "cwe_ids", "references",
}


# --------------------------------------------------------------------------- #
# In-process MOCK http.server (127.0.0.1, ephemeral port). NOT NVD.           #
# --------------------------------------------------------------------------- #
_STATE = {
    "mode": "ok",        # ok | http_500 | bad_json | empty
    "last_method": None,
    "last_path": None,
    "last_api_key": None,
}


class _MockNvdHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        _STATE["last_method"] = self.command
        _STATE["last_path"] = self.path
        _STATE["last_api_key"] = self.headers.get("apiKey")

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
        if _STATE["mode"] == "empty":
            body = b'{"vulnerabilities": []}'
        else:
            body = json.dumps(_NVD_RESPONSE).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _install_redirect(monkeypatch, netloc: str) -> None:
    """Rewrite the hardcoded NVD URL onto our loopback mock, preserving the
    path/query/headers the real client set. ZERO external network."""
    real_urlopen = urllib.request.urlopen

    def _fake(req, *args, **kwargs):
        parts = urlsplit(req.full_url)
        req.full_url = urlunsplit(("http", netloc, parts.path, parts.query, ""))
        return real_urlopen(req, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", _fake)


@pytest.fixture()
def mock_backend(monkeypatch):
    _STATE.update(mode="ok", last_method=None, last_path=None, last_api_key=None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockNvdHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("NVD_LIVE", "1")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    _install_redirect(monkeypatch, f"{host}:{port}")
    try:
        yield f"{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Success: NVD 2.0 reply -> normalized compact CVE, source="nvd"              #
# --------------------------------------------------------------------------- #
def test_live_success_returns_normalized_cve(mock_backend):
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is True
    assert res["source"] == "nvd"
    cve = res["cve"]
    assert set(cve) == _CVE_KEYS
    assert cve["id"] == "CVE-2021-44228"
    assert cve["description"] == "Apache Log4j2 JNDI (Log4Shell)."  # English chosen
    assert cve["cvss_v3_score"] == 10.0
    assert cve["cvss_v3_severity"] == "CRITICAL"
    # CWE ids de-duplicated + sorted; non-CWE weakness values dropped.
    assert cve["cwe_ids"] == ["CWE-20", "CWE-917"]
    # Only url-bearing references surface.
    assert cve["references"] == [
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    ]


def test_live_sends_get_with_cveid_query(mock_backend):
    nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert _STATE["last_method"] == "GET"
    assert "cveId=CVE-2021-44228" in _STATE["last_path"]


def test_live_empty_vulnerabilities_is_not_found(mock_backend):
    _STATE["mode"] = "empty"
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is False
    assert res["error"] == "not_found"
    assert "cve" not in res


# --------------------------------------------------------------------------- #
# Optional API key: sent as apiKey header only when NVD_API_KEY set, never    #
# echoed into the response.                                                   #
# --------------------------------------------------------------------------- #
def test_live_sends_api_key_header_when_set(mock_backend, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-a-real-secret")
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is True
    assert _STATE["last_api_key"] == "test-key-not-a-real-secret"


def test_live_no_api_key_header_when_unset(mock_backend):
    # Fixture already deletes NVD_API_KEY.
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is True
    assert _STATE["last_api_key"] is None


def test_live_api_key_never_appears_in_response(mock_backend, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "super-secret-nvd-key-xyz")
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert "super-secret-nvd-key-xyz" not in json.dumps(res)


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused -> upstream_error       #
# --------------------------------------------------------------------------- #
def test_live_http_500_yields_upstream_error_no_fallback(mock_backend):
    _STATE["mode"] = "http_500"
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # No silent stub fallback: CVE-2021-44228 exists offline, must NOT be served.
    assert "cve" not in res


def test_live_malformed_json_yields_upstream_error(mock_backend):
    _STATE["mode"] = "bad_json"
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "cve" not in res


def test_live_connection_refused_yields_upstream_error(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    refused_port = s.getsockname()[1]
    s.close()

    monkeypatch.setenv("NVD_LIVE", "1")
    _install_redirect(monkeypatch, f"127.0.0.1:{refused_port}")
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "cve" not in res


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
    monkeypatch.setenv("NVD_LIVE", "1")
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _OversizedResp()
    )
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "exceeds" in res["message"]
    assert "cve" not in res


# --------------------------------------------------------------------------- #
# Live opt-out: NVD_LIVE unset -> offline stub (source="stub")                #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_returns_stub(monkeypatch):
    monkeypatch.delenv("NVD_LIVE", raising=False)

    def _boom(*a, **k):  # pragma: no cover - must never run offline
        raise AssertionError("live backend must not be reached when flag unset")

    monkeypatch.setattr(nvd, "_fetch_live", _boom)
    res = nvd.handler({"cve_id": "CVE-2021-44228"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["cve"]["id"] == "CVE-2021-44228"
