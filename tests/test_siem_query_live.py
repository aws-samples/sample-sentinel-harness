"""
Offline live-client tests for the siem_query SIEM tool
======================================================
Exercises the REAL live path of ``tools/siem_query/handler.py`` — the stdlib
``urllib.request`` client reached when ``SIEM_QUERY_LIVE=1`` — against an
**in-process MOCK http.server** bound to ``127.0.0.1:0`` (an ephemeral port).

HONESTY: no real SIEM backend is ever contacted. The "backend" here is a local
mock ``http.server`` we spin up on a background thread and tear down in
teardown. There is ZERO external network I/O: every request stays on the
loopback interface. These tests prove the live client's request SHAPE (POST,
JSON body, optional bearer header), its response PARSING (JSON reply ->
normalized event shape, ``source="live"``), and its ERROR HANDLING (HTTP 500,
malformed JSON, connection refused -> ``upstream_error`` with no crash and no
silent fixture fallback).

``sys.modules`` hygiene: the tool ships a module literally named ``handler``,
so we load it from an explicit path under a UNIQUE module name and never
register the bare ``handler`` name (mirrors tests/test_siem_query.py).
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "siem_query", "handler.py")


def _load_module(unique_name: str, path: str):
    """Import a standalone .py file under a unique name without polluting the
    bare module namespace shared by sibling tools."""
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


# A unique name so this file cannot poison any other tool test.
siem_handler = _load_module("siem_query_handler_live_dedicated", HANDLER_PATH)


# --------------------------------------------------------------------------- #
# In-process MOCK http.server (127.0.0.1, ephemeral port). NOT a real SIEM.   #
# --------------------------------------------------------------------------- #
# One canned backend reply that intentionally exercises normalization:
#  - "raw_summary" (mock-world spelling) must map to "summary"
#  - a missing "false_positive" must default to False
#  - a missing "dst_ip" must default to None
#  - ordering: emitted newest-first so the client's ts/alert_id sort is proven
_CANNED_EVENTS = [
    {
        "alert_id": "alert-2002",
        "ts": "2026-07-02T09:00:00Z",
        "severity": "high",
        "rule_name": "Suspicious Outbound Beacon",
        "host": "web-01",
        "src_ip": "192.0.2.55",
        "dst_ip": "198.51.100.7",
        "technique": "T1071",
        "summary": "Periodic beacon to known-bad host.",
        "false_positive": False,
    },
    {
        "alert_id": "alert-2001",
        "ts": "2026-07-01T08:00:00Z",
        "severity": "critical",
        "rule_name": "Log4Shell JNDI Exploit Attempt",
        "host": "web-01",
        "src_ip": "203.0.113.66",
        # dst_ip intentionally omitted -> must normalize to None
        "technique": "T1190",
        # raw_summary (not summary) -> must project to "summary"
        "raw_summary": "Inbound exploit attempt.",
        # false_positive intentionally omitted -> must default to False
    },
]

# Shared mutable state the mock handler reads and records into, per test.
_STATE = {
    "mode": "ok",          # ok | http_500 | bad_json
    "last_method": None,
    "last_body": None,
    "last_auth": None,     # captured Authorization header (or None)
    "last_content_type": None,
}


class _MockSiemHandler(BaseHTTPRequestHandler):
    """Canned backend. Records the inbound request shape for assertions."""

    def log_message(self, *args):  # silence per-request stderr logging
        pass

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length", 0))
        _STATE["last_method"] = self.command
        _STATE["last_body"] = self.rfile.read(length).decode("utf-8")
        _STATE["last_auth"] = self.headers.get("Authorization")
        _STATE["last_content_type"] = self.headers.get("Content-Type")

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

        payload = json.dumps({"events": _CANNED_EVENTS}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def mock_backend(monkeypatch):
    """Stand up the mock server on 127.0.0.1:0, point SIEM_QUERY_URL at it,
    enable the live flag, and guarantee teardown. Zero external network."""
    _STATE.update(
        mode="ok", last_method=None, last_body=None,
        last_auth=None, last_content_type=None,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockSiemHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.setenv("SIEM_QUERY_URL", f"http://{host}:{port}/api/query")
    monkeypatch.delenv("SIEM_QUERY_TOKEN", raising=False)
    try:
        yield f"http://{host}:{port}/api/query"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


_NORMALIZED_KEYS = {
    "alert_id", "ts", "severity", "rule_name", "host",
    "src_ip", "dst_ip", "technique", "summary", "false_positive",
}


# --------------------------------------------------------------------------- #
# Success: JSON reply -> normalized shape, source="live"                      #
# --------------------------------------------------------------------------- #
def test_live_success_returns_normalized_events(mock_backend):
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["count"] == 2
    # Every event carries EXACTLY the stub's normalized field set.
    for e in res["events"]:
        assert set(e) == _NORMALIZED_KEYS
        assert isinstance(e["false_positive"], bool)
    # Stable sort by (ts, alert_id): 2001 (Jul 1) before 2002 (Jul 2).
    assert [e["alert_id"] for e in res["events"]] == ["alert-2001", "alert-2002"]


def test_live_normalizes_summary_and_optional_defaults(mock_backend):
    res = siem_handler.handler({"host": "web-01"}, None)
    log4shell = next(e for e in res["events"] if e["alert_id"] == "alert-2001")
    # raw_summary projected to summary; never surfaced as raw_summary.
    assert log4shell["summary"] == "Inbound exploit attempt."
    assert "raw_summary" not in log4shell
    # Omitted optionals defaulted, not dropped.
    assert log4shell["dst_ip"] is None
    assert log4shell["false_positive"] is False


def test_live_sends_post_with_json_query_body(mock_backend):
    siem_handler.handler({"technique": "T1190"}, None)
    assert _STATE["last_method"] == "POST"
    assert _STATE["last_content_type"] == "application/json"
    # The validated selector is sent verbatim as the JSON request body.
    assert json.loads(_STATE["last_body"]) == {"technique": "T1190"}


# --------------------------------------------------------------------------- #
# Bearer token: sent as Authorization header only when SIEM_QUERY_TOKEN set   #
# --------------------------------------------------------------------------- #
def test_bearer_token_sent_as_authorization_header(mock_backend, monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_TOKEN", "test-token-not-a-real-secret")
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert _STATE["last_auth"] == "Bearer test-token-not-a-real-secret"


def test_no_token_means_no_authorization_header(mock_backend):
    # Fixture already deletes SIEM_QUERY_TOKEN.
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert _STATE["last_auth"] is None


def test_token_never_appears_in_response(mock_backend, monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_TOKEN", "super-secret-token-xyz")
    res = siem_handler.handler({"host": "web-01"}, None)
    assert "super-secret-token-xyz" not in json.dumps(res)


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused -> upstream_error       #
# --------------------------------------------------------------------------- #
def test_http_500_yields_upstream_error_no_fallback(mock_backend):
    _STATE["mode"] = "http_500"
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # No silent fixture fallback: no events despite web-01 existing offline.
    assert "events" not in res


def test_malformed_json_yields_upstream_error(mock_backend):
    _STATE["mode"] = "bad_json"
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "malformed JSON" in res["message"]
    assert "events" not in res


def test_connection_refused_yields_upstream_error(monkeypatch):
    # Bind then close an ephemeral port so a connect is guaranteed-refused.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    refused_port = s.getsockname()[1]
    s.close()

    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.setenv("SIEM_QUERY_URL", f"http://127.0.0.1:{refused_port}/api")
    monkeypatch.delenv("SIEM_QUERY_TOKEN", raising=False)
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "events" not in res


# --------------------------------------------------------------------------- #
# Live opt-out: SIEM_QUERY_LIVE unset -> offline stub (source="stub")         #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_returns_stub(monkeypatch):
    monkeypatch.delenv("SIEM_QUERY_LIVE", raising=False)
    # Even if a URL is configured, without the flag we stay offline.
    monkeypatch.setenv("SIEM_QUERY_URL", "http://127.0.0.1:9/should-not-be-hit")

    def _boom(k, v):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached when flag unset")

    monkeypatch.setattr(siem_handler, "_fetch_live", _boom)
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


def test_missing_url_with_live_flag_yields_upstream_error(monkeypatch):
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.delenv("SIEM_QUERY_URL", raising=False)
    res = siem_handler.handler({"host": "web-01"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "SIEM_QUERY_URL is not set" in res["message"]
    # Message steers the operator to unset the live flag.
    assert "SIEM_QUERY_LIVE" in res["message"]
