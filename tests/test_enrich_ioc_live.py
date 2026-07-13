"""
Offline tests for the enrich_ioc LIVE client (ENRICH_IOC_LIVE=1)
================================================================
These tests exercise the REAL stdlib-``urllib`` live client in
``tools/enrich_ioc/handler.py`` against an IN-PROCESS **mock** HTTP server bound
to ``127.0.0.1:0`` (an ephemeral loopback port). There is ZERO external network:
nothing leaves the machine, no real threat-intel backend is ever contacted. The
mock server is a plain ``http.server.BaseHTTPRequestHandler`` returning canned
JSON, so these tests prove the *request shape*, the *response normalization*,
the *Authorization header* wiring, and the *error handling* deterministically.

HONESTY NOTE: the server here is a MOCK. A ``source="live"`` result in these
tests means "the real client successfully parsed a reply from our local mock",
NOT that any real reputation feed was queried.

``sys.modules`` hygiene: the tool ships a module literally named ``handler`` (as
do sibling tools), so we load it from an explicit path under a UNIQUE module
name and never register the bare ``handler`` name — mirroring
tests/test_enrich_ioc.py — so this file cannot poison sibling-tool tests.
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "enrich_ioc", "handler.py")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_module(unique_name: str, path: str):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # UNIQUE name only, never bare "handler"
    spec.loader.exec_module(module)
    return module


# A distinct unique name from test_enrich_ioc.py's, so collection order of the
# two files can never make them clobber each other in sys.modules.
enrich = _load_module("enrich_ioc_handler_live_dedicated", HANDLER_PATH)

C2_IP = "203.0.113.66"          # matches mockdata/world.py — the Log4Shell C2
DOC_IP_UNKNOWN = "192.0.2.99"   # valid doc IP, absent from any canned reply


# --------------------------------------------------------------------------- #
# In-process MOCK backend                                                     #
# --------------------------------------------------------------------------- #
class _MockBackend:
    """A tiny in-process MOCK HTTP backend on 127.0.0.1:<ephemeral>.

    Configurable per test via callables/attributes:
      - ``status``      : HTTP status code to return (default 200)
      - ``body``        : raw bytes body to return (default canned JSON)
      - ``captured``    : records the last request's headers + parsed body

    NOT a real reputation feed — canned data only, zero external network.
    """

    def __init__(self):
        self.status = 200
        self.body = b'{"results": {}}'
        self.captured = {"headers": None, "json": None, "path": None, "method": None}
        backend = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence stderr access logs
                pass

            def do_POST(self):  # noqa: N802 (http.server naming)
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
                try:
                    parsed = json.loads(raw.decode("utf-8")) if raw else None
                except (json.JSONDecodeError, UnicodeDecodeError):
                    parsed = None
                backend.captured = {
                    "headers": {k: v for k, v in self.headers.items()},
                    "json": parsed,
                    "path": self.path,
                    "method": "POST",
                }
                self.send_response(backend.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(backend.body)))
                self.end_headers()
                self.wfile.write(backend.body)

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/enrich"
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def backend():
    server = _MockBackend()
    try:
        yield server
    finally:
        server.shutdown()  # torn down in teardown regardless of test outcome


# --------------------------------------------------------------------------- #
# Happy path: real client -> mock server -> normalized source="live"          #
# --------------------------------------------------------------------------- #
def test_live_success_returns_normalized_source_live(monkeypatch, backend):
    backend.body = json.dumps(
        {
            "results": {
                C2_IP: {
                    "type": "ip",
                    "known": True,
                    "threat_category": "c2",
                    "confidence": "high",
                    "first_seen": "2026-06-28T00:00:00Z",
                    "related_hosts": ["web-01"],
                    "verdict": "malicious",
                }
            }
        }
    ).encode("utf-8")
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)
    monkeypatch.delenv("ENRICH_IOC_TOKEN", raising=False)

    res = enrich.handler({"indicator": C2_IP}, None)

    assert res["ok"] is True
    assert res["source"] == "live"
    rec = res["results"][C2_IP]
    assert rec["type"] == "ip"
    assert rec["known"] is True
    assert rec["threat_category"] == "c2"
    assert rec["confidence"] == "high"
    assert rec["first_seen"] == "2026-06-28T00:00:00Z"
    assert rec["related_hosts"] == ["web-01"]
    assert rec["verdict"] == "malicious"
    # The client POSTed JSON with the validated indicator list.
    assert backend.captured["method"] == "POST"
    assert backend.captured["json"] == {"indicators": [C2_IP]}
    assert backend.captured["headers"]["Content-Type"] == "application/json"


def test_live_normalizes_shape_matches_stub_contract(monkeypatch, backend):
    """The normalized live record has EXACTLY the stub's key set."""
    backend.body = json.dumps(
        {"results": {C2_IP: {"type": "ip", "threat_category": "c2",
                             "confidence": "high", "relates_to": ["web-01"]}}}
    ).encode("utf-8")
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicator": C2_IP}, None)
    rec = res["results"][C2_IP]
    assert set(rec) == {
        "type", "known", "threat_category", "confidence",
        "first_seen", "related_hosts", "verdict",
    }
    # derived from category+confidence (no explicit verdict in the reply)
    assert rec["verdict"] == "malicious"
    assert rec["known"] is True
    assert rec["related_hosts"] == ["web-01"]  # ``relates_to`` alias honored


def test_live_batch_flat_map_reply_is_accepted(monkeypatch, backend):
    """A flat ``{indicator: record}`` reply (no envelope) is also accepted."""
    backend.body = json.dumps(
        {C2_IP: {"type": "ip", "threat_category": "c2", "confidence": "high"}}
    ).encode("utf-8")
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicators": [C2_IP, DOC_IP_UNKNOWN]}, None)
    assert res["ok"] is True and res["source"] == "live"
    assert set(res["results"]) == {C2_IP, DOC_IP_UNKNOWN}
    # An indicator the backend omitted degrades to a known:false/unknown record.
    miss = res["results"][DOC_IP_UNKNOWN]
    assert miss["known"] is False
    assert miss["verdict"] == "unknown"
    assert miss["type"] == "ip"


# --------------------------------------------------------------------------- #
# Bearer token: sent as Authorization ONLY when ENRICH_IOC_TOKEN is set        #
# --------------------------------------------------------------------------- #
def test_live_sends_bearer_token_when_set(monkeypatch, backend):
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)
    monkeypatch.setenv("ENRICH_IOC_TOKEN", "s3cr3t-token-value")

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True and res["source"] == "live"
    # The token from the env is present as a Bearer Authorization header.
    assert backend.captured["headers"].get("Authorization") == "Bearer s3cr3t-token-value"
    # And the token never leaks into the response payload.
    assert "s3cr3t-token-value" not in json.dumps(res)


def test_live_omits_authorization_header_when_token_unset(monkeypatch, backend):
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)
    monkeypatch.delenv("ENRICH_IOC_TOKEN", raising=False)

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True
    assert "Authorization" not in backend.captured["headers"]


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused -> upstream_error        #
# --------------------------------------------------------------------------- #
def test_live_http_500_is_upstream_error(monkeypatch, backend):
    backend.status = 500
    backend.body = b'{"error": "boom"}'
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    assert "500" in res["message"]
    # No silent fixture fall-back: there is NO stub verdict smuggled in.
    assert "results" not in res


def test_live_malformed_json_is_upstream_error(monkeypatch, backend):
    backend.status = 200
    backend.body = b"this-is-not-json{{{"
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    assert "malformed JSON" in res["message"]
    assert "results" not in res


def test_live_connection_refused_is_upstream_error(monkeypatch):
    """Point the client at a closed loopback port: connection refused becomes an
    ``upstream_error`` — no crash, no fixture fall-back. ZERO external network."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", f"http://127.0.0.1:{closed_port}/api")
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    assert "results" not in res


def test_live_non_object_json_is_upstream_error(monkeypatch, backend):
    backend.status = 200
    backend.body = b"[1, 2, 3]"  # a JSON array, not an object
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"


def test_live_missing_url_is_upstream_error(monkeypatch, backend):
    monkeypatch.setenv("ENRICH_IOC_LIVE", "1")
    monkeypatch.delenv("ENRICH_IOC_URL", raising=False)
    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "ENRICH_IOC_URL is not set" in res["message"]


# --------------------------------------------------------------------------- #
# The opt-out invariant: ENRICH_IOC_LIVE unset -> offline stub, ZERO network   #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_still_returns_source_stub(monkeypatch, backend):
    """Even with a reachable backend URL configured, WITHOUT ENRICH_IOC_LIVE=1
    the handler stays offline (source='stub') and never touches the network."""
    monkeypatch.delenv("ENRICH_IOC_LIVE", raising=False)
    monkeypatch.setenv("ENRICH_IOC_URL", backend.url)

    res = enrich.handler({"indicator": C2_IP}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    # The mock backend was never contacted (no captured request).
    assert backend.captured["method"] is None
    # And the offline verdict is the real deterministic mock-world one.
    assert res["results"][C2_IP]["verdict"] == "malicious"
