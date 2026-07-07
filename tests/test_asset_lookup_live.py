"""
Live-client tests for the asset_lookup exposure-surface tool
============================================================
Exercises the REAL stdlib HTTP client on ``tools/asset_lookup/handler.py`` —
the branch reached when ``ASSET_LOOKUP_LIVE=1``. There is NO external network:
every request goes to an IN-PROCESS **mock** ``http.server`` bound to
``127.0.0.1:0`` (an ephemeral loopback port) that we start on a background
thread per test and tear down in teardown. Nothing here contacts a real CMDB /
scanner / asset-inventory backend — we only prove the request *shape* (method,
JSON body, optional bearer header), the response *parsing/normalization* into
the stub's surface contract, and the *error handling* (non-2xx, malformed JSON,
connection refused) that must yield ``upstream_error`` with no fixture fallback.

Like tests/test_asset_lookup.py this is a good ``sys.modules`` citizen: the tool
ships a module literally named ``handler``, so we load it from an explicit file
path under a UNIQUE module name and never register the bare ``handler`` name,
so this file cannot collide with any sibling tool test regardless of collection
order.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "asset_lookup")
HANDLER_PATH = os.path.join(ASSET_TOOL_DIR, "handler.py")


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


# A unique name distinct from the ones test_asset_lookup.py / test_attack_mapper.py
# use, so all three files co-exist in a single pytest run.
asset_handler = _load_module("asset_lookup_handler_live", HANDLER_PATH)


# --------------------------------------------------------------------------- #
# In-process mock backend server                                              #
# --------------------------------------------------------------------------- #
# A canned backend reply that is intentionally NOT byte-identical to the stub:
# it uses different host ids / a different subnet so a passing assertion proves
# the surface came from the live client, not a fixture fallback. It also carries
# an extra unknown field ("owner") to prove normalization drops noise.
_CANNED_BACKEND_REPLY = {
    "surface": {
        "hosts": [
            {
                "id": "live-web-01",
                "subnet": "192.0.2.0/24",
                "internet_exposed": True,
                "owner": "should-be-dropped",
                "services": [
                    {
                        "port": 443,
                        "proto": "tcp",
                        "name": "https",
                        "known_vuln": True,
                        "cve_id": "CVE-2021-44228",
                        "extra": "ignored",
                    }
                ],
            }
        ],
        "trust_edges": [
            {"src": "live-web-01", "dst": "live-db-01", "kind": "ssh_key_reuse"}
        ],
    }
}


class _MockBackend:
    """A single-purpose mock HTTP backend on 127.0.0.1:<ephemeral>.

    Captures the last request (method, path, headers, parsed JSON body) so tests
    can assert the request shape, and returns a configurable status + body.
    """

    def __init__(self, status=200, body=None, raw_body=None):
        self.status = status
        # ``body`` is JSON-encoded; ``raw_body`` (bytes) overrides it verbatim so
        # a test can send deliberately malformed JSON.
        self.body = body
        self.raw_body = raw_body
        self.last_method = None
        self.last_path = None
        self.last_headers = None
        self.last_json = None
        self._server = None
        self._thread = None

        server = self  # capture for the nested handler

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence stderr access logs
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
                server.last_method = self.command
                server.last_path = self.path
                server.last_headers = dict(self.headers)
                try:
                    server.last_json = json.loads(raw.decode("utf-8")) if raw else None
                except ValueError:
                    server.last_json = None

                self.send_response(server.status)
                self.send_header("Content-Type", "application/json")
                if server.raw_body is not None:
                    payload = server.raw_body
                else:
                    payload = json.dumps(
                        server.body if server.body is not None else {}
                    ).encode("utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._handler_cls = _Handler

    def start(self):
        self._server = HTTPServer(("127.0.0.1", 0), self._handler_cls)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        return self

    @property
    def url(self):
        host, port = self._server.server_address
        return f"http://{host}:{port}/asset"

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


@pytest.fixture
def mock_backend():
    """Yield a factory that starts a mock backend and guarantees teardown."""
    servers = []

    def _make(status=200, body=None, raw_body=None):
        srv = _MockBackend(status=status, body=body, raw_body=raw_body).start()
        servers.append(srv)
        return srv

    yield _make

    for srv in servers:
        srv.stop()


@pytest.fixture(autouse=True)
def _clean_live_env(monkeypatch):
    """Every test starts from a known env: live off, no URL, no token."""
    monkeypatch.delenv("ASSET_LOOKUP_LIVE", raising=False)
    monkeypatch.delenv("ASSET_LOOKUP_URL", raising=False)
    monkeypatch.delenv("ASSET_LOOKUP_TOKEN", raising=False)


# --------------------------------------------------------------------------- #
# Happy path: live client fetches + normalizes into the stub's contract       #
# --------------------------------------------------------------------------- #
def test_live_success_returns_normalized_surface(mock_backend, monkeypatch):
    backend = mock_backend(status=200, body=_CANNED_BACKEND_REPLY)
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)

    res = asset_handler.handler({"query": "192.0.2.0/24"}, None)

    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["query"] == "192.0.2.0/24"

    hosts = res["surface"]["hosts"]
    assert len(hosts) == 1
    host = hosts[0]
    # Exactly the stub's host shape — no stray backend fields leak through.
    assert set(host) == {"id", "subnet", "internet_exposed", "services"}
    assert host["id"] == "live-web-01"
    assert host["subnet"] == "192.0.2.0/24"
    assert host["internet_exposed"] is True

    svc = host["services"][0]
    assert set(svc) == {"port", "proto", "name", "known_vuln", "cve_id"}
    assert svc["port"] == 443
    assert svc["proto"] == "tcp"
    assert svc["name"] == "https"
    assert svc["known_vuln"] is True
    assert svc["cve_id"] == "CVE-2021-44228"

    edges = res["surface"]["trust_edges"]
    assert len(edges) == 1
    assert set(edges[0]) == {"src", "dst", "kind"}
    assert edges[0] == {
        "src": "live-web-01",
        "dst": "live-db-01",
        "kind": "ssh_key_reuse",
    }


def test_live_request_is_a_json_post_of_the_query(mock_backend, monkeypatch):
    """The live client POSTs the validated query as a JSON body."""
    backend = mock_backend(status=200, body=_CANNED_BACKEND_REPLY)
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)

    asset_handler.handler({"query": "web-01"}, None)

    assert backend.last_method == "POST"
    assert backend.last_json == {"query": "web-01"}
    # Content-Type header advertises JSON (header names are case-insensitive).
    ctype = {k.lower(): v for k, v in backend.last_headers.items()}.get("content-type")
    assert ctype == "application/json"


# --------------------------------------------------------------------------- #
# Bearer token is sent ONLY from the environment                              #
# --------------------------------------------------------------------------- #
def test_bearer_token_sent_when_env_set(mock_backend, monkeypatch):
    backend = mock_backend(status=200, body=_CANNED_BACKEND_REPLY)
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)
    monkeypatch.setenv("ASSET_LOOKUP_TOKEN", "s3cr3t-token-value")

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "live"

    headers = {k.lower(): v for k, v in backend.last_headers.items()}
    assert headers.get("authorization") == "Bearer s3cr3t-token-value"


def test_no_authorization_header_when_token_absent(mock_backend, monkeypatch):
    backend = mock_backend(status=200, body=_CANNED_BACKEND_REPLY)
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)
    # No ASSET_LOOKUP_TOKEN set (autouse fixture cleared it).

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True

    headers = {k.lower() for k in backend.last_headers}
    assert "authorization" not in headers


def test_token_value_never_appears_in_error_message(mock_backend, monkeypatch):
    """Even on a backend failure the bearer token must not leak into the
    upstream_error message."""
    backend = mock_backend(status=500, body={"error": "boom"})
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)
    monkeypatch.setenv("ASSET_LOOKUP_TOKEN", "do-not-leak-me")

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "do-not-leak-me" not in res["message"]


# --------------------------------------------------------------------------- #
# Error handling: non-2xx / malformed JSON / connection refused               #
# --------------------------------------------------------------------------- #
def test_http_500_yields_upstream_error_no_fallback(mock_backend, monkeypatch):
    backend = mock_backend(status=500, body={"error": "server on fire"})
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "500" in res["message"]
    # No silent fixture fallback.
    assert "surface" not in res


def test_malformed_json_yields_upstream_error(mock_backend, monkeypatch):
    backend = mock_backend(status=200, raw_body=b"this is { not json")
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "malformed JSON" in res["message"]
    assert "surface" not in res


def test_non_object_json_yields_upstream_error(mock_backend, monkeypatch):
    """A syntactically valid JSON reply that is not an object (e.g. a list) is
    still a contract violation -> upstream_error, never coerced to empty."""
    backend = mock_backend(status=200, raw_body=b"[1, 2, 3]")
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "surface" not in res


def test_connection_refused_yields_upstream_error(monkeypatch):
    """No server is listening on 127.0.0.1:1 -> connection refused surfaces as
    upstream_error with no crash and no fixture fallback. ZERO external network."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.setenv("ASSET_LOOKUP_URL", "http://127.0.0.1:1/asset")

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "surface" not in res


def test_missing_url_yields_upstream_error(monkeypatch):
    """ASSET_LOOKUP_LIVE=1 with no URL is an explicit upstream_error telling the
    operator to unset the live flag — never a fixture fallback."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    # autouse fixture already cleared ASSET_LOOKUP_URL.
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "ASSET_LOOKUP_URL" in res["message"]
    assert "ASSET_LOOKUP_LIVE" in res["message"]


# --------------------------------------------------------------------------- #
# Default (live off) still serves the offline stub                            #
# --------------------------------------------------------------------------- #
def test_live_unset_still_returns_stub(mock_backend, monkeypatch):
    """With ASSET_LOOKUP_LIVE unset the tool serves the offline stub surface and
    never touches the (running) mock backend."""
    backend = mock_backend(status=200, body=_CANNED_BACKEND_REPLY)
    monkeypatch.setenv("ASSET_LOOKUP_URL", backend.url)
    # ASSET_LOOKUP_LIVE intentionally NOT set.

    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    # Served the real offline fixture, not the mock backend's canned reply.
    assert {h["id"] for h in res["surface"]["hosts"]} == {
        "web-01", "app-01", "db-01", "bastion-01"
    }
    # The mock backend was never contacted.
    assert backend.last_method is None
