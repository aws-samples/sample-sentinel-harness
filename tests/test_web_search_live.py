"""
Offline live-client tests for the web_search tool (WEB_SEARCH_LIVE=1)
=====================================================================
Exercises the REAL live path of ``tools/web_search/handler.py`` — the stdlib
``urllib.request`` client reached when ``WEB_SEARCH_LIVE=1`` that queries the
single configured ``WEB_SEARCH_ENDPOINT`` chokepoint — against an **in-process
MOCK http.server** bound to ``127.0.0.1:0`` (an ephemeral port).

HONESTY: no real search provider is ever contacted. Unlike the hardcoded-URL
sibling tools, web_search reads its endpoint from ``WEB_SEARCH_ENDPOINT``, so we
simply point that env var at our loopback mock. A ``source="live"`` result here
means "the real client parsed a reply from our local mock", NOT that any real
search API was queried. There is ZERO external network I/O.

These tests prove the live client's request SHAPE (GET, ``q`` + ``count`` query
params, optional ``Authorization: Bearer`` from ``WEB_SEARCH_API_KEY``), its
response PARSING (provider ``results`` shape -> text-only title/url/snippet
records, capped at max_results), its EGRESS INVARIANT (only title/url/snippet
strings surface — no page bodies), and its ERROR HANDLING (HTTP 500 / malformed
JSON / connection-refused / missing endpoint -> upstream_error) — never a silent
fixture fallback, and the API key is never echoed into the response.

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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "web_search", "handler.py")


def _load_module(unique_name: str, path: str):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # UNIQUE name only, never bare "handler"
    spec.loader.exec_module(module)
    return module


web_search = _load_module("web_search_handler_live_dedicated", HANDLER_PATH)

# A provider reply with MORE items than requested, mixing field spellings
# (url vs link, snippet vs description) plus a leakable body-like field the
# normalizer must NOT surface (proving the text-only egress invariant).
_PROVIDER_REPLY = {
    "results": [
        {
            "title": "Log4Shell advisory",
            "url": "https://example.test/advisory/1",
            "snippet": "CVE-2021-44228 active exploitation notice.",
            "page_body": "SHOULD-NOT-LEAK binary payload bytes",
        },
        {
            "title": "Second write-up",
            "link": "https://example.test/advisory/2",
            "description": "Follow-up analysis of the vulnerability.",
        },
        {
            "title": "Third result beyond the cap",
            "url": "https://example.test/advisory/3",
            "snippet": "This one must be dropped when max_results < 3.",
        },
    ]
}

_RESULT_KEYS = {"title", "url", "snippet"}


# --------------------------------------------------------------------------- #
# In-process MOCK http.server (127.0.0.1, ephemeral port). NOT a real API.    #
# --------------------------------------------------------------------------- #
_STATE = {
    "mode": "ok",         # ok | http_500 | bad_json
    "last_method": None,
    "last_query": None,   # parsed query dict
    "last_auth": None,
}


class _MockSearchHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        _STATE["last_method"] = self.command
        _STATE["last_query"] = parse_qs(urlsplit(self.path).query)
        _STATE["last_auth"] = self.headers.get("Authorization")

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

        body = json.dumps(_PROVIDER_REPLY).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def mock_backend(monkeypatch):
    _STATE.update(mode="ok", last_method=None, last_query=None, last_auth=None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockSearchHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("WEB_SEARCH_LIVE", "1")
    monkeypatch.setenv("WEB_SEARCH_ENDPOINT", f"http://{host}:{port}/search")
    monkeypatch.delenv("WEB_SEARCH_API_KEY", raising=False)
    try:
        yield f"http://{host}:{port}/search"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Success: provider reply -> text-only normalized results, source="live"      #
# --------------------------------------------------------------------------- #
def test_live_success_returns_text_only_results(mock_backend):
    res = web_search.handler({"query": "Log4Shell advisory", "max_results": 2}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["query"] == "Log4Shell advisory"
    assert res["note"] == "text-only; no page bodies or binaries were downloaded"
    # Capped at max_results even though the provider returned three.
    assert len(res["results"]) == 2
    for rec in res["results"]:
        assert set(rec) == _RESULT_KEYS
    first, second = res["results"]
    assert first["url"] == "https://example.test/advisory/1"
    assert first["snippet"] == "CVE-2021-44228 active exploitation notice."
    # link -> url and description -> snippet aliases honored.
    assert second["url"] == "https://example.test/advisory/2"
    assert second["snippet"] == "Follow-up analysis of the vulnerability."


def test_live_never_leaks_page_body_field(mock_backend):
    """The egress invariant: only title/url/snippet strings surface, never any
    provider-supplied body-like field."""
    res = web_search.handler({"query": "Log4Shell advisory", "max_results": 3}, None)
    assert "SHOULD-NOT-LEAK" not in json.dumps(res)
    for rec in res["results"]:
        assert "page_body" not in rec


def test_live_sends_get_with_query_and_count(mock_backend):
    web_search.handler({"query": "beacon c2", "max_results": 4}, None)
    assert _STATE["last_method"] == "GET"
    assert _STATE["last_query"]["q"] == ["beacon c2"]
    assert _STATE["last_query"]["count"] == ["4"]


# --------------------------------------------------------------------------- #
# Optional API key: sent as Authorization: Bearer only when set, never echoed #
# --------------------------------------------------------------------------- #
def test_live_sends_bearer_token_when_set(mock_backend, monkeypatch):
    monkeypatch.setenv("WEB_SEARCH_API_KEY", "test-key-not-a-real-secret")
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is True
    assert _STATE["last_auth"] == "Bearer test-key-not-a-real-secret"


def test_live_no_authorization_header_when_key_unset(mock_backend):
    # Fixture already deletes WEB_SEARCH_API_KEY.
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is True
    assert _STATE["last_auth"] is None


def test_live_api_key_never_appears_in_response(mock_backend, monkeypatch):
    monkeypatch.setenv("WEB_SEARCH_API_KEY", "super-secret-search-key-xyz")
    res = web_search.handler({"query": "beacon c2"}, None)
    assert "super-secret-search-key-xyz" not in json.dumps(res)


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused / no-endpoint -> error  #
# --------------------------------------------------------------------------- #
def test_live_http_500_yields_upstream_error_no_fallback(mock_backend):
    _STATE["mode"] = "http_500"
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # No silent stub fallback despite the live flag being on.
    assert "results" not in res


def test_live_malformed_json_yields_upstream_error(mock_backend):
    _STATE["mode"] = "bad_json"
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "results" not in res


def test_live_connection_refused_yields_upstream_error(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    refused_port = s.getsockname()[1]
    s.close()

    monkeypatch.setenv("WEB_SEARCH_LIVE", "1")
    monkeypatch.setenv("WEB_SEARCH_ENDPOINT", f"http://127.0.0.1:{refused_port}/s")
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "results" not in res


def test_live_missing_endpoint_yields_upstream_error(monkeypatch):
    monkeypatch.setenv("WEB_SEARCH_LIVE", "1")
    monkeypatch.delenv("WEB_SEARCH_ENDPOINT", raising=False)
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "WEB_SEARCH_ENDPOINT is not configured" in res["message"]


# --------------------------------------------------------------------------- #
# Live opt-out: WEB_SEARCH_LIVE unset -> offline stub (source="stub")         #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_returns_stub(monkeypatch):
    monkeypatch.delenv("WEB_SEARCH_LIVE", raising=False)
    # Even with an endpoint configured, without the flag we stay offline.
    monkeypatch.setenv("WEB_SEARCH_ENDPOINT", "http://127.0.0.1:9/should-not-be-hit")

    def _boom(*a, **k):  # pragma: no cover - must never run offline
        raise AssertionError("live backend must not be reached when flag unset")

    monkeypatch.setattr(web_search, "_search_live", _boom)
    res = web_search.handler({"query": "beacon c2"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"


# --------------------------------------------------------------------------- #
# SSRF guard: metadata IP must never reach urlopen; safe URLs must pass       #
# --------------------------------------------------------------------------- #
def test_ssrf_metadata_ip_never_reaches_urlopen(monkeypatch):
    """Guard must fire BEFORE urlopen: the spy raising proves it was never reached.

    A prior implementation lacking the guard would produce upstream_error too
    (connection refused/timeout) but would still reach urlopen first. The spy
    distinguishes "guard fired early" from "network failure after reaching urlopen".
    """
    monkeypatch.setenv("WEB_SEARCH_LIVE", "1")
    monkeypatch.setenv("WEB_SEARCH_ENDPOINT", "http://169.254.169.254/")

    reached = {"urlopen": False}

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        reached["urlopen"] = True
        raise AssertionError(
            "SSRF guard did not fire: urlopen was reached for the metadata IP"
        )

    monkeypatch.setattr(web_search.urllib.request, "urlopen", _boom)
    res = web_search.handler({"query": "beacon c2"}, None)
    assert reached["urlopen"] is False, "urlopen must not be reached for a blocked URL"
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
    assert "results" not in res


@pytest.mark.parametrize("safe_url", [
    "https://search.example.internal/api",
    "http://127.0.0.1:8080/search",
])
def test_ssrf_assert_safe_url_allows_safe_targets(safe_url):
    """_assert_safe_url must not raise for a normal https endpoint or loopback."""
    web_search._assert_safe_url(safe_url)  # must not raise
