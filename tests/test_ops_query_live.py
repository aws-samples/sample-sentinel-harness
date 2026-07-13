"""
Offline live-client tests for the ops_query multi-account operations tool
=========================================================================
Exercises the REAL ``OPS_QUERY_LIVE=1`` path of ``tools/ops_query/handler.py``
against an IN-PROCESS **mock** ``http.server`` bound to ``127.0.0.1:0`` (an
ephemeral port on loopback). There is ZERO external network: nothing leaves the
machine, and no real ops backend is ever contacted — the server is a local
stand-in whose sole job is to prove the client's request shape, response
parsing, and error handling.

What these tests pin down:

- A live query returns ``source="live"`` with the SAME normalized shape the
  offline stub returns (``accounts`` list / ``findings`` list) — the transport
  is invisible to the caller.
- The validated selector is POSTed as JSON, and an ``OPS_QUERY_TOKEN`` bearer
  (env only) is sent as an ``Authorization: Bearer …`` header when set — and
  absent when unset.
- A 500, a malformed-JSON body, and a refused connection EACH yield
  ``{"ok": False, "error": "upstream_error"}`` — no crash, no silent fixture
  fallback.
- With ``OPS_QUERY_LIVE`` unset the handler still returns ``source="stub"``.

Like the sibling suites, the handler is loaded from an explicit file path under
a UNIQUE module name so importing a module literally named ``handler`` never
collides in ``sys.modules`` when the whole suite runs.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPS_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "ops_query")
HANDLER_PATH = os.path.join(OPS_TOOL_DIR, "handler.py")

# The handler does ``from mockdata.accounts import ...`` — make the repo root
# importable so that resolves regardless of pytest's rootdir.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


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


# UNIQUE name (distinct from tests/test_ops_query.py's) so neither poisons the
# other regardless of collection order.
ops_handler = _load_module("ops_query_handler_live_dedicated", HANDLER_PATH)


# --------------------------------------------------------------------------- #
# In-process mock backend (http.server on 127.0.0.1:0). NOT a real ops API.    #
# --------------------------------------------------------------------------- #
class _MockBackend:
    """A tiny loopback HTTP server standing in for the ops backend.

    Records the last request (path, parsed JSON body, headers) so tests can
    assert the client's request shape, and replies with whatever ``status`` /
    ``body`` the test configured. Purely local — ZERO external network.
    """

    def __init__(self, status: int = 200, body: bytes = b"{}"):
        self.status = status
        self.body = body
        self.last_body: dict | None = None
        self.last_headers: dict | None = None
        self.last_path: str | None = None

        backend = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
                try:
                    backend.last_body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    backend.last_body = None
                backend.last_headers = dict(self.headers)
                backend.last_path = self.path
                self.send_response(backend.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(backend.body)))
                self.end_headers()
                self.wfile.write(backend.body)

            def log_message(self, *args):  # silence server stderr logging
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def __enter__(self) -> "_MockBackend":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/ops"


@pytest.fixture
def live_env(monkeypatch):
    """Opt into the live path; start clean (no token) each test."""
    monkeypatch.setenv("OPS_QUERY_LIVE", "1")
    monkeypatch.delenv("OPS_QUERY_TOKEN", raising=False)
    return monkeypatch


# --------------------------------------------------------------------------- #
# Happy path: normalized shape + source="live"                                #
# --------------------------------------------------------------------------- #
def test_live_wildcard_returns_normalized_accounts(live_env):
    canned = {
        "accounts": [
            {
                "account_id": "111111111111",
                "name": "prod-payments (fictional)",
                "environment": "prod",
                "region": "us-east-1",
                "resources": {"ec2": 24, "s3_buckets": 12, "iam_roles": 18},
                "findings": [],
            }
        ]
    }
    with _MockBackend(200, json.dumps(canned).encode("utf-8")) as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["accounts"] == canned["accounts"]
    # The validated selector was POSTed verbatim as JSON.
    assert backend.last_body == {"query": "*"}
    assert backend.last_path == "/ops"


def test_live_single_account_posts_selector(live_env):
    canned = {"accounts": [{"account_id": "222222222222", "name": "x"}]}
    with _MockBackend(200, json.dumps(canned).encode("utf-8")) as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"account": "222222222222"}, None)

    assert res["ok"] is True and res["source"] == "live"
    assert res["accounts"] == canned["accounts"]
    assert backend.last_body == {"account": "222222222222"}


def test_live_finding_type_returns_normalized_findings(live_env):
    canned = {
        "finding_type": "public_s3",
        "findings": [
            {
                "account_id": "111111111111",
                "account_name": "prod-payments (fictional)",
                "finding_id": "OPS-111-001",
                "finding_type": "public_s3",
                "severity": "high",
            }
        ],
    }
    with _MockBackend(200, json.dumps(canned).encode("utf-8")) as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"finding_type": "public_s3"}, None)

    assert res["ok"] is True and res["source"] == "live"
    assert res["finding_type"] == "public_s3"
    assert res["findings"] == canned["findings"]
    # finding_type selector is POSTed as-is.
    assert backend.last_body == {"finding_type": "public_s3"}


# --------------------------------------------------------------------------- #
# Bearer token: sent only from env, only when set                             #
# --------------------------------------------------------------------------- #
def test_live_sends_bearer_authorization_header_when_token_set(live_env):
    canned = {"accounts": []}
    with _MockBackend(200, json.dumps(canned).encode("utf-8")) as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        live_env.setenv("OPS_QUERY_TOKEN", "s3cr3t-ops-token")
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is True and res["source"] == "live"
    # http.server lowercases header lookup; dict keys preserve original casing.
    auth = {k.lower(): v for k, v in backend.last_headers.items()}.get(
        "authorization"
    )
    assert auth == "Bearer s3cr3t-ops-token"


def test_live_omits_authorization_header_when_token_absent(live_env):
    canned = {"accounts": []}
    with _MockBackend(200, json.dumps(canned).encode("utf-8")) as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        # No OPS_QUERY_TOKEN (fixture already deleted it).
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is True
    lowered = {k.lower() for k in backend.last_headers}
    assert "authorization" not in lowered


def test_live_request_is_json_content_type(live_env):
    with _MockBackend(200, b'{"accounts": []}') as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        ops_handler.handler({"query": "*"}, None)

    ctype = {k.lower(): v for k, v in backend.last_headers.items()}.get(
        "content-type"
    )
    assert ctype == "application/json"


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused → upstream_error         #
# --------------------------------------------------------------------------- #
def test_live_http_500_is_upstream_error(live_env):
    with _MockBackend(500, b'{"error": "boom"}') as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "500" in res["message"]
    # Must NOT fall back to the offline fixtures.
    assert "accounts" not in res


def test_live_malformed_json_is_upstream_error(live_env):
    with _MockBackend(200, b"this-is-not-json{{{") as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "accounts" not in res


def test_live_reply_wrong_shape_is_upstream_error(live_env):
    # Valid JSON, but no 'accounts' list → hard error, not a silent empty result.
    with _MockBackend(200, b'{"unexpected": true}') as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "accounts" not in res


def test_live_connection_refused_is_upstream_error(live_env):
    # 127.0.0.1:1 — privileged loopback port nothing listens on → refused.
    live_env.setenv("OPS_QUERY_URL", "http://127.0.0.1:1/ops")
    res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "accounts" not in res


def test_live_without_url_is_upstream_error(live_env):
    live_env.delenv("OPS_QUERY_URL", raising=False)
    res = ops_handler.handler({"query": "*"}, None)

    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "OPS_QUERY_URL is not set" in res["message"]


# --------------------------------------------------------------------------- #
# Offline remains the default: LIVE unset → source="stub", zero network        #
# --------------------------------------------------------------------------- #
def test_live_unset_still_returns_stub(monkeypatch):
    monkeypatch.delenv("OPS_QUERY_LIVE", raising=False)

    def _boom(sel):  # pragma: no cover - must never be called offline
        raise AssertionError("live client must not be reached in offline mode")

    monkeypatch.setattr(ops_handler, "_fetch_live", _boom)
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "stub"


def test_live_token_never_appears_in_response(live_env):
    """Defense-in-depth: even on success the token must not leak into output."""
    with _MockBackend(200, b'{"accounts": []}') as backend:
        live_env.setenv("OPS_QUERY_URL", backend.url)
        live_env.setenv("OPS_QUERY_TOKEN", "must-not-leak-token")
        res = ops_handler.handler({"query": "*"}, None)

    assert "must-not-leak-token" not in json.dumps(res)
