"""
Offline live-client tests for the attack_lookup tool (ATTACK_LIVE=1)
====================================================================
Exercises the REAL live path of ``tools/attack_lookup/handler.py`` — the stdlib
``urllib.request`` client reached when ``ATTACK_LIVE=1`` that pulls the MITRE
ATT&CK STIX bundle — against an **in-process MOCK http.server** bound to
``127.0.0.1:0`` (an ephemeral port).

HONESTY: no real ATT&CK / GitHub host is ever contacted. The tool hardcodes the
upstream URL, so we monkeypatch ``urllib.request.urlopen`` to REWRITE the request
netloc onto our loopback mock while preserving the path, query, and headers the
real client set. A ``source="live"`` result here means "the real client parsed a
reply from our local mock", NOT that MITRE was queried. There is ZERO external
network I/O: every request stays on the loopback interface.

These tests prove the live client's request SHAPE (GET with the sentinel
User-Agent), its response PARSING (STIX bundle -> normalized technique), its
ERROR HANDLING (HTTP 500 / malformed JSON / connection-refused -> upstream_error,
missing technique -> not_found), and the BYTE-CAP guard (an over-limit body
raises rather than buffering unboundedly) — never a silent fixture fallback.

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

HANDLER_PATH = os.path.join(REPO_ROOT, "tools", "attack_lookup", "handler.py")


def _load_module(unique_name: str, path: str):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # UNIQUE name only, never bare "handler"
    spec.loader.exec_module(module)
    return module


attack = _load_module("attack_lookup_handler_live_dedicated", HANDLER_PATH)


# A STIX bundle exercising normalization: kill_chain_phases -> tactics,
# x_mitre_is_subtechnique -> bool, x_mitre_platforms -> platforms, and the
# mitre-attack external_reference supplying id + url. A decoy object with the
# wrong external_id must be skipped, proving the id match logic.
_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "identity",  # non-attack-pattern object must be ignored
            "name": "The MITRE Corporation",
        },
        {
            "type": "attack-pattern",
            "name": "Some Other Technique",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"},
            ],
        },
        {
            "type": "attack-pattern",
            "name": "PowerShell",
            "x_mitre_is_subtechnique": True,
            "x_mitre_platforms": ["Windows"],
            "description": "Adversaries may abuse PowerShell for execution.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "other-framework", "phase_name": "ignored"},
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059.001",
                    "url": "https://attack.mitre.org/techniques/T1059/001/",
                },
                {"source_name": "capec", "external_id": "CAPEC-1"},
            ],
        },
    ],
}

_TECHNIQUE_KEYS = {
    "id", "name", "is_subtechnique", "tactics",
    "platforms", "description", "references",
}


# --------------------------------------------------------------------------- #
# In-process MOCK http.server (127.0.0.1, ephemeral port). NOT MITRE.         #
# --------------------------------------------------------------------------- #
_STATE = {
    "mode": "ok",       # ok | http_500 | bad_json
    "last_method": None,
    "last_path": None,
    "last_user_agent": None,
}


class _MockAttackHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence per-request stderr logging
        pass

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        _STATE["last_method"] = self.command
        _STATE["last_path"] = self.path
        _STATE["last_user_agent"] = self.headers.get("User-Agent")

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

        payload = json.dumps(_STIX_BUNDLE).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _install_redirect(monkeypatch, netloc: str) -> None:
    """Rewrite the hardcoded upstream URL onto our loopback mock, preserving the
    path/query/headers the real client set. ZERO external network."""
    real_urlopen = urllib.request.urlopen

    def _fake(req, *args, **kwargs):
        parts = urlsplit(req.full_url)
        req.full_url = urlunsplit(("http", netloc, parts.path, parts.query, ""))
        return real_urlopen(req, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", _fake)


@pytest.fixture()
def mock_backend(monkeypatch):
    _STATE.update(mode="ok", last_method=None, last_path=None, last_user_agent=None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockAttackHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("ATTACK_LIVE", "1")
    _install_redirect(monkeypatch, f"{host}:{port}")
    try:
        yield f"{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Success: STIX bundle -> normalized technique, source="live"                 #
# --------------------------------------------------------------------------- #
def test_live_success_returns_normalized_technique(mock_backend):
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is True
    assert res["source"] == "live"
    tech = res["technique"]
    assert set(tech) == _TECHNIQUE_KEYS
    assert tech["id"] == "T1059.001"
    assert tech["name"] == "PowerShell"
    assert tech["is_subtechnique"] is True
    # Only the mitre-attack kill-chain phase becomes a tactic; other frameworks drop.
    assert tech["tactics"] == ["execution"]
    assert tech["platforms"] == ["Windows"]
    # Only the mitre-attack reference URL is surfaced.
    assert tech["references"] == ["https://attack.mitre.org/techniques/T1059/001/"]


def test_live_sends_get_with_sentinel_user_agent(mock_backend):
    attack.handler({"technique_id": "T1059.001"}, None)
    assert _STATE["last_method"] == "GET"
    assert _STATE["last_user_agent"] == "sentinel-harness"


def test_live_technique_absent_from_bundle_is_not_found(mock_backend):
    # Valid format, but no matching attack-pattern in the bundle -> not_found.
    res = attack.handler({"technique_id": "T1046"}, None)
    assert res["ok"] is False
    assert res["error"] == "not_found"
    assert "technique" not in res


# --------------------------------------------------------------------------- #
# Error handling: 500 / bad-JSON / connection-refused -> upstream_error       #
# --------------------------------------------------------------------------- #
def test_live_http_500_yields_upstream_error_no_fallback(mock_backend):
    _STATE["mode"] = "http_500"
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    # No silent stub fallback: T1059.001 exists offline, but must NOT be served.
    assert "technique" not in res


def test_live_malformed_json_yields_upstream_error(mock_backend):
    _STATE["mode"] = "bad_json"
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "technique" not in res


def test_live_connection_refused_yields_upstream_error(monkeypatch):
    # Bind then close an ephemeral port so a connect is guaranteed-refused.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    refused_port = s.getsockname()[1]
    s.close()

    monkeypatch.setenv("ATTACK_LIVE", "1")
    _install_redirect(monkeypatch, f"127.0.0.1:{refused_port}")
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "technique" not in res


# --------------------------------------------------------------------------- #
# Byte-cap: an over-limit body RAISES rather than buffering unboundedly        #
# --------------------------------------------------------------------------- #
class _OversizedResp:
    """A fake response whose ``read(n)`` always returns exactly ``n`` bytes, so
    the client's ``read(_MAX + 1)`` yields ``_MAX + 1`` bytes and trips the cap
    regardless of the cap's numeric value. Cap-agnostic and allocation-light."""

    def read(self, amt=-1):
        return b"\x00" * (amt if amt and amt > 0 else 0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_live_oversized_body_raises_and_maps_to_upstream_error(monkeypatch):
    monkeypatch.setenv("ATTACK_LIVE", "1")
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _OversizedResp()
    )
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "exceeds" in res["message"]
    assert "technique" not in res


# --------------------------------------------------------------------------- #
# Live opt-out: ATTACK_LIVE unset -> offline stub (source="stub")             #
# --------------------------------------------------------------------------- #
def test_live_flag_unset_returns_stub(monkeypatch):
    monkeypatch.delenv("ATTACK_LIVE", raising=False)

    def _boom(*a, **k):  # pragma: no cover - must never run offline
        raise AssertionError("live backend must not be reached when flag unset")

    monkeypatch.setattr(attack, "_fetch_live", _boom)
    res = attack.handler({"technique_id": "T1059.001"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    assert res["technique"]["id"] == "T1059.001"
