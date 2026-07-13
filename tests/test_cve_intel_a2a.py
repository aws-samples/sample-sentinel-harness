"""
Offline A2A contract test for the cve-intel specialist
======================================================
Proves the A2A protocol END-TO-END **in process** with a MOCKED model — ZERO
network, ZERO creds, ZERO real LiteLLM/Bedrock call. What this asserts:

1. the agent-card is served through the A2A discovery surface and is well-formed
   (name / description / skills / url);
2. a task ``message/send`` round-trips through the mocked model to a *structured*
   A2A response envelope;
3. an unknown method / malformed message yields a clean JSON-RPC A2A **error**
   (not an exception / crash);
4. the mock proves ZERO network — a socket guard makes any real connect fail the
   test, and we assert the round-trip still succeeds under that guard.

HONESTY: no live LLM or A2A network call happens here. The model is a deterministic
in-process fake (``echo_model_callable``); the transport is a direct function call.

The module under test is loaded by an explicit path under a UNIQUE name so it can
never collide with the bare ``agent_a2a`` module every specialist ships (which
would cross-poison sibling specialists' tests via a shared sys.modules entry).
"""
from __future__ import annotations

import importlib.util
import os
import socket
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(REPO_ROOT, "specialists", "cve-intel", "local_a2a.py")
_UNIQUE_NAME = "cve_intel_local_a2a_test"
_spec = importlib.util.spec_from_file_location(_UNIQUE_NAME, _MODULE_PATH)
local_a2a = importlib.util.module_from_spec(_spec)
sys.modules[_UNIQUE_NAME] = local_a2a
_spec.loader.exec_module(local_a2a)


# --------------------------------------------------------------------------- #
# ZERO-network guard                                                          #
# --------------------------------------------------------------------------- #
@pytest.fixture
def no_network(monkeypatch):
    """Make ANY outbound socket connect raise, proving the harness never touches
    the network. Applied to the round-trip test so a regression that smuggles in a
    real HTTP/LiteLLM call fails loudly instead of silently dialing out."""

    def _boom(*args, **kwargs):
        raise AssertionError("network access attempted — A2A harness must be fully offline")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "connect_ex", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    return True


# --------------------------------------------------------------------------- #
# 1. Agent-card is served + well-formed                                       #
# --------------------------------------------------------------------------- #
def test_agent_card_served_and_well_formed():
    server = local_a2a.LocalA2AServer(url="http://127.0.0.1:9000")
    client = local_a2a.LocalA2AClient(server)
    card = client.get_agent_card()

    assert card["name"] == "cve-intel"
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["url"] == "http://127.0.0.1:9000"
    # skills: non-empty, each with id/name/description
    skills = card["skills"]
    assert isinstance(skills, list) and skills
    for s in skills:
        assert s["id"] and s["name"] and s["description"]
    # discovery contract label present
    assert any(s["id"] == "cve.lookup" for s in skills)


def test_agent_card_is_the_canonical_card_not_a_copy():
    """The harness must SERVE the existing card, not redefine it — url aside, it is
    byte-identical to agent_a2a.agent_card()."""
    served = local_a2a.LocalA2AServer(url="http://x").agent_card()
    canonical = local_a2a.agent_card(url="http://x")
    assert served == canonical


def test_agent_card_json_serializable():
    import json

    json.dumps(local_a2a.LocalA2AServer().agent_card())  # must not raise


# --------------------------------------------------------------------------- #
# 2. Task message round-trips through the mocked model -> structured response  #
# --------------------------------------------------------------------------- #
def test_message_send_round_trip_structured(no_network):
    server = local_a2a.LocalA2AServer()  # default deterministic echo model
    client = local_a2a.LocalA2AClient(server)

    response = client.send_message("Enrich CVE-2021-44228; return CVSS, EPSS, KEV.")

    # JSON-RPC success envelope
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "1"
    assert "error" not in response
    result = response["result"]
    assert result["role"] == "agent"
    assert result["kind"] == "message"
    assert result["messageId"]

    # structured data part + human text part
    kinds = [p["kind"] for p in result["parts"]]
    assert "data" in kinds and "text" in kinds

    verdict = local_a2a.verdict_from_response(response)
    assert verdict["cve_id"] == "CVE-2021-44228"
    # full envelope schema present
    for field in ("cve_id", "cvss", "severity", "epss", "kev", "summary", "references", "grounded"):
        assert field in verdict
    # honest mock: no tool grounding, marked as such
    assert verdict["grounded"] is False
    assert verdict["engine"] == "echo-mock"
    assert verdict["references"] == []


def test_round_trip_is_deterministic(no_network):
    """Same input -> same verdict (messageId aside), proving reproducibility."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    v1 = local_a2a.verdict_from_response(client.send_message("look up CVE-2014-0160"))
    v2 = local_a2a.verdict_from_response(client.send_message("look up cve-2014-0160"))
    assert v1 == v2
    assert v1["cve_id"] == "CVE-2014-0160"  # normalized upper-case


def test_injected_model_callable_is_used(no_network):
    """The model is a real seam: an injected callable is what produces the verdict
    (this is exactly where a real Strands/LiteLLM model would plug in)."""
    calls = {}

    def fake_model(text: str) -> dict:
        calls["text"] = text
        return {"cve_id": "CVE-2000-0001", "summary": "injected", "grounded": True}

    server = local_a2a.LocalA2AServer(model_callable=fake_model)
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(client.send_message("please enrich CVE-2000-0001"))

    assert calls["text"] == "please enrich CVE-2000-0001"
    assert verdict == {"cve_id": "CVE-2000-0001", "summary": "injected", "grounded": True}


# --------------------------------------------------------------------------- #
# 3. Unknown / malformed message -> clean A2A error (not a crash)             #
# --------------------------------------------------------------------------- #
def test_unknown_method_yields_error():
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "2.0", "id": "9", "method": "tasks/cancel", "params": {}})
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_METHOD_NOT_FOUND
    assert resp["id"] == "9"


def test_wrong_jsonrpc_version_yields_error():
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "1.0", "id": "1", "method": "message/send", "params": {}})
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_REQUEST


def test_non_dict_request_yields_error_not_crash():
    server = local_a2a.LocalA2AServer()
    for bad in (None, "not-a-request", 42, ["list"]):
        resp = server.handle(bad)
        assert "error" in resp and "result" not in resp
        assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_REQUEST


def test_malformed_message_missing_parts_yields_error():
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_raw(
        {"jsonrpc": "2.0", "id": "7", "method": "message/send", "params": {"message": {}}}
    )
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS
    assert resp["id"] == "7"


def test_message_without_cve_id_yields_clean_error():
    """A task with no CVE id must come back as an A2A error, not a fabricated
    verdict (the mock refuses to confabulate)."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_message("what is the weather today?")
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS


def test_model_callable_exception_becomes_clean_error():
    """Even an unexpected bug in the model callable is serialized as a JSON-RPC
    error rather than escaping handle() as an exception."""

    def broken_model(text: str) -> dict:
        raise RuntimeError("boom")

    server = local_a2a.LocalA2AServer(model_callable=broken_model)
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": "5",
            "method": "message/send",
            "params": {"message": {"parts": [{"kind": "text", "text": "CVE-2021-44228"}]}},
        }
    )
    assert resp["error"]["code"] == local_a2a.JSONRPC_INTERNAL_ERROR
    assert "boom" in resp["error"]["message"]


# --------------------------------------------------------------------------- #
# 4. The mock proves ZERO network                                             #
# --------------------------------------------------------------------------- #
def test_zero_network_proven_by_guard(no_network):
    """Sanity: the guard itself is armed (any connect would raise) AND a full
    round-trip completes under it — together this proves the harness never dials
    out."""
    # guard is armed
    with pytest.raises(AssertionError):
        socket.create_connection(("192.0.2.1", 80))  # RFC-5737 TEST-NET-1
    # round-trip still succeeds -> no network was needed
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(client.send_message("enrich CVE-2021-44228"))
    assert verdict["cve_id"] == "CVE-2021-44228"


def test_helpers_extract_cve_id():
    assert local_a2a.extract_cve_id("see CVE-2021-44228 now") == "CVE-2021-44228"
    assert local_a2a.extract_cve_id("cve-2014-0160") == "CVE-2014-0160"
    assert local_a2a.extract_cve_id("no id here") is None
    assert local_a2a.extract_cve_id(None) is None
