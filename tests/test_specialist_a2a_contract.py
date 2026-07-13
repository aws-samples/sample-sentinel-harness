"""
Offline A2A contract test for the attack-mapper + threat-hunt specialists
=========================================================================
Parametrized sibling of ``tests/test_cve_intel_a2a.py``. Proves the A2A protocol
END-TO-END **in process** with a MOCKED model — ZERO network, ZERO creds, ZERO
real LiteLLM/Bedrock call — for BOTH specialists that reuse the shared A2A
contract harness (``specialists/_a2a_contract.py``). What this asserts, per
specialist:

1. the agent-card is served through the A2A discovery surface and is well-formed
   (name / description / skills / url), and is byte-identical to the specialist's
   own canonical ``agent_card()`` (the harness SERVES the card, never redefines it);
2. a task ``message/send`` round-trips through the mocked model to a *structured*
   A2A response envelope (agent role, data + text parts, messageId);
3. an unknown method / wrong version / non-dict / malformed message yields a clean
   JSON-RPC A2A **error** (not an exception / crash);
4. the mock proves ZERO network — a socket guard makes any real connect fail the
   test, and the round-trip still succeeds under that guard.

HONESTY: no live LLM or A2A network call happens here. The model is a deterministic
in-process fake (each specialist's ``echo_model_callable``); the transport is a
direct function call. A mocked A2A contract proves protocol/handler wiring, not a
live model call.

Each specialist's ``local_a2a`` module is loaded by an explicit path under a
UNIQUE name so it can never collide with the bare ``agent_a2a`` / ``local_a2a``
modules every specialist ships (which would cross-poison sibling tests via a
shared sys.modules entry).
"""
from __future__ import annotations

import importlib.util
import os
import socket
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALISTS_DIR = os.path.join(REPO_ROOT, "specialists")

# The two siblings this test brings to cve-intel parity. cve-intel has its own
# dedicated test (test_cve_intel_a2a.py) and is intentionally NOT re-covered here.
SPECIALISTS = ("attack-mapper", "threat-hunt")


def _load_local_a2a(name: str):
    """Load a specialist's local_a2a under a unique module name (collision-proof)."""
    unique = f"{name.replace('-', '_')}_local_a2a__contract_test"
    path = os.path.join(SPECIALISTS_DIR, name, "local_a2a.py")
    spec = importlib.util.spec_from_file_location(unique, path)
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(params=SPECIALISTS)
def local_a2a(request):
    """Parametrized: yields each sibling specialist's loaded local_a2a module."""
    return _load_local_a2a(request.param)


# --------------------------------------------------------------------------- #
# ZERO-network guard                                                          #
# --------------------------------------------------------------------------- #
@pytest.fixture
def no_network(monkeypatch):
    """Make ANY outbound socket connect raise, proving the harness never touches
    the network. Applied to the round-trip tests so a regression that smuggles in
    a real HTTP/LiteLLM call fails loudly instead of silently dialing out."""

    def _boom(*args, **kwargs):
        raise AssertionError("network access attempted — A2A harness must be fully offline")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "connect_ex", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    return True


# --------------------------------------------------------------------------- #
# 1. Agent-card is served + well-formed                                       #
# --------------------------------------------------------------------------- #
def test_agent_card_served_and_well_formed(local_a2a):
    server = local_a2a.LocalA2AServer(url="http://127.0.0.1:9000")
    client = local_a2a.LocalA2AClient(server)
    card = client.get_agent_card()

    assert card["name"] == local_a2a.SPECIALIST_NAME
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["url"] == "http://127.0.0.1:9000"
    # skills: non-empty, each with id/name/description
    skills = card["skills"]
    assert isinstance(skills, list) and skills
    for s in skills:
        assert s["id"] and s["name"] and s["description"]
    assert card["protocol"] == "a2a"


def test_agent_card_is_the_canonical_card_not_a_copy(local_a2a):
    """The harness must SERVE the existing card, not redefine it — url aside, it is
    byte-identical to the specialist's own agent_card()."""
    served = local_a2a.LocalA2AServer(url="http://x").agent_card()
    canonical = local_a2a.agent_card(url="http://x")
    assert served == canonical


def test_agent_card_json_serializable(local_a2a):
    import json

    json.dumps(local_a2a.LocalA2AServer().agent_card())  # must not raise


# --------------------------------------------------------------------------- #
# 2. Task message round-trips through the mocked model -> structured response  #
# --------------------------------------------------------------------------- #
def test_message_send_round_trip_structured(local_a2a, no_network):
    server = local_a2a.LocalA2AServer()  # default deterministic echo model
    client = local_a2a.LocalA2AClient(server)

    response = client.send_message(
        "credential dumping via lsass on domain controllers; internet-exposed http-app host"
    )

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
    assert isinstance(verdict, dict)
    # provenance marker: honest "mock, not a live model"
    assert verdict["engine"] == "echo-mock"
    # a summary is present for the text part
    assert isinstance(verdict.get("summary"), str) and verdict["summary"].strip()


def test_round_trip_is_deterministic(local_a2a, no_network):
    """Same input -> same verdict (messageId aside), proving reproducibility."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    text = "possible lateral movement via psexec and credential dumping"
    v1 = local_a2a.verdict_from_response(client.send_message(text))
    v2 = local_a2a.verdict_from_response(client.send_message(text))
    assert v1 == v2


def test_injected_model_callable_is_used(local_a2a, no_network):
    """The model is a real seam: an injected callable is what produces the verdict
    (this is exactly where a real Strands/LiteLLM model would plug in)."""
    calls = {}

    def fake_model(text: str) -> dict:
        calls["text"] = text
        return {"summary": "injected", "grounded": True}

    server = local_a2a.LocalA2AServer(model_callable=fake_model)
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(client.send_message("hello specialist"))

    assert calls["text"] == "hello specialist"
    assert verdict == {"summary": "injected", "grounded": True}


# --------------------------------------------------------------------------- #
# 3. Unknown / malformed message -> clean A2A error (not a crash)             #
# --------------------------------------------------------------------------- #
def test_unknown_method_yields_error(local_a2a):
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "2.0", "id": "9", "method": "tasks/cancel", "params": {}})
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_METHOD_NOT_FOUND
    assert resp["id"] == "9"


def test_wrong_jsonrpc_version_yields_error(local_a2a):
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "1.0", "id": "1", "method": "message/send", "params": {}})
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_REQUEST


def test_non_dict_request_yields_error_not_crash(local_a2a):
    server = local_a2a.LocalA2AServer()
    for bad in (None, "not-a-request", 42, ["list"]):
        resp = server.handle(bad)
        assert "error" in resp and "result" not in resp
        assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_REQUEST


def test_malformed_message_missing_parts_yields_error(local_a2a):
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_raw(
        {"jsonrpc": "2.0", "id": "7", "method": "message/send", "params": {"message": {}}}
    )
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS
    assert resp["id"] == "7"


def test_missing_params_yields_error(local_a2a):
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "2.0", "id": "3", "method": "message/send"})
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS


def test_empty_message_yields_clean_error(local_a2a):
    """A task with an empty/whitespace body must come back as an A2A error, not a
    fabricated verdict (the mock refuses to confabulate)."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_message("   ")
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS


def test_model_callable_exception_becomes_clean_error(local_a2a):
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
            "params": {"message": {"parts": [{"kind": "text", "text": "some hypothesis"}]}},
        }
    )
    assert resp["error"]["code"] == local_a2a.JSONRPC_INTERNAL_ERROR
    assert "boom" in resp["error"]["message"]


# --------------------------------------------------------------------------- #
# 4. The mock proves ZERO network                                             #
# --------------------------------------------------------------------------- #
def test_zero_network_proven_by_guard(local_a2a, no_network):
    """Sanity: the guard itself is armed (any connect would raise) AND a full
    round-trip completes under it — together this proves the harness never dials
    out."""
    # guard is armed
    with pytest.raises(AssertionError):
        socket.create_connection(("192.0.2.1", 80))  # RFC-5737 TEST-NET-1
    # round-trip still succeeds -> no network was needed
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(
        client.send_message("credential dumping on domain controllers")
    )
    assert isinstance(verdict, dict)
    assert verdict["engine"] == "echo-mock"


# --------------------------------------------------------------------------- #
# 5. Shared harness identity: siblings reuse the SAME contract module          #
# --------------------------------------------------------------------------- #
def test_error_codes_match_shared_contract(local_a2a):
    """The JSON-RPC error codes each sibling exposes are the canonical JSON-RPC
    2.0 reserved values from the shared contract."""
    assert local_a2a.JSONRPC_INVALID_REQUEST == -32600
    assert local_a2a.JSONRPC_METHOD_NOT_FOUND == -32601
    assert local_a2a.JSONRPC_INVALID_PARAMS == -32602
    assert local_a2a.JSONRPC_INTERNAL_ERROR == -32603
