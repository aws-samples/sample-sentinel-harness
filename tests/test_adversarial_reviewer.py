"""
Offline tests for the adversarial-reviewer A2A specialist
=========================================================
ZERO AWS calls, ZERO network, ZERO real LiteLLM/Bedrock call, no real sleep.
Deterministic. Mirrors ``tests/test_specialist_a2a_contract.py`` (A2A envelope +
socket-connect guard) and ``tests/test_specialist_containers.py`` (Dockerfile /
requirements packaging contract), and adds direct coverage of the REAL
``review_detection`` critique reasoner.

Provable surfaces:

1. ``specialists/adversarial-reviewer/agent_a2a.py`` — mirrors the cve-intel
   skeleton: imports WITHOUT the heavy specialist stack, exposes a well-formed
   agent-card, and carries a REAL deterministic ``review_detection`` reasoner we
   exercise directly (a flawed rule -> objections/revise; a clean rule -> approve).
2. The A2A contract via the SHARED harness: the agent-card round-trips through a
   MOCKED model under a socket-connect guard (zero network); malformed input
   yields clean JSON-RPC errors.
3. Packaging: the Dockerfile is two-stage / non-root / EXPOSE 9000 / pinned base,
   the requirements match cve-intel exactly, and the baked model id is
   version-pinned.

Each module is loaded by an explicit file path under a UNIQUE module name so it
never collides with the bare ``agent_a2a`` / ``local_a2a`` modules every
specialist ships (which would cross-poison sibling tests via a shared
``sys.modules`` entry).
"""
from __future__ import annotations

import importlib.util
import os
import re
import socket
import sys
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALISTS_DIR = os.path.join(REPO_ROOT, "specialists")
SPECIALIST = "adversarial-reviewer"
SPECIALIST_DIR = os.path.join(SPECIALISTS_DIR, SPECIALIST)
REFERENCE = "cve-intel"  # the source-of-truth specialist the packaging must match


def _load_module(unique_name: str, path: str):
    """Import a standalone .py file under a unique name without polluting the bare
    module namespace shared by sibling specialists."""
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


agent_a2a = _load_module(
    "adversarial_reviewer_agent_a2a", os.path.join(SPECIALIST_DIR, "agent_a2a.py")
)
local_a2a = _load_module(
    "adversarial_reviewer_local_a2a", os.path.join(SPECIALIST_DIR, "local_a2a.py")
)


# --------------------------------------------------------------------------- #
# Rule fixtures                                                                #
# --------------------------------------------------------------------------- #
# A clean, well-scoped Sigma rule: titled, has a logsource, a level, a condition
# that references only DEFINED selections, an exclusion filter, and documented
# false positives. This must PASS (verdict=approve).
_CLEAN_RULE = """\
title: Suspicious npm postinstall reading private-key material
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '.ssh/id_rsa'
            - 'wallet.dat'
    filter_ci:
        Image|endswith: '/usr/bin/known-ci-runner'
    condition: selection and not filter_ci
falsepositives:
    - Legitimate CI runners that read deploy keys
level: high
"""

# A flawed rule: no title, no logsource, no level, a lone-wildcard selection (alert
# cannon), no FP scoping at all. This must be REVISED with objections + high fp_risk.
_FLAWED_RULE = """\
detection:
    selection:
        CommandLine: '*'
    condition: selection
"""

# A rule whose condition references an identifier ('selection2') that is never
# defined in the detection map -> a logic flaw.
_LOGIC_FLAW_RULE = """\
title: Broken condition reference
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    filter_ok:
        User: 'SYSTEM'
    condition: selection and not selection2
falsepositives:
    - none known
level: medium
"""


# --------------------------------------------------------------------------- #
# 1. Module imports without heavy deps; public surface present                #
# --------------------------------------------------------------------------- #
def test_module_imports_without_heavy_deps():
    """agent_a2a must import even when strands/litellm/bedrock-agentcore are
    absent — the heavy deps are imported lazily inside the factory, not at top."""
    assert agent_a2a.SPECIALIST_NAME == "adversarial-reviewer"


def test_factory_and_public_surface_present():
    for attr in ("build_agent", "build_app", "serve", "agent_card",
                 "review_detection"):
        assert callable(getattr(agent_a2a, attr)), f"{attr} must be callable"


# --------------------------------------------------------------------------- #
# 2. Agent-card / capability metadata is well-formed                          #
# --------------------------------------------------------------------------- #
def test_agent_card_shape():
    card = agent_a2a.agent_card()
    assert card["name"] == "adversarial-reviewer"
    assert card["version"] == agent_a2a.SPECIALIST_VERSION
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["protocol"] == "a2a"
    caps = card["capabilities"]
    assert isinstance(caps, list) and caps
    assert all(isinstance(c, str) and c for c in caps)
    assert "detection.review" in caps
    # A2A-native skills mirror capabilities so either discovery convention works.
    skill_ids = {s["id"] for s in card["skills"]}
    assert skill_ids == set(caps)
    for s in card["skills"]:
        assert s["name"] and s["description"]
    assert card["defaultInputModes"] == ["text"]
    assert card["defaultOutputModes"] == ["text"]


def test_agent_card_url_defaults_none_and_overridable():
    assert agent_a2a.agent_card()["url"] is None
    card = agent_a2a.agent_card(url="http://127.0.0.1:9000")
    assert card["url"] == "http://127.0.0.1:9000"


def test_agent_card_metadata_has_model_and_tool_hints():
    md = agent_a2a.agent_card()["metadata"]
    assert md["modelHint"] == agent_a2a.DEFAULT_MODEL_ID
    assert list(md["gatewayTools"]) == list(agent_a2a.GATEWAY_TOOLS)
    assert "sigma_yara_lint" in md["gatewayTools"]


def test_agent_card_json_serializable():
    import json

    json.dumps(agent_a2a.agent_card())  # must not raise


def test_agent_card_name_and_description_overridable():
    card = agent_a2a.agent_card(
        name="reviewer-clone", version="9.9.9", description="custom desc"
    )
    assert card["name"] == "reviewer-clone"
    assert card["version"] == "9.9.9"
    assert card["description"] == "custom desc"
    assert all(s["description"] == "custom desc" for s in card["skills"])


def test_no_hardcoded_secrets_or_account_ids():
    """House rule: nothing customer- or account-specific baked in."""
    src = open(
        os.path.join(SPECIALIST_DIR, "agent_a2a.py"), encoding="utf-8"
    ).read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src


# --------------------------------------------------------------------------- #
# 3. Tool loading is safe with no Gateway configured (no network)             #
# --------------------------------------------------------------------------- #
def test_load_gateway_tools_empty_without_url():
    assert agent_a2a._load_gateway_tools(None) == []
    assert agent_a2a._load_gateway_tools("") == []


def test_load_gateway_tools_live_path_with_stubbed_mcp(monkeypatch):
    """When a Gateway URL IS configured, _load_gateway_tools starts an MCP client
    and returns its tools. We stub mcp + strands.tools.mcp so no network happens."""
    events = {}

    class _Client:
        def __init__(self, factory):
            events["factory"] = factory

        def start(self):
            events["started"] = True

        def list_tools_sync(self):
            return ["sigma_yara_lint", "attack_lookup"]

    strands_mod = types.ModuleType("strands")
    tools_mod = types.ModuleType("strands.tools")
    mcp_sub = types.ModuleType("strands.tools.mcp")
    mcp_sub.MCPClient = _Client
    mcp_pkg = types.ModuleType("mcp")
    mcp_client_pkg = types.ModuleType("mcp.client")
    streamable_mod = types.ModuleType("mcp.client.streamable_http")
    streamable_mod.streamablehttp_client = lambda url: ("conn", url)

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.tools", tools_mod)
    monkeypatch.setitem(sys.modules, "strands.tools.mcp", mcp_sub)
    monkeypatch.setitem(sys.modules, "mcp", mcp_pkg)
    monkeypatch.setitem(sys.modules, "mcp.client", mcp_client_pkg)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", streamable_mod)

    tools = agent_a2a._load_gateway_tools("https://gw.example/mcp")
    assert tools == ["sigma_yara_lint", "attack_lookup"]
    assert events["started"] is True


# --------------------------------------------------------------------------- #
# 4. build_agent() is callable with deps stubbed                              #
# --------------------------------------------------------------------------- #
def test_build_agent_with_stubbed_strands(monkeypatch):
    """Exercise the factory contract without a real strands/litellm install."""
    captured = {}
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, system_prompt, tools, name, description):
            captured.update(
                model=model, system_prompt=system_prompt, tools=tools,
                name=name, description=description,
            )

    strands_mod.Agent = _Agent
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")

    class _LiteLLMModel:
        def __init__(self, *, model_id):
            self.model_id = model_id

    litellm_mod.LiteLLMModel = _LiteLLMModel

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)

    assert isinstance(agent, _Agent)
    assert captured["model"].model_id == "bedrock/test-model"
    assert captured["name"] == "adversarial-reviewer"
    assert captured["description"] == agent_a2a.SPECIALIST_DESCRIPTION
    assert captured["system_prompt"] == agent_a2a.SYSTEM_PROMPT
    assert captured["tools"] == []


def test_build_agent_defaults_model_from_env(monkeypatch):
    captured = {}
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, **kw):
            captured["model_id"] = model.model_id

    strands_mod.Agent = _Agent
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")
    litellm_mod.LiteLLMModel = lambda *, model_id: types.SimpleNamespace(
        model_id=model_id
    )

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent_a2a.build_agent()
    assert captured["model_id"] == agent_a2a.DEFAULT_MODEL_ID


def test_build_agent_with_real_strands():
    """If the real specialist stack IS installed, build_agent must work too.
    Skipped cleanly when the deps are absent so CI stays green."""
    pytest.importorskip("strands")
    pytest.importorskip("litellm")
    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)
    assert getattr(agent, "name", None) == "adversarial-reviewer"


# --------------------------------------------------------------------------- #
# 5. REAL deterministic reasoner: review_detection                            #
# --------------------------------------------------------------------------- #
def test_review_clean_rule_can_pass():
    """A well-scoped rule (title/logsource/level, defined condition, exclusion
    filter, documented FPs) elicits an APPROVE with no objections/flaws."""
    review = agent_a2a.review_detection(_CLEAN_RULE)
    assert review["verdict"] == "approve"
    assert review["objections"] == []
    assert review["logic_flaws"] == []
    assert review["fp_risk"] == "low"
    assert review["artifact_kind"] == "sigma"


def test_review_flawed_rule_elicits_objections_and_revise():
    """A flawed rule (no title/logsource/level, lone-wildcard selection, no FP
    scoping) must be REVISED with concrete objections and high fp_risk."""
    review = agent_a2a.review_detection(_FLAWED_RULE)
    assert review["verdict"] == "revise"
    codes = {o["code"] for o in review["objections"]}
    # The alert-cannon wildcard and the missing FP story are the load-bearing finds.
    assert "broad_selection" in codes
    assert "no_fp_scoping" in codes
    assert "missing_title" in codes
    assert "missing_logsource" in codes
    assert review["fp_risk"] == "high"
    # Every objection is well-formed (code/severity/detail).
    for o in review["objections"]:
        assert o["code"] and o["severity"] and o["detail"]


def test_review_detects_undefined_condition_reference_as_logic_flaw():
    """A condition referencing an identifier that is never defined in the
    detection map is a logic flaw -> revise."""
    review = agent_a2a.review_detection(_LOGIC_FLAW_RULE)
    assert review["verdict"] == "revise"
    assert review["logic_flaws"], "an undefined condition reference must be flagged"
    assert any("selection2" in flaw for flaw in review["logic_flaws"])


def test_review_is_deterministic():
    """Same rule in -> same verdict out (proving reproducibility)."""
    a = agent_a2a.review_detection(_FLAWED_RULE)
    b = agent_a2a.review_detection(_FLAWED_RULE)
    assert a == b


def test_review_accepts_parsed_dict_artifact():
    """A structured (already-parsed) artifact takes the same analysis path as raw
    YAML text — a clean dict rule can approve."""
    artifact = {
        "title": "Dict-form clean rule",
        "logsource": {"product": "linux"},
        "detection": {
            "selection": {"CommandLine|contains": ".ssh/id_rsa"},
            "filter_ci": {"Image|endswith": "/usr/bin/ci"},
            "condition": "selection and not filter_ci",
        },
        "falsepositives": ["CI runners"],
        "level": "high",
    }
    review = agent_a2a.review_detection(artifact)
    assert review["verdict"] == "approve"
    assert review["objections"] == []


def test_review_missing_fp_docs_is_medium_not_high():
    """A rule WITH an exclusion filter but WITHOUT documented falsepositives is a
    hygiene note (missing_fp_docs / medium fp_risk), not a hard blocker's high."""
    rule = """\
title: Filter but no FP docs
logsource:
    product: linux
detection:
    selection:
        Image|endswith: '/bin/nc'
    filter_ok:
        User: 'monitoring'
    condition: selection and not filter_ok
level: medium
"""
    review = agent_a2a.review_detection(rule)
    codes = {o["code"] for o in review["objections"]}
    assert "missing_fp_docs" in codes
    assert "no_fp_scoping" not in codes
    assert review["fp_risk"] == "medium"
    assert review["verdict"] == "revise"  # any objection still blocks approval


def test_review_rejects_empty_or_wrong_type():
    """An empty / wrong-typed artifact raises ValueError — the reviewer never
    fabricates a verdict for a nonexistent rule."""
    for bad in ("", "   ", 123, None):
        with pytest.raises(ValueError):
            agent_a2a.review_detection(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 6. A2A contract through the SHARED harness with a MOCKED model + net guard  #
# --------------------------------------------------------------------------- #
@pytest.fixture
def no_network(monkeypatch):
    """Make ANY outbound socket connect raise, proving the harness never touches
    the network. A regression that smuggles in a real HTTP/LiteLLM call fails
    loudly instead of silently dialing out."""

    def _boom(*args, **kwargs):
        raise AssertionError("network access attempted — A2A harness must be fully offline")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "connect_ex", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    return True


def test_agent_card_served_and_well_formed():
    server = local_a2a.LocalA2AServer(url="http://127.0.0.1:9000")
    client = local_a2a.LocalA2AClient(server)
    card = client.get_agent_card()

    assert card["name"] == local_a2a.SPECIALIST_NAME
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["url"] == "http://127.0.0.1:9000"
    skills = card["skills"]
    assert isinstance(skills, list) and skills
    for s in skills:
        assert s["id"] and s["name"] and s["description"]
    assert card["protocol"] == "a2a"


def test_agent_card_is_the_canonical_card_not_a_copy():
    """The harness must SERVE the existing card, not redefine it — url aside, it is
    byte-identical to the specialist's own agent_card()."""
    served = local_a2a.LocalA2AServer(url="http://x").agent_card()
    canonical = local_a2a.agent_card(url="http://x")
    assert served == canonical


def test_agent_card_round_trips_through_mocked_model_under_net_guard(no_network):
    """The agent-card round-trips through a MOCKED model with the socket-connect
    guard armed (zero network)."""
    # guard is armed
    with pytest.raises(AssertionError):
        socket.create_connection(("192.0.2.1", 80))  # RFC-5737 TEST-NET-1
    server = local_a2a.LocalA2AServer(url="http://127.0.0.1:9000")
    client = local_a2a.LocalA2AClient(server)
    # discovery works under the guard
    assert client.get_agent_card()["name"] == "adversarial-reviewer"
    # and so does a full review round-trip (mocked model, no network)
    resp = client.send_message(_FLAWED_RULE)
    verdict = local_a2a.verdict_from_response(resp)
    assert isinstance(verdict, dict)
    assert verdict["engine"] == "echo-mock"


def test_flawed_rule_round_trip_yields_revise(no_network):
    """A flawed rule sent over the A2A round-trip elicits objections + revise."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_message(_FLAWED_RULE)

    assert response_is_success(resp)
    verdict = local_a2a.verdict_from_response(resp)
    assert verdict["verdict"] == "revise"
    assert verdict["objections"]
    assert verdict["grounded"] is True
    assert verdict["engine"] == "echo-mock"
    assert isinstance(verdict["summary"], str) and verdict["summary"].strip()


def test_clean_rule_round_trip_can_pass(no_network):
    """A clean rule sent over the A2A round-trip can APPROVE (no self-approval bias
    concern here — the verdict is the deterministic reasoner's)."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(client.send_message(_CLEAN_RULE))
    assert verdict["verdict"] == "approve"
    assert verdict["objections"] == []
    assert verdict["grounded"] is True


def test_round_trip_is_deterministic(no_network):
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    v1 = local_a2a.verdict_from_response(client.send_message(_FLAWED_RULE))
    v2 = local_a2a.verdict_from_response(client.send_message(_FLAWED_RULE))
    assert v1 == v2


def test_structured_response_envelope(no_network):
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    response = client.send_message(_CLEAN_RULE)
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "1"
    assert "error" not in response
    result = response["result"]
    assert result["role"] == "agent"
    assert result["kind"] == "message"
    assert result["messageId"]
    kinds = [p["kind"] for p in result["parts"]]
    assert "data" in kinds and "text" in kinds


def test_injected_model_callable_is_used(no_network):
    """The model is a real seam: an injected callable is what produces the verdict
    (this is exactly where a real Strands/LiteLLM model would plug in)."""
    calls = {}

    def fake_model(text: str) -> dict:
        calls["text"] = text
        return {"summary": "injected", "grounded": True}

    server = local_a2a.LocalA2AServer(model_callable=fake_model)
    client = local_a2a.LocalA2AClient(server)
    verdict = local_a2a.verdict_from_response(client.send_message("rule text"))
    assert calls["text"] == "rule text"
    assert verdict == {"summary": "injected", "grounded": True}


def response_is_success(resp: dict) -> bool:
    return "result" in resp and "error" not in resp


# --------------------------------------------------------------------------- #
# 7. Clean JSON-RPC errors on malformed input (not a crash)                   #
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


def test_missing_params_yields_error():
    server = local_a2a.LocalA2AServer()
    resp = server.handle({"jsonrpc": "2.0", "id": "3", "method": "message/send"})
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS


def test_empty_artifact_yields_clean_error():
    """An empty/whitespace review body must come back as an A2A error, not a
    fabricated approval (the reviewer refuses to greenlight nothing)."""
    server = local_a2a.LocalA2AServer()
    client = local_a2a.LocalA2AClient(server)
    resp = client.send_message("   ")
    assert "result" not in resp
    assert resp["error"]["code"] == local_a2a.JSONRPC_INVALID_PARAMS


def test_model_callable_exception_becomes_clean_error():
    def broken_model(text: str) -> dict:
        raise RuntimeError("boom")

    server = local_a2a.LocalA2AServer(model_callable=broken_model)
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": "5",
            "method": "message/send",
            "params": {"message": {"parts": [{"kind": "text", "text": "some rule"}]}},
        }
    )
    assert resp["error"]["code"] == local_a2a.JSONRPC_INTERNAL_ERROR
    assert "boom" in resp["error"]["message"]


def test_error_codes_match_shared_contract():
    assert local_a2a.JSONRPC_INVALID_REQUEST == -32600
    assert local_a2a.JSONRPC_METHOD_NOT_FOUND == -32601
    assert local_a2a.JSONRPC_INVALID_PARAMS == -32602
    assert local_a2a.JSONRPC_INTERNAL_ERROR == -32603


# --------------------------------------------------------------------------- #
# 8. build_app() / serve() serving wrappers behind guarded strands/a2a imports #
# --------------------------------------------------------------------------- #
def _stub_a2a_serving(monkeypatch, *, with_to_fastapi=True):
    rec: dict = {}

    class _FastAPI:
        def __init__(self):
            self.routes = {}

        def get(self, route):
            def _decorator(fn):
                self.routes[route] = fn
                return fn

            return _decorator

    fastapi_mod = types.ModuleType("fastapi")
    fastapi_mod.FastAPI = _FastAPI

    class _A2AServer:
        def __init__(self, *, agent, host, port):
            rec.update(agent=agent, host=host, port=port)

        if with_to_fastapi:
            def to_fastapi_app(self):
                app = _FastAPI()
                rec["from_a2a"] = True
                return app

    strands_mod = types.ModuleType("strands")
    multiagent_mod = types.ModuleType("strands.multiagent")
    a2a_mod = types.ModuleType("strands.multiagent.a2a")
    a2a_mod.A2AServer = _A2AServer

    monkeypatch.setitem(sys.modules, "fastapi", fastapi_mod)
    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.multiagent", multiagent_mod)
    monkeypatch.setitem(sys.modules, "strands.multiagent.a2a", a2a_mod)
    return rec, _FastAPI


def test_build_app_wires_a2a_and_ping(monkeypatch):
    rec, _ = _stub_a2a_serving(monkeypatch, with_to_fastapi=True)
    sentinel_agent = object()

    app = agent_a2a.build_app(host="127.0.0.1", port=1234, agent=sentinel_agent)

    assert rec["agent"] is sentinel_agent
    assert rec["host"] == "127.0.0.1"
    assert rec["port"] == 1234
    assert rec.get("from_a2a") is True
    assert "/ping" in app.routes
    assert app.routes["/ping"]() == {"status": "healthy", "agent": "adversarial-reviewer"}


def test_build_app_falls_back_to_fastapi_without_to_fastapi_app(monkeypatch):
    rec, _FastAPI = _stub_a2a_serving(monkeypatch, with_to_fastapi=False)
    app = agent_a2a.build_app(host="0.0.0.0", port=9000, agent=object())
    assert isinstance(app, _FastAPI)
    assert "from_a2a" not in rec
    assert app.routes["/ping"]() == {"status": "healthy", "agent": "adversarial-reviewer"}


def test_build_app_builds_agent_when_none_given(monkeypatch):
    rec, _ = _stub_a2a_serving(monkeypatch, with_to_fastapi=True)
    made = object()
    monkeypatch.setattr(agent_a2a, "build_agent", lambda: made)
    agent_a2a.build_app(host="127.0.0.1", port=1)
    assert rec["agent"] is made


def test_serve_runs_uvicorn_with_built_app(monkeypatch):
    calls = {}
    uvicorn_mod = types.ModuleType("uvicorn")

    def _run(app, *, host, port):
        calls.update(app=app, host=host, port=port)

    uvicorn_mod.run = _run
    monkeypatch.setitem(sys.modules, "uvicorn", uvicorn_mod)

    fake_app = object()
    captured = {}

    def _fake_build_app(*, host, port):
        captured.update(host=host, port=port)
        return fake_app

    monkeypatch.setattr(agent_a2a, "build_app", _fake_build_app)

    agent_a2a.serve(host="127.0.0.1", port=8765)

    assert captured == {"host": "127.0.0.1", "port": 8765}
    assert calls["app"] is fake_app
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8765


# --------------------------------------------------------------------------- #
# 9. Packaging contract: Dockerfile two-stage/non-root/EXPOSE/pinned + reqs    #
# --------------------------------------------------------------------------- #
_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
_SECRET_PATTERNS = ("sk-", "ghp_", "AKIA", "ASIA", "-----BEGIN")
_MODEL_ID_RE = re.compile(r"anthropic\.claude[a-z0-9.:\-]*")
_MODEL_VERSION_SUFFIX_RE = re.compile(r"-\d{8}-v\d+:\d+$")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _dockerfile() -> str:
    return _read(os.path.join(SPECIALIST_DIR, "Dockerfile"))


def _requirement_lines(name: str) -> list[str]:
    out = []
    for raw in _read(os.path.join(SPECIALISTS_DIR, name, "requirements.txt")).splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out


def _requirement_map(name: str) -> dict:
    out: dict = {}
    for ln in _requirement_lines(name):
        m = re.split(r"(==|~=)", ln, maxsplit=1)
        assert len(m) == 3, f"unpinned requirement in {name}: {ln!r}"
        pkg, _op, ver = m
        out[pkg.strip().lower()] = ver.strip()
    return out


def test_packaging_files_exist():
    for fname in ("Dockerfile", "requirements.txt", "agent_a2a.py", "local_a2a.py",
                  "README.md"):
        assert os.path.isfile(os.path.join(SPECIALIST_DIR, fname)), f"missing {fname}"


def test_dockerfile_is_two_stage():
    """Two-stage build: a builder stage feeding a runtime stage (COPY --from)."""
    src = _dockerfile()
    from_stages = [ln for ln in src.splitlines() if ln.strip().upper().startswith("FROM ")]
    assert len(from_stages) >= 2, "expected a multi-stage (builder + runtime) build"
    assert "AS builder" in src and "AS runtime" in src
    assert "COPY --from=builder" in src


def test_dockerfile_pins_base_not_latest():
    src = _dockerfile()
    for ln in src.splitlines():
        if not ln.strip().upper().startswith("FROM "):
            continue
        toks = [t for t in ln.split() if not t.upper().startswith("--PLATFORM")]
        image_ref = toks[1]
        if re.fullmatch(r"\w+", image_ref):  # internal stage ref, needs no tag
            continue
        assert ":" in image_ref, f"base image not tagged: {image_ref}"
        assert not image_ref.endswith(":latest"), f"base pinned to :latest: {image_ref}"
    assert "python:3.13-slim" in src


def test_dockerfile_declares_non_root_user():
    src = _dockerfile()
    user_lines = [ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("USER ")]
    assert user_lines, "Dockerfile must declare a USER"
    last_user = user_lines[-1].split()[1]
    assert last_user.lower() not in ("root", "0"), f"container runs as {last_user}"


def test_dockerfile_exposes_9000():
    src = _dockerfile()
    expose = [ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("EXPOSE")]
    assert expose, "Dockerfile must EXPOSE the A2A port"
    ports = {tok for ln in expose for tok in ln.split()[1:]}
    assert "9000" in ports, f"expected A2A port 9000 exposed, saw {ports}"


def test_dockerfile_has_cmd():
    src = "\n" + _dockerfile().upper()
    assert "\nCMD " in src or "\nCMD[" in src or "\nENTRYPOINT" in src


def test_dockerfile_no_hardcoded_secret_or_account():
    src = _dockerfile()
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"hardcoded account id in Dockerfile: {m}"
    for pat in _SECRET_PATTERNS:
        assert pat not in src, f"possible hardcoded secret in Dockerfile: {pat}"


def test_dockerfile_cmd_launches_agent_a2a():
    assert "agent_a2a" in _dockerfile(), "CMD must launch the agent_a2a module"


def test_requirements_are_all_pinned():
    reqs = _requirement_lines(SPECIALIST)
    assert reqs, "requirements.txt has no requirements"
    for ln in reqs:
        assert "==" in ln or "~=" in ln, f"unpinned requirement: {ln!r}"


def test_requirements_match_cve_intel_exactly():
    assert _requirement_map(SPECIALIST) == _requirement_map(REFERENCE)


def test_requirements_list_the_specialist_stack():
    joined = "\n".join(_requirement_lines(SPECIALIST)).lower()
    assert "strands-agents" in joined
    assert "a2a" in joined and "litellm" in joined
    assert "uvicorn" in joined and "fastapi" in joined


def test_default_port_is_9000():
    assert agent_a2a.DEFAULT_PORT == 9000


def test_default_model_id_is_version_pinned():
    """The baked Bedrock model id must carry a full version suffix (-YYYYMMDD-vN:M)
    so a container cannot ship a silently-broken bare model id."""
    candidates = [agent_a2a.DEFAULT_MODEL_ID]
    candidates.extend(_MODEL_ID_RE.findall(_read(os.path.join(SPECIALIST_DIR, "agent_a2a.py"))))
    assert candidates
    for mid in candidates:
        for found in _MODEL_ID_RE.findall(mid) or [mid]:
            assert _MODEL_VERSION_SUFFIX_RE.search(found), (
                f"default model id {found!r} is not version-pinned"
            )
