"""
Offline tests for the threat-hunt A2A specialist
================================================
ZERO AWS calls, ZERO network. Two provable surfaces:

1. The A2A skeleton is importable and inspectable WITHOUT the heavy specialist
   stack (strands / litellm / bedrock-agentcore) installed — those are imported
   lazily inside the factory, so the import + agent-card + capability-metadata
   tests run everywhere. The build_agent/build_app tests either stub the heavy
   deps in ``sys.modules`` or ``importorskip`` the real ones.
2. ``build_hunt_plan`` is a REAL deterministic pure-Python function (no LLM, no
   network) — a known hypothesis returns the right ATT&CK ids + observables; an
   unknown hypothesis returns a safe generic plan and never crashes.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

# The specialist lives outside the package tree (specialists/threat-hunt/). Each
# specialist ships a module literally named ``agent_a2a`` (threat-hunt,
# attack-mapper, cve-intel, ...), so we must NOT import it under the bare name
# ``agent_a2a`` — that would collide in ``sys.modules`` with sibling specialist
# test files and whichever ran first would win. Load THIS specialist's file
# under a unique module name via an explicit spec so the suite is order-
# independent and never cross-contaminates. No AWS, no network.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALIST_DIR = os.path.join(REPO_ROOT, "specialists", "threat-hunt")
_MODULE_PATH = os.path.join(SPECIALIST_DIR, "agent_a2a.py")
_UNIQUE_NAME = "threat_hunt_agent_a2a"

_spec = importlib.util.spec_from_file_location(_UNIQUE_NAME, _MODULE_PATH)
agent_a2a = importlib.util.module_from_spec(_spec)
sys.modules[_UNIQUE_NAME] = agent_a2a
_spec.loader.exec_module(agent_a2a)


# --------------------------------------------------------------------------- #
# Import is dependency-free                                                    #
# --------------------------------------------------------------------------- #
def test_module_imports_without_heavy_deps():
    """agent_a2a must import even when strands/litellm/bedrock-agentcore are
    absent — the heavy deps are imported lazily inside the factory, not at top."""
    assert agent_a2a.SPECIALIST_NAME == "threat-hunt"


def test_factory_and_public_surface_present():
    for attr in ("build_agent", "build_app", "serve", "agent_card", "build_hunt_plan"):
        assert callable(getattr(agent_a2a, attr)), f"{attr} must be callable"


# --------------------------------------------------------------------------- #
# Agent-card / capability metadata is well-formed                             #
# --------------------------------------------------------------------------- #
def test_agent_card_shape():
    card = agent_a2a.agent_card()
    assert card["name"] == "threat-hunt"
    assert card["version"] == agent_a2a.SPECIALIST_VERSION
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["protocol"] == "a2a"
    # Capabilities: non-empty list of stable string labels (discovery contract).
    caps = card["capabilities"]
    assert isinstance(caps, list) and caps
    assert all(isinstance(c, str) and c for c in caps)
    assert "hunt.plan" in caps
    # A2A-native skills mirror capabilities so either discovery convention works.
    skill_ids = {s["id"] for s in card["skills"]}
    assert skill_ids == set(caps)
    for s in card["skills"]:
        assert s["name"] and s["description"]
    # IO modes present.
    assert card["defaultInputModes"] == ["text"]
    assert card["defaultOutputModes"] == ["text"]


def test_agent_card_url_defaults_none_and_overridable():
    assert agent_a2a.agent_card()["url"] is None
    card = agent_a2a.agent_card(url="http://127.0.0.1:9000")
    assert card["url"] == "http://127.0.0.1:9000"


def test_agent_card_metadata_hints():
    md = agent_a2a.agent_card()["metadata"]
    assert md["modelHint"] == agent_a2a.DEFAULT_MODEL_ID
    assert list(md["gatewayTools"]) == list(agent_a2a.GATEWAY_TOOLS)
    # build_hunt_plan (the real core) is advertised as a Gateway tool.
    assert "build_hunt_plan" in md["gatewayTools"]


def test_agent_card_json_serializable():
    """The card is pushed to the Registry / A2A well-known endpoint as JSON."""
    import json

    json.dumps(agent_a2a.agent_card())  # must not raise


def test_no_hardcoded_secrets_or_account_ids():
    """House rule: nothing customer- or account-specific baked in."""
    import re

    src = open(os.path.join(SPECIALIST_DIR, "agent_a2a.py"), encoding="utf-8").read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src


# --------------------------------------------------------------------------- #
# REAL deterministic core: build_hunt_plan                                    #
# --------------------------------------------------------------------------- #
def test_build_hunt_plan_known_hypothesis_credential_dumping():
    """A known hypothesis returns the right ATT&CK ids + observables."""
    plan = agent_a2a.build_hunt_plan(
        "possible credential dumping via lsass on domain controllers"
    )
    assert plan["matched"] is True
    assert "credential_dumping" in plan["matched_ttps"]
    # ATT&CK ids for OS Credential Dumping.
    for tid in ("T1003", "T1003.001", "T1003.003"):
        assert tid in plan["attack_techniques"]
    # An observable a hunter would actually query for lsass access.
    assert any("lsass" in obs.lower() for obs in plan["observables_to_query"])
    # Structured plan surfaces all four required sections, all non-empty.
    for field in (
        "abductive_questions",
        "observables_to_query",
        "attack_techniques",
        "suggested_queries",
    ):
        assert isinstance(plan[field], list) and plan[field]
    # The original hypothesis is echoed back unmodified.
    assert plan["hypothesis"].startswith("possible credential dumping")


def test_build_hunt_plan_is_deterministic():
    """Same input → identical output (no LLM, no randomness)."""
    h = "lateral movement with psexec across the fleet"
    assert agent_a2a.build_hunt_plan(h) == agent_a2a.build_hunt_plan(h)


def test_build_hunt_plan_matches_multiple_ttps():
    """A hypothesis spanning two behaviours merges both plans, deduped."""
    plan = agent_a2a.build_hunt_plan(
        "phishing leading to credential dumping"
    )
    assert plan["matched"] is True
    assert "phishing_initial_access" in plan["matched_ttps"]
    assert "credential_dumping" in plan["matched_ttps"]
    # Merged technique list is de-duplicated (stable, no repeats).
    techniques = plan["attack_techniques"]
    assert len(techniques) == len(set(techniques))
    assert "T1566" in techniques and "T1003" in techniques


def test_build_hunt_plan_unknown_hypothesis_safe_generic_plan():
    """An unknown hypothesis returns a safe generic plan, never crashes."""
    plan = agent_a2a.build_hunt_plan(
        "unicorn glitter anomaly in the marketing dashboard"
    )
    assert plan["matched"] is False
    assert plan["matched_ttps"] == []
    # Generic discovery techniques, not a confabulated specific technique.
    assert plan["attack_techniques"] == ["T1057", "T1082"]
    for field in (
        "abductive_questions",
        "observables_to_query",
        "attack_techniques",
        "suggested_queries",
    ):
        assert isinstance(plan[field], list) and plan[field]


def test_build_hunt_plan_case_insensitive():
    """Matching is stable regardless of casing / spacing in the hypothesis."""
    lower = agent_a2a.build_hunt_plan("credential dumping")
    upper = agent_a2a.build_hunt_plan("  CREDENTIAL   DUMPING  ")
    assert lower["matched_ttps"] == upper["matched_ttps"]
    assert lower["attack_techniques"] == upper["attack_techniques"]


def test_build_hunt_plan_rejects_empty_input():
    """Empty / non-string input raises rather than returning a misleading plan."""
    for bad in ("", "   ", None, 123):
        with pytest.raises(ValueError):
            agent_a2a.build_hunt_plan(bad)  # type: ignore[arg-type]


def test_build_hunt_plan_attack_ids_are_wellformed():
    """Every technique id the core emits is a valid ATT&CK id (Tnnnn[.nnn])."""
    import re

    pat = re.compile(r"^T\d{4}(\.\d{3})?$")
    seen = set()
    for entry in agent_a2a._TTP_LIBRARY.values():
        seen.update(entry["attack_techniques"])
    seen.update(agent_a2a._GENERIC_PLAN["attack_techniques"])
    assert seen  # the library is non-empty
    for tid in seen:
        assert pat.match(tid), f"malformed ATT&CK id in library: {tid!r}"


# --------------------------------------------------------------------------- #
# Factory contract with STUBBED heavy deps (no real install needed)           #
# --------------------------------------------------------------------------- #
def test_build_agent_with_stubbed_strands(monkeypatch):
    """build_agent wires model/prompt/tools/name onto the Strands Agent."""
    captured = {}

    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, system_prompt, tools, name, description):
            captured["model"] = model
            captured["system_prompt"] = system_prompt
            captured["tools"] = tools
            captured["name"] = name
            captured["description"] = description

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
    assert captured["name"] == "threat-hunt"
    assert captured["description"] == agent_a2a.SPECIALIST_DESCRIPTION
    assert captured["system_prompt"] == agent_a2a.SYSTEM_PROMPT
    assert captured["tools"] == []


def test_build_agent_defaults_model_from_env(monkeypatch):
    """When no model_id is passed, build_agent uses DEFAULT_MODEL_ID."""
    captured = {}
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, **kw):
            captured["model_id"] = model.model_id

    strands_mod.Agent = _Agent
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")
    litellm_mod.LiteLLMModel = lambda *, model_id: types.SimpleNamespace(model_id=model_id)

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent_a2a.build_agent()
    assert captured["model_id"] == agent_a2a.DEFAULT_MODEL_ID


# --------------------------------------------------------------------------- #
# Tool loading is safe with no Gateway configured (no network)                #
# --------------------------------------------------------------------------- #
def test_load_gateway_tools_empty_without_url():
    """No Gateway URL -> no tools, and crucially no network / no MCP import."""
    assert agent_a2a._load_gateway_tools(None) == []
    assert agent_a2a._load_gateway_tools("") == []


# --------------------------------------------------------------------------- #
# Real-dependency path (skipped in CI without the specialist stack)           #
# --------------------------------------------------------------------------- #
def test_build_agent_with_real_strands():
    """If the real specialist stack IS installed, build_agent must work against
    it too. Skipped cleanly when the deps are absent so CI stays green."""
    pytest.importorskip("strands")
    pytest.importorskip("litellm")
    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)
    assert getattr(agent, "name", None) == "threat-hunt"


# --------------------------------------------------------------------------- #
# Extra build_hunt_plan / agent_card branch coverage                          #
# --------------------------------------------------------------------------- #
def test_build_hunt_plan_single_ttp_no_dedup_needed():
    """A single-TTP match relays that TTP's sections verbatim (matched=True)."""
    plan = agent_a2a.build_hunt_plan("suspected data exfiltration via dns tunnel")
    assert plan["matched"] is True
    assert plan["matched_ttps"] == ["exfiltration"]
    # attack_techniques mirror the library slice exactly, in order, no repeats.
    assert plan["attack_techniques"] == ["T1041", "T1048", "T1071", "T1567"]


def test_build_hunt_plan_generic_plan_is_copied_not_shared():
    """The generic fallback returns fresh list copies, so a caller mutating the
    result never corrupts the module-level _GENERIC_PLAN template."""
    plan = agent_a2a.build_hunt_plan("no known ttp keyword here at all")
    assert plan["matched"] is False
    plan["attack_techniques"].append("T9999")
    plan["observables_to_query"].clear()
    # The shared template is untouched.
    assert agent_a2a._GENERIC_PLAN["attack_techniques"] == ["T1057", "T1082"]
    assert agent_a2a._GENERIC_PLAN["observables_to_query"]


def test_build_hunt_plan_privilege_escalation_and_persistence():
    """Two more library TTPs match on their trigger keywords (branch coverage)."""
    privesc = agent_a2a.build_hunt_plan("uac bypass privilege escalation attempt")
    assert privesc["matched_ttps"] == ["privilege_escalation"]
    assert "T1068" in privesc["attack_techniques"]
    persist = agent_a2a.build_hunt_plan("suspicious scheduled task persistence")
    assert persist["matched_ttps"] == ["persistence_scheduled_task"]
    assert "T1053" in persist["attack_techniques"]


def test_dedupe_preserve_order_drops_repeats():
    """_dedupe_preserve_order keeps first occurrence and skips later repeats,
    exercising both branches of its membership test."""
    assert agent_a2a._dedupe_preserve_order(
        ["a", "b", "a", "c", "b"]
    ) == ["a", "b", "c"]


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
            return ["build_hunt_plan", "attack_lookup"]

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
    assert tools == ["build_hunt_plan", "attack_lookup"]
    assert events["started"] is True


def test_agent_card_overrides_thread_through():
    """agent_card threads custom name/version/description overrides into the card
    and its mirrored skills."""
    card = agent_a2a.agent_card(
        name="hunt-clone", version="2.0.0", description="custom hunt desc"
    )
    assert card["name"] == "hunt-clone"
    assert card["version"] == "2.0.0"
    assert card["description"] == "custom hunt desc"
    assert all(s["description"] == "custom hunt desc" for s in card["skills"])


# --------------------------------------------------------------------------- #
# build_app() / serve() serving wrappers behind guarded strands/a2a imports.  #
# We inject stub fastapi + strands.multiagent.a2a + uvicorn modules into       #
# sys.modules (mirroring the build_agent stubbing) so the lazy imports resolve #
# and the wiring runs with no real deps, no socket bind, no network.          #
# --------------------------------------------------------------------------- #
def _stub_a2a_serving(monkeypatch, *, with_to_fastapi=True):
    """Inject stub fastapi + strands.multiagent.a2a modules and return the
    recorder dict the stubs write into plus the fake FastAPI class."""
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
    """build_app wraps the given agent in an A2AServer, uses its FastAPI app,
    and mounts a dependency-free /ping health endpoint naming this specialist."""
    rec, _ = _stub_a2a_serving(monkeypatch, with_to_fastapi=True)
    sentinel_agent = object()

    app = agent_a2a.build_app(host="127.0.0.1", port=1234, agent=sentinel_agent)

    assert rec["agent"] is sentinel_agent
    assert rec["host"] == "127.0.0.1"
    assert rec["port"] == 1234
    assert rec.get("from_a2a") is True
    assert "/ping" in app.routes
    assert app.routes["/ping"]() == {"status": "healthy", "agent": "threat-hunt"}


def test_build_app_falls_back_to_fastapi_without_to_fastapi_app(monkeypatch):
    """When A2AServer has no to_fastapi_app, build_app falls back to a bare
    FastAPI() app and still mounts /ping."""
    rec, _FastAPI = _stub_a2a_serving(monkeypatch, with_to_fastapi=False)
    app = agent_a2a.build_app(host="0.0.0.0", port=9000, agent=object())
    assert isinstance(app, _FastAPI)
    assert "from_a2a" not in rec
    assert app.routes["/ping"]() == {"status": "healthy", "agent": "threat-hunt"}


def test_build_app_builds_agent_when_none_given(monkeypatch):
    """When no agent is passed, build_app calls build_agent() to make one."""
    rec, _ = _stub_a2a_serving(monkeypatch, with_to_fastapi=True)
    made = object()
    monkeypatch.setattr(agent_a2a, "build_agent", lambda: made)
    agent_a2a.build_app(host="127.0.0.1", port=1)
    assert rec["agent"] is made


def test_serve_runs_uvicorn_with_built_app(monkeypatch):
    """serve() builds the app and hands it to uvicorn.run with host/port — no
    real socket bind (uvicorn is stubbed)."""
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
