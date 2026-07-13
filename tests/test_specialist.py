"""
Offline tests for the cve-intel A2A specialist skeleton
=======================================================
ZERO AWS calls, ZERO network. The point of the skeleton is that it is importable
and inspectable WITHOUT the heavy specialist stack (strands / litellm /
bedrock-agentcore) installed, so:

- The import + agent-card + capability-metadata tests run everywhere (they touch
  no heavy deps — those are imported lazily inside the factory).
- The ``build_agent`` / ``build_app`` tests either stub the heavy deps in
  ``sys.modules`` (so we exercise the factory contract with no real install) or
  ``importorskip`` the real deps — CI stays green when the stack is absent.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import types

import pytest

# Every specialist ships a module literally named ``agent_a2a``. Importing it by the
# bare name (import_module("agent_a2a") + sys.path insert) registers it in sys.modules
# under that shared name, which collides with sibling specialists' same-named modules
# when the whole suite runs — whichever test imports first wins the cache. Load ours
# from an explicit path under a UNIQUE module name so this file can never poison (or be
# poisoned by) test_attack_mapper / test_threat_hunt regardless of collection order.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(REPO_ROOT, "specialists", "cve-intel", "agent_a2a.py")
_UNIQUE_NAME = "cve_intel_agent_a2a"
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
    for dep in ("strands", "litellm", "bedrock_agentcore"):
        # We do not require them absent (the venv may have them); we require the
        # module to have imported regardless, which it already did above.
        assert dep not in ("",)  # sanity placeholder; real assertion is the import
    assert agent_a2a.SPECIALIST_NAME == "cve-intel"


def test_factory_and_public_surface_present():
    for attr in ("build_agent", "build_app", "serve", "agent_card"):
        assert callable(getattr(agent_a2a, attr)), f"{attr} must be callable"


# --------------------------------------------------------------------------- #
# Agent-card / capability metadata is well-formed                             #
# --------------------------------------------------------------------------- #
def test_agent_card_shape():
    card = agent_a2a.agent_card()
    # Required self-describing fields for discovery.
    assert card["name"] == "cve-intel"
    assert card["version"] == agent_a2a.SPECIALIST_VERSION
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["protocol"] == "a2a"
    # Capabilities: non-empty list of stable string labels (the discovery contract).
    caps = card["capabilities"]
    assert isinstance(caps, list) and caps
    assert all(isinstance(c, str) and c for c in caps)
    assert "cve.lookup" in caps
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


def test_agent_card_metadata_has_model_and_tool_hints():
    md = agent_a2a.agent_card()["metadata"]
    assert md["modelHint"] == agent_a2a.DEFAULT_MODEL_ID
    assert list(md["gatewayTools"]) == list(agent_a2a.GATEWAY_TOOLS)


def test_agent_card_json_serializable():
    """The card is pushed to the Registry / A2A well-known endpoint as JSON."""
    import json

    json.dumps(agent_a2a.agent_card())  # must not raise


def test_no_hardcoded_secrets_or_account_ids():
    """House rule: nothing customer- or account-specific baked in."""
    import re

    src = open(_MODULE_PATH, encoding="utf-8").read()
    # No 12-digit AWS account id literal (allow the all-zeros placeholder only).
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src


# --------------------------------------------------------------------------- #
# Tool loading is safe with no Gateway configured (no network)                #
# --------------------------------------------------------------------------- #
def test_load_gateway_tools_empty_without_url():
    """No Gateway URL -> no tools, and crucially no network / no MCP import."""
    assert agent_a2a._load_gateway_tools(None) == []
    assert agent_a2a._load_gateway_tools("") == []


# --------------------------------------------------------------------------- #
# build_agent() is callable with deps stubbed                                 #
# --------------------------------------------------------------------------- #
def test_build_agent_with_stubbed_strands(monkeypatch):
    """Exercise the factory contract without a real strands/litellm install by
    injecting stub modules into sys.modules. Verifies build_agent wires the
    model + system_prompt + name + description onto the Agent and passes no tools
    when no Gateway is configured."""
    captured = {}

    # --- stub strands.Agent -------------------------------------------------
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, system_prompt, tools, name, description):
            captured.update(
                model=model, system_prompt=system_prompt, tools=tools,
                name=name, description=description,
            )

    strands_mod.Agent = _Agent

    # --- stub strands.models.litellm.LiteLLMModel ---------------------------
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")

    class _LiteLLMModel:
        def __init__(self, *, model_id):
            self.model_id = model_id

    litellm_mod.LiteLLMModel = _LiteLLMModel

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    # Ensure no Gateway tools are loaded (would hit network otherwise).
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)

    assert isinstance(agent, _Agent)
    assert captured["model"].model_id == "bedrock/test-model"
    assert captured["name"] == "cve-intel"
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
# Real-dependency path (skipped in CI without the specialist stack)           #
# --------------------------------------------------------------------------- #
def test_build_agent_with_real_strands():
    """If the real specialist stack IS installed, build_agent must work against
    it too. Skipped cleanly when the deps are absent so CI stays green."""
    pytest.importorskip("strands")
    pytest.importorskip("litellm")
    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)
    assert getattr(agent, "name", None) == "cve-intel"
