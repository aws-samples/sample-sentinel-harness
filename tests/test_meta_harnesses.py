"""
Offline loader tests for the meta-agent + agent-ops harnesses
=============================================================
Load both north-star orchestration harnesses (ROADMAP §3/§5.2) through
``sentinel_harness.loader.load_harness_config`` and assert the resulting kwargs
have the shapes ``core.create_harness(**kwargs)`` expects.

HARD RULE: ZERO AWS calls. ``load_harness_config`` is pure/offline — we only ever
inspect the kwargs dict it returns. Required env (``SENTINEL_GATEWAY_ARN`` etc.)
is set to ``000000000000`` placeholders in a tmp env — no real account/role/secret.
Mirrors tests/test_loader.py's hermetic-import + gateway_env fixture pattern.
"""
from __future__ import annotations

import os
import re

import pytest

# --- Make the import hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import loader  # noqa: E402

# harness name rule (factory._NAME_RE): letter, then up to 39 [a-zA-Z0-9_], no hyphens.
NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")
# gateway-scoped tool grammar: @scope/tool.
GATEWAY_TOOL_RE = re.compile(r"^@[a-zA-Z0-9_]+/[a-zA-Z0-9_]+$")

_HARNESSES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harnesses"
)
META_HARNESSES = ["meta-agent", "agent-ops"]


def _yaml_path(name: str) -> str:
    return os.path.join(_HARNESSES_DIR, name, "harness.yaml")


@pytest.fixture()
def gateway_env(monkeypatch):
    """A tmp env with a 000000000000 placeholder Gateway ARN (12-factor).

    agent-ops references ${SENTINEL_GATEWAY_ARN}; meta-agent does not, but setting
    it is harmless and keeps the fixture identical to test_loader.py.
    """
    monkeypatch.setenv(
        "SENTINEL_GATEWAY_ARN",
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test-gw",
    )
    return os.environ["SENTINEL_GATEWAY_ARN"]


@pytest.mark.parametrize("name", META_HARNESSES)
def test_meta_harness_loads(gateway_env, name):
    """Each meta harness loads into well-formed, loader-consumable kwargs."""
    kwargs = loader.load_harness_config(_yaml_path(name))

    # harnessName maps to `name` and satisfies the no-hyphen naming rule.
    assert "name" in kwargs
    assert NAME_RE.match(kwargs["name"]), f"{kwargs['name']!r} violates the harness naming rule"

    # systemPrompt resolved from a path to a non-empty string (core wraps it as text).
    sp = kwargs["system_prompt"]
    assert isinstance(sp, str) and sp.strip(), "systemPrompt must resolve to non-empty text"

    # model id present under the bedrockModelConfig shape.
    assert "bedrockModelConfig" in kwargs["model"]
    assert kwargs["model"]["bedrockModelConfig"]["modelId"], "model id must be present"

    # allowedTools is an EXPLICIT list and never '*' / never contains '*'.
    allowed = kwargs["allowed_tools"]
    assert isinstance(allowed, list) and allowed, "allowedTools must be a non-empty explicit list"
    assert allowed != ["*"], "allowedTools must never be ['*']"
    for entry in allowed:
        assert isinstance(entry, str) and entry and entry != "*", f"bad allowedTools entry {entry!r}"
        if entry.startswith("@"):
            assert GATEWAY_TOOL_RE.match(entry), f"{entry!r} is not valid @scope/tool grammar"
        else:
            assert NAME_RE.match(entry), f"plain tool name {entry!r} is malformed"

    # memory is configured as a managedMemoryConfiguration.
    assert "managedMemoryConfiguration" in kwargs["memory"]

    # bounded limits pass through under the core kwarg names.
    assert isinstance(kwargs["max_iterations"], int)
    assert isinstance(kwargs["timeout_seconds"], int)


def test_meta_agent_is_opus_and_has_no_build_tools(gateway_env):
    """meta-agent uses Opus (deep reasoning) and emits specs only — it must NOT be
    able to build/modify/invoke a harness (no harness_ops in its allowlist)."""
    kwargs = loader.load_harness_config(_yaml_path("meta-agent"))
    assert "opus" in kwargs["model"]["bedrockModelConfig"]["modelId"].lower()
    assert "emit_harness_spec" in kwargs["allowed_tools"]
    assert not any("harness_ops" in t for t in kwargs["allowed_tools"]), (
        "meta-agent must not have harness lifecycle tools — that is agent-ops' job"
    )


def test_agent_ops_is_sonnet_with_harness_ops(gateway_env):
    """agent-ops uses Sonnet and its explicit allowlist is exactly the harness_ops tool."""
    kwargs = loader.load_harness_config(_yaml_path("agent-ops"))
    assert "sonnet" in kwargs["model"]["bedrockModelConfig"]["modelId"].lower()
    assert kwargs["allowed_tools"] == ["@gateway/harness_ops"]
    assert kwargs["timeout_seconds"] == 300
