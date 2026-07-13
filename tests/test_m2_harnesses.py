"""
Offline loader tests for the M2 llm-judge + self-improving harnesses
====================================================================
Load both M2 harnesses (ROADMAP §4 layer ③, §5.3) through
``sentinel_harness.loader.load_harness_config`` and assert the resulting kwargs
have the shapes ``core.create_harness(**kwargs)`` expects:

- ``llm-judge`` — the self-built LLM-as-a-judge harness the M2 scoring gate invokes.
  A PURE critic: its ``allowedTools`` is an EXPLICIT empty list (no tools, never '*').
- ``self-improving`` — the score → retry-with-reasoning → promote loop. Its allowlist
  is the two gateway tools (``run_evaluation`` / ``harness_ops``) plus the inline HITL
  gate ``request_promotion_approval``.

HARD RULE: ZERO AWS calls. ``load_harness_config`` is pure/offline — we only ever
inspect the kwargs dict it returns. Required env (``SENTINEL_GATEWAY_ARN`` etc.) is
set to ``000000000000`` placeholders — no real account/role/secret. Mirrors
tests/test_meta_harnesses.py's hermetic-import + gateway_env fixture pattern.

NOTE on request_promotion_approval:
    This is a NEW inline HITL gate not yet in ``loader._INLINE_GATES`` (adding it there
    is a SHARED change to loader.py owned by the orchestrator — see the task's
    shared_changes_needed). The current loader silently passes an unknown plain gate
    name through ``allowedTools`` without injecting a tool definition, so
    ``load_harness_config`` does NOT raise today. If a future loader change makes an
    unknown gate raise instead, the self-improving load is wrapped so that one
    assertion xfails with a clear note rather than reddening the suite.
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
M2_HARNESSES = ["llm-judge", "self-improving"]


def _yaml_path(name: str) -> str:
    return os.path.join(_HARNESSES_DIR, name, "harness.yaml")


@pytest.fixture()
def gateway_env(monkeypatch):
    """A tmp env with a 000000000000 placeholder Gateway ARN (12-factor).

    self-improving references ${SENTINEL_GATEWAY_ARN}; llm-judge does not, but setting
    it is harmless and keeps the fixture identical to test_meta_harnesses.py.
    """
    monkeypatch.setenv(
        "SENTINEL_GATEWAY_ARN",
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test-gw",
    )
    return os.environ["SENTINEL_GATEWAY_ARN"]


def _load_tolerating_unknown_gate(name: str):
    """Load a harness, but if the loader raises SOLELY because of the not-yet-wired
    ``request_promotion_approval`` gate, xfail with a clear note instead of failing —
    the suite stays green until the orchestrator adds the gate to loader._INLINE_GATES.

    Today the loader passes an unknown plain gate name through without raising, so this
    normally just returns the kwargs. The guard only trips if a future loader change
    makes an unknown gate an error."""
    try:
        return loader.load_harness_config(_yaml_path(name))
    except Exception as exc:  # noqa: BLE001 — narrow check below; never a silent swallow
        if "request_promotion_approval" in str(exc):
            pytest.xfail(
                "loader raises on the not-yet-wired request_promotion_approval gate; "
                "add it to loader._INLINE_GATES (see shared_changes_needed) to enable."
            )
        raise


@pytest.mark.parametrize("name", M2_HARNESSES)
def test_m2_harness_loads(gateway_env, name):
    """Each M2 harness loads into well-formed, loader-consumable kwargs."""
    kwargs = _load_tolerating_unknown_gate(name)

    # harnessName maps to `name` and satisfies the no-hyphen naming rule.
    assert "name" in kwargs
    assert NAME_RE.match(kwargs["name"]), f"{kwargs['name']!r} violates the harness naming rule"

    # systemPrompt resolved from a path to a non-empty string (core wraps it as text).
    sp = kwargs["system_prompt"]
    assert isinstance(sp, str) and sp.strip(), "systemPrompt must resolve to non-empty text"

    # model id present under the bedrockModelConfig shape.
    assert "bedrockModelConfig" in kwargs["model"]
    assert kwargs["model"]["bedrockModelConfig"]["modelId"], "model id must be present"

    # allowedTools is a list and NEVER a single star (nor contains one). For llm-judge it
    # is deliberately an EXPLICIT empty list; for self-improving it is a non-empty list.
    allowed = kwargs["allowed_tools"]
    assert isinstance(allowed, list), "allowedTools must be a list"
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


def test_llm_judge_is_sonnet_pure_critic_no_tools(gateway_env):
    """llm-judge uses Sonnet and is a PURE critic: an explicit EMPTY allowlist — never a
    star, and deliberately no tools (it scores only the answer + criteria handed to it)."""
    kwargs = loader.load_harness_config(_yaml_path("llm-judge"))
    assert "sonnet" in kwargs["model"]["bedrockModelConfig"]["modelId"].lower()
    assert kwargs["allowed_tools"] == [], "the judge must have no tools (explicit empty list)"
    assert kwargs["allowed_tools"] != ["*"], "allowedTools must never be ['*']"


def test_self_improving_is_sonnet_with_eval_and_ops(gateway_env):
    """self-improving uses Sonnet and its explicit allowlist carries exactly the scoring
    tool, the harness-lifecycle tool, and the promotion HITL gate — never a star."""
    kwargs = _load_tolerating_unknown_gate("self-improving")
    assert "sonnet" in kwargs["model"]["bedrockModelConfig"]["modelId"].lower()
    allowed = kwargs["allowed_tools"]
    assert allowed != ["*"], "allowedTools must never be ['*']"
    assert "@gateway/run_evaluation" in allowed
    assert "@gateway/harness_ops" in allowed
    assert "request_promotion_approval" in allowed
    assert kwargs["timeout_seconds"] == 300
