"""
Offline loader test for the ops-automation multi-account supervisor harness
===========================================================================
Load ``harnesses/ops-automation`` through
``sentinel_harness.loader.load_harness_config`` and assert the resulting kwargs
have the shapes ``core.create_harness(**kwargs)`` expects:

- a valid ``harnessName`` (letter + up to 39 [a-zA-Z0-9_], no hyphens);
- a non-empty ``systemPrompt`` (resolved from the file);
- ``allowedTools`` an EXPLICIT list (never ``'*'`` and never containing one),
  carrying the read-only ops query, the ticketing write, and the HITL change
  gate;
- SEMANTIC + SUMMARIZATION managed memory.

HARD RULE: ZERO AWS calls. ``load_harness_config`` is pure/offline — we only
inspect the kwargs dict it returns. Required env (``SENTINEL_GATEWAY_ARN`` etc.)
is set to ``000000000000`` placeholders — no real account/role/secret. Mirrors
tests/test_m2_harnesses.py's hermetic-import + gateway_env fixture pattern.

The ops-automation harness uses ``request_containment_approval``, which is
already built into ``loader._INLINE_GATES`` — so this loads today with NO shared
loader change required.
"""
from __future__ import annotations

import os
import re

import pytest

# --- Make the import hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import loader  # noqa: E402

NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")
GATEWAY_TOOL_RE = re.compile(r"^@[a-zA-Z0-9_]+/[a-zA-Z0-9_]+$")

_HARNESSES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harnesses"
)
_NAME = "ops-automation"


def _yaml_path(name: str) -> str:
    return os.path.join(_HARNESSES_DIR, name, "harness.yaml")


@pytest.fixture()
def gateway_env(monkeypatch):
    """A tmp env with a 000000000000 placeholder Gateway ARN (12-factor)."""
    monkeypatch.setenv(
        "SENTINEL_GATEWAY_ARN",
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test-gw",
    )
    return os.environ["SENTINEL_GATEWAY_ARN"]


def test_ops_harness_loads_wellformed(gateway_env):
    """The ops-automation harness loads into well-formed, loader-consumable kwargs."""
    kwargs = loader.load_harness_config(_yaml_path(_NAME))

    # harnessName maps to `name` and satisfies the no-hyphen naming rule.
    assert "name" in kwargs
    assert kwargs["name"] == "sentinel_ops_automation"
    assert NAME_RE.match(kwargs["name"]), f"{kwargs['name']!r} violates the naming rule"

    # systemPrompt resolved from a path to a non-empty string.
    sp = kwargs["system_prompt"]
    assert isinstance(sp, str) and sp.strip(), "systemPrompt must be non-empty text"
    assert "multi-account" in sp.lower()

    # model id present under the bedrockModelConfig shape.
    assert "bedrockModelConfig" in kwargs["model"]
    assert kwargs["model"]["bedrockModelConfig"]["modelId"], "model id must be present"

    # memory is a managedMemoryConfiguration with SEM + SUM.
    strategies = kwargs["memory"]["managedMemoryConfiguration"]["strategies"]
    assert "SEMANTIC" in strategies and "SUMMARIZATION" in strategies

    # bounded limits pass through.
    assert isinstance(kwargs["max_iterations"], int)
    assert isinstance(kwargs["timeout_seconds"], int)


def test_ops_harness_allowed_tools_is_explicit_list_never_star(gateway_env):
    """allowedTools is an EXPLICIT list — never '*', never containing one — and
    each entry is either valid @scope/tool grammar or a plain tool/gate name."""
    kwargs = loader.load_harness_config(_yaml_path(_NAME))
    allowed = kwargs["allowed_tools"]

    assert isinstance(allowed, list), "allowedTools must be a list"
    assert allowed != ["*"], "allowedTools must never be ['*']"
    assert "*" not in allowed, "allowedTools must not contain a bare '*'"
    assert allowed, "allowedTools must be a non-empty explicit list"

    for entry in allowed:
        assert isinstance(entry, str) and entry and entry != "*", f"bad entry {entry!r}"
        if entry.startswith("@"):
            assert GATEWAY_TOOL_RE.match(entry), f"{entry!r} is not valid @scope/tool grammar"
        else:
            assert NAME_RE.match(entry), f"plain tool name {entry!r} is malformed"


def test_ops_harness_allowlist_carries_ops_query_ticket_and_gate(gateway_env):
    """The explicit allowlist wires exactly the multi-account ops query (read),
    the ticketing write, and the HITL change gate."""
    kwargs = loader.load_harness_config(_yaml_path(_NAME))
    allowed = kwargs["allowed_tools"]
    assert "@gateway/ops_query" in allowed
    assert "@gateway/create_ticket" in allowed
    assert "request_containment_approval" in allowed
    # No remediation/change tool is exposed directly — change is request-only.
    assert not any("contain_action" in a or a == "remediate" for a in allowed)
