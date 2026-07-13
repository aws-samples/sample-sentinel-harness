"""
Offline configuration-validation tests for sentinel-harness
===========================================================
These tests validate the *shape* of what the builder functions emit — the same
invariants the AgentCore control plane enforces server-side, but checked locally
so a bad harness config fails in CI instead of silently at deploy time.

HARD RULE: these tests make ZERO AWS calls. ``sentinel_harness.core`` constructs
boto3 clients at import time, but client construction is offline (no network, no
credentials needed). We set dummy env before import so nothing tries to resolve a
real region/profile, and we monkeypatch the control-plane client so that
``create_harness`` never leaves the process — we only inspect the request kwargs
it *would* have sent.

Invariants covered:
  * harness name regex  [a-zA-Z][a-zA-Z0-9_]{0,39}
  * systemPrompt normalized to the GA list shape [{"text": ...}]
  * runtimeSessionId >= 33 chars (new_session)
  * tool config shapes (code_interpreter / remote_mcp / gateway / inline)
  * model + memory builder shapes
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

from sentinel_harness import core as sh  # noqa: E402

# The name rule the control plane enforces (mirrored from create_harness' docstring).
NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def capture_create(monkeypatch):
    """Monkeypatch the control-plane client so create_harness never hits AWS.

    Returns a dict that, after a create_harness call, holds the exact kwargs that
    would have been sent to the service under key ``kwargs``.
    """
    captured: dict = {}

    class _FakeControl:
        def create_harness(self, **kwargs):
            captured["kwargs"] = kwargs
            # Minimal shape create_harness() indexes into ([\"harness\"]).
            return {"harness": {"harnessId": "hid-test", "arn": "arn:aws:test:harness/hid-test", **kwargs}}

    monkeypatch.setattr(sh, "_control", _FakeControl())
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    return captured


# --------------------------------------------------------------------------- #
# Harness name regex                                                          #
# --------------------------------------------------------------------------- #
VALID_NAMES = [
    "s",                                     # single letter (min)
    "sentinel_cve_triage",
    "Detection_Reviewer_2",
    "a" * 40,                                # 40 chars (max)
    "H",
    "spec_research_0",
]
INVALID_NAMES = [
    "",                                      # empty
    "1sentinel",                             # starts with digit
    "_leading_underscore",                   # starts with underscore
    "has-hyphen",                            # hyphen not allowed
    "has space",                             # space not allowed
    "has.dot",                               # dot not allowed
    "a" * 41,                                # 41 chars (too long)
    "unicode_名前",                           # non-ASCII
    "trailing!",                             # punctuation
]


@pytest.mark.parametrize("name", VALID_NAMES)
def test_name_regex_accepts_valid(name):
    assert NAME_RE.match(name), f"expected {name!r} to be a valid harness name"


@pytest.mark.parametrize("name", INVALID_NAMES)
def test_name_regex_rejects_invalid(name):
    assert not NAME_RE.match(name), f"expected {name!r} to be rejected"


def test_scenario_names_are_valid():
    """Every harness name the shipped scenarios use must satisfy the rule."""
    scenario_names = [
        "sentinel_cve_triage",
        "sentinel_spec_research",
        "sentinel_spec_detection",
        "sentinel_spec_triage",
        "sentinel_supervisor",
        "sentinel_detect_gen",
        "sentinel_detect_reviewer",
        "sentinel_detect_publisher",
    ]
    for n in scenario_names:
        assert NAME_RE.match(n), f"scenario harness name {n!r} violates the naming rule"


# --------------------------------------------------------------------------- #
# systemPrompt list-shape normalization                                       #
# --------------------------------------------------------------------------- #
def test_system_prompt_normalized_to_list_shape(capture_create):
    sh.create_harness("valid_name", "You are a SecOps analyst.")
    sp = capture_create["kwargs"]["systemPrompt"]
    assert isinstance(sp, list), "systemPrompt must be a list"
    assert sp == [{"text": "You are a SecOps analyst."}]
    assert isinstance(sp[0], dict) and set(sp[0].keys()) == {"text"}


def test_create_harness_sends_execution_role(capture_create):
    sh.create_harness("valid_name", "prompt")
    assert capture_create["kwargs"]["executionRoleArn"].startswith("arn:aws:iam::")
    assert capture_create["kwargs"]["harnessName"] == "valid_name"


def test_create_harness_forwards_optional_fields(capture_create):
    sh.create_harness(
        "valid_name",
        "prompt",
        model=sh.bedrock_model(sh.MODEL_HAIKU),
        tools=[sh.tool_code_interpreter()],
        memory=sh.managed_memory(strategies=["SEMANTIC"]),
        allowed_tools=["code_interpreter"],
        max_iterations=15,
        max_tokens=4096,
        timeout_seconds=300,
    )
    kw = capture_create["kwargs"]
    assert "bedrockModelConfig" in kw["model"]
    assert kw["tools"][0]["type"] == "agentcore_code_interpreter"
    assert kw["allowedTools"] == ["code_interpreter"]
    assert kw["maxIterations"] == 15
    assert kw["maxTokens"] == 4096
    assert kw["timeoutSeconds"] == 300
    assert "managedMemoryConfiguration" in kw["memory"]


def test_create_harness_omits_unset_optional_fields(capture_create):
    """Optional args left as None must NOT appear in the request (avoids sending
    empty/None values the service would reject)."""
    sh.create_harness("valid_name", "prompt")
    kw = capture_create["kwargs"]
    for absent in ("model", "tools", "skills", "memory", "allowedTools",
                   "maxIterations", "maxTokens", "timeoutSeconds"):
        assert absent not in kw, f"{absent} should be omitted when not provided"


def test_create_harness_zero_values_are_forwarded(capture_create):
    """max_iterations=0 / max_tokens=0 are meaningful and use `is not None`
    guards, so they must be forwarded (not dropped as falsy)."""
    sh.create_harness("valid_name", "prompt", max_iterations=0, max_tokens=0, timeout_seconds=0)
    kw = capture_create["kwargs"]
    assert kw["maxIterations"] == 0
    assert kw["maxTokens"] == 0
    assert kw["timeoutSeconds"] == 0


def test_create_harness_requires_execution_role(monkeypatch):
    """Without SENTINEL_EXECUTION_ROLE_ARN, create_harness must fail loudly
    (never silently create against an unknown role)."""
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", None)
    with pytest.raises(RuntimeError, match="SENTINEL_EXECUTION_ROLE_ARN"):
        sh.create_harness("valid_name", "prompt")


# --------------------------------------------------------------------------- #
# sessionId >= 33 chars                                                        #
# --------------------------------------------------------------------------- #
def test_new_session_min_length():
    for prefix in ("sentinel", "cve", "spec", "sup", "x"):
        sid = sh.new_session(prefix)
        assert len(sid) >= 33, f"session id {sid!r} for prefix {prefix!r} is too short ({len(sid)})"
        assert sid.startswith(prefix + "-")


def test_new_session_is_unique():
    ids = {sh.new_session("t") for _ in range(200)}
    assert len(ids) == 200, "session ids must be unique"


def test_new_session_default_prefix():
    sid = sh.new_session()
    assert sid.startswith("sentinel-")
    assert len(sid) >= 33


# --------------------------------------------------------------------------- #
# Tool config shapes                                                          #
# --------------------------------------------------------------------------- #
def test_tool_code_interpreter_shape():
    t = sh.tool_code_interpreter()
    assert t == {"type": "agentcore_code_interpreter", "name": "code_interpreter"}
    assert sh.tool_code_interpreter("py")["name"] == "py"


def test_tool_remote_mcp_shape_without_headers():
    t = sh.tool_remote_mcp("intel_mcp", "https://mcp.example.internal/sse")
    assert t["type"] == "remote_mcp"
    assert t["name"] == "intel_mcp"
    assert t["config"]["remoteMcp"] == {"url": "https://mcp.example.internal/sse"}
    assert "headers" not in t["config"]["remoteMcp"]


def test_tool_remote_mcp_shape_with_headers():
    t = sh.tool_remote_mcp(
        "intel_mcp",
        "https://mcp.example.internal/sse",
        headers={"Authorization": "${arn:aws:secretsmanager:...:token}"},
    )
    rm = t["config"]["remoteMcp"]
    assert rm["url"] == "https://mcp.example.internal/sse"
    assert rm["headers"]["Authorization"].startswith("${arn:")


def test_tool_gateway_shape():
    t = sh.tool_gateway("gw", "arn:aws:bedrock-agentcore:us-east-1:000:gateway/g")
    assert t["type"] == "agentcore_gateway"
    cfg = t["config"]["agentCoreGateway"]
    assert cfg["gatewayArn"].startswith("arn:aws:bedrock-agentcore:")
    assert "outboundAuth" not in cfg


def test_tool_gateway_with_outbound_auth():
    t = sh.tool_gateway("gw", "arn:aws:bedrock-agentcore:us-east-1:000:gateway/g",
                        outbound_auth={"type": "OAUTH"})
    assert t["config"]["agentCoreGateway"]["outboundAuth"] == {"type": "OAUTH"}


def test_tool_inline_shape():
    schema = {
        "type": "object",
        "properties": {"cve_id": {"type": "string"}, "severity": {"type": "string"}},
        "required": ["cve_id"],
    }
    t = sh.tool_inline("request_human_review", "Analyst review gate.", schema)
    assert t["type"] == "inline_function"
    assert t["name"] == "request_human_review"
    fn = t["config"]["inlineFunction"]
    assert fn["description"] == "Analyst review gate."
    assert fn["inputSchema"] == schema
    assert fn["inputSchema"]["type"] == "object"
    assert isinstance(fn["inputSchema"]["properties"], dict)
    assert isinstance(fn["inputSchema"]["required"], list)


@pytest.mark.parametrize("tool", [
    sh.tool_code_interpreter(),
    sh.tool_remote_mcp("m", "https://x/sse"),
    sh.tool_gateway("g", "arn:aws:bedrock-agentcore:us-east-1:000:gateway/g"),
    sh.tool_inline("f", "d", {"type": "object", "properties": {}}),
])
def test_every_tool_has_type_and_name(tool):
    assert "type" in tool and isinstance(tool["type"], str) and tool["type"]
    assert "name" in tool and isinstance(tool["name"], str) and tool["name"]


# --------------------------------------------------------------------------- #
# Model + memory builder shapes                                               #
# --------------------------------------------------------------------------- #
def test_bedrock_model_shape():
    m = sh.bedrock_model(sh.MODEL_SONNET)
    assert m == {"bedrockModelConfig": {"modelId": sh.MODEL_SONNET}}


def test_bedrock_model_passes_extra():
    m = sh.bedrock_model(sh.MODEL_OPUS, maxTokens=8192, temperature=0.2)
    cfg = m["bedrockModelConfig"]
    assert cfg["modelId"] == sh.MODEL_OPUS
    assert cfg["maxTokens"] == 8192
    assert cfg["temperature"] == 0.2


def test_model_constants_are_nonempty_strings():
    for m in (sh.MODEL_SONNET, sh.MODEL_HAIKU, sh.MODEL_OPUS):
        assert isinstance(m, str) and m, "model id constant must be a non-empty string"


def test_managed_memory_shape():
    mem = sh.managed_memory(strategies=["SEMANTIC", "SUMMARIZATION"], expiry_days=90)
    cfg = mem["managedMemoryConfiguration"]
    assert cfg["strategies"] == ["SEMANTIC", "SUMMARIZATION"]
    assert cfg["eventExpiryDuration"] == 90


def test_managed_memory_empty_shape():
    mem = sh.managed_memory()
    assert mem == {"managedMemoryConfiguration": {}}


def test_byo_memory_shape():
    rc = {"/facts/{actorId}/": {"topK": 5, "relevanceScore": 0.5}}
    mem = sh.byo_memory("arn:aws:bedrock-agentcore:us-east-1:000:memory/m", retrieval_config=rc)
    cfg = mem["agentCoreMemoryConfiguration"]
    assert cfg["arn"].startswith("arn:aws:bedrock-agentcore:")
    assert cfg["retrievalConfig"] == rc


def test_byo_memory_without_retrieval_config():
    mem = sh.byo_memory("arn:aws:bedrock-agentcore:us-east-1:000:memory/m")
    assert mem["agentCoreMemoryConfiguration"] == {
        "arn": "arn:aws:bedrock-agentcore:us-east-1:000:memory/m"
    }
