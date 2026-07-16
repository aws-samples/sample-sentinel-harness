"""
Offline loader tests for sentinel-harness
==========================================
Load each of the three shipped ``harnesses/<name>/harness.yaml`` files through
``sentinel_harness.loader.load_harness_config`` and assert the resulting kwargs
have the correct shapes for ``core.create_harness(**kwargs)``.

HARD RULE: ZERO AWS calls. ``load_harness_config`` is pure/offline; we only ever
inspect the kwargs dict it returns. ``create_from_config`` (which would reach the
control plane) is exercised only against a monkeypatched fake client so nothing
leaves the process. Required env (``SENTINEL_GATEWAY_ARN`` etc.) is set to
``000000000000`` placeholders in a tmp env — no real account/role/secret.
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
from sentinel_harness import loader  # noqa: E402

NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")
GATEWAY_TOOL_RE = re.compile(r"^@[a-zA-Z0-9_]+/[a-zA-Z0-9_]+$")

_HARNESSES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harnesses"
)
SHIPPED = ["research-supervisor", "alert-triage", "detection-eng"]


def _yaml_path(name: str) -> str:
    return os.path.join(_HARNESSES_DIR, name, "harness.yaml")


# --------------------------------------------------------------------------- #
# Env fixture — placeholder gateway ARN, no real resources.                   #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def gateway_env(monkeypatch):
    """A tmp env with a 000000000000 placeholder Gateway ARN (12-factor)."""
    monkeypatch.setenv(
        "SENTINEL_GATEWAY_ARN",
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test-gw",
    )
    return os.environ["SENTINEL_GATEWAY_ARN"]


@pytest.fixture()
def capture_create(monkeypatch):
    """Monkeypatch the control-plane client so create_from_config never hits AWS."""
    captured: dict = {}

    class _FakeControl:
        def create_harness(self, **kwargs):
            captured["kwargs"] = kwargs
            return {"harness": {"harnessId": "hid-test", "arn": "arn:aws:test:harness/hid-test", **kwargs}}

    monkeypatch.setattr(sh, "_control", _FakeControl())
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    return captured


# --------------------------------------------------------------------------- #
# Each shipped harness loads to well-formed kwargs.                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_harness_loads(gateway_env, name):
    kwargs = loader.load_harness_config(_yaml_path(name))

    # name maps from harnessName and satisfies the no-hyphen naming rule.
    assert "name" in kwargs
    assert NAME_RE.match(kwargs["name"]), f"{kwargs['name']!r} violates the harness naming rule"

    # systemPrompt resolved from a path to a non-empty string (core wraps it).
    sp = kwargs["system_prompt"]
    assert isinstance(sp, str) and sp.strip(), "systemPrompt must resolve to a non-empty string"

    # model passes through as a bedrockModelConfig shape.
    assert "bedrockModelConfig" in kwargs["model"]
    assert kwargs["model"]["bedrockModelConfig"]["modelId"]

    # tools list is well-formed: every tool has a non-empty string type + name.
    for t in kwargs["tools"]:
        assert isinstance(t, dict)
        assert isinstance(t.get("type"), str) and t["type"]
        assert isinstance(t.get("name"), str) and t["name"]

    # allowedTools entries are either plain names or @gateway/tool grammar; never '*'.
    for entry in kwargs["allowed_tools"]:
        assert isinstance(entry, str) and entry and entry != "*"
        if entry.startswith("@"):
            assert GATEWAY_TOOL_RE.match(entry), f"{entry!r} is not valid @scope/tool grammar"
        else:
            assert NAME_RE.match(entry), f"plain tool name {entry!r} is malformed"

    # memory is a managedMemoryConfiguration.
    assert "managedMemoryConfiguration" in kwargs["memory"]

    # limits pass through under the core kwarg names.
    assert isinstance(kwargs["max_iterations"], int)
    assert isinstance(kwargs["timeout_seconds"], int)


def test_gateway_arn_env_expanded(gateway_env):
    """${SENTINEL_GATEWAY_ARN} inside a tool config is expanded from os.environ."""
    kwargs = loader.load_harness_config(_yaml_path("research-supervisor"))
    gw = [t for t in kwargs["tools"] if t["type"] == "agentcore_gateway"][0]
    arn = gw["config"]["agentCoreGateway"]["gatewayArn"]
    assert arn == gateway_env
    assert "${" not in arn, "env ref must be fully expanded"
    assert "000000000000" in arn  # placeholder account, no real id


def test_missing_env_var_raises_named(monkeypatch):
    """A missing ${ENV_VAR} raises a clear error naming the variable."""
    monkeypatch.delenv("SENTINEL_GATEWAY_ARN", raising=False)
    with pytest.raises(KeyError, match="SENTINEL_GATEWAY_ARN"):
        loader.load_harness_config(_yaml_path("alert-triage"))


def test_token_vault_arn_left_untouched(gateway_env, tmp_path):
    """${arn:...} token-vault interpolation must NOT be expanded by the loader."""
    prompt = tmp_path / "sp.md"
    prompt.write_text("You are a test agent.\n")
    yaml_text = (
        "harnessName: test_vault_untouched\n"
        "systemPrompt: sp.md\n"
        "tools:\n"
        "  - type: remote_mcp\n"
        "    name: intel\n"
        "    config:\n"
        "      remoteMcp:\n"
        "        url: https://mcp.example.internal/sse\n"
        "        headers:\n"
        "          Authorization: ${arn:aws:secretsmanager:us-east-1:000000000000:secret:tok}\n"
    )
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(yaml_text)
    kwargs = loader.load_harness_config(str(cfg))
    hdr = kwargs["tools"][0]["config"]["remoteMcp"]["headers"]["Authorization"]
    assert hdr.startswith("${arn:"), "token-vault ARN ref must be left untouched"


# --------------------------------------------------------------------------- #
# Inline HITL gate injection.                                                 #
# --------------------------------------------------------------------------- #
def test_inline_gate_injected_from_allowed_tools(gateway_env):
    """alert-triage lists request_containment_approval in allowedTools but not in
    tools; the loader must inject the matching inline_function definition."""
    kwargs = loader.load_harness_config(_yaml_path("alert-triage"))
    inline = [t for t in kwargs["tools"] if t["type"] == "inline_function"]
    names = {t["name"] for t in inline}
    assert "request_containment_approval" in names
    fn = [t for t in inline if t["name"] == "request_containment_approval"][0]
    assert fn["config"]["inlineFunction"]["inputSchema"]["type"] == "object"


def test_detection_eng_publish_gate_injected(gateway_env):
    kwargs = loader.load_harness_config(_yaml_path("detection-eng"))
    names = {t["name"] for t in kwargs["tools"] if t["type"] == "inline_function"}
    assert "request_publish_approval" in names


def test_no_inline_gate_when_none_referenced(gateway_env):
    """research-supervisor references only @gateway/ tools — no inline gate injected."""
    kwargs = loader.load_harness_config(_yaml_path("research-supervisor"))
    assert not [t for t in kwargs["tools"] if t["type"] == "inline_function"]


# --------------------------------------------------------------------------- #
# create_from_config wires load -> create_harness (offline, faked client).    #
# --------------------------------------------------------------------------- #
def test_create_from_config_offline(gateway_env, capture_create):
    loader.create_from_config(_yaml_path("detection-eng"))
    kw = capture_create["kwargs"]
    assert kw["harnessName"] == "sentinel_detection_eng"
    # core normalized the resolved prompt string to the GA list shape.
    assert isinstance(kw["systemPrompt"], list) and kw["systemPrompt"][0].get("text")
    assert kw["executionRoleArn"].startswith("arn:aws:iam::")
    assert kw["maxIterations"] == 18
    assert kw["timeoutSeconds"] == 300
    assert kw["allowedTools"] and "*" not in kw["allowedTools"]


# --------------------------------------------------------------------------- #
# regression (round-2 audit): systemPrompt containment + allowedTools shape   #
# --------------------------------------------------------------------------- #
def test_systemprompt_absolute_path_rejected(gateway_env, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET")
    hdir = tmp_path / "h"
    hdir.mkdir()
    cfg = hdir / "harness.yaml"
    cfg.write_text(f"harnessName: t\nsystemPrompt: {secret}\n")
    with pytest.raises(ValueError, match="absolute"):
        loader.load_harness_config(str(cfg))


def test_systemprompt_parent_escape_rejected(gateway_env, tmp_path):
    (tmp_path / "secret.txt").write_text("TOPSECRET")
    hdir = tmp_path / "h"
    hdir.mkdir()
    cfg = hdir / "harness.yaml"
    cfg.write_text("harnessName: t\nsystemPrompt: ../secret.txt\n")
    with pytest.raises(ValueError, match="escapes"):
        loader.load_harness_config(str(cfg))


def test_scalar_allowedtools_rejected(gateway_env, tmp_path):
    hdir = tmp_path / "h"
    hdir.mkdir()
    (hdir / "sp.md").write_text("prompt")
    cfg = hdir / "harness.yaml"
    cfg.write_text("harnessName: t\nsystemPrompt: sp.md\n"
                   "allowedTools: request_containment_approval\n")  # scalar, not a list
    with pytest.raises(ValueError, match="must be a list"):
        loader.load_harness_config(str(cfg))


def test_wildcard_allowedtools_rejected(gateway_env, tmp_path):
    hdir = tmp_path / "h"
    hdir.mkdir()
    (hdir / "sp.md").write_text("prompt")
    cfg = hdir / "harness.yaml"
    cfg.write_text("harnessName: t\nsystemPrompt: sp.md\nallowedTools: ['*']\n")
    with pytest.raises(ValueError, match="forbidden"):
        loader.load_harness_config(str(cfg))
