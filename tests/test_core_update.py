"""
Offline tests for sentinel_harness.core.update_harness
=======================================================
UpdateHarness is a THIN, full-replacement wrapper (the caller ships the complete
desired config; unspecified fields are not merged server-side). These tests prove
the arg-assembly contract with ZERO AWS calls: ``core._control`` is monkeypatched
to a fake that captures the kwargs passed to ``update_harness``.

Coverage:
- harnessId is always set from the positional arg,
- systemPrompt is normalized to the GA list shape ``[{"text": ...}]``,
- None optional fields are omitted (not sent as None),
- provided optional fields (incl. falsy-but-not-None like max_iterations=0) are sent,
- executionRoleArn falls back to core._role() when not given, and honors an explicit arg,
- extra kw (e.g. tags) passes straight through,
- the ``["harness"]`` unwrap + raw-response fallback both work.

No real account/role/secret: the 000000000000 placeholder is set below.
"""
from __future__ import annotations

import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402


class _CapturingControl:
    """Captures update_harness kwargs; returns a canned response envelope.

    Any other attribute access blows up so an accidental real code path is loud."""

    def __init__(self, response=None):
        self.update_calls: list[dict] = []
        self._response = response if response is not None else {
            "harness": {"harnessId": "hid-x", "status": "UPDATING"}
        }

    def update_harness(self, **kwargs):
        self.update_calls.append(kwargs)
        return self._response

    def __getattr__(self, item):  # pragma: no cover - defensive
        raise AssertionError(f"update_harness test must not touch _control.{item}")


@pytest.fixture()
def fake_control(monkeypatch):
    ctrl = _CapturingControl()
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    return ctrl


def test_harness_id_and_role_fallback(fake_control):
    """harnessId set from positional; executionRoleArn falls back to _role()."""
    sh.update_harness("hid-42")
    call = fake_control.update_calls[0]
    assert call["harnessId"] == "hid-42"
    assert call["executionRoleArn"] == os.environ["SENTINEL_EXECUTION_ROLE_ARN"]


def test_system_prompt_wrapped_to_list_shape(fake_control):
    sh.update_harness("hid-42", system_prompt="You are a triage agent.")
    call = fake_control.update_calls[0]
    assert call["systemPrompt"] == [{"text": "You are a triage agent."}]


def test_none_optional_fields_are_omitted(fake_control):
    """A bare update sends only harnessId + role — no None-valued optionals leak."""
    sh.update_harness("hid-42")
    call = fake_control.update_calls[0]
    assert set(call) == {"harnessId", "executionRoleArn"}
    for k in ("systemPrompt", "model", "tools", "skills", "memory",
              "allowedTools", "maxIterations", "maxTokens", "timeoutSeconds"):
        assert k not in call


def test_provided_fields_are_sent_including_falsy(fake_control):
    """Falsy-but-not-None values (max_iterations=0) must still be sent."""
    model = {"bedrockModelConfig": {"modelId": "global.anthropic.claude-haiku-4-5"}}
    tools = [{"type": "agentcore_code_interpreter", "name": "code_interpreter"}]
    sh.update_harness(
        "hid-42", model=model, tools=tools, skills=["s1"],
        memory={"managedMemoryConfiguration": {}}, allowed_tools=["code_interpreter"],
        max_iterations=0, max_tokens=4096, timeout_seconds=300,
    )
    call = fake_control.update_calls[0]
    assert call["model"] == model
    assert call["tools"] == tools
    assert call["skills"] == ["s1"]
    assert call["memory"] == {"managedMemoryConfiguration": {}}
    assert call["allowedTools"] == ["code_interpreter"]
    assert call["maxIterations"] == 0
    assert call["maxTokens"] == 4096
    assert call["timeoutSeconds"] == 300


def test_explicit_execution_role_overrides_fallback(fake_control):
    role = "arn:aws:iam::000000000000:role/other-role"
    sh.update_harness("hid-42", execution_role_arn=role)
    assert fake_control.update_calls[0]["executionRoleArn"] == role


def test_kw_passthrough(fake_control):
    """Extra kw (e.g. tags, authorizerConfiguration) passes straight through."""
    sh.update_harness("hid-42", tags={"team": "secops"})
    assert fake_control.update_calls[0]["tags"] == {"team": "secops"}


def test_returns_unwrapped_harness(fake_control):
    out = sh.update_harness("hid-42")
    assert out == {"harnessId": "hid-x", "status": "UPDATING"}


def test_returns_raw_response_when_no_harness_key(monkeypatch):
    ctrl = _CapturingControl(response={"ResponseMetadata": {"HTTPStatusCode": 200}})
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    out = sh.update_harness("hid-42")
    assert out == {"ResponseMetadata": {"HTTPStatusCode": 200}}


def test_role_required_when_unset(monkeypatch):
    """No env role and no explicit arg -> _role() raises loudly (never silently None)."""
    ctrl = _CapturingControl()
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", None)
    with pytest.raises(RuntimeError, match="SENTINEL_EXECUTION_ROLE_ARN"):
        sh.update_harness("hid-42")
    assert ctrl.update_calls == []
