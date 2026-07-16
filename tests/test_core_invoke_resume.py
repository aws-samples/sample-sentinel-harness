"""
Offline tests for sentinel_harness.core.invoke_with_tool_result (HITL resume)
=============================================================================
``invoke_with_tool_result`` closes the human-in-the-loop loop: on the SAME
session it re-invokes the harness with a two-message turn — the assistant
``toolUse`` FOLLOWED BY the user ``toolResult`` carrying the matching
``toolUseId`` — so the paused inline_function gate resumes. These tests prove
that message-assembly contract with ZERO AWS calls: ``core._data`` is
monkeypatched to a stub whose ``invoke_harness`` CAPTURES the kwargs it receives
and returns an empty event stream (``{"stream": iter([])}``), which
``_consume_stream`` drains to an empty structured result.

Coverage:
- exactly two messages, ordered assistant-then-user,
- message[0] toolUse echoes the toolUseId/name/input from the pending call,
- message[1] toolResult carries the SAME toolUseId, forwards ``status``, and
  wraps the result in a text content block,
- a dict result is JSON-serialized (ensure_ascii=False) into that text block
  while a str result passes through verbatim,
- actorId is sent ONLY when actor_id is given.

No real account/role/secret: the 000000000000 placeholder is set below.
"""
from __future__ import annotations

import json
import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402


class _CapturingData:
    """Stub bedrock-agentcore data client that CAPTURES invoke kwargs.

    ``invoke_harness`` records every kwargs dict and returns an EMPTY event
    stream so ``_consume_stream`` drains to a benign empty result — the test
    asserts on what was SENT, not on any streamed content. Any other attribute
    access is loud so an accidental real code path cannot slip through."""

    def __init__(self):
        self.calls: list[dict] = []

    def invoke_harness(self, **kwargs):
        self.calls.append(kwargs)
        return {"stream": iter([])}

    def __getattr__(self, item):  # pragma: no cover - defensive
        raise AssertionError(f"resume test must not touch _data.{item}")


@pytest.fixture()
def fake_data(monkeypatch):
    data = _CapturingData()
    monkeypatch.setattr(sh, "_data", data)
    return data


HARNESS_ARN = "arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/h-123"
SESSION = "sentinel-00000000-0000-0000-0000-000000000000-deadbeef"
TOOL_USE = {
    "toolUseId": "tu-abc-123",
    "name": "analyst_approval_gate",
    "input": {"action": "contain_host", "host": "workstation-7"},
}


def _messages(call: dict) -> list:
    return call["messages"]


# --------------------------------------------------------------- structure
def test_resume_sends_exactly_two_messages_assistant_then_user(fake_data):
    """The resume turn is precisely [assistant toolUse, user toolResult]."""
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    msgs = _messages(fake_data.calls[0])
    assert len(msgs) == 2
    assert msgs[0]["role"] == "assistant"
    assert msgs[1]["role"] == "user"


def test_resume_targets_same_session_and_arn(fake_data):
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    call = fake_data.calls[0]
    assert call["harnessArn"] == HARNESS_ARN
    assert call["runtimeSessionId"] == SESSION


# --------------------------------------------------------------- message[0] toolUse echo
def test_assistant_tooluse_echoes_pending_call(fake_data):
    """message[0] re-emits the paused inline_function call verbatim."""
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    tu = _messages(fake_data.calls[0])[0]["content"][0]["toolUse"]
    assert tu["toolUseId"] == TOOL_USE["toolUseId"]
    assert tu["name"] == TOOL_USE["name"]
    assert tu["input"] == TOOL_USE["input"]


def test_tooluse_input_defaults_to_empty_dict_when_absent(fake_data):
    """A pending call with no ``input`` resumes with an empty-dict input."""
    sh.invoke_with_tool_result(
        HARNESS_ARN, SESSION, {"toolUseId": "tu-x", "name": "gate"}, "ok"
    )
    tu = _messages(fake_data.calls[0])[0]["content"][0]["toolUse"]
    assert tu["input"] == {}


# --------------------------------------------------------------- message[1] toolResult
def test_toolresult_carries_same_tooluseid_and_status(fake_data):
    """The user toolResult must reference the SAME toolUseId and forward status."""
    sh.invoke_with_tool_result(
        HARNESS_ARN, SESSION, TOOL_USE, "denied by analyst", status="error"
    )
    tr = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]
    assert tr["toolUseId"] == TOOL_USE["toolUseId"]
    assert tr["status"] == "error"


def test_status_defaults_to_success(fake_data):
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    tr = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]
    assert tr["status"] == "success"


# --------------------------------------------------------------- str result verbatim
def test_str_result_passes_verbatim_into_text_block(fake_data):
    """A str result is placed verbatim into the toolResult text block."""
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved: contain host")
    content = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]["content"]
    assert content == [{"text": "approved: contain host"}]


# --------------------------------------------------------------- dict result JSON-serialized
def test_dict_result_is_json_serialized_into_text_block(fake_data):
    """A dict result is JSON-serialized (ensure_ascii=False) into the text block."""
    result = {"decision": "approve", "analyst": "on-call", "reason": "confirmed benign"}
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, result)
    content = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]["content"]
    assert content == [{"text": json.dumps(result, ensure_ascii=False)}]
    # Round-trips back to the original dict — nothing lost in serialization.
    assert json.loads(content[0]["text"]) == result


def test_dict_result_uses_ensure_ascii_false(fake_data):
    """Non-ASCII in a dict result stays human-readable (ensure_ascii=False)."""
    result = {"note": "已批准 — 隔离主机"}
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, result)
    text = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]["content"][0]["text"]
    assert "已批准" in text
    assert "\\u" not in text  # not escaped


# --------------------------------------------------------------- actorId gating
def test_actor_id_sent_only_when_given(fake_data):
    """actorId reaches the API iff an actor_id is supplied."""
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    assert "actorId" not in fake_data.calls[0]

    sh.invoke_with_tool_result(
        HARNESS_ARN, SESSION, TOOL_USE, "approved", actor_id="analyst-42"
    )
    assert fake_data.calls[1]["actorId"] == "analyst-42"


# --------------------------------------------------------------- both results, one session
def test_both_str_and_dict_over_two_calls(fake_data):
    """Drive BOTH a str and a dict result and confirm each toolResult text block."""
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "verbatim string")
    dict_result = {"k": "v"}
    sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, dict_result)

    first = _messages(fake_data.calls[0])[1]["content"][0]["toolResult"]["content"]
    second = _messages(fake_data.calls[1])[1]["content"][0]["toolResult"]["content"]
    assert first == [{"text": "verbatim string"}]
    assert second == [{"text": json.dumps(dict_result, ensure_ascii=False)}]


def test_empty_stream_yields_benign_structured_result(fake_data):
    """The stub's empty stream drains to the documented empty structured shape."""
    out = sh.invoke_with_tool_result(HARNESS_ARN, SESSION, TOOL_USE, "approved")
    assert out["text"] == ""
    assert out["events"] == []
    assert out["stop_reason"] is None
    assert out["tools_used"] == []
    assert out["tool_use"] is None
    assert out["error"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# --------------------------------------------------------------------------- #
# regression (round-2 audit HIGH): parallel tool_use blocks must ALL be kept  #
# --------------------------------------------------------------------------- #
def _block(tuid, name, raw):
    return [
        {"contentBlockStart": {"start": {"toolUse": {"toolUseId": tuid, "name": name}}}},
        {"contentBlockDelta": {"delta": {"toolUse": {"input": raw}}}},
        {"contentBlockStop": {}},
    ]


def test_parallel_tool_use_blocks_all_captured():
    stream = (_block("tu1", "gateA", '{"a": 1}')
              + _block("tu2", "gateB", '{"b": 2}')
              + [{"messageStop": {"stopReason": "tool_use"}}])
    r = sh._consume_stream(iter(stream))
    assert r["tools_used"] == ["gateA", "gateB"]
    assert len(r["tool_uses"]) == 2
    assert [t["toolUseId"] for t in r["tool_uses"]] == ["tu1", "tu2"]
    assert r["tool_use"]["toolUseId"] == "tu1"  # back-compat: first
    assert [t["input"] for t in r["tool_uses"]] == [{"a": 1}, {"b": 2}]


def test_malformed_tool_input_preserves_raw_in_unparsed():
    stream = ([{"contentBlockStart": {"start": {"toolUse": {"toolUseId": "x", "name": "g"}}}},
               {"contentBlockDelta": {"delta": {"toolUse": {"input": '{"action": '}}}},  # truncated
               {"contentBlockStop": {}},
               {"messageStop": {"stopReason": "tool_use"}}])
    r = sh._consume_stream(iter(stream))
    assert r["tool_use"]["input"] == {"_unparsed": '{"action": '}  # raw preserved, not empty


def test_no_pending_tool_uses_when_not_paused():
    stream = _block("tu1", "gateA", "{}") + [{"messageStop": {"stopReason": "end_turn"}}]
    r = sh._consume_stream(iter(stream))
    assert r["tool_uses"] == [] and r["tool_use"] is None
