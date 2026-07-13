"""
Offline unit tests for tools/harness_ops/handler.py
====================================================
``harness_ops`` is the deterministic harness-lifecycle MCP tool: it validates a
structured ``{action, params}`` request and delegates to ``sentinel_harness.core.*``
(or ``core._control.create_harness_endpoint`` for the one action core does not
wrap yet). It contains NO LLM and NO business logic — so these tests pin exactly
that: each action routes to the right ``core`` function with the right args, and
malformed requests become labeled ``validation_error`` results.

HARD RULE: ZERO network / ZERO AWS. Every ``core.*`` function the handler could
reach is monkeypatched to a recording stub, and ``core._control`` is replaced
with a fake object, so no boto client is ever constructed or called.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_harness_ops.py -q
"""
from __future__ import annotations

import importlib.util
import os

import pytest

from sentinel_harness import core

_TOOLS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
)


def _load(tool_name: str):
    """Load tools/<tool_name>/handler.py by path (tools/ is a scripts tree)."""
    path = os.path.join(_TOOLS_DIR, tool_name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{tool_name}_handler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ops = _load("harness_ops")


class _FakeControl:
    """Records create_harness_endpoint calls; the handler reaches this via
    core._control, the only action with no core wrapper yet."""

    def __init__(self):
        self.calls = []

    def create_harness_endpoint(self, **kw):
        self.calls.append(kw)
        return {
            "endpointName": kw["endpointName"],
            "status": "CREATING",
            "targetVersion": kw.get("targetVersion"),
        }


@pytest.fixture
def stub_core(monkeypatch):
    """Replace every core.* the handler can call with a recorder. Returns the
    dict of recorded calls so a test can assert on the exact args forwarded."""
    calls: dict = {}

    def rec(name, ret):
        def fn(*args, **kw):
            calls.setdefault(name, []).append({"args": args, "kwargs": kw})
            return ret
        return fn

    monkeypatch.setattr(
        core, "create_harness",
        rec("create_harness",
            {"harnessId": "h-abc", "arn": "arn:aws:...:harness/h-abc",
             "status": "CREATING"}))
    # update_harness is added to core in parallel; it may not exist at test time,
    # so we set it unconditionally (monkeypatch.setattr with raising=False).
    monkeypatch.setattr(
        core, "update_harness",
        rec("update_harness", {"harness": {"harnessId": "h-abc"}}),
        raising=False)
    monkeypatch.setattr(
        core, "invoke",
        rec("invoke",
            {"text": "hello", "stop_reason": "end_turn", "tools_used": ["t1"],
             "tool_use": None, "events": [], "metadata": {}}))
    monkeypatch.setattr(
        core, "wait_ready", rec("wait_ready", {"status": "READY"}))
    monkeypatch.setattr(
        core, "list_harnesses",
        rec("list_harnesses", [{"harnessName": "a"}, {"harnessName": "b"}]))
    monkeypatch.setattr(core, "delete_harness", rec("delete_harness", {}))
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "sess-" + "0" * 33)

    fake_control = _FakeControl()
    monkeypatch.setattr(core, "_control", fake_control)
    calls["_control"] = fake_control
    return calls


# --------------------------------------------------------------------------- #
# routing: each action hits the right core.* with the right args               #
# --------------------------------------------------------------------------- #
def test_create_routes_to_create_harness(stub_core):
    r = ops.handler(
        {"action": "create",
         "params": {"name": "triage_bot", "system_prompt": "You are triage."}},
        None)
    assert r["ok"] is True and r["action"] == "create"
    assert r["harnessId"] == "h-abc"
    assert r["arn"] == "arn:aws:...:harness/h-abc"
    assert r["status"] == "CREATING"
    call = stub_core["create_harness"][0]
    assert call["kwargs"]["name"] == "triage_bot"
    assert call["kwargs"]["system_prompt"] == "You are triage."


def test_update_pops_harness_id_and_forwards_rest(stub_core):
    r = ops.handler(
        {"action": "update",
         "params": {"harness_id": "h-abc", "system_prompt": "new", "maxIterations": 7}},
        None)
    assert r["ok"] is True and r["action"] == "update"
    assert r["harnessId"] == "h-abc"
    call = stub_core["update_harness"][0]
    # harness_id is the first positional arg; it is NOT left in kwargs.
    assert call["args"] == ("h-abc",)
    assert "harness_id" not in call["kwargs"]
    assert call["kwargs"] == {"system_prompt": "new", "maxIterations": 7}


def test_update_does_not_mutate_caller_params(stub_core):
    params = {"harness_id": "h-abc", "system_prompt": "new"}
    ops.handler({"action": "update", "params": params}, None)
    assert params == {"harness_id": "h-abc", "system_prompt": "new"}


def test_invoke_routes_with_positional_args(stub_core):
    r = ops.handler(
        {"action": "invoke",
         "params": {"arn": "arn:h", "session_id": "s" * 40, "text": "hi",
                    "actor_id": "analyst1"}},
        None)
    assert r["ok"] is True and r["action"] == "invoke"
    assert r["text"] == "hello"
    assert r["stop_reason"] == "end_turn"
    assert r["tools_used"] == ["t1"]
    assert r["tool_use"] is None
    call = stub_core["invoke"][0]
    assert call["args"] == ("arn:h", "s" * 40, "hi")
    assert call["kwargs"] == {"actor_id": "analyst1"}


def test_invoke_mints_session_when_absent(stub_core):
    r = ops.handler(
        {"action": "invoke", "params": {"arn": "arn:h", "text": "hi"}}, None)
    assert r["ok"] is True
    call = stub_core["invoke"][0]
    # session_id was auto-generated by core.new_session and passed positionally.
    assert call["args"][1] == "sess-" + "0" * 33
    assert r["session_id"] == "sess-" + "0" * 33


def test_wait_ready_routes(stub_core):
    r = ops.handler(
        {"action": "wait_ready", "params": {"harness_id": "h-abc"}}, None)
    assert r["ok"] is True and r["action"] == "wait_ready"
    assert r["status"] == "READY"
    assert stub_core["wait_ready"][0]["args"] == ("h-abc",)


def test_list_routes(stub_core):
    r = ops.handler({"action": "list", "params": {}}, None)
    assert r["ok"] is True and r["action"] == "list"
    assert r["harnesses"] == [{"harnessName": "a"}, {"harnessName": "b"}]
    assert "list_harnesses" in stub_core


def test_delete_routes(stub_core):
    r = ops.handler({"action": "delete", "params": {"harness_id": "h-xyz"}}, None)
    assert r["ok"] is True and r["action"] == "delete"
    assert r["deleted"] == "h-xyz"
    assert stub_core["delete_harness"][0]["args"] == ("h-xyz",)


def test_create_endpoint_calls_control_directly(stub_core):
    r = ops.handler(
        {"action": "create_endpoint",
         "params": {"harness_id": "h-abc", "endpoint_name": "prod",
                    "target_version": "3", "description": "promote"}},
        None)
    assert r["ok"] is True and r["action"] == "create_endpoint"
    assert r["endpointName"] == "prod"
    assert r["harnessId"] == "h-abc"
    kw = stub_core["_control"].calls[0]
    assert kw["harnessId"] == "h-abc"
    assert kw["endpointName"] == "prod"
    assert kw["targetVersion"] == "3"
    assert kw["description"] == "promote"


def test_create_endpoint_omits_unset_optionals(stub_core):
    ops.handler(
        {"action": "create_endpoint",
         "params": {"harness_id": "h-abc", "endpoint_name": "prod"}},
        None)
    kw = stub_core["_control"].calls[0]
    assert set(kw) == {"harnessId", "endpointName"}  # no None optionals leaked


# --------------------------------------------------------------------------- #
# validation errors                                                            #
# --------------------------------------------------------------------------- #
def test_unknown_action_is_validation_error(stub_core):
    r = ops.handler({"action": "frobnicate", "params": {}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "unknown action" in r["message"]


def test_missing_action_is_validation_error(stub_core):
    r = ops.handler({"params": {}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_dict_event_is_validation_error(stub_core):
    r = ops.handler("not-a-dict", None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_dict_params_is_validation_error(stub_core):
    r = ops.handler({"action": "list", "params": "nope"}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


@pytest.mark.parametrize("params", [
    {},                                  # no name / no prompt
    {"name": "triage_bot"},              # missing system_prompt
    {"system_prompt": "hi"},             # missing name
    {"name": "1bad", "system_prompt": "hi"},   # name breaks the regex
    {"name": "has-hyphen", "system_prompt": "hi"},
])
def test_create_bad_params_is_validation_error(stub_core, params):
    r = ops.handler({"action": "create", "params": params}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "create_harness" not in stub_core  # never reached the control plane


@pytest.mark.parametrize("action,params", [
    ("update", {}),                      # missing harness_id
    ("update", {"system_prompt": "x"}),  # still missing harness_id
    ("invoke", {"text": "hi"}),          # missing arn
    ("invoke", {"arn": "arn:h"}),        # missing text
    ("wait_ready", {}),                  # missing harness_id
    ("delete", {}),                      # missing harness_id
    ("create_endpoint", {"harness_id": "h"}),      # missing endpoint_name
    ("create_endpoint", {"endpoint_name": "p"}),   # missing harness_id
])
def test_missing_required_params_is_validation_error(stub_core, action, params):
    r = ops.handler({"action": action, "params": params}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# error labeling: control-plane failure is upstream_error (surfaced, not eaten) #
# --------------------------------------------------------------------------- #
def test_boto_failure_becomes_upstream_error(stub_core, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("AccessDeniedException: no")
    monkeypatch.setattr(core, "list_harnesses", boom)
    r = ops.handler({"action": "list", "params": {}}, None)
    assert r["ok"] is False and r["error"] == "upstream_error"
    assert "AccessDeniedException" in r["message"]  # message surfaced, not swallowed


def test_update_missing_wrapper_surfaces_as_error(stub_core, monkeypatch):
    """If core.update_harness is absent (parallel work not landed), the handler
    must not crash — it surfaces a labeled error rather than raising."""
    monkeypatch.delattr(core, "update_harness", raising=False)
    r = ops.handler(
        {"action": "update", "params": {"harness_id": "h-abc"}}, None)
    assert r["ok"] is False
    assert r["error"] in ("upstream_error", "validation_error")
