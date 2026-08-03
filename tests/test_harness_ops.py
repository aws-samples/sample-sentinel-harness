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

    # Added for INV-OPS-7: the gate covers all THREE promotion actions, so the fake has
    # to be able to serve them. Their absence made two of the new tests fail with
    # `upstream_error` — a missing fake method, not a gate defect. Recorded because a
    # fake that cannot serve the path under test produces a failure that LOOKS like a
    # finding.
    def update_harness_endpoint(self, **kw):
        self.calls.append(kw)
        return {
            "endpointName": kw.get("endpointName"),
            "status": "UPDATING",
            "targetVersion": kw.get("targetVersion"),
        }

    def list_harness_endpoints(self, **kw):
        self.calls.append(kw)
        return {"harnessEndpoints": []}


@pytest.fixture
def gate_witnessed(monkeypatch):
    """Declare that a driver ran the promotion HITL gate (INV-OPS-7).

    The three promotion actions refuse unless a driver says it gated them. Tests that
    pin the REQUEST SHAPE of a promotion need the witness; the gate itself is asserted
    separately in TestPromotionGate, so setting it here does not weaken anything."""
    monkeypatch.setenv("SENTINEL_PROMOTION_GATE_WITNESSED", "1")


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
    """CONTRACT CHANGE (round 20, INV-OPS-6): the payload, not the intent.

    This used to demonstrate "forwards rest" with `maxIterations: 7` — a raw API-level
    key, which is now refused. The INTENT (harness_id becomes the positional arg, the
    remaining params are forwarded verbatim) is unchanged and still asserted; only the
    example key moved to the documented snake_case form.

    `core.update_harness` takes `max_iterations` as a named parameter, so the camelCase
    spelling was never the supported way to set it — it was only the way to reach
    `args.update(kw)` and beat whatever this handler had validated.
    """
    r = ops.handler(
        {"action": "update",
         "params": {"harness_id": "h-abc", "system_prompt": "new", "max_iterations": 7}},
        None)
    assert r["ok"] is True and r["action"] == "update"
    assert r["harnessId"] == "h-abc"
    call = stub_core["update_harness"][0]
    # harness_id is the first positional arg; it is NOT left in kwargs.
    assert call["args"] == ("h-abc",)
    assert "harness_id" not in call["kwargs"]
    assert call["kwargs"] == {"system_prompt": "new", "max_iterations": 7}


@pytest.mark.parametrize("action,params", [
    ("create", {"name": "ok_name", "system_prompt": "p", "harnessName": "other"}),
    ("create", {"name": "ok_name", "system_prompt": "p", "allowedTools": ["*"]}),
    ("create", {"name": "ok_name", "system_prompt": "p",
                "executionRoleArn": "arn:aws:iam::000000000000:role/not_resolved"}),
    ("create", {"name": "ok_name", "system_prompt": "p", "systemPrompt": "override"}),
    ("update", {"harness_id": "h-abc", "maxIterations": 9999}),
    ("update", {"harness_id": "h-abc", "harnessId": "h-DIFFERENT"}),
    ("invoke", {"arn": "arn:approved", "text": "hi", "harnessArn": "arn:different"}),
    ("invoke", {"arn": "arn:approved", "text": "hi", "allowedTools": ["*"]}),
    ("invoke", {"arn": "arn:approved", "text": "hi", "messages": [{"role": "user"}]}),
    ("wait_ready", {"harness_id": "h-abc", "timeoutSeconds": 1}),
])
def test_a_raw_api_level_key_is_refused(stub_core, action, params):
    """INV-OPS-6: the control plane is deterministic by contract.

    `core.create_harness` ends with `args.update(kw)` and `core.invoke` with
    `kw.update(overrides)`, so ANY passthrough key wins over what this handler computed.
    Reproduced end to end before the fix: `harnessName` beat the validated `name`, and
    `harnessArn` retargeted an invoke to a harness the caller never named — with the
    handler returning `ok: True`.
    """
    r = ops.handler({"action": action, "params": params}, None)
    assert r["ok"] is False, f"{action} accepted a raw API key: {params}"
    assert r["error"] == "validation_error"
    assert "raw API-level key" in r["message"]
    # And nothing reached the control plane. Only the LIST-valued entries are call
    # logs — `stub_core["_control"]` is the fake client object itself and is always
    # truthy, so `any(stub_core.values())` would pass vacuously (it did, first try).
    calls = {op: log for op, log in stub_core.items()
             if isinstance(log, list) and log}
    assert not calls, f"a call was made despite the refusal: {calls}"


@pytest.mark.parametrize("action,params", [
    ("create", {"name": "ok_name", "system_prompt": "p", "max_iterations": 5}),
    ("create", {"name": "ok_name", "system_prompt": "p", "allowed_tools": ["siem_query"]}),
    ("update", {"harness_id": "h-abc", "max_iterations": 5}),
    ("invoke", {"arn": "arn:approved", "text": "hi", "actor_id": "analyst"}),
    ("wait_ready", {"harness_id": "h-abc"}),
])
def test_the_documented_snake_case_params_still_work(stub_core, action, params):
    """CONTROL. A denylist that also blocks the supported spelling would be routed
    around, and every legitimate caller is on the snake_case form."""
    r = ops.handler({"action": action, "params": params}, None)
    assert r["ok"] is True, f"{action} refused a legitimate param set {params}: {r}"


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


def test_create_endpoint_calls_control_directly(stub_core, gate_witnessed):
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


def test_create_endpoint_omits_unset_optionals(stub_core, gate_witnessed):
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


# --------------------------------------------------------------------------- #
# INV-OPS-7 — a promotion action requires a witnessed HITL gate                #
# --------------------------------------------------------------------------- #
class TestPromotionGate:
    """`docs/THREAT-MODEL.md` §1 claims: "Publish / contain / promote are
    inline_function HITL gates ...; the agent can only *request* them, never execute
    them."

    That held for the two DRIVER paths and not for a direct handler call:

      agent_loop.run_agent_loop        gates all 3 promotion actions
      autonomy.run_improvement_loop    gates via approve_fn, fail-closed when None
      harness_ops.handler(...) direct  NO gate  <- reproduced: promoted 'prod', ok:True

    The direct path is real: scenario_agent_factory_loop.py describes itself as calling
    "the harness_ops handler directly rather than over a Gateway MCP target". It happens
    to use only create/wait_ready/invoke/delete, so nothing was exploited — but nothing
    prevented promote either, which made the claim a convention, not a mechanism. The
    same shape as INV-PROMOTE-3, where a docstring delegated a fail-closed posture to
    "the caller" and no caller implemented it.

    `sentinel_agent_ops` is why it matters: allowedTools is exactly
    `@gateway/harness_ops` with NO gate, while `sentinel_self_improving` holds the same
    tool WITH `request_promotion_approval`.
    """

    _PROMOTION_ACTIONS = ("create_endpoint", "update_endpoint", "promote_endpoint")

    @pytest.mark.parametrize("action", _PROMOTION_ACTIONS)
    def test_promotion_is_refused_without_a_witnessed_gate(self, stub_core, action, monkeypatch):
        monkeypatch.delenv("SENTINEL_PROMOTION_GATE_WITNESSED", raising=False)
        r = ops.handler(
            {"action": action,
             "params": {"harness_id": "h-abc", "endpoint_name": "prod"}},
            None)
        assert r["ok"] is False, f"{action} promoted with no gate: {r}"
        assert r["error"] == "validation_error"
        assert "human-approval gate" in r["message"]
        # and NOTHING reached the control plane
        calls = {op: log for op, log in stub_core.items()
                 if isinstance(log, list) and log}
        assert not calls, f"a promotion call was made despite the refusal: {calls}"

    @pytest.mark.parametrize("action", _PROMOTION_ACTIONS)
    def test_promotion_proceeds_when_a_driver_witnessed_the_gate(
            self, stub_core, action, gate_witnessed):
        """CONTROL: the gate must not break the legitimate driver path, or drivers get
        patched around it."""
        r = ops.handler(
            {"action": action,
             "params": {"harness_id": "h-abc", "endpoint_name": "prod"}},
            None)
        assert r["ok"] is True, f"{action} refused a witnessed promotion: {r}"

    @pytest.mark.parametrize("falsey", ["", "0", "false", "no", "off", "maybe"])
    def test_a_non_affirmative_witness_is_refusal(self, stub_core, falsey, monkeypatch):
        """Fail-closed on the VALUE too: only an affirmative token counts. `bool("false")`
        is True in Python, and this repo has four recorded recurrences of that trap
        (INV-COERCE), so the check is token-based, not truthiness-based."""
        monkeypatch.setenv("SENTINEL_PROMOTION_GATE_WITNESSED", falsey)
        r = ops.handler(
            {"action": "promote_endpoint",
             "params": {"harness_id": "h-abc", "endpoint_name": "prod"}},
            None)
        assert r["ok"] is False, f"witness={falsey!r} was accepted as approval: {r}"

    @pytest.mark.parametrize("action", ["create", "update", "invoke", "wait_ready",
                                        "list", "delete", "list_endpoints"])
    def test_non_promotion_actions_are_unaffected(self, stub_core, action, monkeypatch):
        """CONTROL: the gate covers promotion ONLY. A guard that also blocked
        create/invoke would make the tool unusable and get removed."""
        monkeypatch.delenv("SENTINEL_PROMOTION_GATE_WITNESSED", raising=False)
        params = {
            "create": {"name": "ok_name", "system_prompt": "p"},
            "update": {"harness_id": "h-abc", "system_prompt": "p"},
            "invoke": {"arn": "arn:h", "text": "hi"},
            "wait_ready": {"harness_id": "h-abc"},
            "list": {},
            "delete": {"harness_id": "h-abc"},
            "list_endpoints": {"harness_id": "h-abc"},
        }[action]
        r = ops.handler({"action": action, "params": params}, None)
        assert r["ok"] is True, f"the promotion gate blocked {action}: {r}"

    def test_the_action_list_matches_the_driver(self):
        """The two layers must agree on WHICH actions are promotions. If the driver
        gates an action this tool does not (or vice versa), one layer has a hole — the
        exact drift that produced this finding."""
        from sentinel_harness.agent_loop import default_is_promotion
        for action in self._PROMOTION_ACTIONS:
            assert default_is_promotion(
                "harness_ops", {"action": action, "params": {"harness_id": "h"}}
            ), f"the driver does not classify {action!r} as a promotion"
        assert set(self._PROMOTION_ACTIONS) == set(ops._PROMOTION_ACTIONS), (
            "the tool's _PROMOTION_ACTIONS drifted from the list asserted here"
        )
