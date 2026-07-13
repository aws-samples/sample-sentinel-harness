"""Offline unit tests for tools/run_evaluation/handler.py
========================================================
``run_evaluation`` is the deterministic M2 scoring gate: it validates a
structured ``{action, params}`` request and either (a) invokes a self-built
LLM-judge harness via ``sentinel_harness.core.invoke`` and parses a structured
verdict from the reply (``score_answer``), or (b) parses a judge reply offline
with no model call (``parse_verdict``). The verdict parser is a PURE function —
so these tests pin exactly that: parsing is tolerant of fenced / bare / prose /
no-json replies, ``score_answer`` routes through ``core.invoke`` and returns a
parsed verdict, and malformed requests become labeled ``validation_error``
results.

HARD RULE: ZERO network / ZERO AWS. ``core.invoke`` is monkeypatched to a
recording stub that returns a canned judge reply, so no boto client is ever
constructed or called. ``parse_verdict`` is pure and needs no patching.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_run_evaluation.py -q
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


ev = _load("run_evaluation")


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the judge-invoke retry backoff so tests exercising the retry path never
    sleep on real wall-clock (offline tests must be fast + deterministic)."""
    monkeypatch.setattr(ev, "_JUDGE_BACKOFF_SECONDS", 0)


@pytest.fixture
def stub_invoke(monkeypatch):
    """Replace core.invoke with a recorder that returns a canned judge reply.

    Returns a dict: ``calls`` records each (args, kwargs) so a test can assert the
    exact prompt/session forwarded; ``reply`` is mutable so a test can set the
    judge text before invoking. new_session is stubbed to a deterministic id."""
    state: dict = {"calls": [], "reply": '{"score": 0.8, "pass": true, '
                                         '"reasons": ["ok"], "suggestions": ["tighten"]}'}

    def fake_invoke(*args, **kw):
        state["calls"].append({"args": args, "kwargs": kw})
        return {"text": state["reply"], "stop_reason": "end_turn",
                "tools_used": [], "tool_use": None, "events": [], "metadata": {}}

    monkeypatch.setattr(core, "invoke", fake_invoke)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    return state


# --------------------------------------------------------------------------- #
# parse_verdict — pure parsing: fenced / bare / prose / no-json                #
# --------------------------------------------------------------------------- #
def test_parse_verdict_bare_json():
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": '{"score": 0.75, "pass": true, '
                            '"reasons": ["r1"], "suggestions": ["s1"]}'}},
        None)
    assert r["ok"] is True and r["action"] == "parse_verdict"
    assert r["score"] == 0.75
    assert r["passed"] is True
    assert r["reasons"] == ["r1"]
    assert r["suggestions"] == ["s1"]


def test_parse_verdict_fenced_json():
    text = ("Here is my verdict:\n```json\n"
            '{"score": 0.2, "pass": false, "reasons": ["missing X"], "suggestions": []}\n'
            "```\nThanks.")
    r = ev.handler({"action": "parse_verdict", "params": {"text": text}}, None)
    assert r["ok"] is True
    assert r["score"] == 0.2
    assert r["passed"] is False
    assert r["reasons"] == ["missing X"]


def test_parse_verdict_json_embedded_in_prose():
    text = ('The answer is decent. {"score": 0.6, "pass": true, "reasons": [], '
            '"suggestions": ["add detail"]} — end of review.')
    r = ev.handler({"action": "parse_verdict", "params": {"text": text}}, None)
    assert r["ok"] is True
    assert r["score"] == 0.6
    assert r["passed"] is True
    assert r["suggestions"] == ["add detail"]


def test_parse_verdict_prose_fallback_pass():
    # No JSON at all → prose scan: "pass" present, "fail" absent → passed, score 1.0
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": "This answer is acceptable, I pass it."}}, None)
    assert r["ok"] is True
    assert r["passed"] is True
    assert r["score"] == 1.0
    assert r["reasons"] == [] and r["suggestions"] == []


def test_parse_verdict_prose_fallback_fail():
    # "fail" present → not passed, score 0.0 (even though "pass" also appears)
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": "It does not pass; this is a fail."}}, None)
    assert r["ok"] is True
    assert r["passed"] is False
    assert r["score"] == 0.0


def test_parse_verdict_score_clamped_and_pass_coerced():
    # score above 1 clamps to 1.0; a truthy non-bool pass coerces to bool.
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": '{"score": 5, "pass": 1, "reasons": "one", '
                            '"suggestions": "two"}'}}, None)
    assert r["score"] == 1.0
    assert r["passed"] is True
    # a bare-string reasons/suggestions coerces to a one-item list.
    assert r["reasons"] == ["one"]
    assert r["suggestions"] == ["two"]


def test_parse_verdict_negative_score_clamped_to_zero():
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": '{"score": -3, "pass": false}'}}, None)
    assert r["score"] == 0.0
    assert r["passed"] is False


def test_parse_verdict_malformed_score_defaults_by_pass():
    # A valid pass flag but an unparseable score → score defaults to the pass value.
    r = ev.handler(
        {"action": "parse_verdict",
         "params": {"text": '{"score": "N/A", "pass": true}'}}, None)
    assert r["passed"] is True
    assert r["score"] == 1.0


# --------------------------------------------------------------------------- #
# score_answer — routes to core.invoke, returns a parsed verdict               #
# --------------------------------------------------------------------------- #
def test_score_answer_routes_to_invoke_and_parses(stub_invoke):
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "the sky is blue",
                    "criteria": "Must be factually correct."}},
        None)
    assert r["ok"] is True and r["action"] == "score_answer"
    assert r["score"] == 0.8
    assert r["passed"] is True
    assert r["reasons"] == ["ok"]
    assert r["suggestions"] == ["tighten"]
    assert "0.8" in r["raw"]  # the raw judge reply is surfaced
    # exactly one model call, to the judge arn, with an auto-minted judge session.
    assert len(stub_invoke["calls"]) == 1
    call = stub_invoke["calls"][0]
    assert call["args"][0] == "arn:judge"
    assert call["args"][1] == "judge-" + "0" * 33
    prompt = call["args"][2]
    assert "the sky is blue" in prompt         # agent answer spliced in
    assert "Must be factually correct." in prompt  # criteria spliced in


def test_score_answer_criteria_list_becomes_numbered_block(stub_invoke):
    ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "ans",
                    "criteria": ["is complete", "is concise"]}},
        None)
    prompt = stub_invoke["calls"][0]["args"][2]
    assert "1. is complete" in prompt
    assert "2. is concise" in prompt


def test_score_answer_includes_expected_when_given(stub_invoke):
    ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "ans",
                    "criteria": "c", "expected": "the gold answer"}},
        None)
    prompt = stub_invoke["calls"][0]["args"][2]
    assert "the gold answer" in prompt


def test_score_answer_forwards_overrides_and_uses_given_session(stub_invoke):
    ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "ans", "criteria": "c",
                    "session_id": "s" * 40, "actor_id": "analyst1"}},
        None)
    call = stub_invoke["calls"][0]
    assert call["args"][1] == "s" * 40          # caller session honored, not minted
    assert call["kwargs"] == {"actor_id": "analyst1"}  # override forwarded
    # consumed keys must NOT leak into invoke kwargs.
    for leaked in ("judge_arn", "agent_answer", "criteria", "expected", "session_id"):
        assert leaked not in call["kwargs"]


def test_score_answer_prose_reply_falls_back(stub_invoke):
    stub_invoke["reply"] = "Solid answer overall — I pass it."
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "ans", "criteria": "c"}},
        None)
    assert r["ok"] is True
    assert r["passed"] is True
    assert r["score"] == 1.0


def test_score_answer_does_not_mutate_caller_params(stub_invoke):
    params = {"judge_arn": "arn:judge", "agent_answer": "ans", "criteria": "c"}
    ev.handler({"action": "score_answer", "params": params}, None)
    assert params == {"judge_arn": "arn:judge", "agent_answer": "ans", "criteria": "c"}


# --------------------------------------------------------------------------- #
# validation errors                                                            #
# --------------------------------------------------------------------------- #
def test_unknown_action_is_validation_error(stub_invoke):
    r = ev.handler({"action": "frobnicate", "params": {}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "unknown action" in r["message"]


def test_missing_action_is_validation_error():
    r = ev.handler({"params": {}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    r = ev.handler("not-a-dict", None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_dict_params_is_validation_error():
    r = ev.handler({"action": "parse_verdict", "params": "nope"}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


@pytest.mark.parametrize("params", [
    {},                                                    # nothing
    {"agent_answer": "a", "criteria": "c"},                # missing judge_arn
    {"judge_arn": "arn", "criteria": "c"},                 # missing agent_answer
    {"judge_arn": "arn", "agent_answer": "a"},             # missing criteria
    {"judge_arn": "arn", "agent_answer": "a", "criteria": []},   # empty list
    {"judge_arn": "arn", "agent_answer": "a", "criteria": 5},    # wrong type
])
def test_score_answer_bad_params_is_validation_error(stub_invoke, params):
    r = ev.handler({"action": "score_answer", "params": params}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    # a validation failure must never reach the model.
    assert stub_invoke["calls"] == []


def test_parse_verdict_missing_text_is_validation_error():
    r = ev.handler({"action": "parse_verdict", "params": {}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# error labeling: a model/boto failure is upstream_error (surfaced, not eaten)  #
# --------------------------------------------------------------------------- #
def test_invoke_failure_becomes_upstream_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ThrottlingException: slow down")
    monkeypatch.setattr(core, "invoke", boom)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c"}},
        None)
    assert r["ok"] is False and r["error"] == "upstream_error"
    assert "ThrottlingException" in r["message"]  # surfaced, not swallowed


def test_bad_invoke_override_is_validation_error(monkeypatch):
    # An unexpected core.invoke kwarg raises TypeError inside invoke → the handler
    # labels a caller-malformed request as validation_error, not upstream.
    def strict_invoke(arn, session, text, *, actor_id=None):
        return {"text": "{}"}
    monkeypatch.setattr(core, "invoke", strict_invoke)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c",
                    "bogus_override": 1}},
        None)
    assert r["ok"] is False and r["error"] == "validation_error"
