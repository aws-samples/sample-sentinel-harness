"""
Offline proof that the LIVE self-improve scenario wires into the C1 controller.

ZERO AWS, ZERO network. `scenario_self_improve_loop.build_live_loop_callables`
builds (score_fn, revise_fn, approve_fn) over the scenario's real sh.* ops; here
we replace `sh` + the judge with in-process fakes, drive them through the REAL
`sentinel_harness.autonomy.run_improvement_loop`, and assert the controller
reaches the same decisions the live scenario hardcodes:
  - weak agent scores below the bar → controller revises (real update+re-invoke) →
    re-scores above the bar → human approves → promotable;
  - human reject → not promoted;
  - a throttled/errored judge → safety-neutral 0 score → not promoted (honest).

This proves the runner→controller wiring works; the only thing gated on real
account quota is the actual AWS round-trip, not the mechanism.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import autonomy as A  # noqa: E402


def _load_scenario(monkeypatch, *, judge_scores, invoke_answers):
    """Load the self-improve scenario with `sh` and `run_evaluation` faked.

    ``judge_scores`` maps an answer string → the verdict dict `_score` should
    yield; ``invoke_answers`` is a list the fake sh.invoke pops from (weak first,
    then the revised answer)."""
    # Fake harness ops (sh) — records calls, returns canned shapes, ZERO AWS.
    calls = {"update": 0, "invoke": 0, "wait_ready": 0}

    class _FakeSh:
        MODEL_HAIKU = "haiku-test"

        @staticmethod
        def bedrock_model(m):
            return {"model": m}

        @staticmethod
        def new_session(prefix):
            return prefix + "x" * 33

        @staticmethod
        def update_harness(hid, **kw):
            calls["update"] += 1
            return {"harnessId": hid, "version": calls["update"] + 1}

        @staticmethod
        def wait_ready(hid, *a, **k):
            calls["wait_ready"] += 1

        @staticmethod
        def invoke(arn, session, task, **kw):
            calls["invoke"] += 1
            ans = invoke_answers[min(calls["invoke"] - 1, len(invoke_answers) - 1)]
            return {"text": ans}

    # Fake run_evaluation.handler — scores an answer per judge_scores.
    class _FakeRunEval:
        @staticmethod
        def handler(event, ctx):
            answer = event["params"]["agent_answer"]
            return judge_scores.get(answer, {"ok": True, "score": 0.0, "passed": False,
                                             "suggestions": ["be specific"]})

    # Load the module fresh with these fakes injected before run-time use.
    path = os.path.join(REPO_ROOT, "scenarios", "scenario_self_improve_loop.py")
    spec = importlib.util.spec_from_file_location("selfimprove_wiring_undertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "sh", _FakeSh)
    monkeypatch.setattr(mod, "run_evaluation", _FakeRunEval)
    return mod, calls


def test_wiring_weak_then_strong_promotes(monkeypatch):
    weak, strong = "vague answer", "STRONG grounded CVSS/KEV answer"
    mod, calls = _load_scenario(
        monkeypatch,
        judge_scores={
            weak: {"ok": True, "score": 0.3, "passed": False, "suggestions": ["cite KEV"]},
            strong: {"ok": True, "score": 0.95, "passed": True, "suggestions": []},
        },
        invoke_answers=[strong],  # the revise step's re-invoke returns the strong answer
    )
    score_fn, revise_fn, approve_fn = mod.build_live_loop_callables(
        "judge-arn", "agent-id", "agent-arn", strong_prompt="STRONG")

    result = A.run_improvement_loop(weak, score_fn, revise_fn, threshold=0.7,
                                    max_rounds=3, approve_fn=approve_fn)
    assert result.promoted is True
    assert result.rounds_used == 2          # weak scored, revised, strong scored+passed
    assert calls["update"] == 1             # a real full-replacement update happened
    assert calls["invoke"] == 1             # the revise re-invoke


def test_wiring_human_reject_withholds(monkeypatch):
    weak, strong = "vague", "STRONG"
    mod, _ = _load_scenario(
        monkeypatch,
        judge_scores={weak: {"ok": True, "score": 0.3, "passed": False},
                      strong: {"ok": True, "score": 0.95, "passed": True}},
        invoke_answers=[strong],
    )
    score_fn, revise_fn, _ = mod.build_live_loop_callables("j", "a", "arn", strong_prompt="S")
    result = A.run_improvement_loop(weak, score_fn, revise_fn, threshold=0.7,
                                    max_rounds=3, approve_fn=lambda a, s: False)
    assert result.promoted is False
    assert result.human_approved is False


def test_wiring_throttled_judge_does_not_promote(monkeypatch):
    """A judge invoke that errored/throttled (ok=False) scores 0 with a
    safety-neutral dim → the controller must NOT promote (honest non-pass)."""
    weak = "vague"
    mod, _ = _load_scenario(
        monkeypatch,
        judge_scores={weak: {"ok": False, "error": "upstream_error",
                             "message": "HTTP 403 throttled"}},
        invoke_answers=[weak],
    )
    score_fn, revise_fn, approve_fn = mod.build_live_loop_callables("j", "a", "arn")
    result = A.run_improvement_loop(weak, score_fn, revise_fn, threshold=0.7,
                                    max_rounds=1, approve_fn=approve_fn)
    assert result.promoted is False
    assert result.final_score == 0.0


def test_score_fn_projects_verdict_into_controller_shape(monkeypatch):
    mod, _ = _load_scenario(
        monkeypatch,
        judge_scores={"ans": {"ok": True, "score": 0.8, "passed": True,
                              "suggestions": ["tighten"]}},
        invoke_answers=["ans"],
    )
    score_fn, _, _ = mod.build_live_loop_callables("j", "a", "arn")
    s = score_fn("ans")
    assert s["score"] == 0.8
    assert "safety" in s["dimension_scores"] and "correctness" in s["dimension_scores"]
    assert s["feedback"]["judge_ok"] is True


def test_revise_fn_does_real_update_and_reinvoke(monkeypatch):
    mod, calls = _load_scenario(
        monkeypatch,
        judge_scores={"revised": {"ok": True, "score": 0.9, "passed": True}},
        invoke_answers=["revised"],
    )
    _, revise_fn, _ = mod.build_live_loop_callables("j", "aid", "aarn", strong_prompt="S")
    out = revise_fn("weak", {"score": 0.2})
    assert out == "revised"
    assert calls["update"] == 1 and calls["wait_ready"] == 1 and calls["invoke"] == 1


@pytest.mark.parametrize("approve", [True, False])
def test_approve_fn_default_returns_true(monkeypatch, approve):
    """The built approve_fn is the HITL seam; its default returns True (a real
    deployment substitutes the inline_function gate decision)."""
    mod, _ = _load_scenario(monkeypatch, judge_scores={}, invoke_answers=["x"])
    _, _, approve_fn = mod.build_live_loop_callables("j", "a", "arn")
    assert approve_fn("answer", {"score": 0.9}) is True
