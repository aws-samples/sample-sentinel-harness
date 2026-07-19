"""Tests for the agent-authored orchestration driver (agent_loop.py).

These tests exercise the driver's guard logic — witness-gated promotion,
allowlist, HITL gate, hard cap, handler errors — with SCRIPTED fake agents
(canned invoke/resume sequences). No model, no AWS, fully deterministic.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel_harness.agent_loop import (
    AgentLoopResult,
    run_agent_loop,
    result_to_dict,
    default_is_promotion,
)


def _make_tool_use(name, input_dict=None, tool_use_id="tu-001"):
    return {"toolUseId": tool_use_id, "name": name, "input": input_dict or {}}


def _passing_eval_result():
    return {"score": 0.85, "dimension_scores": {"correctness": 0.85, "safety": 1.0}, "feedback": {}}


def _failing_eval_result():
    return {"score": 0.3, "dimension_scores": {"correctness": 0.3, "safety": 1.0}, "feedback": {}}


def _safety_fail_result():
    return {"score": 0.9, "dimension_scores": {"correctness": 0.9, "safety": 0.2}, "feedback": {}}


class TestDefaultIsPromotion:
    def test_harness_ops_create_endpoint_is_promotion(self):
        assert default_is_promotion("harness_ops", {"action": "create_endpoint"})

    def test_harness_ops_update_is_not_promotion(self):
        assert not default_is_promotion("harness_ops", {"action": "update"})

    def test_other_tool_is_not_promotion(self):
        assert not default_is_promotion("run_evaluation", {"action": "create_endpoint"})


class TestHappyPath:
    """Agent scores → passes → gets human approval → promotes."""

    def test_full_happy_path(self):
        calls = [
            # 1) Agent calls run_evaluation
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {"dataset": "cve"}, "tu-1")]},
            # 2) Agent calls request_promotion_approval
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {"rationale": "scored 0.85"}, "tu-2")]},
            # 3) Agent calls harness_ops create_endpoint
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint", "endpoint_name": "prod"}, "tu-3")]},
            # 4) Agent finishes
            {"stop_reason": "end_turn", "text": "Promoted successfully.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        def eval_handler(inp):
            return _passing_eval_result()

        def harness_ops_handler(inp):
            return {"ok": True, "endpoint": "ep-123"}

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": eval_handler, "harness_ops": harness_ops_handler},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is True
        assert result.stopped_by == "end_turn"
        assert result.witnessed_pass is True
        assert result.witnessed_approval is True
        assert result.refused_promotions == 0
        assert result.tool_calls_used == 3


class TestPromotionRefused:
    """Agent tries to promote without first passing eval or getting approval."""

    def test_promote_without_eval(self):
        """Agent jumps to promotion without calling run_evaluation first."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint"}, "tu-1")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert "no witnessed passing evaluation" in result.trace[0].detail

    def test_promote_without_human_approval(self):
        """Agent passes eval but skips the HITL gate."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint"}, "tu-2")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert "no witnessed human approval" in result.trace[1].detail

    def test_promote_after_failing_eval(self):
        """Agent calls eval (fails), then tries to promote."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint"}, "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _failing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert result.witnessed_pass is False


class TestSafetyVeto:
    """A safety-failing eval never gets witnessed_pass."""

    def test_safety_fail_blocks_promotion(self):
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint"}, "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _safety_fail_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.witnessed_pass is False


class TestHitlGate:
    """HITL gate behavior."""

    def test_human_reject_blocks_promotion(self):
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", {"action": "create_endpoint"}, "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: False,   # REJECTED
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.witnessed_approval is False
        assert result.refused_promotions == 1

    def test_no_approve_fn_means_refused(self):
        """A missing approve_fn is fail-closed: always REFUSED."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result()},
            approve_fn=None,
            threshold=0.7,
        )
        assert result.witnessed_approval is False


class TestAllowlistAndCap:
    """Unknown tools and hard cap enforcement."""

    def test_unknown_tool_gets_error_result(self):
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("not_real", {}, "tu-1")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result()},
            threshold=0.7,
        )
        assert result.trace[0].outcome == "unknown_tool"
        assert result.promoted is False

    def test_hard_cap_stops_spinning_agent(self):
        """A spinning agent hits the max_tool_calls cap."""
        spin_result = {"stop_reason": "tool_use",
                       "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-spin")]}

        def invoke_fn():
            return spin_result

        def resume_fn(answers):
            return spin_result

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _failing_eval_result()},
            threshold=0.7,
            max_tool_calls=5,
        )
        assert result.stopped_by == "cap"
        assert result.tool_calls_used == 5
        assert result.promoted is False


class TestHandlerErrors:
    """A handler that raises doesn't kill the session."""

    def test_handler_error_recorded(self):
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        call_idx = [0]

        def invoke_fn():
            return calls[0]

        def resume_fn(answers):
            call_idx[0] += 1
            return calls[call_idx[0]]

        def broken_handler(inp):
            raise RuntimeError("simulated crash")

        result = run_agent_loop(
            invoke_fn=invoke_fn,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": broken_handler},
            threshold=0.7,
        )
        assert result.trace[0].outcome == "handler_error"
        assert "simulated crash" in result.trace[0].detail


class TestSessionErrors:
    """Invoke/resume failures are auditable, not crashes."""

    def test_invoke_error(self):
        result = run_agent_loop(
            invoke_fn=lambda: (_ for _ in ()).throw(ConnectionError("network down")),
            resume_fn=lambda a: {},
            dispatch={},
            threshold=0.7,
        )
        assert result.stopped_by == "session_error"
        assert result.promoted is False
        assert result.tool_calls_used == 0


class TestResultSerialization:
    """result_to_dict roundtrips cleanly."""

    def test_serializable(self):
        result = AgentLoopResult(
            promoted=False, stopped_by="end_turn", tool_calls_used=0,
            trace=[], final_text="", witnessed_pass=False,
            witnessed_approval=False, refused_promotions=0)
        d = result_to_dict(result)
        assert d["promoted"] is False
        assert isinstance(d["trace"], list)


class TestValidation:
    def test_max_tool_calls_zero_raises(self):
        with pytest.raises(ValueError, match="max_tool_calls"):
            run_agent_loop(lambda: {}, lambda a: {}, {}, threshold=0.7, max_tool_calls=0)

    def test_threshold_out_of_range_raises(self):
        with pytest.raises(ValueError, match="threshold"):
            run_agent_loop(lambda: {}, lambda a: {}, {}, threshold=1.5)
