"""Tests for the agent-authored orchestration driver (agent_loop.py).

These tests exercise the driver's guard logic — witness-gated promotion with
SUBJECT BINDING (confused-deputy fix), allowlist, HITL gate, hard cap, handler
errors, the resume contract, and the optional telemetry seam — with SCRIPTED
fake agents (canned invoke/resume sequences). No model, no AWS, fully
deterministic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel_harness.agent_loop import (
    AgentLoopResult,
    run_agent_loop,
    result_to_dict,
    default_is_promotion,
    default_subject_of_eval,
    default_subject_of_promotion,
)
from sentinel_harness.tracing import Tracer

# The harness every happy-path fixture scores AND promotes — the subject-binding
# gate requires the two to agree.
SUBJECT = "harness_A"


def _make_tool_use(name, input_dict=None, tool_use_id="tu-001"):
    return {"toolUseId": tool_use_id, "name": name, "input": input_dict or {}}


def _promotion_input(harness_id=SUBJECT, action="create_endpoint"):
    """A harness_ops promotion input shaped like the REAL tool contract
    (arguments nested under ``params``, per tools/harness_ops/handler.py)."""
    return {"action": action, "params": {"harness_id": harness_id, "endpoint_name": "prod"}}


def _passing_eval_result(harness_id=SUBJECT):
    return {"score": 0.85, "dimension_scores": {"correctness": 0.85, "safety": 1.0},
            "feedback": {}, "harness_id": harness_id}


def _failing_eval_result(harness_id=SUBJECT):
    return {"score": 0.3, "dimension_scores": {"correctness": 0.3, "safety": 1.0},
            "feedback": {}, "harness_id": harness_id}


def _safety_fail_result(harness_id=SUBJECT):
    return {"score": 0.9, "dimension_scores": {"correctness": 0.9, "safety": 0.2},
            "feedback": {}, "harness_id": harness_id}


class ContractResume:
    """A resume_fn fake that VERIFIES the live core.invoke_with_tool_results
    contract on every round instead of ignoring ``answers`` (the false-green
    killer): every pending toolUseId from the PREVIOUS result must be answered
    exactly once, every answer payload must be valid JSON, and every
    refusal/cap/error answer must use the 3-tuple form with status="error"."""

    _ERROR_CODES = {"promotion_refused", "tool_call_cap", "unknown_tool", "handler_error"}

    def __init__(self, calls, raise_on_round=None):
        self.calls = list(calls)
        self.idx = 0
        self.rounds = 0
        self.raise_on_round = raise_on_round  # 1-based resume round that raises

    def invoke_fn(self):
        return self.calls[0]

    @staticmethod
    def _pending(result):
        return result.get("tool_uses") or (
            [result["tool_use"]] if result.get("tool_use") else [])

    def resume_fn(self, answers):
        self.rounds += 1
        prev = self.calls[self.idx]
        pending_ids = [tu["toolUseId"] for tu in self._pending(prev)]
        answered_ids = []
        for ans in answers:
            assert isinstance(ans, tuple) and len(ans) in (2, 3), \
                f"answer must be a (tool_use, json[, status]) tuple, got {ans!r}"
            if len(ans) == 3:
                tu, payload, status = ans
                assert status == "error", f"3-tuple status must be 'error', got {status!r}"
            else:
                tu, payload = ans
            parsed = json.loads(payload)  # every payload must be valid JSON
            if isinstance(parsed, dict) and parsed.get("error") in self._ERROR_CODES:
                assert len(ans) == 3 and ans[2] == "error", \
                    f"refusal/cap answer {parsed.get('error')!r} must be a 3-tuple with status='error'"
            answered_ids.append(tu["toolUseId"])
        assert sorted(answered_ids) == sorted(pending_ids), \
            f"every pending toolUseId must be answered exactly once: {answered_ids} vs {pending_ids}"
        if self.raise_on_round is not None and self.rounds == self.raise_on_round:
            raise ConnectionError(f"simulated session drop on resume round {self.rounds}")
        self.idx += 1
        return self.calls[self.idx]


class TestDefaultIsPromotion:
    def test_harness_ops_create_endpoint_is_promotion(self):
        assert default_is_promotion("harness_ops", {"action": "create_endpoint"})

    def test_harness_ops_update_is_not_promotion(self):
        assert not default_is_promotion("harness_ops", {"action": "update"})

    def test_other_tool_is_not_promotion(self):
        assert not default_is_promotion("run_evaluation", {"action": "create_endpoint"})


class TestDefaultSubjectPredicates:
    def test_eval_subject_reads_harness_id(self):
        assert default_subject_of_eval({"score": 1.0, "harness_id": "hX"}) == "hX"

    def test_eval_subject_missing_is_none(self):
        assert default_subject_of_eval({"score": 1.0}) is None

    def test_eval_subject_non_string_is_none(self):
        # Fail-closed: a subject we cannot read is ABSENT, not truthy garbage.
        assert default_subject_of_eval({"harness_id": 123}) is None
        assert default_subject_of_eval({"harness_id": "  "}) is None
        assert default_subject_of_eval("not-a-dict") is None

    def test_promotion_subject_prefers_nested_params(self):
        # The real harness_ops contract nests args under 'params'.
        tool_input = {"action": "create_endpoint",
                      "params": {"harness_id": "hP"}, "harness_id": "hFlat"}
        assert default_subject_of_promotion(tool_input) == "hP"

    def test_promotion_subject_falls_back_to_flat(self):
        assert default_subject_of_promotion({"harness_id": "hFlat"}) == "hFlat"

    def test_promotion_subject_missing_is_none(self):
        assert default_subject_of_promotion({"action": "create_endpoint", "params": {}}) is None


class TestHappyPath:
    """Agent scores → passes → gets human approval → promotes."""

    def test_full_happy_path(self):
        calls = [
            # 1) Agent calls run_evaluation
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {"dataset": "cve"}, "tu-1")]},
            # 2) Agent calls request_promotion_approval
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {"rationale": "scored 0.85"}, "tu-2")]},
            # 3) Agent calls harness_ops create_endpoint on the SAME harness the eval scored
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-3")]},
            # 4) Agent finishes
            {"stop_reason": "end_turn", "text": "Promoted successfully.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        def eval_handler(inp):
            return _passing_eval_result()

        def harness_ops_handler(inp):
            return {"ok": True, "endpoint": "ep-123"}

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": eval_handler, "harness_ops": harness_ops_handler},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is True
        assert result.stopped_by == "end_turn"
        assert result.witnessed_pass is True
        assert result.witnessed_approval is True
        assert result.witnessed_subject == SUBJECT
        assert result.refused_promotions == 0
        assert result.tool_calls_used == 3


class TestPromotionRefused:
    """Agent tries to promote without first passing eval or getting approval."""

    def test_promote_without_eval(self):
        """Agent jumps to promotion without calling run_evaluation first."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-1")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert "no witnessed passing evaluation" in result.trace[0].detail
        assert result.refusal_reasons and "no witnessed passing evaluation" in result.refusal_reasons[0]

    def test_promote_without_human_approval(self):
        """Agent passes eval but skips the HITL gate."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-2")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _failing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert result.witnessed_pass is False
        assert result.witnessed_subject is None  # a failing eval binds no subject


class TestSafetyVeto:
    """A safety-failing eval never gets witnessed_pass."""

    def test_safety_fail_blocks_promotion(self):
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
        agent = ContractResume(calls)

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
        agent = ContractResume(calls)

        def broken_handler(inp):
            raise RuntimeError("simulated crash")

        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
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
        assert d["witnessed_subject"] is None
        assert d["refusal_reasons"] == []
        json.dumps(d)  # JSON-able end to end

    def test_carries_subject_and_refusals(self):
        result = AgentLoopResult(
            promoted=True, stopped_by="end_turn", tool_calls_used=3,
            trace=[], final_text="", witnessed_pass=True,
            witnessed_approval=True, refused_promotions=1,
            witnessed_subject="hA", refusal_reasons=["subject mismatch: ..."])
        d = result_to_dict(result)
        assert d["witnessed_subject"] == "hA"
        assert d["refusal_reasons"] == ["subject mismatch: ..."]


class TestValidation:
    def test_max_tool_calls_zero_raises(self):
        with pytest.raises(ValueError, match="max_tool_calls"):
            run_agent_loop(lambda: {}, lambda a: {}, {}, threshold=0.7, max_tool_calls=0)

    def test_threshold_out_of_range_raises(self):
        with pytest.raises(ValueError, match="threshold"):
            run_agent_loop(lambda: {}, lambda a: {}, {}, threshold=1.5)


# --------------------------------------------------------------------------- #
# Subject binding (confused-deputy fix)                                       #
# --------------------------------------------------------------------------- #
def _happy_calls(promote_input):
    """eval → HITL approve → promote(promote_input) → end_turn."""
    return [
        {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
        {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
        {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", promote_input, "tu-3")]},
        {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
    ]


class TestSubjectBinding:
    """The confused-deputy fix: promotion must target the harness the eval scored."""

    def _run(self, promote_input, eval_out):
        agent = ContractResume(_happy_calls(promote_input))
        return run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: eval_out,
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )

    def test_score_a_promote_b_refused(self):
        """Adversarial: score harness A (pass + approval), then promote harness B."""
        result = self._run(_promotion_input(harness_id="harness_B"),
                           _passing_eval_result(harness_id="harness_A"))
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert result.witnessed_subject == "harness_A"
        assert "subject mismatch" in result.trace[-1].detail
        assert "harness_A" in result.trace[-1].detail and "harness_B" in result.trace[-1].detail
        assert any("subject mismatch" in r for r in result.refusal_reasons)

    def test_eval_without_subject_refuses_promotion(self):
        """FAIL-CLOSED: a passing eval that names no harness witnesses nothing."""
        eval_out = {"score": 0.9, "dimension_scores": {"safety": 1.0}}  # no harness_id
        result = self._run(_promotion_input(harness_id="harness_A"), eval_out)
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert result.witnessed_subject is None
        assert "eval did not identify its subject" in result.trace[-1].detail

    def test_promotion_without_subject_refused(self):
        """A promotion call that names no harness cannot match the witnessed subject."""
        result = self._run({"action": "create_endpoint", "params": {"endpoint_name": "prod"}},
                           _passing_eval_result())
        assert result.promoted is False
        assert result.refused_promotions == 1
        assert "promotion did not identify its subject" in result.trace[-1].detail

    def test_subject_match_promotes(self):
        """Same subject scored and promoted → promotion executes."""
        result = self._run(_promotion_input(harness_id="harness_A"),
                           _passing_eval_result(harness_id="harness_A"))
        assert result.promoted is True
        assert result.refused_promotions == 0
        assert result.witnessed_subject == "harness_A"
        assert "harness_A" in result.trace[-1].detail

    def test_flat_harness_id_promotion_shape_matches(self):
        """The flat harness_id fallback (non-params promotion surfaces) also binds."""
        result = self._run({"action": "create_endpoint", "harness_id": SUBJECT},
                           _passing_eval_result())
        assert result.promoted is True

    def test_custom_subject_predicates_injectable(self):
        """The predicates are a seam: a custom promotion surface can bind differently."""
        agent = ContractResume(_happy_calls({"action": "create_endpoint", "target": SUBJECT}))
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: {"score": 0.9,
                                                     "dimension_scores": {"safety": 1.0},
                                                     "subject": SUBJECT},
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            subject_of_eval=lambda out: out.get("subject"),
            subject_of_promotion=lambda ti: ti.get("target"),
            threshold=0.7,
        )
        assert result.promoted is True
        assert result.witnessed_subject == SUBJECT

    def test_new_failing_eval_clears_witnessed_subject(self):
        """A later failing eval revokes the earlier witness (subject cleared)."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {"round": 1}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {"round": 2}, "tu-3")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-4")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)
        outs = [_passing_eval_result(), _failing_eval_result()]
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: outs[inp["round"] - 1],
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is False
        assert result.witnessed_subject is None
        assert result.refused_promotions == 1


# --------------------------------------------------------------------------- #
# Resume contract (false-green killer)                                        #
# --------------------------------------------------------------------------- #
class TestResumeContract:
    """The answers a resume_fn receives ARE the live core.invoke_with_tool_results
    contract; ContractResume asserts it on every round."""

    def test_two_parallel_gates_in_one_turn(self):
        """One turn pausing on TWO gates (HITL + eval) must answer BOTH toolUseIds."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [
                _make_tool_use("request_promotion_approval", {}, "tu-hitl"),
                _make_tool_use("run_evaluation", {}, "tu-eval"),
            ]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-3")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.promoted is True
        assert result.tool_calls_used == 3
        assert agent.rounds == 2

    def test_singular_tool_use_fallback(self):
        """A result with only the SINGULAR tool_use key (empty/missing tool_uses)
        still dispatches and answers that one gate."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [],
             "tool_use": _make_tool_use("run_evaluation", {}, "tu-solo")},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result()},
            threshold=0.7,
        )
        assert result.tool_calls_used == 1
        assert result.witnessed_pass is True
        assert result.trace[0].outcome == "executed"

    def test_resume_raises_on_round_n_preserves_trace(self):
        """resume_fn raising mid-session → stopped_by=session_error, prior trace kept."""
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("run_evaluation", {}, "tu-1")]},
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("request_promotion_approval", {}, "tu-2")]},
            {"stop_reason": "end_turn", "text": "never reached", "tool_uses": []},
        ]
        agent = ContractResume(calls, raise_on_round=2)
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result()},
            approve_fn=lambda inp: True,
            threshold=0.7,
        )
        assert result.stopped_by == "session_error"
        assert result.tool_calls_used == 2
        assert [r.outcome for r in result.trace] == ["executed", "hitl"]
        assert result.witnessed_pass is True  # state up to the failure preserved

    def test_cap_answers_carry_error_status(self):
        """Cap-refused remainder gates still satisfy the contract (3-tuple, error)."""
        seen = {}

        def resume_fn(answers):
            # First (and only) round: 3 pending, cap 2 → third answered as cap error.
            seen["answers"] = answers
            raise ConnectionError("stop here")

        calls0 = {"stop_reason": "tool_use", "tool_uses": [
            _make_tool_use("run_evaluation", {}, "tu-1"),
            _make_tool_use("run_evaluation", {}, "tu-2"),
            _make_tool_use("run_evaluation", {}, "tu-3"),
        ]}
        result = run_agent_loop(
            invoke_fn=lambda: calls0,
            resume_fn=resume_fn,
            dispatch={"run_evaluation": lambda inp: _failing_eval_result()},
            threshold=0.7,
            max_tool_calls=2,
        )
        assert result.tool_calls_used == 2
        answers = seen["answers"]
        assert len(answers) == 3  # EVERY pending gate answered
        assert [a[0]["toolUseId"] for a in answers] == ["tu-1", "tu-2", "tu-3"]
        cap_answer = answers[2]
        assert len(cap_answer) == 3 and cap_answer[2] == "error"
        assert json.loads(cap_answer[1])["error"] == "tool_call_cap"

    def test_incumbent_and_strict_improvement_passthrough(self):
        """The regression guard actually bites inside the witnessed gate: a score
        equal to the incumbent fails under require_strict_improvement."""
        agent = ContractResume(_happy_calls(_promotion_input()))
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),  # 0.85
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
            incumbent_best=0.85,
            require_strict_improvement=True,
        )
        assert result.witnessed_pass is False
        assert result.promoted is False
        assert result.refused_promotions == 1

        # Same policy WITHOUT strict improvement: 0.85 >= 0.85 passes.
        agent2 = ContractResume(_happy_calls(_promotion_input()))
        result2 = run_agent_loop(
            invoke_fn=agent2.invoke_fn,
            resume_fn=agent2.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
            incumbent_best=0.85,
            require_strict_improvement=False,
        )
        assert result2.promoted is True


# --------------------------------------------------------------------------- #
# Telemetry seam                                                              #
# --------------------------------------------------------------------------- #
class TestTelemetrySeam:
    """Optional tracer/log sinks; defaults None => behavior identical to before."""

    def _run_happy(self, **kwargs):
        agent = ContractResume(_happy_calls(_promotion_input()))
        return run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"run_evaluation": lambda inp: _passing_eval_result(),
                      "harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
            **kwargs,
        )

    def test_defaults_none_identical_result(self):
        """With tracer/log left None the result is identical to an instrumented run."""
        bare = self._run_happy()
        lines = []
        tracer = Tracer("agent-loop-test", log=lines.append)
        instrumented = self._run_happy(tracer=tracer, log=lines.append)
        assert result_to_dict(bare) == result_to_dict(instrumented)

    def test_spans_align_with_trace_seq(self):
        """One session span + one child span per dispatched call, outcomes 1:1."""
        lines = []
        tracer = Tracer("agent-loop-test", log=lines.append)
        result = self._run_happy(tracer=tracer, log=lines.append)
        assert result.promoted is True

        session = tracer.spans[0]
        assert session.name == "agent_loop.session"
        assert session.parent_span_id is None

        call_spans = tracer.spans[1:]
        assert len(call_spans) == len(result.trace) == 3
        for span, rec in zip(call_spans, result.trace):
            assert span.parent_span_id == session.span_id
            assert span.name == f"agent_loop.call.{rec.tool}"
            assert span.attributes["sentinel.seq"] == rec.seq
            assert span.attributes["sentinel.outcome"] == rec.outcome

    def test_log_lines_carry_hitl_eval_and_refusals(self):
        """The log sink receives emit_hitl_gate / emit_eval_score-style lines plus
        a refused_promotions count; every line is valid JSON."""
        lines = []
        self._run_happy(log=lines.append)
        parsed = [json.loads(x) for x in lines]
        metrics = [p["metric"] for p in parsed]
        assert "eval_score" in metrics
        assert "hitl_gate" in metrics
        assert "refused_promotions" in metrics

        eval_line = next(p for p in parsed if p["metric"] == "eval_score")
        assert eval_line["eval_score"] == pytest.approx(0.85)
        assert eval_line["passed"] is True
        assert eval_line["subject"] == SUBJECT

        hitl_line = next(p for p in parsed if p["metric"] == "hitl_gate")
        assert hitl_line["gate"] == "request_promotion_approval"
        assert hitl_line["decision"] == "approved"

        refused_line = next(p for p in parsed if p["metric"] == "refused_promotions")
        assert refused_line["refused_promotions"] == 0.0

    def test_refused_promotion_counted_in_log(self):
        """A refused promotion is reflected in the emitted refusal counter."""
        lines = []
        calls = [
            {"stop_reason": "tool_use", "tool_uses": [_make_tool_use("harness_ops", _promotion_input(), "tu-1")]},
            {"stop_reason": "end_turn", "text": "Done.", "tool_uses": []},
        ]
        agent = ContractResume(calls)
        result = run_agent_loop(
            invoke_fn=agent.invoke_fn,
            resume_fn=agent.resume_fn,
            dispatch={"harness_ops": lambda inp: {"ok": True}},
            approve_fn=lambda inp: True,
            threshold=0.7,
            log=lines.append,
        )
        assert result.refused_promotions == 1
        parsed = [json.loads(x) for x in lines]
        refused_line = next(p for p in parsed if p["metric"] == "refused_promotions")
        assert refused_line["refused_promotions"] == 1.0

    def test_session_error_still_emits_refusal_counter(self):
        """Even the first-invoke error path emits the final counter (no silent gap)."""
        lines = []
        result = run_agent_loop(
            invoke_fn=lambda: (_ for _ in ()).throw(ConnectionError("down")),
            resume_fn=lambda a: {},
            dispatch={},
            threshold=0.7,
            log=lines.append,
        )
        assert result.stopped_by == "session_error"
        parsed = [json.loads(x) for x in lines]
        assert any(p["metric"] == "refused_promotions" for p in parsed)
