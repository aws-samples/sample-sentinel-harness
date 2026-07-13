"""
Offline tests for Layer 2 (Simulation) — Play Mode attack-simulation runner
===========================================================================
These tests exercise ``sentinel_harness.simulation.PlayModeRunner`` plan /
checkpoint / decision logic WITHOUT any AWS calls. We inject fake ``invoke_fn``
and ``resume_fn`` that return scripted results, so:

  * a scripted ``tool_use`` pause is captured per step,
  * APPROVE advances the plan and records a SIMULATED no-op execution,
  * REJECT halts the plan (Play Mode invariant),
  * an ungated step (no tool_use) also halts,
  * checkpoint state round-trips through JSON.

HARD RULE (mirrors tests/test_config_validation.py): ZERO AWS calls. We set
dummy env before import and never touch the real Layer-1 invoke/resume — the
runner is fully dependency-injected here.
"""
from __future__ import annotations

import json
import os

# --- Make the import hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import simulation as sim  # noqa: E402

ARN = "arn:aws:test:harness/hid-test"
SESSION = "playmode-test-session-000000000000000000"

PLAN = [
    {"phase": "recon", "technique": "T1595", "objective": "sim recon"},
    {"phase": "initial-access", "technique": "T1190", "objective": "sim initial access"},
    {"phase": "execution", "technique": "T1059", "objective": "sim execution"},
]


# --------------------------------------------------------------------------- #
# Fakes: scripted invoke/resume that make ZERO AWS calls                      #
# --------------------------------------------------------------------------- #
class FakeHarness:
    """Records calls and returns a scripted tool_use pause on every invoke."""

    def __init__(self, pause=True):
        self.pause = pause
        self.invokes = []
        self.resumes = []
        self._n = 0

    def invoke(self, harness_arn, session_id, text, **kw):
        self.invokes.append({"arn": harness_arn, "session": session_id, "text": text})
        if not self.pause:
            return {"stop_reason": "end_turn", "tool_use": None, "text": "no gate"}
        self._n += 1
        return {
            "stop_reason": "tool_use",
            "tool_use": {"toolUseId": f"tu-{self._n}", "name": sim.PlayModeRunner.GATE_NAME,
                         "input": {"technique": f"T{self._n}"}},
            "text": "",
        }

    def resume(self, harness_arn, session_id, tool_use, result, status="success", **kw):
        self.resumes.append({"tool_use": tool_use, "result": result, "status": status})
        return {"stop_reason": "end_turn", "text": "resumed", "tool_use": None}


def make_runner(fake, decision_fn, checkpoint_path=None, plan=None):
    return sim.PlayModeRunner(
        ARN,
        plan=plan or PLAN,
        session_id=SESSION,
        plan_id="test",
        checkpoint_path=checkpoint_path,
        invoke_fn=fake.invoke,
        resume_fn=fake.resume,
        decision_fn=decision_fn,
        logger=lambda m: None,
    )


# --------------------------------------------------------------------------- #
# Approve path                                                                #
# --------------------------------------------------------------------------- #
def test_approve_advances_and_executes_all_steps():
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_approve)
    state = runner.run()

    assert not state.halted
    assert state.is_complete()
    assert all(s.status == sim.EXECUTED for s in state.steps)
    # every step captured the gate's toolUseId (paused) ...
    assert all(s.tool_use_id is not None for s in state.steps)
    # ... and each resumed the SAME session
    assert all(r["result"]["decision"] == "APPROVED" for r in fake.resumes)
    assert len(fake.resumes) == len(PLAN)
    assert all(c["session"] == SESSION for c in fake.invokes)


def test_approve_execution_is_simulated_noop():
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_approve)
    state = runner.run()
    for s in state.steps:
        assert s.execution_log is not None
        assert "SIMULATED" in s.execution_log
        assert "would execute technique" in s.execution_log
        assert s.technique in s.execution_log


def test_approve_verdict():
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_approve)
    runner.run()
    v = runner.verdict()
    assert v["every_step_gated"] is True
    assert v["approved_step_resumed"] is True
    assert v["reject_halts_plan"] is False
    assert v["closed_loop"] is True
    assert v["counts"][sim.EXECUTED] == len(PLAN)


# --------------------------------------------------------------------------- #
# Reject path                                                                 #
# --------------------------------------------------------------------------- #
def test_reject_first_step_halts_immediately():
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_reject)
    state = runner.run()

    assert state.halted
    assert state.steps[0].status == sim.REJECTED
    # subsequent steps never ran
    assert state.steps[1].status == sim.PENDING
    assert state.steps[2].status == sim.PENDING
    # only ONE invoke happened before the halt
    assert len(fake.invokes) == 1
    # the rejection was reported back to the harness as an error toolResult
    assert fake.resumes[-1]["status"] == "error"


def test_reject_after_one_approves_then_halts():
    fake = FakeHarness()
    runner = make_runner(fake, sim.reject_after(1))
    state = runner.run()

    assert state.halted
    assert state.steps[0].status == sim.EXECUTED   # first approved + simulated
    assert state.steps[1].status == sim.REJECTED   # second rejected -> halt
    assert state.steps[2].status == sim.PENDING    # third never reached
    v = runner.verdict()
    assert v["approved_step_resumed"] is True
    assert v["reject_halts_plan"] is True


# --------------------------------------------------------------------------- #
# Ungated step (protocol violation) halts                                     #
# --------------------------------------------------------------------------- #
def test_ungated_step_halts_plan():
    fake = FakeHarness(pause=False)   # harness never hits the gate
    runner = make_runner(fake, sim.auto_approve)
    state = runner.run()
    assert state.halted
    assert "did not pass through" in (state.halted_reason or "")
    # no resume attempted because there was no tool_use to answer
    assert fake.resumes == []


# --------------------------------------------------------------------------- #
# Checkpoint round-trip                                                       #
# --------------------------------------------------------------------------- #
def test_checkpoint_roundtrips(tmp_path):
    ckpt = str(tmp_path / "ckpt.json")
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_approve, checkpoint_path=ckpt)
    state = runner.run()

    assert os.path.exists(ckpt)
    reloaded = sim.load_checkpoint(ckpt)
    assert reloaded.to_dict() == state.to_dict()
    # spot-check a couple of fields survived serialization
    assert reloaded.session_id == SESSION
    assert all(s.status == sim.EXECUTED for s in reloaded.steps)


def test_checkpoint_written_atomically_is_valid_json(tmp_path):
    ckpt = str(tmp_path / "ckpt.json")
    fake = FakeHarness()
    make_runner(fake, sim.auto_approve, checkpoint_path=ckpt).run()
    with open(ckpt) as f:
        data = json.load(f)   # must parse
    assert data["plan_id"] == "test"
    assert len(data["steps"]) == len(PLAN)


def test_resume_from_checkpoint_preserves_state(tmp_path):
    ckpt = str(tmp_path / "ckpt.json")
    fake = FakeHarness()
    make_runner(fake, sim.reject_after(1), checkpoint_path=ckpt).run()

    # Rebuild a runner purely from the checkpoint; state must be intact.
    resumed = sim.PlayModeRunner.resume_from_checkpoint(
        ARN, ckpt,
        invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        logger=lambda m: None,
    )
    assert resumed.state.halted
    assert resumed.state.steps[0].status == sim.EXECUTED
    assert resumed.state.steps[1].status == sim.REJECTED
    assert resumed.state.session_id == SESSION


# --------------------------------------------------------------------------- #
# Plan-state helpers                                                          #
# --------------------------------------------------------------------------- #
def test_next_pending_and_counts():
    fake = FakeHarness()
    runner = make_runner(fake, sim.auto_approve)
    assert runner.state.next_pending().index == 0
    assert runner.state.counts()[sim.PENDING] == len(PLAN)
    runner.run()
    assert runner.state.next_pending() is None
    assert runner.state.counts()[sim.EXECUTED] == len(PLAN)


def test_decision_policies():
    step = sim.StepState(index=0, phase="recon", technique="T1595", objective="x")
    assert sim.auto_approve(step, {})["decision"] == "APPROVED"
    assert sim.auto_reject(step, {})["decision"] == "REJECTED"
    pol = sim.reject_after(2)
    assert pol(sim.StepState(0, "p", "T1", "o"), {})["decision"] == "APPROVED"
    assert pol(sim.StepState(1, "p", "T2", "o"), {})["decision"] == "APPROVED"
    assert pol(sim.StepState(2, "p", "T3", "o"), {})["decision"] == "REJECTED"
