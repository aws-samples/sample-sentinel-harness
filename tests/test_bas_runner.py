"""
Offline tests for the bas-runner long-running Runtime skeleton
==============================================================
ZERO AWS calls, ZERO network. We inject fake ``invoke_fn`` / ``resume_fn`` into
the Play-Mode runner (as ``tests/test_simulation.py`` does) and drive the
``BasRunnerLoop`` / entrypoint over them, so nothing touches boto3 or the network.

Coverage:
  * ``bedrock_entrypoint`` imports WITHOUT ``bedrock_agentcore`` (guarded import).
  * checkpoint round-trips (state persisted by the loop reloads identically).
  * EVERY offensive step is gated; a reject HALTS the plan and later steps do not run.
  * the security hooks reject a path-traversal and a disallowed command,
    delegating to ``sentinel_harness.sandbox_hooks``.
  * mode semantics: run_once advances one step; pause does nothing.
  * the session cap WIP-checkpoints and signals a restart, and a resumed run
    finishes WITHOUT re-approving earlier steps.

HARD RULE: dummy AWS env set before import; the runner is fully DI'd here.
"""
from __future__ import annotations

import os
import sys

import pytest

# --- Make imports hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# bas-runner modules live under longrunning/bas-runner/, not in the package.
_BAS_DIR = os.path.join(os.path.dirname(__file__), "..", "longrunning", "bas-runner")
sys.path.insert(0, os.path.abspath(_BAS_DIR))

from sentinel_harness import simulation as sim  # noqa: E402

import runner_loop as rl  # noqa: E402
from runner_loop import BasRunnerLoop, SessionCapReached  # noqa: E402

ARN = "arn:aws:test:harness/hid-bas"
SESSION = "bas-test-session-00000000000000000000000000"

PLAN = [
    {"phase": "recon", "technique": "T1595", "objective": "sim recon"},
    {"phase": "initial-access", "technique": "T1190", "objective": "sim initial access"},
    {"phase": "execution", "technique": "T1059", "objective": "sim execution"},
]


# --------------------------------------------------------------------------- #
# Fakes: scripted invoke/resume that make ZERO AWS calls                      #
# --------------------------------------------------------------------------- #
class FakeHarness:
    """Scripted harness that pauses on the gate every invoke (no AWS/network)."""

    def __init__(self, pause=True):
        self.pause = pause
        self.invokes = []
        self.resumes = []
        self._n = 0

    def invoke(self, harness_arn, session_id, text, **kw):
        self.invokes.append({"arn": harness_arn, "session": session_id})
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


def make_loop(fake, *, decision_fn, mode=rl.CONTINUOUS, checkpoint_path=None,
              max_steps_per_session=None, plan=None):
    runner = sim.PlayModeRunner(
        ARN,
        plan=plan or PLAN,
        session_id=SESSION,
        plan_id="bastest",
        checkpoint_path=checkpoint_path,
        invoke_fn=fake.invoke,
        resume_fn=fake.resume,
        decision_fn=decision_fn,
        logger=lambda m: None,
    )
    return BasRunnerLoop(runner, mode=mode, max_steps_per_session=max_steps_per_session)


# --------------------------------------------------------------------------- #
# 1. Entrypoint imports without bedrock_agentcore (guarded)                   #
# --------------------------------------------------------------------------- #
def test_entrypoint_imports_without_agentcore():
    """The @app.entrypoint module must import even when bedrock_agentcore is absent."""
    pytest.importorskip  # noqa: B018 - sanity that pytest is present
    import bedrock_entrypoint as ep
    # In an offline env bedrock_agentcore is not installed → app is None.
    assert ep._HAS_AGENTCORE in (True, False)
    if not ep._HAS_AGENTCORE:
        assert ep.app is None
    # The pure-Python driver is always importable/usable regardless.
    assert callable(ep.build_loop)
    assert callable(ep.run_plan)


# --------------------------------------------------------------------------- #
# 2. Every offensive step is gated; approve executes a simulated no-op        #
# --------------------------------------------------------------------------- #
def test_continuous_gates_every_step_and_simulates():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve)
    turn = loop.run()

    assert turn.complete and not turn.halted
    assert turn.steps_advanced == len(PLAN)
    # every step paused on the gate (captured a toolUseId) ...
    assert all(s.tool_use_id is not None for s in loop.state.steps)
    # ... and execution was a SIMULATED no-op, never a real action.
    for s in loop.state.steps:
        assert s.status == sim.EXECUTED
        assert "SIMULATED" in (s.execution_log or "")
    v = loop.runner.verdict()
    assert v["every_step_gated"] is True
    assert v["approved_step_resumed"] is True


# --------------------------------------------------------------------------- #
# 3. Reject HALTS the plan; later steps never run                             #
# --------------------------------------------------------------------------- #
def test_reject_halts_plan():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_reject)
    turn = loop.run()

    assert turn.halted
    assert loop.state.steps[0].status == sim.REJECTED
    assert loop.state.steps[1].status == sim.PENDING
    assert loop.state.steps[2].status == sim.PENDING
    # only ONE invoke before the halt; the rejection was sent back as an error.
    assert len(fake.invokes) == 1
    assert fake.resumes[-1]["status"] == "error"
    assert loop.runner.verdict()["reject_halts_plan"] is True


def test_reject_after_one_approves_then_halts():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.reject_after(1))
    loop.run()
    assert loop.state.steps[0].status == sim.EXECUTED
    assert loop.state.steps[1].status == sim.REJECTED
    assert loop.state.steps[2].status == sim.PENDING


def test_ungated_step_halts():
    """If the harness never hits the gate, that is a protocol violation → halt."""
    fake = FakeHarness(pause=False)
    loop = make_loop(fake, decision_fn=sim.auto_approve)
    turn = loop.run()
    assert turn.halted
    assert "did not pass through" in (turn.halted_reason or "")
    assert fake.resumes == []


# --------------------------------------------------------------------------- #
# 4. Checkpoint round-trip                                                    #
# --------------------------------------------------------------------------- #
def test_checkpoint_roundtrips(tmp_path):
    ckpt = str(tmp_path / "bas.json")
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve, checkpoint_path=ckpt)
    loop.run()

    assert os.path.exists(ckpt)
    reloaded = sim.load_checkpoint(ckpt)
    assert reloaded.to_dict() == loop.state.to_dict()
    assert reloaded.session_id == SESSION
    assert all(s.status == sim.EXECUTED for s in reloaded.steps)


# --------------------------------------------------------------------------- #
# 5. Mode semantics: run_once advances one step; pause does nothing           #
# --------------------------------------------------------------------------- #
def test_run_once_advances_exactly_one_step(tmp_path):
    ckpt = str(tmp_path / "bas.json")
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve, mode=rl.RUN_ONCE, checkpoint_path=ckpt)
    turn = loop.run()
    assert turn.steps_advanced == 1
    assert loop.state.steps[0].status == sim.EXECUTED
    assert loop.state.steps[1].status == sim.PENDING
    # a second run_once turn advances the next step (fresh-context-per-turn)
    turn2 = loop.run()
    assert turn2.steps_advanced == 1
    assert loop.state.steps[1].status == sim.EXECUTED


def test_pause_mode_does_no_work():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve, mode=rl.PAUSE)
    turn = loop.run()
    assert turn.steps_advanced == 0
    assert fake.invokes == []
    assert all(s.status == sim.PENDING for s in loop.state.steps)


def test_invalid_mode_rejected():
    fake = FakeHarness()
    with pytest.raises(ValueError):
        make_loop(fake, decision_fn=sim.auto_approve, mode="nope")


# --------------------------------------------------------------------------- #
# 6. Session cap → WIP-commit + restart; resume finishes without re-approving #
# --------------------------------------------------------------------------- #
def test_session_cap_checkpoints_and_signals_restart(tmp_path):
    ckpt = str(tmp_path / "bas.json")
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve, checkpoint_path=ckpt,
                     max_steps_per_session=1)
    with pytest.raises(SessionCapReached) as ei:
        loop.run()
    assert ei.value.checkpoint_path == ckpt
    assert ei.value.steps_done == 1
    # WIP checkpoint was written; exactly one step executed so far.
    reloaded = sim.load_checkpoint(ckpt)
    assert reloaded.steps[0].status == sim.EXECUTED
    assert reloaded.steps[1].status == sim.PENDING

    # Resume from the checkpoint: continue WITHOUT re-approving step 0.
    fake2 = FakeHarness()
    resumed_runner = sim.PlayModeRunner.resume_from_checkpoint(
        ARN, ckpt, invoke_fn=fake2.invoke, resume_fn=fake2.resume,
        decision_fn=sim.auto_approve, logger=lambda m: None,
    )
    resumed_loop = BasRunnerLoop(resumed_runner, mode=rl.CONTINUOUS)
    turn = resumed_loop.run()
    assert turn.complete
    assert all(s.status == sim.EXECUTED for s in resumed_loop.state.steps)
    # step 0 was NOT re-invoked on resume (only steps 1 and 2 remained pending).
    assert len(fake2.invokes) == len(PLAN) - 1


# --------------------------------------------------------------------------- #
# 7. Security hooks reject traversal / disallowed command (delegating)        #
# --------------------------------------------------------------------------- #
def test_security_hook_blocks_path_traversal():
    from src.security import pre_tool_use
    res = pre_tool_use("read_file", {"path": "../../etc/passwd"})
    assert res.allow is False
    assert "traversal" in res.reason


def test_security_hook_blocks_disallowed_command():
    from src.security import pre_tool_use
    res = pre_tool_use("bash", {"command": "nmap -sS 10.0.0.1"})
    assert res.allow is False
    assert "allowlist" in res.reason


def test_security_hook_blocks_destructive_command():
    from src.security import pre_tool_use
    res = pre_tool_use("shell", {"command": "rm -rf /workspace"})
    assert res.allow is False and res.reason


def test_security_hook_allows_safe_command():
    from src.security import pre_tool_use
    res = pre_tool_use("bash", {"command": "git status"})
    assert res.allow is True


def test_security_hook_shell_without_command_denied():
    from src.security import pre_tool_use
    res = pre_tool_use("bash", {})
    assert res.allow is False


def test_security_hook_non_shell_tool_without_path_allowed():
    from src.security import pre_tool_use
    res = pre_tool_use("nvd_lookup", {"cve_id": "CVE-0000-00000"})
    assert res.allow is True


def test_post_tool_use_flags_sensitive_path():
    from src.security import post_tool_use
    assert post_tool_use("bash", "reading /etc/shadow now").allow is False
    assert post_tool_use("bash", "all fine here").allow is True
