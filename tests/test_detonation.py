"""
Offline tests for the sample-detonation long-running Runtime skeleton
=====================================================================
ZERO AWS calls, ZERO network, ZERO real VM, ZERO real detonation. Everything is
the SIMULATED skeleton: the one-shot microVM is an in-memory abstraction, the
sample is a reference-only s3:// uri, and the plan is driven through the existing
Play-Mode gate with injected fake ``invoke_fn`` / ``resume_fn`` (as
``tests/test_bas_runner.py`` does), so nothing touches boto3 or the network.

Coverage:
  * ``bedrock_entrypoint`` imports WITHOUT ``bedrock_agentcore`` (guarded import).
  * ``OneShotMicroVM`` acquire -> run_action -> destroy lifecycle (simulated).
  * destroy-after-use is enforced: using a destroyed handle raises.
  * a path-traversal and a disallowed command are BLOCKED by the sandbox hooks
    (delegating to ``sentinel_harness.sandbox_hooks``).
  * a sample enters ONLY by s3:// reference; a live-fetch-shaped uri is rejected.
  * a simulated detonation step is HITL-gated (reuse Play Mode) and a reject halts.

HARD RULE: dummy AWS env set before import; the runner is fully DI'd here.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

# --- Make imports hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# detonation + bas-runner modules live under longrunning/, not in the package.
# ``longrunning`` is not a Python package and ``bas-runner`` cannot be one (its
# name has a dash), so these dirs are put on sys.path directly (the same
# convention tests/test_bas_runner.py uses). NOTE: the detonation entrypoint
# shares the basename ``bedrock_entrypoint`` with bas-runner's, so we load it by
# explicit file path via importlib (below) to avoid a module-name collision.
import importlib.util  # noqa: E402

_LR = os.path.join(os.path.dirname(__file__), "..", "longrunning")
sys.path.insert(0, os.path.abspath(os.path.join(_LR, "bas-runner")))
sys.path.insert(0, os.path.abspath(os.path.join(_LR, "detonation", "src")))

from sentinel_harness import simulation as sim  # noqa: E402

import runner_loop as rl  # noqa: E402
from runner_loop import BasRunnerLoop  # noqa: E402
from vm import (  # noqa: E402
    ACQUIRED,
    DESTROYED,
    ActionRefused,
    OneShotMicroVM,
    Sample,
    VMAlreadyDestroyedError,
    VMError,
)


def _load_detonation_entrypoint():
    """Load longrunning/detonation/bedrock_entrypoint.py under a unique module
    name so it never collides with bas-runner's identically-named module."""
    path = os.path.abspath(
        os.path.join(_LR, "detonation", "bedrock_entrypoint.py")
    )
    spec = importlib.util.spec_from_file_location("detonation_bedrock_entrypoint", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

ARN = "arn:aws:test:harness/hid-detonation"
SESSION = "detonation-test-session-000000000000000000000000"

# A generic SIMULATED detonation plan (technique ids illustrative, nothing real).
PLAN = [
    {"phase": "detonation-setup", "technique": "T1204", "objective": "sim stage sample"},
    {"phase": "execution", "technique": "T1059", "objective": "sim detonate"},
    {"phase": "collection", "technique": "T1005", "objective": "sim collect artifacts"},
]


# --------------------------------------------------------------------------- #
# Fake: scripted invoke/resume that make ZERO AWS calls (mirrors bas-runner)  #
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


def make_loop(fake, *, decision_fn, mode=rl.CONTINUOUS, checkpoint_path=None, plan=None):
    runner = sim.PlayModeRunner(
        ARN,
        plan=plan or PLAN,
        session_id=SESSION,
        plan_id="detotest",
        checkpoint_path=checkpoint_path,
        invoke_fn=fake.invoke,
        resume_fn=fake.resume,
        decision_fn=decision_fn,
        logger=lambda m: None,
    )
    return BasRunnerLoop(runner, mode=mode)


# --------------------------------------------------------------------------- #
# 1. Entrypoint imports without bedrock_agentcore (guarded)                   #
# --------------------------------------------------------------------------- #
def test_entrypoint_imports_without_agentcore():
    """The @app.entrypoint module must import even when bedrock_agentcore is absent."""
    ep = _load_detonation_entrypoint()
    assert ep._HAS_AGENTCORE in (True, False)
    if not ep._HAS_AGENTCORE:
        assert ep.app is None
    # The pure-Python detonation driver is always importable/usable regardless.
    assert callable(ep.build_runner)
    assert callable(ep.run_detonation)


# --------------------------------------------------------------------------- #
# 2. One-shot microVM lifecycle: acquire -> run_action -> destroy (simulated) #
# --------------------------------------------------------------------------- #
def test_microvm_acquire_run_destroy_lifecycle():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    assert handle.state == ACQUIRED
    assert handle.is_live

    res = vm.run_action(handle, {"kind": "run", "command": "ls /workspace"})
    assert res["ok"] is True
    assert res["simulated"] is True  # NEVER a real execution
    assert "SIMULATED" in res["note"]
    assert handle.action_log and handle.action_log[-1] is res

    path_res = vm.run_action(handle, {"kind": "read", "path": "artifacts/report.txt"})
    assert path_res["simulated"] is True

    destroyed = vm.destroy(handle)
    assert destroyed["state"] == DESTROYED
    assert handle.state == DESTROYED


def test_one_shot_refuses_second_live_vm():
    """One-shot / no-reuse: can't acquire a second VM while one is live."""
    vm = OneShotMicroVM()
    h1 = vm.acquire(SESSION)
    with pytest.raises(VMError):
        vm.acquire("another-session")
    vm.destroy(h1)
    # after destroy, a fresh acquire is allowed
    h2 = vm.acquire("another-session")
    assert h2.is_live and h2.vm_id != h1.vm_id


# --------------------------------------------------------------------------- #
# 3. destroy-after-use is enforced: a destroyed handle cannot run actions     #
# --------------------------------------------------------------------------- #
def test_destroy_after_use_enforced():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    vm.destroy(handle)
    with pytest.raises(VMAlreadyDestroyedError):
        vm.run_action(handle, {"kind": "run", "command": "ls"})


def test_destroy_is_idempotent():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    first = vm.destroy(handle)
    second = vm.destroy(handle)
    assert first["idempotent_noop"] is False
    assert second["idempotent_noop"] is True


# --------------------------------------------------------------------------- #
# 4. Sandbox hooks BLOCK a path-traversal and a disallowed command            #
# --------------------------------------------------------------------------- #
def test_path_traversal_blocked_by_sandbox_hooks():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    with pytest.raises(ActionRefused) as ei:
        vm.run_action(handle, {"kind": "read", "path": "../../etc/passwd"})
    assert "traversal" in ei.value.reason
    # the refused action was NOT (simulated-)executed / logged.
    assert handle.action_log == []


def test_disallowed_command_blocked_by_sandbox_hooks():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    with pytest.raises(ActionRefused):
        vm.run_action(handle, {"kind": "run", "command": "rm -rf /"})
    assert handle.action_log == []


def test_unknown_action_kind_rejected():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    with pytest.raises(ValueError):
        vm.run_action(handle, {"kind": "detonate_for_real", "command": "x"})


# --------------------------------------------------------------------------- #
# 5. A sample enters ONLY by s3:// reference — never a live fetch             #
# --------------------------------------------------------------------------- #
def test_sample_reference_only():
    ok = Sample(s3_uri="s3://dropbox-bucket/quarantine/abc123", dropbox_id="drop-1")
    assert ok.s3_uri.startswith("s3://")
    assert ok.sha256 is None  # never computed here (bytes never read)
    # a live-fetch-shaped reference is rejected.
    for bad in ("https://evil.example/malware.bin", "/tmp/local/sample.exe", "ftp://x"):
        with pytest.raises(ValueError):
            Sample(s3_uri=bad)


# --------------------------------------------------------------------------- #
# 6. A simulated detonation step is HITL-gated (Play Mode); reject halts       #
# --------------------------------------------------------------------------- #
def test_detonation_step_is_hitl_gated_and_simulated():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve)
    turn = loop.run()
    assert turn.complete and not turn.halted
    # every detonation step paused on the gate ...
    assert all(s.tool_use_id is not None for s in loop.state.steps)
    # ... and "execution" was a SIMULATED no-op, never a real detonation.
    for s in loop.state.steps:
        assert s.status == sim.EXECUTED
        assert "SIMULATED" in (s.execution_log or "")
    v = loop.runner.verdict()
    assert v["every_step_gated"] is True
    assert v["approved_step_resumed"] is True


def test_detonation_reject_halts_plan():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_reject)
    turn = loop.run()
    assert turn.halted
    assert loop.state.steps[0].status == sim.REJECTED
    assert loop.state.steps[1].status == sim.PENDING
    assert loop.state.steps[2].status == sim.PENDING
    assert len(fake.invokes) == 1  # halted before later steps ran
    assert fake.resumes[-1]["status"] == "error"
    assert loop.runner.verdict()["reject_halts_plan"] is True


# --------------------------------------------------------------------------- #
# 7. End-to-end driver: acquire -> gated plan -> destroy-after-use            #
# --------------------------------------------------------------------------- #
def test_run_detonation_destroys_vm_after_use(tmp_path):
    ep = _load_detonation_entrypoint()

    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve,
                     checkpoint_path=str(tmp_path / "d.json"))
    vm = OneShotMicroVM()
    sample = Sample(s3_uri="s3://dropbox/quarantine/xyz")
    result = ep.run_detonation(loop, vm=vm, session_id=SESSION, sample=sample)

    assert result["event"] == "plan_complete"
    # destroy-after-use: the VM is torn down when the plan finishes.
    assert result["vm"]["state"] == DESTROYED
    assert result["vm"]["session_id"] == SESSION


def test_run_detonation_destroys_vm_even_when_halted(tmp_path):
    ep = _load_detonation_entrypoint()

    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_reject,
                     checkpoint_path=str(tmp_path / "d.json"))
    vm = OneShotMicroVM()
    result = ep.run_detonation(loop, vm=vm, session_id=SESSION)

    assert result["event"] == "plan_halted"
    # destroy-after-use holds even on a halt (destroy is in a finally).
    assert result["vm"]["state"] == DESTROYED


# --------------------------------------------------------------------------- #
# 8. run_detonation: session-cap turns into a restart_required event, and the  #
#    VM is STILL destroyed in the finally (WIP-commit, not an error).          #
# --------------------------------------------------------------------------- #
class _CapLoop:
    """A minimal loop stand-in whose .run() raises SessionCapReached, letting us
    exercise run_detonation's restart branch without env fiddling. Mirrors the
    BasRunnerLoop surface run_detonation touches (state/runner/checkpoint)."""

    def __init__(self, checkpoint_path, steps_done):
        self._cap = rl.SessionCapReached(checkpoint_path, steps_done)

        class _Runner:
            checkpoint_path = None

            def verdict(self):
                return {"capped": True}

            def _log(self, note):
                self.last_note = note

        self.runner = _Runner()
        self.runner.checkpoint_path = checkpoint_path

    def run(self):
        raise self._cap


def test_run_detonation_session_cap_becomes_restart_required(tmp_path):
    ep = _load_detonation_entrypoint()
    ckpt = str(tmp_path / "cap.json")
    loop = _CapLoop(ckpt, steps_done=1)
    vm = OneShotMicroVM()
    handle_session = "cap-session-000000000000000000"

    result = ep.run_detonation(loop, vm=vm, session_id=handle_session)

    assert result["event"] == "restart_required"
    assert result["steps_done"] == 1
    assert result["checkpoint_path"] == ckpt
    assert result["reason"]  # str(cap) is surfaced
    assert result["verdict"] == {"capped": True}
    # destroy-after-use holds even when the session cap fires (finally).
    assert result["vm"]["state"] == DESTROYED
    assert result["vm"]["session_id"] == handle_session
    # the destroy note was logged through the runner.
    assert "destroyed" in getattr(loop.runner, "last_note", "").lower()


# --------------------------------------------------------------------------- #
# 9. The @app.entrypoint async-generator flow (offline; agentcore mocked out)  #
# --------------------------------------------------------------------------- #
def _drive(agen):
    """Synchronously drain an async generator into a list of yielded events."""
    async def _collect():
        out = []
        async for ev in agen:
            out.append(ev)
        return out

    return asyncio.run(_collect())


def _fresh_ep(tmp_path, monkeypatch):
    """Load the entrypoint module and pin its checkpoint dir to a temp path so no
    checkpoint files land in the cwd (12-factor env override)."""
    monkeypatch.setenv("SENTINEL_DETONATION_CHECKPOINT_DIR", str(tmp_path / "ckpt"))
    # Ensure the session cap is disabled unless a test opts in.
    monkeypatch.delenv("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION", raising=False)
    return _load_detonation_entrypoint()


def _patch_build_runner(ep, monkeypatch, fake, *, decision_fn=sim.auto_approve, captured=None):
    """Replace ep.build_runner with an offline, AWS-free version that drives the
    plan through our scripted FakeHarness. This is the module's own DI seam — it
    builds a real PlayModeRunner (so GATE_NAME etc. stay intact) wired to fake
    invoke/resume fns, still honoring the env-driven session cap via ep._session_cap().
    """
    def _build(harness_arn, *, plan=None, plan_id="detonation", session_id=None,
               mode=rl.CONTINUOUS, resume=False, **_ignored):
        if captured is not None:
            captured["session_id"] = session_id
            captured["plan_id"] = plan_id
        runner = sim.PlayModeRunner(
            harness_arn,
            plan=plan or ep.DEFAULT_DETONATION_PLAN,
            plan_id=plan_id,
            session_id=session_id,
            checkpoint_path=ep._checkpoint_path(plan_id),
            invoke_fn=fake.invoke,
            resume_fn=fake.resume,
            decision_fn=decision_fn,
            logger=lambda m: None,
        )
        return BasRunnerLoop(runner, mode=mode, max_steps_per_session=ep._session_cap())

    monkeypatch.setattr(ep, "build_runner", _build)


def test_entrypoint_missing_harness_arn_yields_error(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    events = _drive(ep._detonation_entrypoint({}))
    assert len(events) == 1
    assert events[0]["event"] == "error"
    assert "harness_arn" in events[0]["reason"]


def test_entrypoint_none_payload_yields_error(tmp_path, monkeypatch):
    """A None payload is normalised to {} → still the missing-arn error branch."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    events = _drive(ep._detonation_entrypoint(None))
    assert events == [
        {"event": "error", "reason": "payload.harness_arn is required for a detonation run"}
    ]


def test_entrypoint_invalid_sample_reference_yields_error(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    events = _drive(
        ep._detonation_entrypoint(
            {"harness_arn": ARN, "sample_s3_uri": "https://evil.example/malware.bin"}
        )
    )
    assert len(events) == 1
    assert events[0]["event"] == "error"
    assert "invalid sample reference" in events[0]["reason"]


def test_entrypoint_full_flow_started_then_result(tmp_path, monkeypatch):
    """Drive the whole async-gen main flow offline: started(HEALTHY_BUSY) event,
    then the terminal run_detonation result. auto_approve so the plan completes."""
    ep = _fresh_ep(tmp_path, monkeypatch)

    fake = FakeHarness()
    _patch_build_runner(ep, monkeypatch, fake)

    events = _drive(
        ep._detonation_entrypoint(
            {
                "harness_arn": ARN,
                "plan_id": "detoflow",
                "session_id": SESSION,
                "sample_s3_uri": "s3://dropbox/quarantine/xyz",
                "plan": PLAN,
            }
        )
    )

    assert len(events) == 2
    started, result = events
    assert started["event"] == "started"
    assert started["status"] == "HEALTHY_BUSY"
    assert started["plan_id"] == "detoflow"
    assert started["sample"]["s3_uri"] == "s3://dropbox/quarantine/xyz"

    assert result["event"] == "plan_complete"
    assert result["vm"]["state"] == DESTROYED
    # every step was gated + resumed (offline, simulated) before VM teardown.
    assert len(fake.resumes) == len(PLAN)


def test_entrypoint_no_sample_started_event_has_null_sample(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    fake = FakeHarness()
    _patch_build_runner(ep, monkeypatch, fake)

    events = _drive(ep._detonation_entrypoint({"harness_arn": ARN, "plan": PLAN}))
    started, result = events
    assert started["sample"] is None
    assert result["event"] == "plan_complete"


def test_entrypoint_session_id_falls_back_to_context(tmp_path, monkeypatch):
    """When payload has no session_id, the runtimeSessionId comes from context."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    fake = FakeHarness()
    captured = {}
    _patch_build_runner(ep, monkeypatch, fake, captured=captured)

    class _Ctx:
        session_id = "ctx-session-000000000000000000"

    events = _drive(ep._detonation_entrypoint({"harness_arn": ARN, "plan": PLAN}, _Ctx()))
    assert captured["session_id"] == "ctx-session-000000000000000000"
    assert events[-1]["event"] == "plan_complete"


def test_entrypoint_restart_required_when_session_capped(tmp_path, monkeypatch):
    """A low per-session step cap makes the CONTINUOUS loop raise SessionCapReached
    mid-plan; the entrypoint surfaces it as a restart_required terminal event."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    monkeypatch.setenv("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION", "1")

    fake = FakeHarness()
    _patch_build_runner(ep, monkeypatch, fake)

    events = _drive(ep._detonation_entrypoint({"harness_arn": ARN, "plan": PLAN}))
    started, result = events
    assert started["event"] == "started"
    assert result["event"] == "restart_required"
    assert result["steps_done"] == 1
    assert result["checkpoint_path"]  # WIP-committed for the resume
    # destroy-after-use still holds even when the cap fires.
    assert result["vm"]["state"] == DESTROYED


# --------------------------------------------------------------------------- #
# 10. add_async_task busy-ping wiring: HEALTHY_BUSY path + unavailable fallback #
# --------------------------------------------------------------------------- #
def test_entrypoint_add_async_task_invoked_when_in_image(tmp_path, monkeypatch):
    """When running 'in-image' (agentcore present), the async task is registered
    so the ping reports HEALTHY_BUSY. Simulated with a fake app; no AWS."""
    ep = _fresh_ep(tmp_path, monkeypatch)

    calls = []

    class _FakeApp:
        def add_async_task(self, name):
            calls.append(name)

    monkeypatch.setattr(ep, "_HAS_AGENTCORE", True)
    monkeypatch.setattr(ep, "app", _FakeApp())

    fake = FakeHarness()
    _patch_build_runner(ep, monkeypatch, fake)

    events = _drive(ep._detonation_entrypoint({"harness_arn": ARN, "plan": PLAN}))
    assert calls == ["detonation_plan"]
    assert events[0]["event"] == "started"
    assert events[-1]["event"] == "plan_complete"


def test_entrypoint_add_async_task_unavailable_falls_back(tmp_path, monkeypatch, capsys):
    """If add_async_task raises (wiring unavailable), the run must NOT fail — it
    logs and continues to produce the started + terminal events."""
    ep = _fresh_ep(tmp_path, monkeypatch)

    class _FlakyApp:
        def add_async_task(self, name):
            raise RuntimeError("async task wiring unavailable")

    monkeypatch.setattr(ep, "_HAS_AGENTCORE", True)
    monkeypatch.setattr(ep, "app", _FlakyApp())

    fake = FakeHarness()
    _patch_build_runner(ep, monkeypatch, fake)

    events = _drive(ep._detonation_entrypoint({"harness_arn": ARN, "plan": PLAN}))
    # The run survived the flaky heartbeat wiring.
    assert events[0]["event"] == "started"
    assert events[-1]["event"] == "plan_complete"
    out = capsys.readouterr().out
    assert "add_async_task unavailable" in out


# --------------------------------------------------------------------------- #
# 11. build_runner: fresh construction, resume-from-checkpoint, cap wiring      #
# --------------------------------------------------------------------------- #
def test_build_runner_fresh_builds_loop_over_default_plan(tmp_path, monkeypatch):
    """build_runner with resume=False builds a loop over the DEFAULT plan (no
    checkpoint read). No AWS: we only construct, never .run()."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    loop = ep.build_runner(ARN, plan_id="detobuild", session_id=SESSION)
    assert isinstance(loop, BasRunnerLoop)
    # default plan wired in (three illustrative steps).
    assert len(loop.state.steps) == len(ep.DEFAULT_DETONATION_PLAN)
    assert loop.runner.checkpoint_path.endswith("detobuild.json")
    # session cap unset -> disabled.
    assert loop.max_steps_per_session is None


def test_build_runner_honors_session_cap_env(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    monkeypatch.setenv("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION", "2")
    loop = ep.build_runner(ARN, plan_id="detocap", session_id=SESSION)
    assert loop.max_steps_per_session == 2


def test_build_runner_resume_reads_existing_checkpoint(tmp_path, monkeypatch):
    """resume=True with an existing checkpoint rebuilds from it (resume path,
    not a fresh construction)."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    plan_id = "detoresume"

    # First, create a real checkpoint by building a fresh loop and checkpointing.
    seed = ep.build_runner(ARN, plan=PLAN, plan_id=plan_id, session_id=SESSION)
    seed.runner._checkpoint()
    ckpt = ep._checkpoint_path(plan_id)
    assert os.path.isfile(ckpt)

    # Now resume=True must load that checkpoint rather than start fresh.
    resumed = ep.build_runner(ARN, plan_id=plan_id, session_id=SESSION, resume=True)
    assert resumed.runner.checkpoint_path == ckpt
    assert resumed.state.session_id == SESSION
    assert len(resumed.state.steps) == len(PLAN)


def test_build_runner_resume_without_checkpoint_starts_fresh(tmp_path, monkeypatch):
    """resume=True but NO checkpoint on disk -> falls through to a fresh runner."""
    ep = _fresh_ep(tmp_path, monkeypatch)
    loop = ep.build_runner(ARN, plan=PLAN, plan_id="detomissing",
                           session_id=SESSION, resume=True)
    assert len(loop.state.steps) == len(PLAN)


# --------------------------------------------------------------------------- #
# 12. _session_cap: invalid (non-int) env value raises a clear ValueError       #
# --------------------------------------------------------------------------- #
def test_session_cap_invalid_env_raises(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    monkeypatch.setenv("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION", "not-an-int")
    with pytest.raises(ValueError, match="must be an int"):
        ep._session_cap()


def test_session_cap_unset_is_none(tmp_path, monkeypatch):
    ep = _fresh_ep(tmp_path, monkeypatch)
    monkeypatch.delenv("SENTINEL_DETONATION_MAX_STEPS_PER_SESSION", raising=False)
    assert ep._session_cap() is None
