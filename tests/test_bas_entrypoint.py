"""
`bas-runner/bedrock_entrypoint.py` — the module's own testability claim, tested.
==============================================================================
This file was the lowest-covered module in the repository at **19%**, and the reason was
not that it is hard to test. Its own docstring says:

    "Import is guarded so this module is importable (and unit-testable) without it —
     ``app`` is then None and :func:`build_loop` / :func:`run_plan` still work for
     offline tests."

`tests/test_bas_runner.py` has 17 tests, all of which exercise `runner_loop.py` (well
covered as a result). It touches this module exactly once:

    import bedrock_entrypoint as ep
    assert callable(ep.build_loop)
    assert callable(ep.run_plan)

It checks that the functions EXIST and never calls them. 19% is precisely "module-level
statements plus three one-line config helpers executed by the import" — the bodies of
`build_loop`, `run_plan`, `_bas_entrypoint`, `_mirror_to_s3` and `_session_cap` never ran.

That matters because the uncovered code is not glue. It holds:

* the `expected_plan` binding in `build_loop` (INV-PLAY-3) — without it a substituted
  checkpoint resumes unchallenged, and this runner mirrors checkpoints to S3, so the file
  lives somewhere with a broader write surface than local disk;
* `run_plan`'s `SessionCapReached` handling, which turns a cap into a WIP-committed
  `restart_required` rather than an error;
* `_mirror_to_s3`'s deliberate exception swallowing — a mirror failure must never break the
  plan loop, and "best effort" is exactly the kind of claim that rots silently.

A self-certified testability claim that nothing exercises is the R16 shape. These tests
call the functions.

ZERO AWS, ZERO network: the runner is dependency-injected (`invoke_fn` / `resume_fn` /
`decision_fn`), and the one S3 path is driven with an injected fake client.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

# Hermetic imports: no real region/profile/credential resolution.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_BAS_DIR = os.path.join(os.path.dirname(__file__), "..", "longrunning", "bas-runner")
sys.path.insert(0, os.path.abspath(_BAS_DIR))

from sentinel_harness import simulation as sim  # noqa: E402

import bedrock_entrypoint as ep  # noqa: E402
import runner_loop as rl  # noqa: E402

ARN = "arn:aws:test:harness/hid-bas-entry"
SESSION = "bas-entry-session-0000000000000000000000000"

PLAN = [
    {"phase": "recon", "technique": "T1595", "objective": "sim recon"},
    {"phase": "initial-access", "technique": "T1190", "objective": "sim initial access"},
    {"phase": "execution", "technique": "T1059", "objective": "sim execution"},
]


def _technique_from_prompt(prompt: str) -> str:
    """The gate payload must name the technique the step is about (INV-PLAY-6)."""
    import re
    match = re.search(r"Technique:\s*([^.\s]+)", prompt or "")
    return match.group(1) if match else "T0000"


class FakeHarness:
    """Scripted harness that pauses on the gate every invoke. No AWS, no network."""

    def __init__(self):
        self.invokes: list = []
        self._n = 0

    def invoke(self, harness_arn, session_id, text, **_kw):
        self.invokes.append(session_id)
        self._n += 1
        return {
            "stop_reason": "tool_use",
            "tool_use": {
                "toolUseId": f"tu-{self._n}",
                "name": sim.PlayModeRunner.GATE_NAME,
                "input": {"technique": _technique_from_prompt(text)},
            },
            "text": "",
        }

    def resume(self, harness_arn, session_id, tool_use, result, status="success", **_kw):
        return {"stop_reason": "end_turn", "text": "resumed", "tool_use": None}


@pytest.fixture
def bas_env(tmp_path, monkeypatch):
    """Point the entrypoint's checkpoint dir at tmp_path and clear its env knobs."""
    monkeypatch.setenv("SENTINEL_BAS_CHECKPOINT_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINEL_BAS_MAX_STEPS_PER_SESSION", raising=False)
    monkeypatch.delenv("SENTINEL_BAS_S3_BUCKET", raising=False)
    monkeypatch.delenv("SENTINEL_BAS_S3_PREFIX", raising=False)
    return tmp_path


# --------------------------------------------------------------------------- #
# config helpers                                                              #
# --------------------------------------------------------------------------- #
class TestConfigHelpers:

    def test_checkpoint_path_honours_the_env_dir(self, bas_env):
        path = ep._checkpoint_path("plan-a")
        assert path == os.path.join(str(bas_env), "plan-a.json")

    def test_checkpoint_dir_defaults_when_unset(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_BAS_CHECKPOINT_DIR", raising=False)
        assert ep._checkpoint_dir() == "bas_checkpoints"

    def test_session_cap_is_none_when_unset(self, bas_env):
        assert ep._session_cap() is None

    def test_session_cap_parses_an_int(self, bas_env, monkeypatch):
        monkeypatch.setenv("SENTINEL_BAS_MAX_STEPS_PER_SESSION", "2")
        assert ep._session_cap() == 2

    def test_session_cap_refuses_a_non_int_loudly(self, bas_env, monkeypatch):
        """A typo'd cap must not silently become "no cap" — that would let a run exceed
        the Runtime lifetime and die without a WIP checkpoint."""
        monkeypatch.setenv("SENTINEL_BAS_MAX_STEPS_PER_SESSION", "lots")
        with pytest.raises(ValueError, match="must be an int"):
            ep._session_cap()


# --------------------------------------------------------------------------- #
# build_loop — including the INV-PLAY-3 plan binding                          #
# --------------------------------------------------------------------------- #
class TestBuildLoop:

    def test_builds_a_fresh_loop_with_the_given_plan(self, bas_env):
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="fresh", session_id=SESSION,
            invoke_fn=fake.invoke, resume_fn=fake.resume,
            decision_fn=sim.auto_approve,
        )
        assert isinstance(loop, rl.BasRunnerLoop)
        assert loop.state.plan_id == "fresh"
        assert loop.runner.checkpoint_path == os.path.join(str(bas_env), "fresh.json")

    def test_the_session_cap_reaches_the_loop(self, bas_env, monkeypatch):
        monkeypatch.setenv("SENTINEL_BAS_MAX_STEPS_PER_SESSION", "1")
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="capped",
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        assert loop.max_steps_per_session == 1

    def test_resume_with_no_checkpoint_starts_fresh(self, bas_env):
        """`resume=True` with nothing on disk must not raise — the first invocation of a
        restartable plan legitimately has no checkpoint yet."""
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="nofile", resume=True,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        assert loop.state.plan_id == "nofile"

    def test_resume_continues_from_a_real_checkpoint(self, bas_env):
        """Run one step, then rebuild with resume=True and confirm the completed step is
        not re-approved."""
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="resumable", session_id=SESSION,
            mode=rl.RUN_ONCE,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        ep.run_plan(loop)
        done_before = sum(1 for s in loop.state.steps if s.status != "pending")
        assert done_before >= 1, "the first turn advanced nothing; the fixture is wrong"

        fake2 = FakeHarness()
        resumed = ep.build_loop(
            ARN, plan=PLAN, plan_id="resumable", resume=True,
            invoke_fn=fake2.invoke, resume_fn=fake2.resume, decision_fn=sim.auto_approve,
        )
        done_after = sum(1 for s in resumed.state.steps if s.status != "pending")
        assert done_after == done_before, (
            "resuming lost or redid completed steps: "
            f"{done_before} done before, {done_after} after"
        )

    def test_resume_refuses_a_substituted_plan(self, bas_env):
        """INV-PLAY-3, at the layer that matters most.

        `build_loop` passes `expected_plan` to `resume_from_checkpoint`. Without it the
        checkpoint is the only source of the plan, so a swapped file resumes unchallenged —
        and it would be internally consistent with a recomputable digest, so no other layer
        could catch it. This runner mirrors checkpoints to S3 when configured, i.e. to a
        location with a broader write surface than local disk.
        """
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="bound", session_id=SESSION, mode=rl.RUN_ONCE,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        ep.run_plan(loop)

        hostile = [
            {"phase": "recon", "technique": "T1595", "objective": "sim recon"},
            {"phase": "impact", "technique": "T1486", "objective": "ransomware, injected"},
        ]
        with pytest.raises(Exception) as excinfo:
            ep.build_loop(
                ARN, plan=hostile, plan_id="bound", resume=True,
                invoke_fn=fake.invoke, resume_fn=fake.resume,
                decision_fn=sim.auto_approve,
            )
        assert excinfo.value is not None, "a substituted plan resumed without complaint"


# --------------------------------------------------------------------------- #
# run_plan — the event shapes, including the restart path                     #
# --------------------------------------------------------------------------- #
class TestRunPlan:

    def test_a_completed_plan_yields_plan_complete(self, bas_env):
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="done", session_id=SESSION,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        result = ep.run_plan(loop)
        assert result["event"] == "plan_complete", result
        assert result["s3_uri"] is None, "no bucket configured; must not invent a URI"
        assert result["verdict"] is not None
        assert result["turn"]["complete"] is True

    def test_a_rejected_step_yields_plan_halted(self, bas_env):
        """A human rejection HALTS the plan — the offensive step must not proceed."""
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="halted", session_id=SESSION,
            invoke_fn=fake.invoke, resume_fn=fake.resume,
            decision_fn=lambda *_a, **_k: {"approved": False, "reason": "analyst said no"},
        )
        result = ep.run_plan(loop)
        assert result["event"] == "plan_halted", result
        executed = [s for s in loop.state.steps if s.status == "executed"]
        assert not executed, f"a step executed after rejection: {executed}"

    def test_the_session_cap_becomes_a_restart_event(self, bas_env, monkeypatch):
        """The whole point of the long-running tier: hitting the cap is a WIP commit and a
        restart request, never an error."""
        monkeypatch.setenv("SENTINEL_BAS_MAX_STEPS_PER_SESSION", "1")
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="capped", session_id=SESSION,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        result = ep.run_plan(loop)
        assert result["event"] == "restart_required", result
        assert result["steps_done"] == 1
        assert result["checkpoint_path"], "a restart event with no checkpoint loses the WIP"
        assert os.path.isfile(result["checkpoint_path"]), "the WIP was not persisted"
        saved = json.loads(open(result["checkpoint_path"], encoding="utf-8").read())
        assert saved, "the checkpoint file is empty"

    def test_run_once_mode_yields_turn_done(self, bas_env):
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="once", session_id=SESSION, mode=rl.RUN_ONCE,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        result = ep.run_plan(loop)
        assert result["event"] in ("turn_done", "plan_complete"), result


# --------------------------------------------------------------------------- #
# _mirror_to_s3 — best-effort means it must NEVER raise into the plan loop     #
# --------------------------------------------------------------------------- #
class TestS3Mirror:

    def test_no_bucket_means_no_mirror(self, bas_env):
        assert ep._mirror_to_s3("/tmp/whatever.json", "plan") is None

    def test_a_configured_bucket_produces_an_s3_uri(self, bas_env, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINEL_BAS_S3_BUCKET", "sentinel-test-bucket")
        monkeypatch.setenv("SENTINEL_BAS_S3_PREFIX", "bas-checkpoints")
        local = tmp_path / "plan-x.json"
        local.write_text("{}", encoding="utf-8")

        uploaded = {}

        class _FakeS3:
            def upload_file(self, path, bucket, key):
                uploaded.update(path=path, bucket=bucket, key=key)

        import boto3
        monkeypatch.setattr(boto3, "client", lambda service, **_kw: _FakeS3())
        uri = ep._mirror_to_s3(str(local), "plan-x")
        assert uri == "s3://sentinel-test-bucket/bas-checkpoints/plan-x.json"
        assert uploaded["bucket"] == "sentinel-test-bucket"
        assert uploaded["key"] == "bas-checkpoints/plan-x.json"

    def test_an_empty_prefix_puts_the_key_at_the_root(self, bas_env, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINEL_BAS_S3_BUCKET", "b")
        monkeypatch.setenv("SENTINEL_BAS_S3_PREFIX", "/")
        local = tmp_path / "p.json"
        local.write_text("{}", encoding="utf-8")
        import boto3
        monkeypatch.setattr(boto3, "client",
                            lambda service, **_kw: type("S", (), {"upload_file": lambda *a: None})())
        assert ep._mirror_to_s3(str(local), "p") == "s3://b/p.json"

    def test_an_upload_failure_is_swallowed_and_local_wins(self, bas_env, monkeypatch,
                                                           tmp_path, capsys):
        """The docstring promises "never raises into the plan loop". Tested, because
        best-effort error handling is exactly the claim that rots unnoticed: an exception
        escaping here would abort a plan that has already banked human approvals."""
        monkeypatch.setenv("SENTINEL_BAS_S3_BUCKET", "b")
        local = tmp_path / "p.json"
        local.write_text("{}", encoding="utf-8")

        class _Boom:
            def upload_file(self, *_a):
                raise RuntimeError("AccessDenied: no s3:PutObject")

        import boto3
        monkeypatch.setattr(boto3, "client", lambda service, **_kw: _Boom())
        assert ep._mirror_to_s3(str(local), "p") is None
        assert "mirror failed" in capsys.readouterr().out, (
            "a silent mirror failure is indistinguishable from a successful one"
        )

    def test_a_mirror_failure_does_not_break_run_plan(self, bas_env, monkeypatch):
        """The property that actually matters: the plan still completes."""
        monkeypatch.setenv("SENTINEL_BAS_S3_BUCKET", "b")

        class _Boom:
            def upload_file(self, *_a):
                raise RuntimeError("network unreachable")

        import boto3
        monkeypatch.setattr(boto3, "client", lambda service, **_kw: _Boom())
        fake = FakeHarness()
        loop = ep.build_loop(
            ARN, plan=PLAN, plan_id="mirrorfail", session_id=SESSION,
            invoke_fn=fake.invoke, resume_fn=fake.resume, decision_fn=sim.auto_approve,
        )
        result = ep.run_plan(loop)
        assert result["event"] == "plan_complete", result
        assert result["s3_uri"] is None


# --------------------------------------------------------------------------- #
# the async entrypoint body                                                   #
# --------------------------------------------------------------------------- #
class TestTheAsyncEntrypoint:
    """`_bas_entrypoint` is kept separate from the `@app.entrypoint` decorator precisely
    so it can be driven without `bedrock_agentcore`. Nothing was driving it."""

    @staticmethod
    def _drain(payload):
        import asyncio

        async def _collect():
            return [event async for event in ep._bas_entrypoint(payload)]

        return asyncio.run(_collect())

    def test_a_missing_harness_arn_yields_a_single_error_event(self, bas_env):
        events = self._drain({})
        assert len(events) == 1, events
        assert events[0]["event"] == "error"
        assert "harness_arn" in events[0]["reason"]

    def test_a_none_payload_is_handled(self, bas_env):
        events = self._drain(None)
        assert events[0]["event"] == "error"

    def test_a_full_run_yields_started_then_a_terminal_event(self, bas_env, monkeypatch):
        """The HEALTHY_BUSY heartbeat contract: `started` must come first, so the platform
        ping reports busy rather than idle while the plan runs.

        `_bas_entrypoint` calls `build_loop` without invoke/resume fns — which in a live run
        is correct (it wants the real AWS ones) and here would reach AWS. So `build_loop` is
        wrapped to inject the fakes. The ORIGINAL is captured before patching: the first
        version of this shim called `ep.build_loop` from inside its own replacement and
        recursed until the stack blew.
        """
        fake = FakeHarness()
        original_build_loop = ep.build_loop

        def _with_fakes(harness_arn, **kwargs):
            kwargs.setdefault("invoke_fn", fake.invoke)
            kwargs.setdefault("resume_fn", fake.resume)
            kwargs.setdefault("decision_fn", sim.auto_approve)
            return original_build_loop(harness_arn, **kwargs)

        monkeypatch.setattr(ep, "build_loop", _with_fakes)
        events = self._drain({"harness_arn": ARN, "plan": PLAN, "plan_id": "asyncrun",
                              "session_id": SESSION})
        assert events[0]["event"] == "started", events
        assert events[0]["status"] == "HEALTHY_BUSY"
        assert events[0]["plan_id"] == "asyncrun"
        assert events[-1]["event"] in ("plan_complete", "plan_halted", "turn_done",
                                       "restart_required"), events


# --------------------------------------------------------------------------- #
# the guarded import, asserted rather than assumed                            #
# --------------------------------------------------------------------------- #
def test_the_module_is_importable_without_agentcore():
    """The docstring's claim. `_HAS_AGENTCORE` False must imply `app is None`, and the
    pure-Python driver must be usable either way."""
    assert ep._HAS_AGENTCORE in (True, False)
    if not ep._HAS_AGENTCORE:
        assert ep.app is None
    assert callable(ep.build_loop) and callable(ep.run_plan)


def test_run_plan_reports_the_verdict_from_the_runner():
    """`verdict()` is what a reviewer reads to see whether any offensive step ran. It must
    come from the runner, not be synthesised by the event shaper."""
    import inspect
    source = inspect.getsource(ep.run_plan)
    assert "loop.runner.verdict()" in source, (
        "run_plan no longer reads the verdict from the runner — a hand-built verdict "
        "could disagree with what actually happened"
    )


class TestTheHealthyBusyHeartbeat:
    """The `add_async_task` wiring — reachable offline by faking the in-image app object.

    It is marked `# pragma: no cover` because it "only [matters] inside the Runtime image",
    and that is true of the SUCCESS path. But the branch below it swallows an exception
    with the comment "never fail the run on heartbeat wiring", and a swallowed exception is
    a claim, not a detail: if it ever stopped holding, a heartbeat-wiring problem would
    abort a plan that may already have banked hours of human approvals. Faking `app` makes
    both paths testable without the image.
    """

    @staticmethod
    def _drain(payload):
        import asyncio

        async def _collect():
            return [event async for event in ep._bas_entrypoint(payload)]

        return asyncio.run(_collect())

    def test_the_async_task_is_registered_when_running_in_image(self, bas_env, monkeypatch):
        calls = []

        class _FakeApp:
            def add_async_task(self, name):
                calls.append(name)

        monkeypatch.setattr(ep, "_HAS_AGENTCORE", True)
        monkeypatch.setattr(ep, "app", _FakeApp())
        events = self._drain({})   # no harness_arn -> returns before build_loop
        # The registration happens only after the arn check, so this proves the ORDER:
        # a payload with no arn must not mark the Runtime busy for a run that never starts.
        assert calls == [], (
            "the Runtime was marked HEALTHY_BUSY for a request that was rejected — the ping "
            f"would report busy with no plan running: {calls}"
        )
        assert events[0]["event"] == "error"

    def test_a_failing_add_async_task_does_not_abort_the_run(self, bas_env, monkeypatch,
                                                            capsys):
        """The swallowed-exception claim. A heartbeat-wiring failure must degrade to a log
        line, never take down a plan holding banked human approvals."""
        class _BrokenApp:
            def add_async_task(self, name):
                raise RuntimeError("async task API unavailable in this image")

        fake = FakeHarness()
        original_build_loop = ep.build_loop

        def _with_fakes(harness_arn, **kwargs):
            kwargs.setdefault("invoke_fn", fake.invoke)
            kwargs.setdefault("resume_fn", fake.resume)
            kwargs.setdefault("decision_fn", sim.auto_approve)
            return original_build_loop(harness_arn, **kwargs)

        monkeypatch.setattr(ep, "_HAS_AGENTCORE", True)
        monkeypatch.setattr(ep, "app", _BrokenApp())
        monkeypatch.setattr(ep, "build_loop", _with_fakes)

        events = self._drain({"harness_arn": ARN, "plan": PLAN, "plan_id": "hbfail",
                              "session_id": SESSION})
        assert events[0]["event"] == "started", events
        assert events[-1]["event"] == "plan_complete", (
            f"a heartbeat-wiring failure aborted the plan: {events}"
        )
        assert "add_async_task unavailable" in capsys.readouterr().out, (
            "the failure was swallowed SILENTLY — an operator cannot tell the Runtime is "
            "not reporting HEALTHY_BUSY"
        )

    def test_a_working_app_registers_the_task_for_a_real_run(self, bas_env, monkeypatch):
        calls = []

        class _FakeApp:
            def add_async_task(self, name):
                calls.append(name)

        fake = FakeHarness()
        original_build_loop = ep.build_loop

        def _with_fakes(harness_arn, **kwargs):
            kwargs.setdefault("invoke_fn", fake.invoke)
            kwargs.setdefault("resume_fn", fake.resume)
            kwargs.setdefault("decision_fn", sim.auto_approve)
            return original_build_loop(harness_arn, **kwargs)

        monkeypatch.setattr(ep, "_HAS_AGENTCORE", True)
        monkeypatch.setattr(ep, "app", _FakeApp())
        monkeypatch.setattr(ep, "build_loop", _with_fakes)
        events = self._drain({"harness_arn": ARN, "plan": PLAN, "plan_id": "hbok",
                              "session_id": SESSION})
        assert calls == ["bas_plan"], f"the async task was not registered: {calls}"
        assert events[-1]["event"] == "plan_complete", events
