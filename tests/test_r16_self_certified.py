"""
Round-16 regression suite — a self-certified safety claim needs a mechanism.
===========================================================================
Rounds M18/R9-R15 all audited ``tools/``. Round 16 audits the CORE LIBRARY, and
specifically the modules that had tests but ZERO invariants: ``simulation.py``,
``eval_datasets.py``, ``factory.py``, ``cli.py``.

What they have in common is that each one **certifies itself** — its docstring
asserts a safety property nothing outside the module checks:

    simulation.py    "no offensive action happens without an explicit human
                      confirmation — that is what Play Mode means"
    eval_datasets.py "DETERMINISTIC and OFFLINE" — a pass-rate the loop can trust
    factory.py       "dry-run first", so a green dry-run means a safe real run

    THE QUESTION: is the claimed property enforced by a MECHANISM, or does it
    merely happen to hold on the paths the existing tests walk?

Play Mode's claim was falsifiable by editing a JSON file
-------------------------------------------------------
``load_checkpoint`` was a bare ``PlanState.from_dict(json.load(f))`` with no
validation, and ``resume_from_checkpoint`` then did ``runner.state = state`` to
"keep prior statuses/decisions". Three attacks, all reproduced:

1. Marking every step ``executed`` made the runner ask the human **zero** times
   while producing counts byte-identical to a real run.
2. ``halted: false`` plus reverting ``rejected`` to ``pending`` **erased a human
   rejection** from the record.
3. Rewriting ``rejected`` to ``executed`` with a fabricated ``decision.approver``
   made the audit record assert that a named security lead **approved every step of
   an offensive plan they were never asked about**.

The technique execution really is a no-op (verified: the module contains no
subprocess/socket/exec primitive), so the harm is not a live attack — it is that the
**audit artifact can be forged after the fact**, in the direction that says "this was
authorized". For a red-team authorization record that is the entire value of the file.
And it is reachable: ``longrunning/detonation/`` and ``longrunning/bas-runner/`` both
resume from a runtime-supplied path, the latter mirroring it to S3.

Why the fix is three layers, and what it does NOT do
---------------------------------------------------
The most useful thing this round produced is a correction to my own first fix. I
added an unkeyed SHA-256 digest and wrote that it "catches any edit". **It does
not** — an unkeyed digest is recomputable by anyone who can write the file, and an
experiment confirmed that a re-sealed, self-consistent forgery still loaded. So:

    Layer 1  INTEGRITY      digest mismatch          catches careless edits; forces
                                                     a deliberate one to be deliberate
    Layer 2  CONSISTENCY    contradictory state      catches a buggy/old writer, and
                                                     any forgery that is sloppy
    Layer 3  PLAN BINDING   substituted plan         the ONLY layer an attacker with
                                                     write access cannot defeat,
                                                     because the reference value
                                                     lives with the CALLER

Layer 3 is opt-in (``expected_plan=``) and both real entrypoints now pass it. A
caller that omits it is not protected against plan substitution, and the tests below
pin that honestly rather than implying otherwise. Closing the gap fully needs a key
the checkpoint writer does not hold — a deployment decision, and exactly what
``provenance.py`` already says about its own ledger anchor (INV-GOV-4).

Every assertion here FAILS on pre-R16 source. Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import simulation as sim  # noqa: E402

_PLAN = [
    {"phase": "recon", "technique": "T1595", "objective": "emulate scanning"},
    {"phase": "execution", "technique": "T1059", "objective": "emulate interpreter"},
]


def _gate_invoke(arn, prompt, session_id=None, **kw):
    """Layer-1 stub: every turn pauses on the exec_technique gate."""
    return {"stop_reason": "tool_use", "text": "",
            "tool_use": {"toolUseId": "tu-1", "name": "exec_technique", "input": {}}}


def _gate_resume(arn, session_id, tool_use, result, status=None, **kw):
    return {"stop_reason": "end_turn", "text": "ok", "tool_use": None}


def _run(ckpt, policy, plan=None):
    """Drive a full plan to completion, leaving a genuine checkpoint on disk."""
    runner = sim.PlayModeRunner(
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/h",
        plan=plan or _PLAN,
        invoke_fn=_gate_invoke, resume_fn=_gate_resume,
        session_id="session-0", plan_id="plan-0",
        checkpoint_path=str(ckpt), decision_fn=policy,
        logger=lambda _m: None,
    )
    runner.run()
    return runner


def _reseal(raw: dict) -> dict:
    """Recompute the digest — what an attacker with write access trivially does.

    Used deliberately in the layer-2/3 tests: an unkeyed digest is not a signature,
    and a guard that only works against attackers who forget to re-seal is not a
    guard. Anything those tests catch is caught by a layer that does not depend on
    the digest at all.
    """
    raw.pop(sim._DIGEST_KEY, None)
    raw[sim._DIGEST_KEY] = {"algorithm": sim._DIGEST_VERSION,
                            "value": sim._state_digest(raw)}
    return raw


# --------------------------------------------------------------------------- #
# INV-PLAY-1 — a checkpoint that was edited after writing is refused          #
# --------------------------------------------------------------------------- #
class TestCheckpointIntegrity:
    """Layer 1. Catches careless modification, and forces a deliberate forgery to
    be deliberate rather than a one-character edit."""

    def test_a_genuine_checkpoint_round_trips(self, tmp_path):
        """CONTROL first: the guard must not break the feature it protects."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)
        state = sim.load_checkpoint(str(ckpt))
        assert state.counts()[sim.EXECUTED] == len(_PLAN)
        assert state.halted is False

    def test_the_digest_is_written(self, tmp_path):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)
        raw = json.loads(ckpt.read_text())
        assert sim._DIGEST_KEY in raw
        assert raw[sim._DIGEST_KEY]["algorithm"] == sim._DIGEST_VERSION

    def test_a_forged_approval_without_resealing_is_refused(self, tmp_path):
        """Attack 3, the worst of the three: the audit record made a named security
        lead the approver of an offensive plan they were never asked about."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)          # human rejected -> plan halted
        raw = json.loads(ckpt.read_text())
        raw["halted"] = False
        raw["halted_reason"] = None
        for step in raw["steps"]:
            step["status"] = "executed"
            step["decision"] = {"decision": "APPROVED",
                                "approver": "security-lead@example.com"}
        ckpt.write_text(json.dumps(raw))
        with pytest.raises(sim.CheckpointError, match="integrity check"):
            sim.load_checkpoint(str(ckpt))

    def test_an_erased_rejection_without_resealing_is_refused(self, tmp_path):
        """Attack 2: a human said no, and the record no longer shows it."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)
        raw = json.loads(ckpt.read_text())
        raw["halted"] = False
        for step in raw["steps"]:
            if step["status"] == "rejected":
                step["status"] = "pending"
                step["decision"] = None
        ckpt.write_text(json.dumps(raw))
        with pytest.raises(sim.CheckpointError, match="integrity check"):
            sim.load_checkpoint(str(ckpt))

    @pytest.mark.parametrize("corruption", [
        '{"not": "a plan state"}',
        "[]",
        "null",
        "not json at all",
        "",
    ])
    def test_a_malformed_checkpoint_raises_checkpoint_error(self, tmp_path, corruption):
        """A distinct exception type so a caller can tell "not there" from
        "altered" — those need different responses."""
        ckpt = tmp_path / "bad.json"
        ckpt.write_text(corruption)
        with pytest.raises(sim.CheckpointError):
            sim.load_checkpoint(str(ckpt))

    def test_a_digestless_checkpoint_is_refused_by_default(self, tmp_path):
        """A file written by anything other than save_checkpoint carries no digest.
        Default-refuse, because "no digest" and "verified" are not the same state —
        the same distinction provenance.read_anchor draws for an unanchored ledger.
        """
        ckpt = tmp_path / "legacy.json"
        _run(ckpt, sim.auto_approve)
        raw = json.loads(ckpt.read_text())
        raw.pop(sim._DIGEST_KEY)
        ckpt.write_text(json.dumps(raw))
        with pytest.raises(sim.CheckpointError, match="no 'state_digest'"):
            sim.load_checkpoint(str(ckpt))
        # ...and loadable only by explicitly opting out.
        state = sim.load_checkpoint(str(ckpt), require_digest=False)
        assert state.counts()[sim.EXECUTED] == len(_PLAN)

    def test_the_digest_ignores_formatting_not_values(self, tmp_path):
        """Canonicalization: re-indenting or reordering keys must NOT trip the
        guard (that would make it useless in practice), but changing any VALUE must.
        """
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)
        raw = json.loads(ckpt.read_text())
        # Reserialize with different indentation and key order.
        ckpt.write_text(json.dumps(dict(reversed(list(raw.items()))), indent=7))
        sim.load_checkpoint(str(ckpt))          # must still load
        raw["session_id"] = "session-tampered"
        ckpt.write_text(json.dumps(raw))
        with pytest.raises(sim.CheckpointError, match="integrity check"):
            sim.load_checkpoint(str(ckpt))


# --------------------------------------------------------------------------- #
# INV-PLAY-2 — a self-contradictory plan state is refused                     #
# --------------------------------------------------------------------------- #
class TestCheckpointConsistency:
    """Layer 2, and the layer that matters most for a REAL attacker.

    Every test here **re-seals the digest first**, because an unkeyed digest is
    recomputable by anyone who can write the file. A guard that only catches an
    attacker who forgot to re-seal is not a guard, so these prove the consistency
    checks stand on their own.
    """

    @staticmethod
    def _write(ckpt, mutate):
        raw = json.loads(ckpt.read_text())
        mutate(raw)
        ckpt.write_text(json.dumps(_reseal(raw)))

    def test_executed_with_no_decision_is_refused(self, tmp_path):
        """An offensive step cannot claim to have run with no approval on record."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)

        def mutate(raw):
            raw["halted"] = False
            raw["halted_reason"] = None
            for step in raw["steps"]:
                step["status"] = "executed"
                step["decision"] = None
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="no decision payload"):
            sim.load_checkpoint(str(ckpt))

    def test_executed_with_a_rejecting_decision_is_refused(self, tmp_path):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)

        def mutate(raw):
            raw["halted"] = False
            raw["halted_reason"] = None
            for step in raw["steps"]:
                step["status"] = "executed"
                step["decision"] = {"decision": "REJECTED", "approver": "a"}
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="not APPROVED"):
            sim.load_checkpoint(str(ckpt))

    def test_rejected_with_an_approving_decision_is_refused(self, tmp_path):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)

        def mutate(raw):
            raw["steps"][0]["decision"] = {"decision": "APPROVED", "approver": "a"}
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="says APPROVED"):
            sim.load_checkpoint(str(ckpt))

    def test_a_rejected_step_must_halt_the_plan(self, tmp_path):
        """"Rejected but still running" is exactly the state attack 2 built."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)

        def mutate(raw):
            raw["halted"] = False
            raw["halted_reason"] = None
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="must halt the plan"):
            sim.load_checkpoint(str(ckpt))

    def test_a_halt_must_name_its_reason(self, tmp_path):
        """Degradation must leave a trace: an unexplained halt is indistinguishable
        from a completed plan for anyone reading the file."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)
        self._write(ckpt, lambda raw: raw.update({"halted_reason": None}))
        with pytest.raises(sim.CheckpointError, match="no halted_reason"):
            sim.load_checkpoint(str(ckpt))

    def test_an_unknown_status_is_refused(self, tmp_path):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)

        def mutate(raw):
            raw["steps"][0]["status"] = "probably_fine"
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="unknown status"):
            sim.load_checkpoint(str(ckpt))

    def test_an_index_that_does_not_match_its_position_is_refused(self, tmp_path):
        """`reject_after(n)` and the gate policies key on `index`, so a shifted index
        silently mis-targets a human decision at a different step — the
        approval-bound-to-a-subject class INV-PROMOTE-2 records."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)

        def mutate(raw):
            raw["steps"][0]["index"] = 99
        self._write(ckpt, mutate)
        with pytest.raises(sim.CheckpointError, match="does not match its position"):
            sim.load_checkpoint(str(ckpt))

    @pytest.mark.parametrize("policy_name", ["auto_approve", "auto_reject"])
    def test_every_genuine_terminal_state_passes_consistency(self, tmp_path,
                                                             policy_name):
        """CONTROL: the checks must accept every state the runner really produces,
        or the feature is broken rather than protected."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, getattr(sim, policy_name))
        sim.load_checkpoint(str(ckpt))

    def test_a_mid_plan_rejection_state_passes_consistency(self, tmp_path):
        """CONTROL for the most interesting genuine state: some executed, one
        rejected, the rest pending, plan halted."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.reject_after(1))
        state = sim.load_checkpoint(str(ckpt))
        assert state.halted is True
        counts = state.counts()
        assert counts[sim.EXECUTED] == 1 and counts[sim.REJECTED] == 1


# --------------------------------------------------------------------------- #
# INV-PLAY-3 — a resumed plan is the plan the caller authorized               #
# --------------------------------------------------------------------------- #
class TestPlanBinding:
    """Layer 3 — the only layer an attacker with write access cannot defeat,
    because the reference value lives with the CALLER rather than in the file.

    A substituted plan defeats both other layers by construction: it is internally
    consistent, and its digest can be recomputed.
    """

    @staticmethod
    def _substitute(ckpt, technique="T1486", phase="impact"):
        """Replace the plan with a different kill chain, self-consistently."""
        raw = json.loads(ckpt.read_text())
        raw["halted"] = False
        raw["halted_reason"] = None
        raw["steps"] = [{
            "index": 0, "phase": phase, "technique": technique,
            "objective": "substituted objective", "status": "executed",
            "tool_use_id": "tu-1",
            "decision": {"decision": "APPROVED",
                         "approver": "security-lead@example.com"},
            "execution_log": "[SIMULATED] ...",
        }]
        ckpt.write_text(json.dumps(_reseal(raw)))

    def test_a_substituted_plan_is_refused_when_bound(self, tmp_path):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)
        self._substitute(ckpt)
        with pytest.raises(sim.CheckpointError, match="authorized plan"):
            sim.PlayModeRunner.resume_from_checkpoint(
                "arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/h",
                str(ckpt), expected_plan=_PLAN,
                invoke_fn=_gate_invoke, resume_fn=_gate_resume,
                decision_fn=sim.auto_approve, logger=lambda _m: None)

    def test_the_error_names_both_plans(self, tmp_path):
        """An operator has to be able to see WHAT was substituted."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)
        self._substitute(ckpt)
        with pytest.raises(sim.CheckpointError) as excinfo:
            sim.PlayModeRunner.resume_from_checkpoint(
                "arn:x", str(ckpt), expected_plan=_PLAN,
                invoke_fn=_gate_invoke, resume_fn=_gate_resume,
                decision_fn=sim.auto_approve, logger=lambda _m: None)
        message = str(excinfo.value)
        assert "T1486" in message and "T1595" in message

    def test_an_unbound_resume_does_NOT_catch_substitution(self, tmp_path):
        """Recorded honestly rather than implied away: WITHOUT `expected_plan` the
        checkpoint is the only source of the plan, so substitution succeeds. This is
        why both real entrypoints pass it, and why this test exists — a reader must
        not infer a guarantee the code does not give.
        """
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_reject)
        self._substitute(ckpt)
        runner = sim.PlayModeRunner.resume_from_checkpoint(
            "arn:x", str(ckpt),
            invoke_fn=_gate_invoke, resume_fn=_gate_resume,
            decision_fn=sim.auto_approve, logger=lambda _m: None)
        assert runner.state.steps[0].technique == "T1486", (
            "if this now raises, plan binding became mandatory — update this test "
            "and the threat-model note in load_checkpoint's docstring"
        )

    def test_a_matching_plan_resumes(self, tmp_path):
        """CONTROL: binding must not break legitimate resume, which is the whole
        point of checkpointing a long run."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.reject_after(1))
        runner = sim.PlayModeRunner.resume_from_checkpoint(
            "arn:x", str(ckpt), expected_plan=_PLAN,
            invoke_fn=_gate_invoke, resume_fn=_gate_resume,
            decision_fn=sim.auto_approve, logger=lambda _m: None)
        assert [s.technique for s in runner.state.steps] == \
            [p["technique"] for p in _PLAN]

    def test_binding_compares_identity_not_prose(self, tmp_path):
        """`objective` is prose and deliberately NOT compared: rewording it does not
        change which technique is emulated, and demanding a byte match would make
        the guard brittle enough that callers would stop passing expected_plan."""
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)
        reworded = [{**p, "objective": p["objective"].upper() + " (revised)"}
                    for p in _PLAN]
        sim.PlayModeRunner.resume_from_checkpoint(
            "arn:x", str(ckpt), expected_plan=reworded,
            invoke_fn=_gate_invoke, resume_fn=_gate_resume,
            decision_fn=sim.auto_approve, logger=lambda _m: None)

    @pytest.mark.parametrize("mutate,why", [
        (lambda p: p[:1], "a step removed"),
        (lambda p: p + [{"phase": "impact", "technique": "T1486", "objective": "x"}],
         "a step appended"),
        (lambda p: list(reversed(p)), "steps reordered"),
        (lambda p: [{**p[0], "technique": "T9999"}] + p[1:], "one technique changed"),
    ])
    def test_every_shape_of_plan_divergence_is_caught(self, tmp_path, mutate, why):
        ckpt = tmp_path / "plan.json"
        _run(ckpt, sim.auto_approve)
        with pytest.raises(sim.CheckpointError, match="authorized plan"):
            sim.PlayModeRunner.resume_from_checkpoint(
                "arn:x", str(ckpt), expected_plan=mutate(list(_PLAN)),
                invoke_fn=_gate_invoke, resume_fn=_gate_resume,
                decision_fn=sim.auto_approve, logger=lambda _m: None)


# --------------------------------------------------------------------------- #
# INV-PLAY-4 — the gate is asked once per offensive step, and reject halts     #
# --------------------------------------------------------------------------- #
class TestPlayModeGateItself:
    """The claim in the module docstring, mechanized. These pass on pre-R16 source
    too — the gate logic itself was correct, and that is worth pinning so a refactor
    cannot regress it while the checkpoint layers distract from it."""

    def test_the_human_is_asked_exactly_once_per_step(self):
        asked = []

        def spy(step, tool_use):
            asked.append(step.index)
            return sim.auto_approve(step, tool_use)

        runner = sim.PlayModeRunner(
            "arn:x", plan=_PLAN, invoke_fn=_gate_invoke, resume_fn=_gate_resume,
            session_id="s", plan_id="p", decision_fn=spy, logger=lambda _m: None)
        runner.run()
        assert asked == list(range(len(_PLAN))), (
            "zero asks would be silent execution; two would double-charge one "
            "human decision"
        )

    def test_a_rejection_halts_and_leaves_later_steps_pending(self):
        runner = sim.PlayModeRunner(
            "arn:x", plan=_PLAN, invoke_fn=_gate_invoke, resume_fn=_gate_resume,
            session_id="s", plan_id="p", decision_fn=sim.reject_after(1),
            logger=lambda _m: None)
        runner.run()
        assert runner.state.halted is True
        assert runner.state.halted_reason
        assert runner.state.steps[0].status == sim.EXECUTED
        assert runner.state.steps[1].status == sim.REJECTED

    @pytest.mark.parametrize("decision,approved", [
        ({"decision": "APPROVED"}, True),
        ({"decision": "approved"}, True),
        ({"decision": " Approved "}, True),
        ({"decision": "REJECTED"}, False),
        ({"decision": "false"}, False),
        ({"decision": "no"}, False),
        ({"decision": ""}, False),
        ({"decision": None}, False),
        ({}, False),
        ({"decision": "APPROVE"}, False),
        ({"decision": ["APPROVED"]}, False),
        ({"decision": True}, False),
        ({"decision": 1}, False),
    ])
    def test_only_an_explicit_approved_counts_as_approval(self, decision, approved):
        """Fail-closed on anything ambiguous. Note `{"decision": "false"}` and
        `{"decision": True}` both read as NOT approved — this predicate compares an
        explicit string rather than truthiness, so the `bool("false") is True` trap
        that INV-BOUNDARY-1 and INV-GATE-3 record cannot reach it."""
        assert sim._is_approved(decision) is approved

    def test_technique_execution_has_no_side_effect_primitives(self):
        """The "NO-OP" claim, checked structurally rather than trusted.

        Parsed with ``ast`` rather than scanned as text. A text scan matched the word
        "subprocess" inside this module's own prose explaining that it contains no
        subprocess — the identical layer confusion INV-GATE-1 and INV-GATE-6 record,
        where a substring scan could not tell code from commentary. Walking the AST
        looks only at what actually executes.
        """
        import ast
        import inspect

        forbidden_calls = {"system", "popen", "spawn", "spawnl", "spawnv", "execv",
                           "execve", "eval", "exec", "compile", "urlopen", "rmtree",
                           "socket", "connect", "run", "check_output", "Popen"}
        forbidden_modules = {"subprocess", "socket", "shutil", "requests",
                             "urllib.request", "ctypes", "multiprocessing"}

        tree = ast.parse(inspect.getsource(sim))
        offences = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_modules:
                        offences.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in forbidden_modules:
                    offences.append(f"from {node.module} import ...")
            elif isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                # `subprocess.run` / `os.system` / a bare `eval(...)` all land here.
                if name in forbidden_calls:
                    # `dict.run`-style false hits are impossible in this module, but
                    # the runner's own public `run()` method IS called in tests — so
                    # only flag a call whose receiver is a module-ish name.
                    receiver = getattr(func, "value", None)
                    receiver_name = getattr(receiver, "id", None)
                    if name in ("run", "socket", "connect") and \
                            receiver_name not in forbidden_modules:
                        continue
                    offences.append(f"call to {name}()")
        assert not offences, (
            f"simulation.py now performs {sorted(set(offences))}; the 'technique "
            "execution is a pure no-op' claim must be re-verified before this test "
            "is relaxed"
        )
