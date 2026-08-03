"""
Round-21 — INV-OPS-7: promotion is human-gated by MECHANISM, not by convention.
=============================================================================
`docs/THREAT-MODEL.md` §1 lists three controls against prompt injection and claims of
the second:

    "Publish / contain / promote are inline_function HITL gates ...; the agent can only
     *request* them, never execute them."

Round 21 asked the R16 question of that claim — *is the stated control actually there?*
— and found it held for two paths and not a third:

    agent_loop.run_agent_loop        gates all 3 promotion actions (agent_loop.py:205)
    autonomy.run_improvement_loop    gates via approve_fn, fail-closed when None
    harness_ops.handler(...) direct  NO gate  <- reproduced: promoted 'prod', ok:True

The direct path is not hypothetical. `scenarios/scenario_agent_factory_loop.py` says of
itself that "delegation here is in-process (the scenario calls the harness_ops handler
directly) rather than over a Gateway MCP target". It calls only
create/wait_ready/invoke/delete, so nothing was exploited — but nothing PREVENTED a
promote either, which is the difference between a mechanism and a convention. The same
shape as INV-PROMOTE-3, where a docstring delegated a fail-closed posture to "the caller"
and no caller implemented it.

`sentinel_agent_ops` is the harness this matters for: its `allowedTools` is exactly
`@gateway/harness_ops` with NO gate on the list, while `sentinel_self_improving` holds the
same tool WITH `request_promotion_approval`. One tool, two harnesses, one gate.

What this file adds that `test_harness_ops.py::TestPromotionGate` does not
-------------------------------------------------------------------------
That class tests the TOOL in isolation (refused without a witness, allowed with one).
This one tests the SEAM: that the driver, having approved a promotion, actually reaches
the tool and succeeds — and that the witness does not outlive the call.

That distinction is the round-19/20 lesson restated: a guard verified only on its
refusing branch is half-verified. Every existing promotion test refuses at the DRIVER,
so none of them ever reached the tool-side gate; a fix that deadlocked the approved path
would have passed the whole suite.

Zero AWS, zero network.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib

import pytest

from sentinel_harness import agent_loop as AL

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_HANDLER = REPO_ROOT / "tools" / "harness_ops" / "handler.py"

WITNESS_ENV = "SENTINEL_PROMOTION_GATE_WITNESSED"


def _load_harness_ops():
    spec = importlib.util.spec_from_file_location("_r21_harness_ops", _HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def ops(monkeypatch):
    """harness_ops with a recording control plane; no witness set."""
    monkeypatch.delenv(WITNESS_ENV, raising=False)
    module = _load_harness_ops()
    from sentinel_harness import core

    calls: list = []

    class _Ctl:
        class exceptions:
            class ConflictException(Exception):
                pass

            class ResourceNotFoundException(Exception):
                pass

        def create_harness_endpoint(self, **kw):
            calls.append(("CreateHarnessEndpoint", kw))
            return {"endpointName": kw.get("endpointName"), "status": "CREATING",
                    "targetVersion": kw.get("targetVersion")}

        def update_harness_endpoint(self, **kw):
            calls.append(("UpdateHarnessEndpoint", kw))
            return {"endpointName": kw.get("endpointName"), "status": "UPDATING",
                    "targetVersion": kw.get("targetVersion")}

    monkeypatch.setattr(core, "_control", _Ctl())
    module._r21_calls = calls  # type: ignore[attr-defined]
    return module


# --------------------------------------------------------------------------- #
# The env var names must agree across the two layers                          #
# --------------------------------------------------------------------------- #
def test_the_two_layers_use_the_same_witness_name():
    """A typo in either constant silently disables the gate: the tool would refuse every
    promotion (loud) or — worse, if the DRIVER's name were wrong — the driver would set a
    variable nobody reads and the tool would refuse the approved path too. Pin both."""
    module = _load_harness_ops()
    assert module._GATE_WITNESS_ENV == AL._PROMOTION_WITNESS_ENV == WITNESS_ENV, (
        f"witness name drift: tool={module._GATE_WITNESS_ENV!r}, "
        f"driver={AL._PROMOTION_WITNESS_ENV!r}"
    )


# --------------------------------------------------------------------------- #
# The SEAM: an approved driver promotion reaches the tool and succeeds         #
# --------------------------------------------------------------------------- #
class TestTheApprovedPathReachesTheTool:
    """The half no existing test covered. Every prior promotion test refuses at the
    driver, so the tool-side gate was only ever exercised on its refusing branch."""

    def test_the_witness_helper_sets_and_restores(self):
        seen = {}

        def handler(_tool_input):
            seen["witness"] = os.environ.get(WITNESS_ENV)
            return {"ok": True}

        os.environ.pop(WITNESS_ENV, None)
        out = AL._with_promotion_witness(handler, {"action": "promote_endpoint"})
        assert out == {"ok": True}
        assert seen["witness"] == "1", "the handler did not see the witness"
        assert WITNESS_ENV not in os.environ, (
            "the witness outlived the call — promotion would be ungoverned for every "
            "later caller in this process, which is the hole INV-OPS-7 closes"
        )

    def test_the_witness_is_restored_even_when_the_handler_raises(self):
        def boom(_tool_input):
            raise RuntimeError("handler blew up")

        os.environ.pop(WITNESS_ENV, None)
        with pytest.raises(RuntimeError):
            AL._with_promotion_witness(boom, {"action": "promote_endpoint"})
        assert WITNESS_ENV not in os.environ, (
            "a handler error leaked an open gate"
        )

    def test_a_pre_existing_value_is_restored_not_clobbered(self):
        os.environ[WITNESS_ENV] = "pre-existing"
        try:
            AL._with_promotion_witness(lambda _ti: {"ok": True}, {"action": "promote"})
            assert os.environ[WITNESS_ENV] == "pre-existing"
        finally:
            os.environ.pop(WITNESS_ENV, None)

    def test_an_approved_driver_promotion_executes_through_the_tool(self, ops):
        """END TO END: drive the real `run_agent_loop` over a scripted agent that
        evaluates, obtains approval, then promotes — and assert the promotion actually
        reached the control plane. Before the witness wiring this deadlocked: the driver
        approved and the tool refused."""
        turns = [
            # 1) evaluate the candidate
            [{"toolUseId": "t1", "name": "run_evaluation",
              "input": {"harness_id": "h-cand"}}],
            # 2) human approval for that same harness, then the promotion
            [{"toolUseId": "t2", "name": "request_promotion_approval",
              "input": {"harness_id": "h-cand"}},
             {"toolUseId": "t3", "name": "harness_ops",
              "input": {"action": "promote_endpoint",
                        "params": {"harness_id": "h-cand", "endpoint_name": "prod"}}}],
        ]
        state = {"i": 0}

        def _build():
            if state["i"] >= len(turns):
                return {"stop_reason": "end_turn", "text": "done", "tool_uses": []}
            turn = turns[state["i"]]
            state["i"] += 1
            return {"stop_reason": "tool_use", "tool_uses": turn}

        def eval_handler(tool_input):
            return {"harness_id": tool_input.get("harness_id"), "score": 0.95,
                    "dimension_scores": {"safety": 1.0, "groundedness": 0.9}}

        result = AL.run_agent_loop(
            invoke_fn=lambda: _build(),
            resume_fn=lambda _answers: _build(),
            dispatch={"run_evaluation": eval_handler,
                      "harness_ops": lambda ti: ops.handler(ti, None)},
            approve_fn=lambda _ti: True,
            threshold=0.7,
        )
        assert result.promoted is True, (
            f"the approved promotion did not execute: stopped_by={result.stopped_by}, "
            f"trace={[(r.tool, r.outcome, r.detail) for r in result.trace]}"
        )
        promoted = [c for c in ops._r21_calls
                    if c[0] in ("CreateHarnessEndpoint", "UpdateHarnessEndpoint")]
        assert promoted, (
            "the driver reported a promotion but nothing reached the control plane — "
            "the tool-side gate refused the approved path"
        )
        assert WITNESS_ENV not in os.environ, "the witness leaked past the loop"

    def test_a_driver_promotion_without_approval_still_refuses(self, ops):
        """CONTROL: the driver gate must still fire. If the witness wiring made every
        driver promotion succeed, this would pass while the whole guarantee was gone."""
        turns = [
            [{"toolUseId": "t1", "name": "harness_ops",
              "input": {"action": "promote_endpoint",
                        "params": {"harness_id": "h-cand", "endpoint_name": "prod"}}}],
        ]
        state = {"i": 0}

        def _build():
            if state["i"] >= len(turns):
                return {"stop_reason": "end_turn", "text": "done", "tool_uses": []}
            turn = turns[state["i"]]
            state["i"] += 1
            return {"stop_reason": "tool_use", "tool_uses": turn}

        result = AL.run_agent_loop(
            invoke_fn=lambda: _build(),
            resume_fn=lambda _answers: _build(),
            dispatch={"harness_ops": lambda ti: ops.handler(ti, None)},
            approve_fn=lambda _ti: True,
            threshold=0.7,
        )
        assert result.promoted is False, "promoted with no eval and no approval"
        assert not ops._r21_calls, (
            f"a promotion reached the control plane unapproved: {ops._r21_calls}"
        )


# --------------------------------------------------------------------------- #
# The manifest-level finding that started the round                            #
# --------------------------------------------------------------------------- #
def test_every_harness_with_a_promotion_capable_tool_is_accounted_for():
    """The selection step, kept executable.

    `sentinel_agent_ops` holds `@gateway/harness_ops` — which can promote — with NO HITL
    gate in its allowedTools, while `sentinel_self_improving` holds the same tool WITH
    `request_promotion_approval`. That asymmetry is what prompted this round.

    The tool-side gate (INV-OPS-7) is what makes the un-gated manifest safe, so this test
    does not demand a gate in every manifest — it demands that any such harness be listed
    here with the reason, so a NEW un-gated grant is a decision someone made rather than
    an oversight. Same mechanism as the round-19 coverage map.
    """
    import yaml

    # harness -> why it may hold a promotion-capable tool without a manifest HITL gate
    _UNGATED_BY_DESIGN = {
        "sentinel_agent_ops":
            "the meta-orchestration harness: its whole surface IS the lifecycle tool, and "
            "it drives create/update/invoke/wait_ready. Promotion from this harness is "
            "refused by INV-OPS-7 at the tool unless a driver gated it, so the missing "
            "manifest gate does not grant unattended promotion.",
    }
    _GATES = {"request_publish_approval", "request_containment_approval",
              "request_human_review", "request_promotion_approval"}
    _PROMOTION_CAPABLE = {"harness_ops"}

    findings = {}
    manifests = sorted((REPO_ROOT / "harnesses").glob("*/harness.yaml"))
    assert len(manifests) >= 5, (
        f"only found {len(manifests)} harness manifests — the glob is broken and this "
        "check is vacuous"
    )
    for path in manifests:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = doc.get("harnessName", path.parent.name)
        allowed = doc.get("allowedTools") or []
        bare = {t.rsplit("/", 1)[-1] for t in allowed if isinstance(t, str)}
        if bare & _PROMOTION_CAPABLE and not (bare & _GATES):
            findings[name] = sorted(bare & _PROMOTION_CAPABLE)

    unexplained = sorted(set(findings) - set(_UNGATED_BY_DESIGN))
    assert not unexplained, (
        f"harness(es) granted a promotion-capable tool with no HITL gate and no entry "
        f"explaining why: { {k: findings[k] for k in unexplained} }. Either add a gate to "
        f"the manifest or record the reason here."
    )
    stale = sorted(set(_UNGATED_BY_DESIGN) - set(findings))
    assert not stale, (
        f"_UNGATED_BY_DESIGN lists harness(es) that now HAVE a gate (or lost the tool): "
        f"{stale}. Remove them — the list only means something if it tracks reality."
    )
