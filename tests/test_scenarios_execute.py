"""
The offline scenarios must actually RUN.
=======================================
`scenarios/` is executable documentation: each script proves a platform claim and writes
an `evidence/*.json` artifact. Five of them had no test coverage of any kind, and a
30-minute test sweep found that `scenario_agent_authored_loop.py` had been **failing
offline** — exiting 1 while still writing its evidence file, so a committed artifact that
claims to prove the happy promotion path actually recorded it being refused.

The cause was a stale stub, not a code defect: `_passing_eval` scored `correctness` and
`safety` but not `groundedness`, and INV-PROMOTE-3's fail-closed rule ("a judge's silence
is not a pass") correctly refused it. The requirement arrived with M18.1; the scenario's
stub never followed. Nothing caught it because nothing ran the scenario — `make test`
covers `tests/`, and the scenarios are only exercised by hand.

That is the INV-AUDITMAP shape one level over: an artifact asserting a claim, with no
mechanism checking the assertion still holds.

What this file does
-------------------
Runs every scenario that is *supposed* to work with zero AWS and asserts exit 0. Scenarios
that genuinely need live AWS or a role ARN are listed explicitly with the precondition they
require, so a NEW scenario is either offline-runnable or a decision someone recorded.

Deliberately not a coverage-for-coverage's-sake sweep: each entry below is a claim about
whether the script can run hermetically, which is checkable and which drifted.
"""
from __future__ import annotations

import os
import pathlib

import pytest

import child_pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCENARIO_DIR = REPO_ROOT / "scenarios"

# Scenarios that CANNOT run hermetically, each with the precondition they need. Verified
# by running them: all three fail with a clear, loud message rather than a silent pass.
_REQUIRES_LIVE_AWS: dict[str, str] = {
    "scenario_hitl_resume":
        "needs SENTINEL_EXECUTION_ROLE_ARN and real credentials — it creates a harness and "
        "exercises the two-message HITL resume against the live data plane",
    "scenario_multi_harness":
        "needs live credentials — it creates and invokes several real harnesses",
    "scenario_play_mode":
        "needs live credentials — Play Mode drives a real harness through the simulation "
        "checkpoint lifecycle",
    "scenario_m18_gates_live":
        "needs live credentials by design (the name says live) — it proves the M18 gates "
        "against the real control plane",
    "scenario_egress_control":
        "needs live credentials — it asserts the default-deny egress posture from inside "
        "the runtime",
    "scenario_agent_factory_loop":
        "needs live credentials — the meta-agent authors a spec and harness_ops really "
        "creates, waits on and invokes a NEW harness on the account",
    "scenario_cve_triage":
        "needs live credentials — the flagship triage run invokes a real harness over "
        "Bedrock",
    "scenario_detection_gen":
        "needs live credentials — it invokes the detection-engineering harness to author "
        "rules against the live data plane",
    "scenario_self_improve_loop":
        "needs live credentials — it evaluates, gates and really promotes a harness "
        "endpoint on the account",
    "scenario_named_supervisor":
        "needs SENTINEL_GATEWAY_ARN and live credentials — it wires the research "
        "supervisor to a real AgentCore Gateway MCP tool surface (refuses loudly with "
        "setup instructions when unset, which is correct)",
}

# Scenarios asserted to run with ZERO AWS. Chosen by running every script, not by reading
# docstrings: an earlier version of this sweep grepped for the word "offline" and
# mis-classified three live scenarios, because their prose mentions offline mode.
_OFFLINE_RUNNABLE = (
    "scenario_agent_authored_loop",
    "scenario_alert_triage_poc",
    "scenario_autonomous_loop",
    "scenario_bas_replay",
    "scenario_benchmark",
    "scenario_cve_asset_triage",
    "scenario_detonation",
    "scenario_e2e_pipeline",
    "scenario_eval_all_domains",
    "scenario_feedback_loop",
    "scenario_live_a2a_runtime",
    "scenario_registry_governance",
    "scenario_tracing",
)


def _hermetic_env() -> dict:
    """The environment an offline scenario runs in: no AWS credentials, no ambient
    SENTINEL_* config.

    Credentials are actively STRIPPED rather than merely absent, so a developer's ambient
    profile cannot make a live-only scenario look hermetic — and cannot let these tests
    reach AWS. `PATH`/`HOME` and the uv/venv variables are preserved because the child
    launcher needs them to start at all: stripping them was how the first version of this
    module died on CI.
    """
    # Drop exactly the two families that could make a live-only scenario look hermetic;
    # keep everything else, because the child launcher needs PATH/HOME/UV_*/VIRTUAL_ENV to
    # start at all. The first version of this module built the env from a tiny allowlist
    # and died on CI — the launcher could not run.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AWS_", "SENTINEL_"))}
    env["SENTINEL_REGION"] = "us-east-1"
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    # A placeholder role: offline scenarios must not need a real one, but several read the
    # variable at import time and refuse loudly when it is unset (correct behaviour).
    env["SENTINEL_EXECUTION_ROLE_ARN"] = (
        "arn:aws:iam::000000000000:role/sentinel-offline-test-role"
    )
    return env


def _all_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("scenario_*.py"))


def test_the_scenario_inventory_is_complete():
    """Guard the guard. Every scenario must be classified — offline-runnable or
    explicitly requiring live AWS. An unclassified script is one nobody has run, which
    is exactly how a failing scenario shipped."""
    found = _all_scenarios()
    assert len(found) >= 15, (
        f"only found {len(found)} scenarios; the glob is broken and this whole module "
        "is vacuous"
    )
    classified = set(_OFFLINE_RUNNABLE) | set(_REQUIRES_LIVE_AWS)
    unclassified = sorted(set(found) - classified)
    assert not unclassified, (
        f"unclassified scenario(s): {unclassified}. Run each one: if it works with no "
        "AWS, add it to _OFFLINE_RUNNABLE; if it needs credentials, add it to "
        "_REQUIRES_LIVE_AWS with the precondition. An unclassified scenario is one that "
        "could be failing silently — scenario_agent_authored_loop was, for several rounds."
    )
    stale = sorted(classified - set(found))
    assert not stale, f"classification names a deleted scenario: {stale}"


@pytest.mark.parametrize("name", sorted(_REQUIRES_LIVE_AWS))
def test_every_live_exemption_names_a_precondition(name):
    reason = _REQUIRES_LIVE_AWS[name]
    assert len(reason.strip()) >= 40, (
        f"the exemption for {name} is too thin to review: {reason!r}"
    )
    assert (SCENARIO_DIR / f"{name}.py").is_file(), f"{name} does not exist"


@pytest.mark.parametrize("name", _OFFLINE_RUNNABLE)
def test_an_offline_scenario_runs_clean(name):
    """Execute the scenario in a subprocess with NO AWS credentials and assert exit 0.

    Credentials are actively stripped rather than merely absent, so a developer's ambient
    profile cannot make a live-only scenario look hermetic — and cannot let this test
    reach AWS.
    """
    result = child_pytest.run_python_script(
        f"scenarios/{name}.py", env=_hermetic_env())
    output = (result.stdout or "") + (result.stderr or "")
    assert "NoCredentialsError" not in output, (
        f"{name} tried to reach AWS but is classified as offline-runnable — move it to "
        f"_REQUIRES_LIVE_AWS:\n{output[-500:]}"
    )
    assert result.returncode == 0, (
        f"{name} exited {result.returncode} with no credentials. A scenario is committed "
        f"evidence for a platform claim; one that fails is an artifact asserting "
        f"something untrue.\n{output[-1500:]}"
    )


def test_the_agent_authored_loop_proves_the_happy_path():
    """The specific regression. This scenario's four paths include `happy_promotion`, and
    it had been reporting `ok=False promoted=False refused=1` — the fail-closed gate
    refusing it because `_passing_eval` never scored `groundedness`.

    Asserted on the evidence FILE, because that is the artifact a reader trusts.
    """
    import json

    result = child_pytest.run_python_script(
        "scenarios/scenario_agent_authored_loop.py", env=_hermetic_env())
    assert result.returncode == 0, (result.stdout + result.stderr)[-1200:]

    evidence = REPO_ROOT / "evidence" / "agent_authored_loop_result.json"
    assert evidence.is_file(), "the scenario produced no evidence file"
    doc = json.loads(evidence.read_text(encoding="utf-8"))
    steps = {s["step"]: s for s in doc.get("steps", [])}

    happy = steps.get("happy_promotion")
    assert happy is not None, f"no happy_promotion step in the evidence: {sorted(steps)}"
    assert happy["ok"] is True, f"the happy path is not ok: {happy}"
    assert happy["data"]["promoted"] is True, (
        f"the happy path did not promote: {happy['data'].get('refusal_reasons')}"
    )
    assert happy["data"]["refused_promotions"] == 0

    # And the three NEGATIVE paths must still refuse — a stub change that made everything
    # pass would satisfy the assertions above while destroying what the scenario proves.
    for name in ("promotion_refused", "safety_trap"):
        step = steps.get(name)
        assert step is not None and step["ok"] is True, f"{name}: {step}"
        assert step["data"]["promoted"] is False, (
            f"{name} PROMOTED — the gate it exists to prove is gone: {step['data']}"
        )
    spin = steps.get("spinning_agent")
    assert spin is not None and spin["data"]["stopped_by"] == "cap", (
        f"the runaway-agent cap did not bite: {spin}"
    )
