"""Offline test for demo/m2_self_improving_demo.py
==================================================
The demo is the runnable, narrated proof of the M2 self-improvement loop
("an agent scores, improves, and promotes an agent"). Its DEFAULT mode is fully
offline: every AWS seam is monkeypatched inside the demo and the judge replies
are fixed canned verdicts, so the loop is deterministic. This test RUNS the demo
in that offline mode and asserts (a) it exits 0 and (b) its narrative hits the
key beats in order: scored-FAIL -> improved -> scored-PASS -> promoted, plus the
HITL reject-withholds-promotion beat.

HARD RULE: ZERO AWS / ZERO network. The demo installs its own in-memory fakes
over ``sentinel_harness.core`` when run offline; this test constructs a dummy env
before importing anything that builds a boto3 client and never makes a real call.
The demo does no wall-clock sleeping in offline mode, so no backoff patching is
needed here.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_m2_demo.py -q
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")


def _load_demo():
    """Load demo/m2_self_improving_demo.py by path (demo/ is a scripts tree, not a
    package). Importing it must NOT touch AWS — the module only sets dummy env and
    defines functions; the fakes are installed when run_offline() runs."""
    demo_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "demo", "m2_self_improving_demo.py")
    spec = importlib.util.spec_from_file_location("m2_self_improving_demo", demo_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


demo = _load_demo()


# The demo installs in-memory fakes over sentinel_harness.core module functions (and
# restores them in its own finally). This autouse fixture is a HARD SAFETY NET: it
# snapshots every core function the demo can replace and force-restores it after each
# test — so even if the demo's own restore is skipped (an assertion fires first, or a
# future refactor misses a name), the fakes can NEVER leak into another test module and
# corrupt it (the cross-file pollution the M2 verifiers flagged). Double-restore is safe.
_CORE_FUNCS = (
    "new_session", "create_harness", "update_harness", "wait_ready", "invoke",
    "create_harness_endpoint", "get_harness_endpoint", "delete_harness_endpoint",
    "delete_harness", "list_harnesses",
)


@pytest.fixture(autouse=True)
def _restore_core_after_test():
    from sentinel_harness import core
    saved = {name: getattr(core, name) for name in _CORE_FUNCS}
    try:
        yield
    finally:
        for name, orig in saved.items():
            setattr(core, name, orig)


def test_offline_demo_exits_zero_and_hits_beats_in_order(capsys):
    """Run the demo in its default offline/mock mode: it must exit 0 and its
    narrative must walk scored-FAIL -> improved -> scored-PASS -> promoted."""
    rc = demo.main([])           # no --live flag -> offline/mock mode
    assert rc == 0

    out = capsys.readouterr().out
    low = out.lower()

    # Runs in offline/mock mode with no AWS.
    assert "offline" in low and "no aws" in low

    # Beat 1: the weak agent is scored and FAILS below the bar.
    assert "expect fail" in low
    assert "passed=false" in low
    assert "below the pass bar" in low

    # Beat 2: the agent is improved (prompt rewrite mints a new version).
    assert "self-improve" in low
    assert "new harness version" in low

    # Beat 3: the re-score PASSES above the bar.
    assert "expect pass" in low
    assert "passed=true" in low
    assert "improved=true" in low

    # Beat 4: the passing agent is promoted to a prod endpoint after HITL approve.
    assert "createharnessendpoint" in low
    assert "promoted to a production endpoint" in low

    # Beat 5: the reject path withholds promotion.
    assert "reject" in low
    assert "not promoted: true" in low

    # Overall: the loop closed and every summary check passed.
    assert "loop closed end to end: true" in low
    assert "[fail]" not in low   # no summary check regressed

    # Ordering: fail strictly precedes improve strictly precedes pass strictly
    # precedes promote. This is the whole story arc; a shuffled narrative is a bug.
    i_fail = low.index("below the pass bar")
    i_improve = low.index("new harness version")
    i_pass = low.index("at/above the pass bar")
    i_promote = low.index("promoted to a production endpoint")
    assert i_fail < i_improve < i_pass < i_promote


def test_offline_demo_makes_no_real_boto_calls(monkeypatch):
    """Belt-and-suspenders: the demo's offline mode must not reach the real boto
    control/data planes. We poison core._control and core._data so ANY real AWS
    call would blow up loudly; the run must still exit 0 because every seam is
    stubbed over before use."""
    from sentinel_harness import core

    class _Poison:
        def __getattr__(self, item):
            raise AssertionError(f"offline demo must not call AWS (_control/_data.{item})")

    monkeypatch.setattr(core, "_control", _Poison())
    monkeypatch.setattr(core, "_data", _Poison(), raising=False)

    assert demo.run_offline() == 0


def test_offline_stub_state_records_the_full_lifecycle():
    """The in-memory fake control plane must record exactly the lifecycle the loop
    drives: one endpoint create (APPROVE path only — the REJECT path makes none),
    an endpoint delete before harness deletes, and both harnesses torn down."""
    from sentinel_harness import core

    state = demo._install_offline_stubs(core)
    try:
        # Drive the same lifecycle the demo does, minimally, against the fakes.
        judge = core.create_harness("sentinel_llm_judge", "judge")
        agent = core.create_harness("sentinel_selfimprove_cve", "weak")
        core.update_harness(agent["harnessId"], system_prompt="You are a senior analyst.")
        assert state["harnesses"][agent["harnessId"]]["version"] == 2   # update minted v2

        core.create_harness_endpoint(agent["harnessId"], "prod")
        got = core.get_harness_endpoint(agent["harnessId"], "prod")
        assert got["endpoint"]["status"] == "READY"

        core.delete_harness_endpoint(agent["harnessId"], "prod")
        core.delete_harness(agent["harnessId"])
        core.delete_harness(judge["harnessId"])

        # Exactly one promotion (approve path); reject path never creates an endpoint.
        assert state["endpoint_creates"] == [agent["harnessId"]]
        # Endpoint torn down before the harnesses.
        assert state["endpoint_deletes"] == [agent["harnessId"]]
        assert set(state["harness_deletes"]) == {agent["harnessId"], judge["harnessId"]}
        # A deleted endpoint is really gone (get now raises).
        try:
            core.get_harness_endpoint(agent["harnessId"], "prod")
            raise AssertionError("endpoint should be gone after delete")
        except RuntimeError:
            pass
    finally:
        # Restore the real core functions so these fakes never leak into another
        # test module in the same process.
        demo._restore_core(core, state)
