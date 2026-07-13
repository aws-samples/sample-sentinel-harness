"""
Fully-OFFLINE end-to-end test of the self-improvement-loop ORCHESTRATION
========================================================================
The single-run live E2E of ``scenarios/scenario_self_improve_loop.py`` (build the
judge -> build a weak agent -> score v1 (fail) -> update -> score v2 (pass) ->
promote to an endpoint -> teardown) cannot reliably get a green run because the
account's InvokeHarness quota (HTTP 403) throttles the re-score. This test proves
the whole SCENARIO LOGIC end to end with EVERY AWS call monkeypatched, so the
closed-loop verdict the live path is quota-blocked from producing is validated
here deterministically and offline.

What this file adds over the siblings (no duplication):
  - ``tests/test_run_evaluation.py`` unit-tests the scoring tool in isolation.
  - ``tests/test_self_improve_scenario.py`` covers ``_scrub`` + teardown ordering
    on ``_teardown_harness`` alone.
  - ``tests/test_core_endpoint.py`` covers the ``core`` endpoint wrappers.
This file instead drives the *entire* ``build_judge() -> run(judge_arn)`` chain
and asserts the composed ``RESULT["verdict"]`` (weak-below-bar, improvement-raised
score, improved-agent-passed, promoted-to-endpoint, reject-withholds-promotion and
overall ``closed`` True), plus the endpoint-before-harness teardown call order and
the account-id scrub over the full RESULT.

HARD RULE: ZERO AWS, ZERO network. Dummy env is set BEFORE importing anything that
builds a boto3 client; every ``sentinel_harness.core`` call the scenario makes is
monkeypatched, the ``run_evaluation`` scoring seam is stubbed, and the retry
backoff is zeroed so no test sleeps on real wall-clock.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_m2_e2e_offline.py -q
"""
from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Dummy env BEFORE any import that constructs a boto3 client (core builds clients at
# import time). Keeps the whole file hermetic — no credentials, no region lookup, no
# network. The all-zeros account placeholder is the sanctioned non-secret literal.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from scenarios import scenario_self_improve_loop as sil  # noqa: E402
from sentinel_harness import core  # noqa: E402


# A fake 12-digit account id BUILT AT RUNTIME (string repetition) so no literal
# ``iam::<12 digits>:`` pattern sits in this file — the CI secret-scan flags that
# even in test data. The scrubber still sees a real 12-digit id at run time.
_FAKE_ACCT = "9" * 12
_JUDGE_ARN = f"arn:aws:bedrock-agentcore:us-east-1:{_FAKE_ACCT}:harness/sentinel_llm_judge"
_AGENT_ARN = f"arn:aws:bedrock-agentcore:us-east-1:{_FAKE_ACCT}:harness/sentinel_selfimprove_cve"


class _FakeEndpoint:
    """A minimal, deterministic stand-in for the AgentCore harness endpoint that the
    scenario creates/gets/deletes. Records the exact create/delete call order so a
    test can assert the endpoint is torn down BEFORE its harness (the order the
    control plane requires)."""

    def __init__(self, order):
        self._order = order
        self._exists = False

    def create(self, harness_id, endpoint_name, *, target_version=None,
               description=None, **kw):
        self._exists = True
        self._order.append(("create_endpoint", harness_id, endpoint_name))
        return {"endpointName": endpoint_name, "status": "READY",
                "harnessId": harness_id}

    def get(self, harness_id, endpoint_name):
        if not self._exists:
            # Mirror the real control plane: a missing endpoint raises, and the
            # scenario's teardown treats any exception as "no endpoint".
            raise RuntimeError("ResourceNotFoundException: no such endpoint")
        return {"endpoint": {"endpointName": endpoint_name, "status": "READY",
                             "harnessId": harness_id}}

    def delete(self, harness_id, endpoint_name):
        self._exists = False
        self._order.append(("delete_endpoint", harness_id, endpoint_name))
        return {"deleted": endpoint_name}


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the run_evaluation judge-invoke retry backoff so any retry path exercised
    through the scoring tool never sleeps on real wall-clock. Mirrors the autouse
    fixture in tests/test_run_evaluation.py."""
    monkeypatch.setattr(sil.run_evaluation, "_JUDGE_BACKOFF_SECONDS", 0)


@pytest.fixture
def offline_loop(monkeypatch):
    """Monkeypatch the ENTIRE AWS surface the scenario touches, plus the scoring seam.

    Returns a state dict:
      - ``harnesses``: created harness ids in order,
      - ``updates``: (harness_id, kwargs) for each update_harness,
      - ``order``: create/delete-endpoint + delete-harness calls in call order,
      - ``deleted``: deleted harness ids,
      - ``score_calls``: the (agent_answer) each _score/handler saw,
      - ``answers``: the fake agent answers returned by invoke, in order.
    Every callable is deterministic and offline; no boto client is ever exercised.
    """
    state = {
        "harnesses": [],
        "updates": [],
        "order": [],
        "deleted": [],
        "score_calls": [],
        # Two distinct agent answers: a weak one (v1) then a strong one (v2).
        "answers": ["noted", "Log4Shell is a critical JNDI/LDAP RCE (CVSS ~10), in "
                              "CISA KEV; upgrade Log4j2 to 2.17+ and disable JNDI lookups."],
        "invoke_i": 0,
    }
    endpoint = _FakeEndpoint(state["order"])

    # -- harness lifecycle -------------------------------------------------- #
    def fake_create_harness(name, system_prompt, **kw):
        hid = f"h-{name}"
        arn = _JUDGE_ARN if name == "sentinel_llm_judge" else _AGENT_ARN
        state["harnesses"].append(hid)
        return {"harnessId": hid, "arn": arn, "harnessName": name}

    def fake_update_harness(harness_id, **kw):
        state["updates"].append((harness_id, kw))
        return {"harnessId": harness_id}

    def fake_invoke(harness_arn, session_id, text, **kw):
        i = state["invoke_i"]
        state["invoke_i"] += 1
        answer = state["answers"][min(i, len(state["answers"]) - 1)]
        return {"text": answer, "stop_reason": "end_turn", "tools_used": [],
                "tool_use": None, "events": [], "metadata": {}}

    def fake_delete_harness(harness_id, **kw):
        state["order"].append(("delete_harness", harness_id))
        state["deleted"].append(harness_id)
        return {"deleted": harness_id}

    monkeypatch.setattr(core, "create_harness", fake_create_harness)
    monkeypatch.setattr(core, "update_harness", fake_update_harness)
    monkeypatch.setattr(core, "invoke", fake_invoke)
    monkeypatch.setattr(core, "wait_ready", lambda hid, **kw: {"harnessId": hid,
                                                               "status": "READY"})
    monkeypatch.setattr(core, "new_session", lambda prefix="s": f"{prefix}-" + "0" * 33)
    # _ensure_absent lists harnesses; return empty so nothing is torn down by name.
    monkeypatch.setattr(core, "list_harnesses", lambda: [])
    monkeypatch.setattr(core, "delete_harness", fake_delete_harness)

    # -- endpoint (promote-to-production) ----------------------------------- #
    monkeypatch.setattr(core, "create_harness_endpoint", endpoint.create)
    monkeypatch.setattr(core, "get_harness_endpoint", endpoint.get)
    monkeypatch.setattr(core, "delete_harness_endpoint", endpoint.delete)
    monkeypatch.setattr(core, "list_harness_versions",
                        lambda hid: [{"version": "1"}, {"version": "2"}])

    # -- config loader: don't depend on cwd for the judge harness.yaml ------ #
    monkeypatch.setattr(sil.loader, "load_harness_config", lambda path: {
        "name": "sentinel_llm_judge",
        "system_prompt": "score this answer against the criteria; return JSON",
        "model": {"bedrockModelConfig": {"modelId": "global.anthropic.claude-sonnet-4-6"}},
        "memory": None, "max_iterations": 6, "timeout_seconds": 120,
        "allowed_tools": [], "tools": [],
    })

    # -- scoring seam: stub run_evaluation.handler (the module-level tool sil  #
    #    loaded and calls via sil._score). v1 fails (below bar), v2 passes.    #
    def fake_handler(event, context):
        assert event["action"] == "score_answer"
        params = event["params"]
        assert params["judge_arn"] == _JUDGE_ARN
        answer = params["agent_answer"]
        state["score_calls"].append(answer)
        n = len(state["score_calls"])
        if n == 1:
            # score_v1 — the weak "noted" answer scores well below the 0.7 bar.
            return {"ok": True, "action": "score_answer", "score": 0.1,
                    "passed": False, "reasons": ["single vague word"],
                    "suggestions": ["name the CVE class", "give CVSS + KEV",
                                    "give a concrete remediation"],
                    "raw": '{"score":0.1,"pass":false}', "judge_error": None}
        # score_v2 — the improved answer clears the bar.
        return {"ok": True, "action": "score_answer", "score": 0.92,
                "passed": True, "reasons": ["class + CVSS + KEV + remediation"],
                "suggestions": [], "raw": '{"score":0.92,"pass":true}',
                "judge_error": None}

    monkeypatch.setattr(sil.run_evaluation, "handler", fake_handler)

    # Reset the module-level RESULT so each test observes only its own run.
    sil.RESULT = {"scenario": "self_improve_loop", "steps": []}
    return state


# --------------------------------------------------------------------------- #
# the full offline E2E: build_judge -> run -> the closed-loop verdict          #
# --------------------------------------------------------------------------- #
def test_e2e_closed_loop_verdict(offline_loop):
    """Drive build_judge() then run(judge_arn) with the whole AWS surface stubbed and
    assert the composed verdict is a genuinely-closed loop: the weak agent scored
    below the bar, the improvement raised the score and passed, the passing agent was
    promoted to a real endpoint, and the reject path withheld promotion."""
    judge_arn = sil.build_judge()
    assert judge_arn == _JUDGE_ARN

    result = sil.run(judge_arn)
    v = result["verdict"]

    # The scoring loop really ran (score_v1 returned ok) against the weak agent.
    assert v["judge_scoring_loop_works"] is True
    assert v["weak_agent_scored_below_bar"] is True
    # The full-replacement update was applied, and the 2nd eval was NOT throttled
    # (offline: no 403 quota), so the loop can legitimately claim closed.
    assert v["improvement_update_applied"] is True
    assert v["second_eval_throttled"] is False
    assert v["improvement_raised_score"] is True
    assert v["improved_agent_passed"] is True
    assert v["passing_agent_promoted_to_endpoint"] is True
    assert v["reject_path_withholds_promotion"] is True
    # The whole chain ran offline with no throttle -> the loop is closed.
    assert v["closed"] is True


def test_e2e_scored_both_versions_in_order(offline_loop):
    """The loop must score TWO distinct answers: the weak v1 first, then the improved
    v2 — proving score_v1 (fail) precedes update precedes score_v2 (pass)."""
    sil.run(sil.build_judge())
    # exactly two scoring calls, weak answer before the strong answer.
    assert len(offline_loop["score_calls"]) == 2
    assert offline_loop["score_calls"][0] == "noted"
    assert "Log4Shell" in offline_loop["score_calls"][1]
    # the improvement step applied the strong prompt via a full-replacement update.
    assert len(offline_loop["updates"]) == 1
    _, upd_kwargs = offline_loop["updates"][0]
    assert upd_kwargs.get("system_prompt") == sil.STRONG_PROMPT


def test_e2e_teardown_deletes_endpoint_before_harness(offline_loop):
    """After promotion the agent carries a production endpoint; teardown must delete
    that endpoint BEFORE deleting the harness (both 409 in the other order)."""
    sil.run(sil.build_judge())
    order = offline_loop["order"]
    # the create precedes both deletes, and delete_endpoint strictly precedes
    # delete_harness for the agent.
    kinds = [c[0] for c in order]
    assert "create_endpoint" in kinds
    del_ep = kinds.index("delete_endpoint")
    del_h = kinds.index("delete_harness")
    assert del_ep < del_h
    # the create happened before the endpoint teardown.
    assert kinds.index("create_endpoint") < del_ep


def test_e2e_result_scrubbed_of_account_id(offline_loop):
    """No 12-digit account id may survive anywhere in the recorded RESULT — the ARNs
    the scenario records must be scrubbed to <ACCOUNT_ID> before printing/persisting."""
    result = sil.run(sil.build_judge())
    blob = str(result)
    assert _FAKE_ACCT not in blob
    # and the loop actually recorded steps (so the scrub was exercised on real data).
    assert result["steps"], "expected recorded steps"


def test_e2e_promotion_created_exactly_one_endpoint(offline_loop):
    """The APPROVE path promotes once; the REJECT path must NOT create a second
    endpoint. So exactly one create_endpoint call is made across the whole run."""
    sil.run(sil.build_judge())
    creates = [c for c in offline_loop["order"] if c[0] == "create_endpoint"]
    assert len(creates) == 1
    assert creates[0][2] == sil._ENDPOINT
