"""
M2 regression tests — lock the four real bugs the M2 self-improvement loop fixed
=================================================================================
During live validation of the M2 evaluation-driven self-improvement loop, four
real bugs were found and fixed. Each silently produced a *plausible-looking* wrong
answer instead of failing loudly, so each is exactly the kind of defect that can
creep back in unnoticed. These tests pin the fixed behaviour so the bugs can never
silently return. Every test names the bug it guards.

BUG 1  run_evaluation.score_answer must SURFACE a judge failure, never fabricate a
       0.0 that looks like a real low score. When core.invoke keeps failing on
       every retry, the handler must return ok=False with an upstream_error and a
       message. When invoke *returns* an errored/empty reply every time, the parsed
       verdict must carry a non-None ``judge_error`` (so a 0.0 is distinguishable
       from a genuine low score). A TypeError from a bad invoke override is a
       validation_error and is NOT retried.

BUG 2  Judge-invoke transient-fault RETRY: if core.invoke raises once (simulated
       stream error / 403) then succeeds, score_answer must retry and return the
       successful parsed verdict, minting a FRESH session on the retry.

BUG 3  core._consume_stream must expose an explicit ``error`` field on a
       runtimeClientError / validationException stream event (the bug was a silent
       empty reply — the MODEL_HAIKU-invalid-id class of failure). A clean stream
       must yield error=None.

BUG 4  Endpoint-aware teardown ORDER: scenario_self_improve_loop._teardown_harness
       must delete a READY endpoint BEFORE the harness (both 409 otherwise), must
       WAIT through a not-yet-READY (CREATING) endpoint, must RETRY the harness
       delete through a ConflictException, and must handle "no endpoint" (get
       raises) by deleting the harness directly.

HARD RULE: 100% OFFLINE, ZERO AWS, ZERO network. ``sentinel_harness.core``
functions are monkeypatched; the run_evaluation retry backoff is zeroed so no test
sleeps on real wall-clock. No account ids, ARNs, or secrets are hardcoded — a
12-digit account id needed in an ARN is BUILT AT RUNTIME by string concatenation
so no literal ``iam::<12 digits>:`` pattern sits in this file (the all-zeros
placeholder is allowed). Dummy env is set before importing anything that builds a
boto3 client.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_m2_regression.py -q
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# --- Hermetic import: dummy env before any boto3 client is constructed. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_harness import core  # noqa: E402
from scenarios import scenario_self_improve_loop as sil  # noqa: E402

_TOOLS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
)


def _load(tool_name: str):
    """Load tools/<tool_name>/handler.py by path (tools/ is a scripts tree)."""
    path = os.path.join(_TOOLS_DIR, tool_name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{tool_name}_handler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("run_evaluation")


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the judge-invoke retry backoff so the retry-path tests never sleep on
    real wall-clock (mirrors the autouse fixture in test_run_evaluation.py)."""
    monkeypatch.setattr(ev, "_JUDGE_BACKOFF_SECONDS", 0)


# --------------------------------------------------------------------------- #
# BUG 1 — a judge failure must be SURFACED, never fabricated as a real 0.0     #
# --------------------------------------------------------------------------- #
def test_bug1_all_invoke_retries_raise_surface_upstream_error_not_fake_zero(monkeypatch):
    """BUG 1: when core.invoke raises on EVERY retry, score_answer must re-raise so
    the handler returns ok=False + upstream_error + a message — NOT ok=True with a
    fabricated 0.0 score that reads like a genuine low verdict."""
    call_count = {"n": 0}

    def always_boom(*a, **k):
        call_count["n"] += 1
        raise RuntimeError("stream error: runtimeClientError 403 slow down")

    monkeypatch.setattr(core, "invoke", always_boom)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)

    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c"}},
        None)

    assert r["ok"] is False, "a total judge failure must NOT report ok=True"
    assert r["error"] == "upstream_error"
    assert r["message"], "the underlying failure message must be surfaced, not swallowed"
    assert "runtimeClientError" in r["message"] or "stream error" in r["message"]
    # It must never fabricate a score/passed that looks like a real low verdict.
    assert "score" not in r and "passed" not in r
    # It really did retry (all attempts exhausted), not give up after one call.
    assert call_count["n"] == ev._JUDGE_RETRIES


def test_bug1_persistent_errored_reply_surfaces_judge_error_not_bare_zero(monkeypatch):
    """BUG 1: when core.invoke *returns* (does not raise) an errored, empty reply on
    every retry, parse_verdict yields score 0.0 via prose-fallback — but that 0.0
    must be accompanied by a non-None ``judge_error`` so a caller can tell it apart
    from a genuine low score. The bug was returning a bare 0.0 with no error."""
    calls = {"n": 0}

    def errored_reply(*a, **k):
        calls["n"] += 1
        return {"text": "", "error": "runtimeClientError: invalid model id",
                "events": [], "stop_reason": None, "tools_used": [],
                "tool_use": None, "metadata": {}}

    monkeypatch.setattr(core, "invoke", errored_reply)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)

    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c"}},
        None)

    # The handler does not raise here (invoke returned), so ok=True, but the failure
    # is not hidden: judge_error is surfaced and non-None alongside the fallback 0.0.
    assert r["ok"] is True
    assert r["judge_error"] is not None, "an errored reply must surface judge_error"
    assert "runtimeClientError" in r["judge_error"]
    assert r["score"] == 0.0  # prose-fallback of empty text — but explicitly flagged
    # An errored+empty reply is retried the full budget (never succeeds).
    assert calls["n"] == ev._JUDGE_RETRIES


def test_bug1_typeerror_from_bad_override_is_validation_error_and_not_retried(monkeypatch):
    """BUG 1: a TypeError from core.invoke (a bad override kwarg = caller-malformed
    request) must be classified as a validation_error and must NOT be retried."""
    calls = {"n": 0}

    def typeerror_invoke(*a, **k):
        # A bad invoke override surfaces as TypeError from core.invoke; simulate that
        # directly and count how many times score_answer calls invoke.
        calls["n"] += 1
        raise TypeError("invoke() got an unexpected keyword argument 'bogus_override'")

    monkeypatch.setattr(core, "invoke", typeerror_invoke)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    # Prove it is not retried even with a generous retry budget.
    monkeypatch.setattr(ev, "_JUDGE_RETRIES", 3)

    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c",
                    "bogus_override": 1}},
        None)

    assert r["ok"] is False
    assert r["error"] == "validation_error", "a bad override is fix-your-input, not upstream"
    # NOT retried: the TypeError is re-raised out of the loop on the FIRST attempt
    # rather than being caught and retried like a transient fault — so invoke is
    # called exactly once, never the full _JUDGE_RETRIES budget.
    assert calls["n"] == 1


# --------------------------------------------------------------------------- #
# BUG 2 — a transient judge fault must be RETRIED with a fresh session         #
# --------------------------------------------------------------------------- #
def test_bug2_transient_fault_retries_then_returns_good_verdict(monkeypatch):
    """BUG 2: core.invoke raises once (simulated stream error / 403), then succeeds.
    score_answer must retry, return the successful parsed verdict, and mint a FRESH
    session on the retry (core.new_session called again for the second attempt)."""
    invoke_calls = []
    sessions_seen = []
    new_session_calls = {"n": 0}

    good_reply = ('{"score": 0.91, "pass": true, "reasons": ["thorough"], '
                  '"suggestions": []}')

    def flaky_invoke(arn, session, text, **kw):
        invoke_calls.append(session)
        sessions_seen.append(session)
        if len(invoke_calls) == 1:
            raise RuntimeError("runtimeClientError: transient stream fault (403)")
        return {"text": good_reply, "error": None, "events": [],
                "stop_reason": "end_turn", "tools_used": [], "tool_use": None,
                "metadata": {}}

    def counting_new_session(prefix="sentinel"):
        new_session_calls["n"] += 1
        return f"judge-{new_session_calls['n']}-" + "0" * 33

    monkeypatch.setattr(core, "invoke", flaky_invoke)
    monkeypatch.setattr(core, "new_session", counting_new_session)

    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a", "criteria": "c"}},
        None)

    # The retry happened and the FINAL (good) verdict came back.
    assert r["ok"] is True
    assert r["score"] == 0.91
    assert r["passed"] is True
    assert r["reasons"] == ["thorough"]
    assert len(invoke_calls) == 2, "must retry exactly once after the transient fault"
    # A FRESH session id is used on the retry (new_session called again for attempt 2:
    # once for the initial session, once for the retry).
    assert new_session_calls["n"] == 2
    assert sessions_seen[0] != sessions_seen[1], "retry must use a fresh session id"


# --------------------------------------------------------------------------- #
# BUG 3 — _consume_stream must expose an explicit ``error`` on a stream fault   #
# --------------------------------------------------------------------------- #
def test_bug3_stream_error_event_surfaces_error_field_and_text_path(monkeypatch):
    """BUG 3: a runtimeClientError stream event must set result["error"] to a
    non-None message (the bug was a silent empty reply — the MODEL_HAIKU-invalid-id
    class of failure) while the text path still returns whatever text arrived."""
    stream = [
        {"contentBlockDelta": {"delta": {"text": "partial "}}},
        {"runtimeClientError": {"message": "the provided model id is invalid"}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    out = core._consume_stream(stream)
    assert out["error"] is not None, "a stream error event must be surfaced explicitly"
    assert "runtimeClientError" in out["error"]
    # The text path still returns (partial text + the inline error marker).
    assert "partial " in out["text"]
    assert "STREAM-ERROR" in out["text"]


def test_bug3_validation_exception_event_surfaces_error_field():
    """BUG 3: a validationException stream event is also surfaced as error (guards the
    same silent-empty-reply class from an invalid harness/model config)."""
    stream = [
        {"validationException": {"message": "invalid harness configuration"}},
    ]
    out = core._consume_stream(stream)
    assert out["error"] is not None
    assert "validationException" in out["error"]


def test_bug3_clean_stream_has_error_none():
    """BUG 3: a clean stream must yield error=None (the flag only fires on a real
    fault; a healthy invoke must not look errored)."""
    stream = [
        {"contentBlockDelta": {"delta": {"text": "all good"}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    out = core._consume_stream(stream)
    assert out["error"] is None
    assert out["text"] == "all good"


def test_bug3_first_stream_error_is_kept_when_multiple(monkeypatch):
    """BUG 3: when several error events arrive, the FIRST is the surfaced error (so the
    root-cause fault is reported, not a downstream cascade)."""
    stream = [
        {"runtimeClientError": {"message": "root cause"}},
        {"internalServerException": {"message": "cascade"}},
    ]
    out = core._consume_stream(stream)
    assert out["error"] is not None
    assert "runtimeClientError" in out["error"] and "root cause" in out["error"]


# --------------------------------------------------------------------------- #
# BUG 4 — endpoint-aware teardown ORDER (wait + conflict-retry angles)          #
# --------------------------------------------------------------------------- #
def test_bug4_teardown_waits_for_creating_endpoint_then_deletes_ep_before_harness(monkeypatch):
    """BUG 4: an endpoint that is still CREATING is not yet deletable; the teardown
    must POLL until it reaches READY, delete the ENDPOINT first, then the harness.
    (Extends the existing READY-only test with the CREATING->READY wait it lacks.)"""
    calls = []
    statuses = iter(["CREATING", "CREATING", "READY"])

    def fake_get(hid, ep):
        calls.append(("get", hid, ep))
        return {"endpoint": {"status": next(statuses)}}

    monkeypatch.setattr(core, "get_harness_endpoint", fake_get)
    monkeypatch.setattr(core, "delete_harness_endpoint",
                        lambda h, e: calls.append(("ep", h, e)))
    monkeypatch.setattr(core, "delete_harness",
                        lambda h: calls.append(("harness", h)))
    # No real sleep between polls.
    monkeypatch.setattr(sil.time, "sleep", lambda *_a, **_k: None)

    r = sil._teardown_harness("hid-creating")
    assert r == {"deleted": "hid-creating"}

    kinds = [c[0] for c in calls]
    # Polled through CREATING at least twice before the endpoint became deletable.
    assert kinds.count("get") >= 3
    # The endpoint delete strictly precedes the harness delete.
    assert kinds.index("ep") < kinds.index("harness")
    assert kinds[-2:] == ["ep", "harness"]


def test_bug4_teardown_retries_harness_delete_through_conflict(monkeypatch):
    """BUG 4: after the endpoint is dropped, the harness delete can still raise a
    ConflictException while the endpoint teardown clears; the teardown must RETRY the
    harness delete until it succeeds (not surface the transient 409 as a failure)."""
    calls = []
    attempts = {"n": 0}

    class ConflictException(Exception):
        pass

    monkeypatch.setattr(core, "get_harness_endpoint",
                        lambda h, e: {"endpoint": {"status": "READY"}})
    monkeypatch.setattr(core, "delete_harness_endpoint",
                        lambda h, e: calls.append(("ep", h, e)))

    def flaky_delete(hid):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConflictException("endpoint still detaching")
        calls.append(("harness", hid))

    monkeypatch.setattr(core, "delete_harness", flaky_delete)
    monkeypatch.setattr(sil.time, "sleep", lambda *_a, **_k: None)

    r = sil._teardown_harness("hid-conflict")
    assert r == {"deleted": "hid-conflict"}
    # It retried the harness delete through the 409s (3 attempts total).
    assert attempts["n"] == 3
    # Endpoint still deleted before the (eventually successful) harness delete.
    assert [c[0] for c in calls] == ["ep", "harness"]


def test_bug4_teardown_no_endpoint_deletes_harness_directly(monkeypatch):
    """BUG 4: when there is NO endpoint (get raises), the teardown must skip the
    endpoint delete and delete the harness directly — never blocking on a missing
    endpoint. (Complements the existing no-endpoint test with an explicit assertion
    that delete_harness_endpoint is never called.)"""
    calls = []

    def get_raises(hid, ep):
        raise RuntimeError("ResourceNotFoundException: no such endpoint")

    def ep_delete_must_not_run(h, e):  # pragma: no cover - asserted never called
        raise AssertionError("delete_harness_endpoint must not run when no endpoint exists")

    monkeypatch.setattr(core, "get_harness_endpoint", get_raises)
    monkeypatch.setattr(core, "delete_harness_endpoint", ep_delete_must_not_run)
    monkeypatch.setattr(core, "delete_harness", lambda h: calls.append(("harness", h)))
    monkeypatch.setattr(sil.time, "sleep", lambda *_a, **_k: None)

    r = sil._teardown_harness("hid-no-ep")
    assert r == {"deleted": "hid-no-ep"}
    assert calls == [("harness", "hid-no-ep")]
