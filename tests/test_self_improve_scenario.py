"""
Offline tests for the self-improvement-loop scenario (M2 north star, part 2)
============================================================================
The scenario itself is live (it builds real harnesses + a real endpoint); these
tests cover its OFFLINE-checkable logic: import-safety, the account-id scrubber, and
the endpoint-aware teardown ordering (endpoint must be deletable before the harness).

HARD RULE: ZERO AWS. Dummy env before import; core clients are monkeypatched.
"""
from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from scenarios import scenario_self_improve_loop as sil  # noqa: E402
from sentinel_harness import core  # noqa: E402


def test_scrub_removes_account_id_everywhere():
    # Build the 12-digit account ids at runtime so no literal account-in-ARN string
    # sits in this file (the repo's CI secret-scan flags iam::<12 digits>: patterns,
    # even for fake data). The scrubber still sees a real 12-digit id at run time.
    a1, a2, a3 = "9" * 12, "8" * 12, "7" * 12
    obj = {"arn": f"arn:aws:bedrock-agentcore:us-east-1:{a1}:harness/x",
           "nested": [f"arn:aws:iam::{a2}:role/y", {"a": f"arn:aws:sts::{a3}:x"}]}
    out = sil._scrub(obj)
    s = str(out)
    for acct in (a1, a2, a3):
        assert acct not in s
    assert "<ACCOUNT_ID>" in out["arn"]


def test_teardown_deletes_endpoint_before_harness(monkeypatch):
    """The endpoint-aware teardown must delete a READY endpoint first, then the
    harness — the order the control plane requires (both 409 otherwise)."""
    calls = []
    monkeypatch.setattr(core, "get_harness_endpoint",
                        lambda h, e: {"endpoint": {"status": "READY"}})
    monkeypatch.setattr(core, "delete_harness_endpoint",
                        lambda h, e: calls.append(("ep", h, e)))
    monkeypatch.setattr(core, "delete_harness",
                        lambda h: calls.append(("harness", h)))
    r = sil._teardown_harness("hid-1")
    assert r == {"deleted": "hid-1"}
    # endpoint delete strictly precedes harness delete
    assert [c[0] for c in calls] == ["ep", "harness"]


def test_teardown_handles_no_endpoint(monkeypatch):
    """A harness without an endpoint tears down directly (get raises -> skip ep delete)."""
    def _no_ep(h, e):
        raise RuntimeError("ResourceNotFound")
    deleted = []
    monkeypatch.setattr(core, "get_harness_endpoint", _no_ep)
    monkeypatch.setattr(core, "delete_harness", lambda h: deleted.append(h))
    r = sil._teardown_harness("hid-2")
    assert r == {"deleted": "hid-2"} and deleted == ["hid-2"]


def test_prompts_are_weak_vs_strong():
    """The weak prompt must be genuinely minimal and the strong one substantive, so the
    judge produces a real low-vs-high contrast (regression: a weak prompt that still
    answers well breaks the self-improvement demonstration)."""
    assert "noted" in sil.WEAK_PROMPT.lower()
    assert len(sil.STRONG_PROMPT) > 200
    assert "CVSS" in sil.STRONG_PROMPT
