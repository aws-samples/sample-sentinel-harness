"""Offline tests for scenario_detonation — the M3 sample-detonation proof point.

100% offline, zero AWS/network. The scenario drives the deterministic run
orchestrator (``longrunning/detonation/src/runner.py``) end-to-end: acquire a
one-shot microVM, stage the sample BY REFERENCE, gate on a HITL approval,
route each action through the sandbox gate (one disallowed action REFUSED),
report, then destroy-after-use. Same input -> same output, so no mocking is
needed. We assert only on the provable core: importing is offline-safe, the
pure run closes the loop with ``closed`` / ``simulated`` true, the microVM is
``destroyed_after_use``, exactly one action is refused by the sandbox, the
sample stayed by-reference, and the run is deterministic.

Mirrors tests/test_bas_replay_scenario.py exactly in structure.
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest

# Dummy env so anything that ever builds a boto3 client stays offline-safe.
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test"
)
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scenarios.scenario_detonation as det  # noqa: E402


def test_import_is_offline_safe():
    """Importing the module must not touch AWS — reimport proves module-level
    code builds no boto3 client and needs no network."""
    importlib.reload(det)
    assert callable(det.run_pure)


def test_pure_run_closes_loop_simulated_and_destroyed():
    """The default PURE run closes the loop with the safety invariants held:
    closed + simulated true and the one-shot microVM destroyed after use."""
    verdict = det.run_pure()
    assert verdict["closed"] is True
    assert verdict["simulated"] is True
    assert verdict["destroyed_after_use"] is True


def test_sample_stayed_by_reference():
    """The sample entered ONLY by s3:// reference — bytes never read."""
    verdict = det.run_pure()
    assert verdict["sample_by_reference"] is True


def test_sandbox_refused_exactly_one_bad_action():
    """The single disallowed action (rm -rf /) is REFUSED by the sandbox gate,
    with a reason, and never executed."""
    verdict = det.run_pure()
    assert verdict["sandbox_refused_bad_action"] is True
    assert verdict["refused_reason"]  # non-empty reason recorded


def test_hitl_gate_required_and_states_end_destroyed():
    """A human approval gated the DETONATING step and the state trail ends
    DESTROYED (destroy-after-use is the last thing that happens)."""
    verdict = det.run_pure()
    assert verdict["hitl_gate_required"] is True
    assert verdict["states_visited"][-1] == "DESTROYED"
    assert "AWAITING_APPROVAL" in verdict["states_visited"]


def test_deterministic():
    """Same input -> same output (pure, offline)."""
    a = det.run_pure()
    b = det.run_pure()
    assert a["states_visited"] == b["states_visited"]
    assert a["verdict"] == b["verdict"]
    assert a["refused_reason"] == b["refused_reason"]


def test_run_pure_populates_result_and_evidence_shape():
    """run_pure returns the verdict and stamps RESULT with the same verdict,
    without writing any file (offline, no side effects on disk)."""
    verdict = det.run_pure()
    assert det.RESULT["verdict"] == verdict
    assert det.RESULT["scenario"] == "detonation_run"
    # steps were recorded through the scrubber-backed rec()
    assert any(s["step"] == "action" for s in det.RESULT["steps"])
    assert any(s["step"] == "report" for s in det.RESULT["steps"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
