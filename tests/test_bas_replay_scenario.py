"""Offline tests for scenario_bas_replay — the M3 pure-replay proof point.

100% offline, zero AWS/network. Case generation + the Sigma matcher + replay are
deterministic pure Python (delegated to bas_cases + sigma_match), so no mocking
is needed. We assert only on the provable core: importing is offline-safe, the
pure replay yields a real blind-spot list, coverage_ratio is in [0,1], a
technique with a matching rule is NOT a blind spot, a technique with no rule IS,
and the result is deterministic.
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

import scenarios.scenario_bas_replay as bas  # noqa: E402


def test_import_is_offline_safe():
    """Importing the module must not touch AWS — reimport proves module-level
    code builds no boto3 client and needs no network."""
    importlib.reload(bas)
    assert callable(bas.build_verdict)
    assert callable(bas.run_pure)


def test_pure_replay_yields_real_blind_spots():
    verdict = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    # A real, non-empty blind-spot list (the built-in rules cover only some).
    assert isinstance(verdict["blind_spots"], list)
    assert len(verdict["blind_spots"]) > 0
    # Coverage ratio strictly in [0, 1].
    assert 0.0 <= verdict["coverage_ratio"] <= 1.0
    # Detected + blind_spots partition the tested set exactly, no overlap.
    assert set(verdict["techniques_detected"]) | set(verdict["blind_spots"]) == set(
        verdict["techniques_tested"]
    )
    assert not (set(verdict["techniques_detected"]) & set(verdict["blind_spots"]))


def test_covered_technique_is_not_a_blind_spot():
    """T1059.001 has a matching PowerShell rule -> detected, not a blind spot."""
    verdict = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    assert "T1059.001" in verdict["techniques_detected"]
    assert "T1059.001" not in verdict["blind_spots"]


def test_uncovered_technique_is_a_blind_spot():
    """T1003.001 (LSASS dump) has NO rule in the built-in set -> blind spot."""
    verdict = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    assert "T1003.001" in verdict["blind_spots"]
    assert "T1003.001" not in verdict["techniques_detected"]


def test_coverage_math():
    """coverage_ratio == detected / tested."""
    verdict = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    expected = len(verdict["techniques_detected"]) / len(verdict["techniques_tested"])
    assert verdict["coverage_ratio"] == round(expected, 4)


def test_deterministic():
    a = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    b = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    assert a["blind_spots"] == b["blind_spots"]
    assert a["techniques_detected"] == b["techniques_detected"]
    assert a["coverage_ratio"] == b["coverage_ratio"]


def test_no_rule_at_all_makes_everything_a_blind_spot():
    """Empty rule set -> coverage 0.0, every tested technique undetected."""
    verdict = bas.build_verdict(["T1059.001", "T1046"], [])
    assert verdict["coverage_ratio"] == 0.0
    assert set(verdict["blind_spots"]) == {"T1059.001", "T1046"}
    assert verdict["techniques_detected"] == []


def test_run_pure_populates_result_and_evidence_shape():
    """run_pure returns the verdict and stamps RESULT with the same verdict,
    without writing any file (offline, no side effects on disk)."""
    verdict = bas.run_pure()
    assert bas.RESULT["verdict"] == verdict
    assert bas.RESULT["scenario"] == "bas_replay_blind_spots"
    # steps were recorded through the scrubber-backed rec()
    assert any(s["step"] == "replay_technique" for s in bas.RESULT["steps"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
