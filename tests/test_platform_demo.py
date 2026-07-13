"""Offline test for demo/platform_demo.py
==========================================
``demo/platform_demo.py`` is the promotion-quality guided TOUR of the whole
platform (L1 → L4). Its default mode is fully offline: it replays committed
``evidence/*.json`` and EXECUTES the deterministic L2 cores (BAS replay + Play
Mode decision logic) in-process — no AWS, no network, no LLM, no sleeps. This
test runs the tour in that default mode and asserts (a) it exits 0, (b) it hits
EVERY beat (1..7, covering L1/M1/M2/L2/L3/L4), and (c) it prints the closing
capability→status→evidence summary table.

HARD RULE: ZERO AWS / ZERO network. We poison ``core._control`` / ``core._data``
so any real control/data-plane call blows up loudly; the tour must still exit 0
because it never touches them. A dummy env is set before importing anything that
builds a boto3 client.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_platform_demo.py -q
"""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEMO_PATH = os.path.join(_REPO_ROOT, "demo", "platform_demo.py")


def _load_demo():
    """Load demo/platform_demo.py by path (demo/ is a scripts tree, not a package).
    Importing it must NOT touch AWS — it only sets dummy env and defines functions."""
    spec = importlib.util.spec_from_file_location("platform_demo", _DEMO_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


demo = _load_demo()


def test_offline_tour_exits_zero_and_hits_every_beat(capsys):
    """Run the tour in its default offline/mock mode: it must exit 0 and its
    narrative must walk every beat 1..7 across all layers, ending in the table."""
    rc = demo.main([])  # no --live -> offline tour
    assert rc == 0

    out = capsys.readouterr().out
    low = out.lower()

    # It advertises the offline/no-AWS contract.
    assert "offline" in low
    assert "no aws" in low

    # Every beat header is present, in order (a shuffled tour is a bug).
    beat_positions = []
    for n in range(1, 8):
        marker = f"beat {n} ·"
        assert marker in low, f"missing {marker!r}"
        beat_positions.append(low.index(marker))
    assert beat_positions == sorted(beat_positions), "beats printed out of order"

    # Every layer/milestone label heads at least one beat (L3/L4 share beat 7's
    # header "L3/L4", so L4 is asserted separately in the summary table below).
    for label in ("l1", "m1", "m2", "l2", "l3"):
        assert re.search(rf"beat \d+ · {label}\b", low), f"no beat labeled {label!r}"
    assert "l3/l4" in low, "beat 7 must cover the L3/L4 foundation"

    # Beat-specific proof lines (each beat really said what it demonstrates).
    assert "hit_human_review_gate" in low              # beat 1 (CVE triage HITL)
    assert "closed_hitl_loop" in low                   # beat 1 (pause->approve->resume)
    assert "parallel_speedup_vs_serial" in low         # beat 2 (multi-harness)
    assert "generator_and_reviewer_are_separate_harnesses" in low  # beat 3
    assert "an agent builds an agent" in low           # beat 4 (M1)
    assert "score → improve → promote-to-endpoint" in low  # beat 5 (M2)
    assert "create_harness_endpoint_succeeded" in low  # beat 5 (promote)
    assert "blind spots" in low                        # beat 6a (BAS)
    assert "coverage_ratio: 0.5" in low                # beat 6a executed live-offline
    assert "reject after step 1 halts the plan: true" in low  # beat 6b play mode
    assert "guardrail_intervened" in low               # beat 7 guardrail masking
    assert "gateway create" in low                     # beat 7 gateway
    assert "rs256" in low                              # beat 7 cognito jwt
    assert "sentinel-observability" in low             # beat 7 observability

    # The closing summary table exists with its columns + the three statuses.
    assert "summary — capability" in low
    assert "capability" in low and "status" in low and "evidence" in low
    assert "live-validated" in low
    assert "built+tested" in low
    assert "skeleton" in low
    # It cites concrete evidence files in the table.
    assert "evidence/cve_triage_result.json" in low
    assert "evidence/gateway_lifecycle_result.json" in low
    # Honest tally line is printed.
    assert "totals:" in low and "live-validated ·" in low


def test_offline_tour_makes_no_real_boto_calls(monkeypatch):
    """Belt-and-suspenders: the offline tour must not reach the real boto planes.
    Poison core._control / core._data so ANY real AWS call blows up; the tour must
    still exit 0 because it never touches them (it replays evidence + runs pure code)."""
    from sentinel_harness import core

    class _Poison:
        def __getattr__(self, item):
            raise AssertionError(f"offline tour must not call AWS (_control/_data.{item})")

    monkeypatch.setattr(core, "_control", _Poison())
    monkeypatch.setattr(core, "_data", _Poison(), raising=False)

    assert demo.run_tour() == 0


def test_live_flag_prints_pointer_and_exits_zero(capsys):
    """--live is informational: it prints how to run the real scenarios (it does not
    run them from the tour) and exits 0. It must name the live scenario scripts."""
    rc = demo.main(["--live"])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "live scenarios" in out
    assert "scenarios/scenario_cve_triage.py" in out
    assert "scenarios/scenario_self_improve_loop.py" in out
    # It must not fabricate a live result — it only points at how to produce one.
    assert "sentinel cleanup" in out


def test_summary_table_rows_are_wellformed():
    """The summary table is driven by SUMMARY_ROWS (single source of truth). Every
    row must use one of the three sanctioned status strings, cover all seven beats,
    and every layer, so the table can never drift from the beats."""
    rows = demo.SUMMARY_ROWS
    assert rows, "summary table must have rows"
    valid_status = {demo.LIVE, demo.BUILT, demo.SKELETON}
    beats_seen = set()
    layers_seen = set()
    for beat_no, layer, capability, status, component, evidence in rows:
        assert status in valid_status, f"bad status {status!r} for {capability!r}"
        assert 1 <= beat_no <= 7
        assert capability and component and evidence
        beats_seen.add(beat_no)
        layers_seen.add(layer)
    assert beats_seen == set(range(1, 8)), f"beats not all covered: {beats_seen}"
    assert {"L1", "M1", "M2", "L2", "L3", "L4"} <= layers_seen


def test_missing_evidence_is_honest_not_fabricated(tmp_path, monkeypatch):
    """If an evidence file is absent, the tour must SAY so (never invent a verdict).
    Point the evidence dir at an empty tmp dir and confirm the honest 'NOT PRESENT'
    provenance string appears rather than a fabricated result."""
    monkeypatch.setattr(demo, "_EVIDENCE_DIR", str(tmp_path))
    verdict, source = demo._evidence_verdict("cve_triage_result.json")
    assert verdict is None
    assert "not present" in source.lower()


def test_bas_replay_beat_executes_real_deterministic_core():
    """Beat 6a is EXECUTED (not replayed): loading the BAS scenario module by path
    and calling build_verdict() must return a real, non-empty blind-spot list with a
    coverage ratio in [0,1] — proving the deterministic Sigma matcher actually ran."""
    bas = demo._load_module_by_path(
        "scenario_bas_replay_test", os.path.join("scenarios", "scenario_bas_replay.py"))
    verdict = bas.build_verdict(bas.DEFAULT_TECHNIQUES, bas.BUILTIN_SIGMA_RULES)
    assert verdict["blind_spots"], "expected real, non-empty blind spots"
    assert 0.0 <= verdict["coverage_ratio"] <= 1.0
    assert set(verdict["techniques_detected"]) <= set(verdict["techniques_tested"])


def test_runs_as_subprocess_exit_zero():
    """End-to-end smoke: run the demo as a real subprocess (as a user would) and
    assert it exits 0 and prints the closing table. Uses the same interpreter and a
    dummy placeholder role — no AWS credentials, no network."""
    env = dict(os.environ)
    env["SENTINEL_EXECUTION_ROLE_ARN"] = "arn:aws:iam::000000000000:role/test"
    env.setdefault("SENTINEL_REGION", "us-east-1")
    env.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    proc = subprocess.run(
        [sys.executable, _DEMO_PATH],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"nonzero exit; stderr:\n{proc.stderr[:2000]}"
    assert "SUMMARY — capability" in proc.stdout
    assert "BEAT 7 ·" in proc.stdout
    # No real 12-digit account id leaked (only the all-zeros placeholder is allowed).
    leaked = [m for m in re.findall(r"\b\d{12}\b", proc.stdout) if m != "000000000000"]
    assert not leaked, f"real account id(s) leaked into demo output: {leaked}"
