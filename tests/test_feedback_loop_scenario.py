"""
Offline tests for the M6 feedback-loop scenario
===============================================
Validates ``scenarios/scenario_feedback_loop.py`` — the end-to-end proof that a
batch of FP dispositions AUTO-drives whitelist optimization + rule regeneration,
HITL-gated. ZERO AWS, ZERO network, no sleep, fast, deterministic.

The whole loop is pure offline logic (the feedback engine + whitelist_optimizer
are LLM-free deterministic tools), so nothing needs mocking. We load the scenario
under a UNIQUE importlib name (never a bare name a sibling test could collide
with), mirroring how the other scenario tests import repo modules. Importing the
scenario must make ZERO AWS/network calls — asserted implicitly by these tests
running offline with only a placeholder role ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Make the import hermetic: placeholder role/region, no real credential resolution.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")

MODULE_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_feedback_loop.py")


def _load_scenario():
    """Load the scenario under a unique name (import-safe, offline)."""
    unique = "scenario_feedback_loop__test"
    spec = importlib.util.spec_from_file_location(unique, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


fl = _load_scenario()


# --------------------------------------------------------------------------
# Import-safety: the module loads offline and exposes its core seams.
# --------------------------------------------------------------------------
def test_import_safe_offline():
    for name in ("build_fp_batch", "close_loop", "request_publish_approval",
                 "simulate_regen_handoff", "run"):
        assert hasattr(fl, name)


# --------------------------------------------------------------------------
# The pure run: every boolean true, closed=true.
# --------------------------------------------------------------------------
def test_pure_run_closes_with_all_booleans_true():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=True)
    for key in ("auto_triggered_whitelist_task", "healthy_rule_no_task",
                "whitelist_suppresses_fps", "whitelist_preserves_tp",
                "rule_regen_task_generated", "hitl_gate_required", "closed"):
        assert v[key] is True, f"{key} was not True"
    assert v["fp_batch_size"] == 4  # 3 CDN FPs + 1 backup FP


def test_run_entrypoint_writes_closed_verdict():
    """The scenario's run() drives the same loop and records a closed verdict."""
    result = fl.run()
    assert result["verdict"]["closed"] is True
    # Every recorded step is scrubbed JSON-able and the verdict step reflects closure.
    assert result["steps"][-1]["step"] == "verdict"
    assert result["steps"][-1]["ok"] is True


def test_determinism_same_batch_same_verdict():
    """Same batch -> identical verdict (no clock, no randomness, no network)."""
    b1 = fl.build_fp_batch()
    b2 = fl.build_fp_batch()
    v1 = fl.close_loop(*b1, approve=True)
    v2 = fl.close_loop(*b2, approve=True)
    keys = ("fp_batch_size", "auto_triggered_whitelist_task", "healthy_rule_no_task",
            "whitelist_suppresses_fps", "whitelist_preserves_tp",
            "rule_regen_task_generated", "hitl_gate_required", "closed")
    assert {k: v1[k] for k in keys} == {k: v2[k] for k in keys}


# --------------------------------------------------------------------------
# Event-driven trigger: the whitelist task is auto-emitted for the noisy rule
# and NO task is emitted for the healthy TP rule.
# --------------------------------------------------------------------------
def test_whitelist_task_targets_only_the_noisy_rule():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=True)
    assert v["whitelist_task"]["rule_name"] == fl.NOISY_RULE
    assert set(v["task_types"]) == {"whitelist_optimization", "rule_regeneration"}
    # The healthy TP rule appears in NO task.
    assert v["healthy_rule_no_task"] is True


# --------------------------------------------------------------------------
# A batch with NO FP majority triggers NO whitelist task.
# --------------------------------------------------------------------------
def test_no_fp_majority_triggers_no_whitelist_task():
    fe = fl.feedback.FeedbackEvent
    # A rule that is mostly true positive (1 FP of 3) -> below the 0.5 threshold.
    events = [
        fe(alert_id="a1", rule_name=fl.HEALTHY_RULE, disposition=fl.feedback.TP_DISPOSITION,
           indicators=["203.0.113.66"]),
        fe(alert_id="a2", rule_name=fl.HEALTHY_RULE, disposition=fl.feedback.TP_DISPOSITION,
           indicators=["203.0.113.66"]),
        fe(alert_id="a3", rule_name=fl.HEALTHY_RULE, disposition=fl.feedback.FP_DISPOSITION,
           indicators=["198.51.100.9"]),
    ]
    v = fl.close_loop(events, {}, [], approve=True)
    assert v["auto_triggered_whitelist_task"] is False
    assert v["whitelist_task"] is None
    assert v["task_types"] == []
    # With no trigger there is nothing to publish, so the loop is not "closed".
    assert v["closed"] is False


# --------------------------------------------------------------------------
# The whitelist never suppresses the injected TP.
# --------------------------------------------------------------------------
def test_whitelist_never_suppresses_injected_tp():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=True)
    wl = v["whitelist_result"]["whitelist"]
    field = next(iter(wl["fields"]))
    value = wl["fields"][field]
    match_type = wl["match_type"]
    # The synthesized clause matches every FP...
    assert v["whitelist_result"]["suppressed_count"] == 3
    # ...and NONE of the true positives (authoritative optimizer matcher).
    assert v["whitelist_preserves_tp"] is True
    for tp in tp_examples:
        assert not fl.whitelist_optimizer._clause_matches(tp, field, match_type, value)


def test_whitelist_refuses_clause_that_would_blind_a_tp():
    """If a TP shares the FP discriminator, the optimizer must refuse (no unsafe clause)."""
    events, alert_details, _ = fl.build_fp_batch()
    # A poisoned TP that shares EVERY discriminator the FP cohort has (the CDN
    # domain suffix AND a src_ip inside the FPs' /24) — so no safe field remains
    # and the optimizer must refuse rather than fall back to another clause.
    poisoned_tp = [{"alert_id": "tp-x", "rule_name": fl.HEALTHY_RULE,
                    "dst_domain": "evil.assets.example.com", "host": "web-01",
                    "src_ip": "192.0.2.10"}]
    v = fl.close_loop(events, alert_details, poisoned_tp, approve=True)
    # No safe whitelist -> not suppressed, but also provably didn't blind the TP.
    assert v["whitelist_suppresses_fps"] is False
    assert v["whitelist_preserves_tp"] is True
    assert v["closed"] is False  # can't close without a safe suppression


# --------------------------------------------------------------------------
# HITL gate: approval required; reject withholds publish.
# --------------------------------------------------------------------------
def test_publish_gate_requires_approval_and_reject_withholds():
    approve = fl.request_publish_approval({"kind": "whitelist_clause"}, approve=True)
    reject = fl.request_publish_approval({"kind": "whitelist_clause"}, approve=False)
    assert approve["approval_required"] is True and reject["approval_required"] is True
    assert approve["published"] is True
    assert reject["published"] is False


def test_reject_path_withholds_publish_so_loop_not_closed():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=False)
    # All the mechanism booleans still hold (the gate itself is correctly required)...
    assert v["hitl_gate_required"] is True
    # ...but a rejection means nothing published, so the loop is NOT closed.
    assert v["closed"] is False


# --------------------------------------------------------------------------
# min_events guard: the lone backup FP never triggers.
# --------------------------------------------------------------------------
def test_lone_backup_fp_is_below_min_events_guard():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=True)
    # The single Scheduled Backup FP must not produce a task (thin evidence).
    assert fl.BACKUP_RULE not in {t.get("rule_name")
                                  for t in [v["whitelist_task"], v["regen_task"]] if t}
    assert v["ledger_rules"][fl.BACKUP_RULE]["total"] == 1


# --------------------------------------------------------------------------
# Regeneration hand-off is a labeled, simulated wiring point (never live).
# --------------------------------------------------------------------------
def test_regen_handoff_is_labeled_simulated_wiring_point():
    events, alert_details, tp_examples = fl.build_fp_batch()
    v = fl.close_loop(events, alert_details, tp_examples, approve=True)
    handoff = v["regen_handoff"]
    assert handoff["simulated"] is True
    assert handoff["wiring_point"] is True
    assert "self-improving" in handoff["target_harness"]
    assert handoff["driver_tool"] == "tools/harness_ops"


# --------------------------------------------------------------------------
# Evidence scrubbing: account ids never survive into the evidence dict.
# --------------------------------------------------------------------------
def test_scrub_masks_account_ids_in_arns():
    acct = "9" * 12
    obj = {"arn": f"arn:aws:iam::{acct}:role/x", "n": [f"arn:aws:sts::{acct}:y"]}
    out = fl._scrub(obj)
    assert acct not in str(out)
    assert "<ACCOUNT_ID>" in out["arn"]
