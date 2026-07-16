"""
Offline tests for the M6 feedback engine
=========================================
Exercises ``sentinel_harness/feedback.py`` — the event-driven feedback loop that
turns triage dispositions (TP/FP/benign) into strategy-improvement TASKS
(whitelist optimization + rule regeneration). ZERO AWS, ZERO network, no sleep,
fast, deterministic.

The engine is pure offline logic, so nothing needs mocking: the default
``TenantFactStore`` is an in-memory dict and no code path touches boto3/AWS.
We load the module under a UNIQUE importlib name (never a bare name a sibling
test could collide with), mirroring how the other tests import repo modules.
Importing the module must make ZERO AWS/network calls — asserted implicitly by
these tests running offline with only a placeholder role ARN in the environment.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODULE_PATH = os.path.join(REPO_ROOT, "sentinel_harness", "feedback.py")


def _load_feedback():
    """Load the feedback module under a unique name (import-safe, offline)."""
    unique = "sentinel_feedback__test"
    spec = importlib.util.spec_from_file_location(unique, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network
    return mod


fb = _load_feedback()


# --------------------------------------------------------------------------
# Helpers — build mock-world FP / TP cohorts (RFC 5737 IPs, example.test hosts).
# --------------------------------------------------------------------------
def _fp_cdn_events():
    """The obvious FP cohort from the mock world: mostly false-positive CDN rule."""
    return [
        fb.FeedbackEvent(
            alert_id="alert-1010", rule_name="Known-Good CDN Traffic",
            disposition="false_positive", host="web-01.example.test",
            indicators=["192.0.2.10"], ts="2026-06-28T14:00:00Z", analyst="triage-agent",
        ),
        fb.FeedbackEvent(
            alert_id="alert-1011", rule_name="Known-Good CDN Traffic",
            disposition="benign", host="web-01.example.test",
            indicators=["192.0.2.11"], ts="2026-06-28T14:05:00Z",
        ),
        fb.FeedbackEvent(
            alert_id="alert-1012", rule_name="Known-Good CDN Traffic",
            disposition="false_positive", host="web-02.example.test",
            indicators=["192.0.2.10"], ts="2026-06-28T14:10:00Z",
        ),
    ]


def _healthy_rule_events():
    """A healthy rule: mostly true positives (should NOT trigger anything)."""
    return [
        fb.FeedbackEvent(
            alert_id="alert-1001", rule_name="Log4Shell JNDI Exploit Attempt",
            disposition="true_positive", host="web-01.example.test",
            indicators=["203.0.113.66"], ts="2026-06-28T14:03:11Z",
        ),
        fb.FeedbackEvent(
            alert_id="alert-1002", rule_name="Log4Shell JNDI Exploit Attempt",
            disposition="true_positive", host="web-01.example.test",
            indicators=["203.0.113.67"], ts="2026-06-28T14:20:00Z",
        ),
        fb.FeedbackEvent(
            alert_id="alert-1005", rule_name="Log4Shell JNDI Exploit Attempt",
            disposition="false_positive", host="web-03.example.test",
            indicators=["198.51.100.9"], ts="2026-06-28T15:00:00Z",
        ),
    ]


# --------------------------------------------------------------------------
# FeedbackEvent validation.
# --------------------------------------------------------------------------
def test_event_rejects_bad_disposition():
    with pytest.raises(ValueError):
        fb.FeedbackEvent(alert_id="a", rule_name="r", disposition="not_a_verdict")


def test_event_requires_alert_id_and_rule_name():
    with pytest.raises(ValueError):
        fb.FeedbackEvent(alert_id="", rule_name="r", disposition="true_positive")
    with pytest.raises(ValueError):
        fb.FeedbackEvent(alert_id="a", rule_name="", disposition="true_positive")


# --------------------------------------------------------------------------
# record_disposition: a mostly-FP rule raises its fp_rate.
# --------------------------------------------------------------------------
def test_record_raises_fp_rate_for_noisy_rule():
    ledger = fb.record_disposition(_fp_cdn_events())
    rule = ledger["rules"]["Known-Good CDN Traffic"]
    assert rule["total"] == 3
    assert rule["tp_count"] == 0
    assert rule["fp_count"] == 3  # false_positive + benign both count as noise
    assert rule["fp_rate"] == 1.0
    # The FP cohort + indicators are captured for the whitelist task (deduped).
    assert rule["fp_alert_ids"] == ["alert-1010", "alert-1011", "alert-1012"]
    assert rule["fp_indicators"] == ["192.0.2.10", "192.0.2.11"]
    assert rule["dispositions"] == {
        "true_positive": 0, "false_positive": 2, "benign": 1,
    }
    assert ledger["total_events"] == 3


def test_record_healthy_rule_low_fp_rate():
    ledger = fb.record_disposition(_healthy_rule_events())
    rule = ledger["rules"]["Log4Shell JNDI Exploit Attempt"]
    assert rule["tp_count"] == 2
    assert rule["fp_count"] == 1
    assert rule["fp_rate"] == pytest.approx(1 / 3)


# --------------------------------------------------------------------------
# detect_triggers: a mostly-FP rule emits a whitelist_optimization task.
# --------------------------------------------------------------------------
def test_detect_emits_whitelist_optimization_for_noisy_rule():
    ledger = fb.record_disposition(_fp_cdn_events())
    tasks = fb.detect_triggers(ledger, fp_threshold=0.5, min_events=3)
    wl = [t for t in tasks if t["type"] == "whitelist_optimization"]
    assert len(wl) == 1
    task = wl[0]
    assert task["rule_name"] == "Known-Good CDN Traffic"
    assert task["fp_events"] == ["alert-1010", "alert-1011", "alert-1012"]
    assert "192.0.2.10" in task["fp_indicators"]
    assert task["fp_rate"] == 1.0
    assert task["sample_size"] == 3
    assert "allowlist" in task["rationale"]


# --------------------------------------------------------------------------
# detect_triggers: a healthy (mostly-TP) rule emits NO task.
# --------------------------------------------------------------------------
def test_detect_emits_nothing_for_healthy_rule():
    ledger = fb.record_disposition(_healthy_rule_events())
    # fp_rate = 1/3 ~= 0.33 < 0.5 threshold -> no whitelist; has a TP -> no regen.
    tasks = fb.detect_triggers(ledger, fp_threshold=0.5, min_events=3)
    assert tasks == []


# --------------------------------------------------------------------------
# min_events guard: too few events -> no trigger even at fp_rate 1.0.
# --------------------------------------------------------------------------
def test_min_events_guard_suppresses_thin_evidence():
    events = [
        fb.FeedbackEvent(alert_id="alert-1003", rule_name="Port Scan Detected",
                         disposition="false_positive", indicators=["198.51.100.5"]),
        fb.FeedbackEvent(alert_id="alert-1004", rule_name="Port Scan Detected",
                         disposition="benign", indicators=["198.51.100.6"]),
    ]  # only 2 events, below the default min_events=3
    ledger = fb.record_disposition(events)
    assert ledger["rules"]["Port Scan Detected"]["fp_rate"] == 1.0
    assert fb.detect_triggers(ledger) == []  # guarded out
    # Lowering the guard to 2 lets it through (proves the guard is the gate).
    tasks = fb.detect_triggers(ledger, min_events=2)
    assert any(t["type"] == "whitelist_optimization" for t in tasks)


# --------------------------------------------------------------------------
# rule_regeneration: a rule with ONLY false positives emits a regen task.
# --------------------------------------------------------------------------
def test_only_fp_rule_emits_rule_regeneration():
    ledger = fb.record_disposition(_fp_cdn_events())  # 3/3 FP, zero TP
    tasks = fb.detect_triggers(ledger, fp_threshold=0.5, min_events=3)
    regen = [t for t in tasks if t["type"] == "rule_regeneration"]
    assert len(regen) == 1
    task = regen[0]
    assert task["rule_name"] == "Known-Good CDN Traffic"
    assert task["target"] == "m1_m2_self_improving_loop"
    assert task["sample_size"] == 3
    assert "only false positives" in task["reason"]
    # An only-FP rule triggers BOTH a whitelist patch AND a regeneration request.
    assert {t["type"] for t in tasks} == {
        "whitelist_optimization", "rule_regeneration",
    }


def test_partial_fp_rule_gets_whitelist_but_not_regeneration():
    """fp_rate over threshold but with a real TP -> tighten, don't regenerate."""
    events = [
        fb.FeedbackEvent(alert_id="a1", rule_name="Noisy But Alive",
                         disposition="false_positive", indicators=["192.0.2.20"]),
        fb.FeedbackEvent(alert_id="a2", rule_name="Noisy But Alive",
                         disposition="false_positive", indicators=["192.0.2.21"]),
        fb.FeedbackEvent(alert_id="a3", rule_name="Noisy But Alive",
                         disposition="true_positive", indicators=["203.0.113.9"]),
    ]  # fp_rate = 2/3 ~= 0.67 >= 0.5, but tp_count == 1
    ledger = fb.record_disposition(events)
    tasks = fb.detect_triggers(ledger, fp_threshold=0.5, min_events=3)
    assert {t["type"] for t in tasks} == {"whitelist_optimization"}


# --------------------------------------------------------------------------
# Determinism + tenant namespacing.
# --------------------------------------------------------------------------
def test_ledger_is_deterministic():
    """Same events -> byte-identical ledger and identical task list."""
    events = _fp_cdn_events()
    l1 = fb.record_disposition(events)
    l2 = fb.record_disposition(events)
    assert l1 == l2
    assert fb.detect_triggers(l1) == fb.detect_triggers(l2)


def test_tenant_namespacing_isolates_facts():
    """Each tenant's verdicts persist under its own facts/{tenant} namespace."""
    store = fb.TenantFactStore()
    fb.record_disposition(_fp_cdn_events(), tenant="tenant-a", store=store)
    fb.record_disposition(_healthy_rule_events(), tenant="tenant-b", store=store)

    a = store.facts("tenant-a")
    b = store.facts("tenant-b")
    assert len(a) == 3 and len(b) == 3
    # No cross-tenant leakage: tenant-a has only CDN facts, tenant-b only Log4Shell.
    assert {f["rule_name"] for f in a} == {"Known-Good CDN Traffic"}
    assert {f["rule_name"] for f in b} == {"Log4Shell JNDI Exploit Attempt"}
    # The namespace string mirrors Memory facts/{tenant}.
    assert fb.TenantFactStore.namespace("tenant-a") == "facts/tenant-a"


def test_ledger_reports_tenant_namespace():
    ledger = fb.record_disposition(_fp_cdn_events(), tenant="acme")
    assert ledger["tenant"] == "acme"
    assert ledger["namespace"] == "facts/acme"


def test_injected_memory_writer_is_invoked_offline():
    """The memory_writer seam fires per fact WITHOUT any AWS (a plain callable)."""
    captured = []
    fb.record_disposition(
        _fp_cdn_events(), tenant="t1",
        memory_writer=lambda ns, fact: captured.append((ns, fact["alert_id"])),
    )
    assert [ns for ns, _ in captured] == ["facts/t1"] * 3
    assert [aid for _, aid in captured] == ["alert-1010", "alert-1011", "alert-1012"]


def test_store_and_memory_writer_are_mutually_exclusive():
    with pytest.raises(ValueError):
        fb.record_disposition(
            _fp_cdn_events(), store=fb.TenantFactStore(), memory_writer=lambda ns, f: None,
        )


def test_record_rejects_non_event():
    with pytest.raises(TypeError):
        fb.record_disposition([{"alert_id": "x"}])  # plain dict, not FeedbackEvent


def test_detect_validates_thresholds():
    ledger = fb.record_disposition(_fp_cdn_events())
    with pytest.raises(ValueError):
        fb.detect_triggers(ledger, fp_threshold=1.5)
    with pytest.raises(ValueError):
        fb.detect_triggers(ledger, min_events=0)


# --------------------------------------------------------------------------- #
# regression (round-2 audit HIGH): a whitelist task must NEVER suppress an     #
# indicator that also appears on a TRUE POSITIVE for the same rule            #
# --------------------------------------------------------------------------- #
def test_whitelist_never_suppresses_a_true_positive_indicator():
    events = [
        fb.FeedbackEvent(alert_id="a1", rule_name="R", disposition="false_positive",
                         indicators=["8.8.8.8", "1.2.3.4"]),
        fb.FeedbackEvent(alert_id="a2", rule_name="R", disposition="false_positive",
                         indicators=["8.8.8.8", "5.6.7.8"]),
        fb.FeedbackEvent(alert_id="a3", rule_name="R", disposition="true_positive",
                         indicators=["8.8.8.8"]),  # 8.8.8.8 is ALSO a TP indicator
    ]
    ledger = fb.record_disposition(events, tenant="t")
    tasks = fb.detect_triggers(ledger, fp_threshold=0.5, min_events=3)
    wl = next(t for t in tasks if t["type"] == "whitelist_optimization")
    assert "8.8.8.8" not in wl["fp_indicators"]          # the TP indicator is withheld
    assert wl["withheld_tp_indicators"] == ["8.8.8.8"]   # and surfaced, not silently dropped
    assert set(wl["fp_indicators"]) == {"1.2.3.4", "5.6.7.8"}


def test_ledger_tracks_tp_indicators():
    events = [fb.FeedbackEvent(alert_id="a", rule_name="R", disposition="true_positive",
                               indicators=["9.9.9.9"])]
    ledger = fb.record_disposition(events, tenant="t")
    assert ledger["rules"]["R"]["tp_indicators"] == ["9.9.9.9"]


def test_clean_rule_at_zero_threshold_emits_no_whitelist_task():
    events = [fb.FeedbackEvent(alert_id=f"c{i}", rule_name="Clean",
                               disposition="true_positive") for i in range(3)]
    ledger = fb.record_disposition(events, tenant="t")
    tasks = fb.detect_triggers(ledger, fp_threshold=0.0, min_events=3)
    assert not any(t["type"] == "whitelist_optimization" for t in tasks)
