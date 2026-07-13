"""
Property-based tests for the whitelist_optimizer over-fit guard
===============================================================
``tools/whitelist_optimizer`` turns a cohort of confirmed false-positive alerts
into a Sigma-style suppression clause. The CRITICAL safety property the whole
M6 feedback loop rests on: a synthesized whitelist must NEVER suppress a
provided true-positive. If it did, the loop would silently blind a detection
rule to a real threat. These Hypothesis tests attack that guard with
arbitrary FP cohorts + TP events instead of a handful of fixed cases.

Invariants exercised (all real, none tautological):
  * OVER-FIT GUARD (the headline): for any generated FP cohort plus any provided
    true-positive event, the emitted whitelist clause NEVER matches that TP.
    Verified against the tool's OWN authoritative ``_clause_matches`` engine.
  * Determinism: identical input yields an identical clause/verdict.
  * suppressed_count is a correct, bounded count of FP-cohort matches.
  * A TP identical to (sharing the discriminator of) the FPs forces the tool to
    refuse — it must return ``no_safe_whitelist`` rather than an unsafe clause.
  * No network / no AWS: the module imports and runs with only a placeholder
    role ARN in the environment (asserted implicitly by running offline).

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. Pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

from hypothesis import given, settings
from hypothesis import strategies as st

# UNIQUE path-based module name to avoid sys.modules collision with sibling
# ``handler`` modules (tools/ is a flat scripts tree, every tool ships handler).
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "whitelist_optimizer", "handler.py",
)
_spec = importlib.util.spec_from_file_location("whitelist_optimizer_handler__prop", _HANDLER_PATH)
wl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wl)

_SETTINGS = settings(max_examples=200, deadline=None)


def _optimize(event) -> dict:
    return wl.handler(event, None)


# The candidate discriminating fields the tool actually keys off, and value
# generators appropriate to each field type.
_domain_values = st.sampled_from(
    [
        "assets.example.com",
        "cdn.example.com",
        "img.assets.example.com",
        "api.example.net",
        "static.example.org",
        "host.internal.test",
    ]
)
_ip_values = st.sampled_from(
    # RFC 5737 documentation ranges only.
    ["192.0.2.10", "192.0.2.11", "192.0.2.200", "198.51.100.5", "203.0.113.7"]
)
_exact_values = st.sampled_from(
    ["backup.exe", "svchost.exe", "chrome.exe", "web-01", "web-02", "user-a", "user-b"]
)

# A single alert event: a mix of the candidate fields with random-ish values.
_alert = st.fixed_dictionaries(
    {},
    optional={
        "dst_domain": _domain_values,
        "process_name": _exact_values,
        "src_ip": _ip_values,
        "host": _exact_values,
        "user": _exact_values,
    },
)


# --------------------------------------------------------------------------- #
# THE CRITICAL INVARIANT: a synthesized whitelist never suppresses a TP.       #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    fp_events=st.lists(_alert, min_size=1, max_size=6),
    tp_events=st.lists(_alert, min_size=1, max_size=4),
)
def test_whitelist_never_suppresses_provided_tp(fp_events, tp_events):
    """For ANY FP cohort + provided true-positive(s): if the tool emits a
    whitelist, that clause must NOT match any provided TP.

    We verify with the tool's OWN authoritative ``_clause_matches`` so we are
    testing the real suppression semantics, not a re-implementation.
    """
    result = _optimize(
        {"rule_name": "r", "fp_events": fp_events, "tp_examples": tp_events}
    )
    assert result["ok"] is True
    wlist = result.get("whitelist")
    if wlist is None:
        # Refusing to synthesize is always safe.
        assert result["verdict"] == "no_safe_whitelist"
        assert result["suppressed_count"] == 0
        return

    match_type = wlist["match_type"]
    (field, value), = wlist["fields"].items()
    # The emitted clause must suppress NONE of the provided true-positives.
    for tp in tp_events:
        assert not wl._clause_matches(tp, field, match_type, value), (
            field, match_type, value, tp,
        )


# --------------------------------------------------------------------------- #
# A TP that shares the FP discriminator FORCES a refusal.                      #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    domain=_domain_values,
    n_fp=st.integers(min_value=1, max_value=5),
)
def test_tp_equal_to_fp_discriminator_forces_refusal(domain, n_fp):
    """When every FP shares an exact domain AND a TP carries that same domain,
    the tool MUST refuse (any clause on that domain would suppress the TP)."""
    # Carry ONLY dst_domain so it is the sole shared discriminator (otherwise a
    # differing per-event field like host could itself become a safe clause).
    fp_events = [{"dst_domain": domain} for _ in range(n_fp)]
    tp_events = [{"dst_domain": domain}]
    result = _optimize(
        {"rule_name": "r", "fp_events": fp_events, "tp_examples": tp_events}
    )
    assert result["ok"] is True
    # The only shared discriminator matches the TP -> no safe whitelist.
    assert result["whitelist"] is None
    assert result["verdict"] == "no_safe_whitelist"


# --------------------------------------------------------------------------- #
# In-line TP markers in the fp_events list are treated as guards, not FPs.     #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(domain=_domain_values, marker=st.sampled_from(["true_positive", "tp", "true-positive"]))
def test_inline_tp_marker_is_protected(domain, marker):
    """An fp_event flagged as a true-positive in-line must never be suppressed
    by the emitted clause even though it lives in the fp_events list."""
    fp_events = [
        {"dst_domain": domain, "host": "web-01"},
        {"dst_domain": domain, "host": "web-02"},
        {"dst_domain": domain, "host": "attacker", "disposition": marker},
    ]
    result = _optimize({"rule_name": "r", "fp_events": fp_events})
    assert result["ok"] is True
    # The shared domain also identifies the in-line TP, so it must refuse.
    assert result["whitelist"] is None
    assert result["verdict"] == "no_safe_whitelist"


# --------------------------------------------------------------------------- #
# Determinism: same input => same clause.                                      #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    fp_events=st.lists(_alert, min_size=1, max_size=6),
    tp_events=st.lists(_alert, min_size=0, max_size=3),
)
def test_deterministic_same_input_same_output(fp_events, tp_events):
    ev = {"rule_name": "noisy-rule", "fp_events": fp_events, "tp_examples": tp_events}
    r1 = _optimize({**ev, "fp_events": list(fp_events), "tp_examples": list(tp_events)})
    r2 = _optimize({**ev, "fp_events": list(fp_events), "tp_examples": list(tp_events)})
    assert r1 == r2


# --------------------------------------------------------------------------- #
# suppressed_count is a correct, bounded count over the FP cohort.             #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(fp_events=st.lists(_alert, min_size=1, max_size=6))
def test_suppressed_count_matches_clause_over_cohort(fp_events):
    """When a whitelist is emitted, suppressed_count equals the number of FP
    events (that were not TP-marked) the clause actually matches, and is >= 1
    and bounded by the cohort size."""
    result = _optimize({"rule_name": "r", "fp_events": fp_events})
    assert result["ok"] is True
    wlist = result.get("whitelist")
    if wlist is None:
        assert result["suppressed_count"] == 0
        return
    match_type = wlist["match_type"]
    (field, value), = wlist["fields"].items()
    # Recompute against the non-TP-marked cohort using the tool's own engine.
    cohort = [e for e in fp_events if not wl._is_tp_marked(e)]
    expected = sum(1 for e in cohort if wl._clause_matches(e, field, match_type, value))
    assert result["suppressed_count"] == expected
    assert 1 <= result["suppressed_count"] <= len(cohort)


# --------------------------------------------------------------------------- #
# No network: importing + running touches no socket. Belt-and-suspenders.      #
# --------------------------------------------------------------------------- #
def test_makes_no_network_call():
    """Patch socket.socket to explode; a normal optimize call must still work,
    proving the tool opens no connections."""
    import socket

    orig = socket.socket

    def _boom(*a, **k):  # pragma: no cover - only fires on a real regression
        raise AssertionError("whitelist_optimizer attempted a network socket")

    socket.socket = _boom
    try:
        result = _optimize(
            {
                "rule_name": "r",
                "fp_events": [
                    {"dst_domain": "assets.example.com"},
                    {"dst_domain": "assets.example.com"},
                ],
            }
        )
        assert result["ok"] is True
        assert result["whitelist"] is not None
    finally:
        socket.socket = orig
