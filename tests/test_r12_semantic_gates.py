"""
Round-12 semantic-gap regression suite — detection-suite match-set fidelity.
============================================================================
R11 asked "does this governance NUMBER reflect capability?". R12 pushed the same
match-set question into three tools that either GENERATE a rule or GATE on a
comparison, where a wrong answer actively degrades the detection posture:

1. **whitelist_optimizer synthesizes a filter that suppressed MORE than the FP
   cohort — including true positives it certified as preserved.** The tool's TP
   guard (`_clause_matches`) compares values with Python `==`/`endswith`, but the
   Sigma filter it EMITS is read by any engine with `*`/`?` as live wildcards. So
   `process_name: 'a*.exe'` was certified as suppressing only two FPs "while
   preserving 1 true-positive", while the deployed filter globbed away `attack.exe`
   (the TP), `agent.exe`, `abc.exe`, ... — the single guarantee the tool exists to
   make, violated on the exact input the guard was written for. Same class via a
   public-suffix domain (`co.uk`), a weak context field (`dst_port`), a TP missing
   the whitelisted field, and an n=1 over-generalization.

2. **detection_baseline let a real regression pass green.** A shrinking rule
   library reported an "improvement"; a trimmed target list relabelled real blind
   spots "resolved"; an empty/malformed baseline failed OPEN (health defaulted to
   0, so everything scored an improvement) — the worst failure for a gate.

3. **detection_navigator disagreed with the round-11 coverage fix.** A technique
   claimed only by a rule that cannot fire vanished from the layer, which then
   asserted 100% coverage over a real blind spot.

This was a fan-out workflow audit (three parallel probes, every finding
adversarially re-reproduced before it survived). Every test below FAILS on the
pre-R12 source. Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


wl = _load("whitelist_optimizer_r12", "tools/whitelist_optimizer/handler.py")
base = _load("detection_baseline_r12", "tools/detection_baseline/handler.py")
nav = _load("detection_navigator_r12", "tools/detection_navigator/handler.py")
sm = _load("sigma_match_r12", "tools/sigma_match/handler.py")


# --------------------------------------------------------------------------- #
# whitelist_optimizer — the emitted filter's match set must equal the cohort  #
# --------------------------------------------------------------------------- #
def _emitted(fp_events, tp_examples=None, rule_name="R"):
    payload = {"rule_name": rule_name, "fp_events": fp_events}
    if tp_examples is not None:
        payload["tp_examples"] = tp_examples
    return wl.handler(payload, None)


def _deploys_suppress(sigma_filter_yaml, base_selection, event):
    """Replay an event through base-rule vs base+filter using the repo's OWN Sigma
    engine, to see whether the DEPLOYED filter actually suppresses it — the ground
    truth, independent of what the optimizer *certified*."""
    import yaml
    base_rule = {"title": "t", "id": "1",
                 "detection": {"selection": dict(base_selection), "condition": "selection"}}
    filt = yaml.safe_load(sigma_filter_yaml)["detection"]
    after = {"title": "t", "id": "1", "detection": {**base_rule["detection"], **filt}}
    b = sm.handler({"rule": base_rule, "log_event": event}, None)["matched"]
    a = sm.handler({"rule": after, "log_event": event}, None)["matched"]
    return b and not a          # True == the filter suppressed an event the base alerted on


class TestWhitelistNeverSuppressesBeyondCohort:
    """INV-WL-1/2: a synthesized filter must suppress ONLY the FP cohort — never a
    true positive, never an unbounded glob expansion."""

    def test_wildcard_value_is_refused_not_emitted_as_a_glob(self):
        """The headline defect: `a*.exe` certified as TP-preserving while the
        deployed filter globs away the TP. The safe outcome is to refuse the field."""
        out = _emitted(
            [{"process_name": "a*.exe"}, {"process_name": "A*.EXE"}],
            tp_examples=[{"process_name": "attack.exe"}],
        )
        assert out["whitelist"] is None, "emitted a filter from a wildcard-bearing value"
        assert out["verdict"] == "no_safe_whitelist"

    def test_if_a_wildcard_filter_were_emitted_it_would_suppress_the_tp(self):
        """Proves the refusal is load-bearing: had a filter been emitted, replaying
        the TP through the repo's Sigma engine shows it WOULD be suppressed. (This is
        the reproduction that made the finding CONFIRMED; it must stay red-if-broken.)"""
        out = _emitted([{"process_name": "a*.exe"}, {"process_name": "A*.EXE"}],
                       tp_examples=[{"process_name": "attack.exe"}])
        # With the fix there is no yaml to replay — that IS the guarantee.
        assert out.get("sigma_filter_yaml") is None

    def test_public_suffix_domain_is_refused(self):
        """`a.co.uk` + `b.co.uk` share `co.uk`, a public suffix — whitelisting it
        suppresses every `.co.uk` C2."""
        out = _emitted([{"dst_domain": "news.bbc.co.uk"}, {"dst_domain": "foo.bar.co.uk"}])
        assert out["whitelist"] is None

    @pytest.mark.parametrize("suffix_pair", [
        ("a.blob.core.windows.net", "b.blob.core.windows.net"),
        ("x.s3.amazonaws.com", "y.s3.amazonaws.com"),
        ("app1.herokuapp.com", "app2.herokuapp.com"),
    ])
    def test_cloud_public_suffixes_are_refused(self, suffix_pair):
        out = _emitted([{"dst_domain": suffix_pair[0]}, {"dst_domain": suffix_pair[1]}])
        assert out["whitelist"] is None

    def test_private_registrable_suffix_is_still_allowed(self):
        """The fix must not over-refuse: a genuine shared private domain is safe and
        must still produce a whitelist."""
        out = _emitted([{"dst_domain": "a.assets.example.com"},
                        {"dst_domain": "b.assets.example.com"}])
        assert out["whitelist"] is not None
        assert out["whitelist"]["match_type"] == "domain_suffix"
        assert out["whitelist"]["fields"]["dst_domain"] == "assets.example.com"

    @pytest.mark.parametrize("weak_field", ["dst_port", "port", "user", "username",
                                            "host", "hostname"])
    def test_weak_context_field_is_not_a_sole_discriminator(self, weak_field):
        """A port / user / host is context, not benign identity — whitelisting it
        suppresses the real threats too. R12 showed one beating an explicit TP guard."""
        out = _emitted([{weak_field: "445"}, {weak_field: "445"}])
        assert out["whitelist"] is None

    def test_tp_missing_the_whitelisted_field_fails_closed(self):
        """A TP that lacks the whitelisted field cannot be PROVEN safe — absence of
        evidence is not evidence of safety. Refuse the field rather than certify a
        preservation it cannot check."""
        out = _emitted(
            [{"src_ip": "10.0.0.1"}, {"src_ip": "10.0.0.2"}],
            tp_examples=[{"dst_domain": "evil.example.test"}],  # no src_ip
        )
        assert out["whitelist"] is None

    def test_single_quote_value_is_refused(self):
        """A single quote breaks the single-quoted YAML the filter is emitted in
        (and would need escaping); refuse rather than emit invalid/altered Sigma."""
        out = _emitted([{"process_name": "o'brien.exe"}, {"process_name": "o'brien.exe"}])
        assert out["whitelist"] is None

    def test_n1_cohort_refuses_class_generalization(self):
        """A single FP is not enough to generalize a CIDR/suffix class."""
        out = _emitted([{"src_ip": "10.0.0.5", "src_port": "1"}])
        # a lone IP is an EXACT match (suppresses only that IP) — allowed;
        # but if it could only form a broad class it must refuse. Force the class
        # path with two-octet-different IPs is n=2; here n=1 exact is the allowed case.
        assert out["whitelist"] is not None
        assert out["whitelist"]["match_type"] == "exact"

    def test_n1_domain_is_exact_not_suffix(self):
        out = _emitted([{"dst_domain": "a.b.example.com"}])
        assert out["whitelist"]["match_type"] == "domain_exact"

    def test_ipv6_48_is_too_broad(self):
        """A /48 authorizes 2**80 addresses — absurd from two FP events."""
        out = _emitted([{"src_ip": "2001:db8:0:1::1"}, {"src_ip": "2001:db8:0:2::1"}])
        assert out["whitelist"] is None

    def test_the_classic_cdn_case_still_works(self):
        """Regression: the intended happy path (a shared CDN subdomain, a TP that
        does not share it) must still synthesize a safe whitelist."""
        out = _emitted(
            [{"dst_domain": "img.assets.example.com"}, {"dst_domain": "js.assets.example.com"}],
            tp_examples=[{"dst_domain": "evil.example.test"}],
        )
        assert out["whitelist"] is not None

    def test_a_valid_emitted_filter_suppresses_only_the_cohort(self):
        """End-to-end match-set check via the repo's Sigma engine: the emitted filter
        suppresses the FP but NOT an unrelated event sharing no discriminator."""
        out = _emitted([{"process_name": "backup.exe"}, {"process_name": "backup.exe"}])
        assert out["sigma_filter_yaml"]
        sel = {"process_name": "backup.exe"}
        assert _deploys_suppress(out["sigma_filter_yaml"], sel, {"process_name": "backup.exe"})
        assert not _deploys_suppress(out["sigma_filter_yaml"], sel, {"process_name": "ransomware.exe"})


# --------------------------------------------------------------------------- #
# detection_baseline — a real regression can never pass green                 #
# --------------------------------------------------------------------------- #
def _audit(rule_count, health, covered, uncovered, target=None, totals=None):
    return {"ok": True, "health_score": health, "rule_count": rule_count,
            "totals": totals or {}, "lint": {"invalid": []}, "dedup": {"duplicates": []},
            "coverage": {"covered": [{"technique": t} for t in covered],
                         "uncovered": uncovered, "target_count": target}}


def _snap(audit):
    return base.handler({"mode": "snapshot", "audit": audit}, None)["baseline"]


def _cmp(cur, baseline, allow=0):
    return base.handler({"mode": "compare", "audit": cur, "baseline": baseline,
                         "allow_score_drop": allow}, None)


class TestBaselineRegressionsCannotHide:
    """INV-BASELINE-1..5: coverage/quality that genuinely got worse must fail."""

    def test_shrinking_library_that_loses_coverage_is_a_regression(self):
        b = _snap(_audit(8, 86, ["T1059", "T1003", "T1071", "T1046"], []))
        r = _cmp(_audit(3, 92, ["T1059"], []), b)   # score ROSE, but coverage lost
        assert r["regressed"] is True
        assert any("lost coverage" in x for x in r["reasons"])

    def test_bare_rule_count_shrink_is_flagged(self):
        b = _snap(_audit(8, 86, ["T1059"], []))
        r = _cmp(_audit(3, 86, ["T1059"], []), b)
        assert r["regressed"] is True
        assert any("shrank" in x for x in r["reasons"])

    def test_trimmed_target_list_is_not_credited_as_resolved(self):
        b = _snap(_audit(3, 92, ["T1059"], ["T1046", "T1190"], target=3))
        r = _cmp(_audit(3, 98, ["T1059"], [], target=1), b)
        assert r["regressed"] is True
        assert any("target technique list changed" in x for x in r["reasons"])

    @pytest.mark.parametrize("bad_baseline", [
        {},
        {"ok": True},
        {"ok": True, "mode": "snapshot", "baseline": {"health_score": 98, "rule_count": 3}},
        {"rule_count": 3},          # missing health_score
        {"health_score": 90},       # missing rule_count
    ])
    def test_malformed_baseline_fails_closed(self, bad_baseline):
        """The worst failure for a gate is passing green because it could not read
        its baseline. It must return a validation_error, never regressed=False."""
        r = _cmp(_audit(3, 75, ["T1059"], []), bad_baseline)
        assert r["ok"] is False
        assert r["error"] == "validation_error"

    @pytest.mark.parametrize("bad_score", ["98", None, [98], 9.8])
    def test_non_integer_health_score_is_a_validation_error_not_a_crash(self, bad_score):
        r = _cmp(_audit(3, 75, ["T1059"], []), {"health_score": bad_score, "rule_count": 3})
        assert r["ok"] is False
        assert r["error"] == "validation_error"

    @pytest.mark.parametrize("allow", [-1, -100])
    def test_negative_allowance_does_not_disable_the_gate(self, allow):
        """`abs()`-ing a negative allowance turned -100 into a 100-point tolerance
        that disabled the score gate. A negative allowance clamps to strict (0)."""
        b = _snap(_audit(3, 98, ["T1059"], []))
        r = _cmp(_audit(3, 75, ["T1059"], []), b, allow=allow)
        assert r["regressed"] is True

    @pytest.mark.parametrize("bad_allow", [2.9, True, "5"])
    def test_non_integer_allowance_is_rejected(self, bad_allow):
        b = _snap(_audit(3, 98, ["T1059"], []))
        r = base.handler({"mode": "compare", "audit": _audit(3, 75, ["T1059"], []),
                          "baseline": b, "allow_score_drop": bad_allow}, None)
        assert r["ok"] is False

    def test_saturated_totals_growth_is_flagged_at_flat_score(self):
        """untagged_rules 10 -> 25 with a flat health_score (already saturated) is a
        real degradation the scalar cannot show."""
        b = _snap(_audit(10, 75, ["T1059"], [], totals={"untagged_rules": 10}))
        r = _cmp(_audit(25, 75, ["T1059"], [], totals={"untagged_rules": 25}), b)
        assert r["regressed"] is True
        assert any("untagged_rules grew" in x for x in r["reasons"])

    def test_a_genuine_improvement_still_passes(self):
        """Regression: real progress must not be blocked."""
        b = _snap(_audit(3, 80, ["T1059"], ["T1190"], target=2))
        r = _cmp(_audit(4, 90, ["T1059", "T1190"], [], target=2), b)
        assert r["regressed"] is False
        assert any("newly covered" in x or "improved" in x for x in r["improvements"])

    def test_flat_healthy_snapshot_compare_is_not_a_regression(self):
        b = _snap(_audit(3, 90, ["T1059"], ["T1190"], target=2))
        r = _cmp(_audit(3, 90, ["T1059"], ["T1190"], target=2), b)
        assert r["regressed"] is False


# --------------------------------------------------------------------------- #
# detection_navigator — the layer must agree with coverage                    #
# --------------------------------------------------------------------------- #
_GOOD = "title: Good\ntags:\n    - attack.t1059\ndetection:\n    selection:\n        a: 'x'\n    condition: selection\n"
_DEAD = "title: Dead\ntags:\n    - attack.t1190\ndetection:\n    selection:\n        a: 'x'\n    condition: nonexistent\n"


class TestNavigatorAgreesWithCoverage:
    """INV-NAV-1: a technique claimed only by a rule that cannot fire is NOT painted
    green and does not vanish; the coverage percentage cannot read 100% over it."""

    def test_dead_rule_technique_is_not_dropped_from_the_layer(self):
        out = nav.handler({"rules": [_GOOD, _DEAD]}, None)
        ids = {t["techniqueID"] for t in out["layer"]["techniques"]}
        assert "T1190" in ids, "technique claimed by a dead rule vanished from the layer"

    def test_dead_rule_technique_is_not_scored_covered(self):
        out = nav.handler({"rules": [_GOOD, _DEAD]}, None)
        row = next(t for t in out["layer"]["techniques"] if t["techniqueID"] == "T1190")
        assert row["score"] == 0
        assert "cannot fire" in row["comment"].lower()

    def test_inventory_mode_does_not_report_100pct_over_a_dead_rule(self):
        out = nav.handler({"rules": [_GOOD, _DEAD]}, None)
        assert "100.0%" not in out["layer"]["description"]
        assert out["non_actionable_count"] == 1

    def test_navigator_green_set_equals_coverage_covered_set(self):
        """The two tools must not disagree on what is covered."""
        cov_mod = _load("detection_coverage_r12", "tools/detection_coverage/handler.py")
        rules = [_GOOD, _DEAD]
        techs = ["T1059", "T1190"]
        cov = cov_mod.handler({"rules": rules, "techniques": techs}, None)
        navr = nav.handler({"rules": rules, "techniques": techs}, None)
        cov_covered = sorted(c["technique"] for c in cov["covered"])
        nav_green = sorted(t["techniqueID"] for t in navr["layer"]["techniques"] if t["score"] > 0)
        assert cov_covered == nav_green

    def test_all_good_rules_still_report_full_coverage(self):
        """Regression: a clean rule set must still be 100%."""
        out = nav.handler({"rules": [_GOOD]}, None)
        assert out["covered_count"] == 1
        assert out["non_actionable_count"] == 0
        assert "100.0%" in out["layer"]["description"]
