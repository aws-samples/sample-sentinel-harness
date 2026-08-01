"""
Round-9 semantic-gap regression suite.
======================================
Audit rounds 3-8 asked "is the code wrong?". Every M18 defect turned out to be a
different question: "was the invariant ever asked?". Round 9 asked that question
of the surfaces M18 did not touch — gateway auth, the feedback thresholds, the
provenance ledger, registry/loader governance — and found six more gaps of the
same shape: a contract stated in prose that the mechanism does not actually
deliver.

The finding that best characterises the round: the provenance module's docstring
promised that "inserting/deleting a record ... will raise". A hash chain does
guarantee that for the MIDDLE of the chain, but it is structurally incapable of
noticing that its own TAIL was deleted — and deleting the last record is the most
natural way to hide a bad promotion. The mechanism was sound; the CLAIM exceeded
it.

Two surfaces were probed and found genuinely solid, recorded here so the next
round does not redo the work: the registry dual gate (deprecated-with-code,
case-mismatch both ways, and an invalid `status` all fail loudly, and governance
reports the drift), and the feedback true-positive guard (an indicator seen on a
true positive is never proposed for suppression).

Every test below FAILS on pre-R9 source. Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import feedback as F        # noqa: E402
from sentinel_harness import gateway as G         # noqa: E402
from sentinel_harness import loader as L          # noqa: E402
from sentinel_harness import provenance as P      # noqa: E402

GOOD_DISCOVERY = "https://cognito-idp.us-east-1.amazonaws.com/pool/.well-known/openid-configuration"


def _entry(**over):
    base = {
        "intake_source": "natural_language",
        "normalized_request": "triage CVE-2021-44228",
        "emitted_spec_summary": "cve-triage harness spec",
        "score_trajectory": [0.4, 0.9],
        "promotion_decision": "promoted",
        "approver": "analyst-1",
    }
    base.update(over)
    return base


def _ev(rule, alert, disposition, indicators):
    return F.FeedbackEvent(alert_id=alert, rule_name=rule,
                           disposition=disposition, indicators=indicators)


def _types(tasks):
    return [t["type"] for t in tasks]


# ========================================================================== #
# INV-GOV-4 — a hash chain cannot detect its own truncation                  #
# ========================================================================== #
class TestLedgerTruncation:
    """PRE-R9: the module promised that deleting a record raises. True for the
    middle of the chain; FALSE for the tail. Deleting the last record left a
    perfectly valid shorter chain — and the last record is exactly the one an
    attacker hiding a bad promotion wants gone."""

    def test_tail_truncation_is_detected_with_an_anchor(self, tmp_path):
        ledger = tmp_path / "l.jsonl"
        for note in ("good-1", "good-2", "the-bad-promotion"):
            P.record_run(_entry(normalized_request=note), ledger_path=ledger)
        P.write_anchor(ledger)
        assert P.verify_ledger(ledger) == 3

        lines = ledger.read_text().splitlines()
        ledger.write_text("\n".join(lines[:-1]) + "\n")

        with pytest.raises(P.ProvenanceError, match="TRUNCATED"):
            P.verify_ledger(ledger)

    def test_emptying_the_ledger_is_detected(self, tmp_path):
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(), ledger_path=ledger)
        P.write_anchor(ledger)
        ledger.write_text("")
        with pytest.raises(P.ProvenanceError, match="TRUNCATED"):
            P.verify_ledger(ledger)

    def test_deleting_the_whole_file_is_detected(self, tmp_path):
        """A missing file reads as an empty ledger, which the anchor still catches."""
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(), ledger_path=ledger)
        P.write_anchor(ledger)
        ledger.unlink()
        with pytest.raises(P.ProvenanceError, match="TRUNCATED"):
            P.verify_ledger(ledger)

    def test_same_length_history_rewrite_is_detected(self, tmp_path):
        """Replacing the tail with a DIFFERENT but internally-valid record keeps the
        length, so a count check alone would pass — the anchored tail hash catches it."""
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(normalized_request="original"), ledger_path=ledger)
        P.record_run(_entry(normalized_request="the-bad-promotion"), ledger_path=ledger)
        P.write_anchor(ledger)

        # Rebuild record #1 with different content, correctly re-chained.
        first = P.load_ledger(ledger, verify=False)[0]
        forged = dict(first)
        forged.update({
            "normalized_request": "an-innocent-looking-run",
            "seq": 1,
            "prev_hash": first["record_hash"],
        })
        forged.pop("record_hash", None)
        forged["record_hash"] = P.compute_record_hash(forged)
        lines = ledger.read_text().splitlines()
        lines[1] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
        ledger.write_text("\n".join(lines) + "\n")

        with pytest.raises(P.ProvenanceError, match="REWRITTEN"):
            P.verify_ledger(ledger)

    def test_appending_after_the_anchor_is_allowed(self, tmp_path):
        """Growth is legitimate — only shrinkage/rewrite is tamper. Otherwise the
        anchor would have to be rewritten in lockstep to log anything at all."""
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(), ledger_path=ledger)
        P.write_anchor(ledger)
        P.record_run(_entry(normalized_request="a later run"), ledger_path=ledger)
        assert P.verify_ledger(ledger) == 2

    def test_require_anchor_refuses_an_unanchored_ledger(self, tmp_path):
        """FAIL-CLOSED: an unanchored ledger carries no truncation guarantee, and
        silence must not read as a pass (same reasoning as INV-PROMOTE-3)."""
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(), ledger_path=ledger)
        assert P.verify_ledger(ledger) == 1          # default stays permissive
        with pytest.raises(P.ProvenanceError, match="no anchor"):
            P.verify_ledger(ledger, require_anchor=True)

    def test_middle_deletion_still_caught_by_the_chain_alone(self, tmp_path):
        """Regression: the pre-existing guarantee must survive the new one."""
        ledger = tmp_path / "l.jsonl"
        for i in range(3):
            P.record_run(_entry(normalized_request=f"r{i}"), ledger_path=ledger)
        lines = ledger.read_text().splitlines()
        ledger.write_text("\n".join([lines[0], lines[2]]) + "\n")
        with pytest.raises(P.ProvenanceError):
            P.verify_ledger(ledger)

    def test_malformed_anchor_raises(self, tmp_path):
        ledger = tmp_path / "l.jsonl"
        P.record_run(_entry(), ledger_path=ledger)
        P.anchor_path_for(ledger).write_text('{"nope": 1}')
        with pytest.raises(P.ProvenanceError, match="malformed"):
            P.verify_ledger(ledger)


# ========================================================================== #
# INV-GOV-5 — a promotion record must name its approver                      #
# ========================================================================== #
class TestPromotedRequiresApprover:
    """PRE-R9: the ledger accepted `promotion_decision='promoted'` with
    `approver=None`, i.e. a governance record asserting "promoted by nobody" —
    which answers the one question the ledger exists to answer with silence."""

    @pytest.mark.parametrize("approver", [None, "", "   "])
    def test_promoted_without_an_approver_is_refused(self, tmp_path, approver):
        with pytest.raises(P.ProvenanceError, match="approver"):
            P.record_run(_entry(approver=approver),
                         ledger_path=tmp_path / "l.jsonl")

    @pytest.mark.parametrize("decision", ["rejected", "held"])
    def test_non_promoted_decisions_need_no_approver(self, tmp_path, decision):
        """A rejected/held run legitimately has no approver yet — the requirement
        must be scoped, not blanket."""
        rec = P.record_run(_entry(promotion_decision=decision, approver=None),
                           ledger_path=tmp_path / "l.jsonl")
        assert rec["promotion_decision"] == decision
        assert rec["approver"] is None

    def test_promoted_with_an_approver_is_accepted(self, tmp_path):
        rec = P.record_run(_entry(approver="analyst-7"),
                           ledger_path=tmp_path / "l.jsonl")
        assert rec["approver"] == "analyst-7"


# ========================================================================== #
# INV-GOV-6 — the OIDC discovery URL決定s the signing keys                    #
# ========================================================================== #
class TestDiscoveryUrlScheme:
    """PRE-R9: any string passed as `discovery_url` was accepted. The discovery
    document is what tells the gateway WHICH KEYS sign a valid token, so over
    plaintext HTTP an on-path attacker substitutes their own JWKS and mints tokens
    the gateway accepts — while the authorizer looks fully configured."""

    @pytest.mark.parametrize("url", [
        "http://evil.test/.well-known/openid-configuration",
        "http://cognito-idp.us-east-1.amazonaws.com/p/.well-known/openid-configuration",
        "ftp://x/.well-known/openid-configuration",
        "not-even-a-url",
        "//no-scheme/.well-known/openid-configuration",
    ])
    def test_non_https_discovery_url_is_refused(self, url):
        with pytest.raises(ValueError):
            G.cognito_jwt_authorizer(url, allowed_clients=["client-1"])

    @pytest.mark.parametrize("url", [
        "https://169.254.169.254/.well-known/openid-configuration",
        "https://127.0.0.1/.well-known/openid-configuration",
        "https://0.0.0.0/.well-known/openid-configuration",
    ])
    def test_non_routable_discovery_host_is_refused(self, url):
        """An IdP must be a real, externally-verifiable endpoint — not the
        metadata service or localhost."""
        with pytest.raises(ValueError, match="non-routable|metadata"):
            G.cognito_jwt_authorizer(url, allowed_clients=["client-1"])

    def test_https_dns_name_is_accepted(self):
        cfg = G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_clients=["client-1"])
        assert cfg["customJWTAuthorizer"]["discoveryUrl"] == GOOD_DISCOVERY

    def test_exactly_one_of_audience_or_clients_still_enforced(self):
        """Regression on the pre-existing guarantee."""
        with pytest.raises(ValueError):
            G.cognito_jwt_authorizer(GOOD_DISCOVERY)
        with pytest.raises(ValueError):
            G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_audience=["a"],
                                     allowed_clients=["c"])


# ========================================================================== #
# INV-GOV-7 — the claim lists ARE the auth boundary                          #
# ========================================================================== #
class TestClaimValueHygiene:
    """PRE-R9: `allowed_clients=["*"]` was accepted verbatim. The repo's ironclad
    rule #1 forbids `allowedTools: ['*']` for exactly this reason; the same
    reasoning applies to the list that decides WHOSE token is accepted."""

    @pytest.mark.parametrize("clients", [["*"], ["*", "c1"], ["cli*"]])
    def test_wildcard_client_is_refused(self, clients):
        with pytest.raises(ValueError, match="wildcard"):
            G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_clients=clients)

    @pytest.mark.parametrize("clients", [[""], ["   "], ["c1", ""], ["c1", None]])
    def test_blank_client_entry_is_refused(self, clients):
        with pytest.raises(ValueError, match="empty|blank"):
            G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_clients=clients)

    @pytest.mark.parametrize("audience", [["*"], [""], ["  "]])
    def test_audience_gets_the_same_hygiene(self, audience):
        with pytest.raises(ValueError):
            G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_audience=audience)

    def test_concrete_values_are_accepted(self):
        cfg = G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_clients=["c1", "c2"])
        assert cfg["customJWTAuthorizer"]["allowedClients"] == ["c1", "c2"]
        cfg = G.cognito_jwt_authorizer(GOOD_DISCOVERY, allowed_audience="aud-1")
        assert cfg["customJWTAuthorizer"]["allowedAudience"] == ["aud-1"]


# ========================================================================== #
# INV-GOV-8 — a near-miss HITL gate name must fail loudly                    #
# ========================================================================== #
class TestHitlGateNearMiss:
    """PRE-R9: `allowedTools: ["request_publish_approval "]` — a trailing space,
    invisible in YAML — injected NOTHING while remaining in allowedTools. The
    config read as "this harness has a publish gate" in review; the gate did not
    exist. That is the worst failure mode for a human-approval control: it looks
    present and is absent."""

    @staticmethod
    def _load(allowed_tools_yaml, prompt="You are a test agent."):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "sp.md"), "w", encoding="utf-8") as fh:
            fh.write(prompt)
        path = os.path.join(d, "harness.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""
                harnessName: r9probe
                systemPrompt: sp.md
                allowedTools: {allowed_tools_yaml}
            """))
        return L.load_harness_config(path)

    def test_exact_gate_name_is_injected(self):
        cfg = self._load('["request_publish_approval"]')
        names = [t.get("name") for t in cfg.get("tools") or []]
        assert "request_publish_approval" in names

    @pytest.mark.parametrize("entry", [
        "request_publish_approval ",
        " request_publish_approval",
        "Request_Publish_Approval",
        "REQUEST_PUBLISH_APPROVAL",
        "request_containment_approval ",
        "Request_Promotion_Approval",
    ])
    def test_near_miss_gate_name_raises(self, entry):
        with pytest.raises(ValueError, match="looks like the built-in HITL gate"):
            self._load(f'["{entry}"]')

    def test_a_genuinely_unrelated_tool_name_is_left_alone(self):
        """Only NEAR MISSES raise; an ordinary non-gate tool name is untouched."""
        cfg = self._load('["siem_query", "@gw/asset_lookup"]')
        assert cfg["allowed_tools"] == ["siem_query", "@gw/asset_lookup"]

    def test_wildcard_allowed_tools_still_refused(self):
        """Regression on ironclad rule #1."""
        with pytest.raises(ValueError):
            self._load('["*"]')


# ========================================================================== #
# INV-GOV-9 — never emit a suppression task with nothing safe to suppress    #
# ========================================================================== #
class TestUnsuppressableNoise:
    """PRE-R9: when EVERY false-positive indicator was also a true-positive
    indicator, the true-positive guard correctly stripped them all — and then the
    task was emitted anyway with `fp_indicators: []`. The comment above the code
    said it would only emit "if there is still noise left to suppress"; the
    condition it actually checked was `fp_count > 0`.

    Worse, suppressing that rule's alert COHORT is not a safe fallback: those
    alerts fired on exactly the indicators we just refused to allowlist."""

    def test_all_indicators_withheld_emits_no_whitelist_task(self):
        events = [_ev("Z", f"f{i}", "false_positive", ["8.8.8.8"]) for i in range(3)]
        events.append(_ev("Z", "t1", "true_positive", ["8.8.8.8"]))
        ledger = F.record_disposition(events, tenant="t")
        tasks = F.detect_triggers(ledger)
        assert "whitelist_optimization" not in _types(tasks)

    def test_the_withholding_is_recorded_not_silent(self):
        """A skipped remedy must leave a trace — "checked and found nothing safe"
        has to look different from "never checked"."""
        events = [_ev("Z", f"f{i}", "false_positive", ["8.8.8.8"]) for i in range(3)]
        events.append(_ev("Z", "t1", "true_positive", ["8.8.8.8"]))
        ledger = F.record_disposition(events, tenant="t")
        F.detect_triggers(ledger)
        reason = ledger["rules"]["Z"].get("no_actionable_suppression")
        assert reason and "8.8.8.8" in reason

    def test_unsuppressable_noise_still_gets_a_regeneration_task(self):
        """The rule is 75% noise; emitting NOTHING would be worse than either
        remedy. It needs to become more specific, which is what regeneration is."""
        events = [_ev("Z", f"f{i}", "false_positive", ["8.8.8.8"]) for i in range(3)]
        events.append(_ev("Z", "t1", "true_positive", ["8.8.8.8"]))
        tasks = F.detect_triggers(F.record_disposition(events, tenant="t"))
        regen = [t for t in tasks if t["type"] == "rule_regeneration"]
        assert len(regen) == 1
        assert regen[0]["trigger"] == "noisy_but_unsuppressable"
        assert regen[0]["withheld_tp_indicators"] == ["8.8.8.8"]

    def test_partial_overlap_still_emits_a_whitelist_task(self):
        """When SOME indicators are safe, the task is emitted for those only, with
        the withheld ones surfaced. This is the pre-existing behaviour and must
        not regress into over-suppression of the task."""
        events = [
            _ev("P", "f1", "false_positive", ["8.8.8.8"]),
            _ev("P", "f2", "false_positive", ["1.2.3.4"]),
            _ev("P", "f3", "false_positive", ["1.2.3.4"]),
            _ev("P", "t1", "true_positive", ["8.8.8.8"]),
        ]
        tasks = F.detect_triggers(F.record_disposition(events, tenant="t"))
        wl = [t for t in tasks if t["type"] == "whitelist_optimization"]
        assert len(wl) == 1
        assert wl[0]["fp_indicators"] == ["1.2.3.4"]
        assert wl[0]["withheld_tp_indicators"] == ["8.8.8.8"]

    def test_no_indicators_at_all_still_emits_a_whitelist_task(self):
        """A rule with no indicators can still be suppressed by alert cohort —
        blunt but legitimate, and NOT the unsuppressable case."""
        events = [_ev("N", f"n{i}", "false_positive", []) for i in range(3)]
        tasks = F.detect_triggers(F.record_disposition(events, tenant="t"))
        wl = [t for t in tasks if t["type"] == "whitelist_optimization"]
        assert len(wl) == 1
        assert wl[0]["fp_events"] == ["n0", "n1", "n2"]

    def test_ordinary_noisy_rule_is_unaffected(self):
        """Regression: the common case must keep emitting both tasks."""
        events = [_ev("R", f"a{i}", "false_positive", [f"1.1.1.{i}"]) for i in range(3)]
        tasks = F.detect_triggers(F.record_disposition(events, tenant="t"))
        assert _types(tasks) == ["whitelist_optimization", "rule_regeneration"]

    def test_healthy_rule_emits_nothing(self):
        events = [_ev("H", f"h{i}", "true_positive", [f"3.3.3.{i}"]) for i in range(3)]
        assert F.detect_triggers(F.record_disposition(events, tenant="t")) == []


# ========================================================================== #
# Surfaces probed and found SOLID — recorded so round 10 does not redo them  #
# ========================================================================== #
class TestVerifiedSolidSurfaces:
    """These assert guarantees that ALREADY held before R9. They are kept as
    tripwires: each is a place a plausible-looking refactor would silently open a
    governance hole."""

    def test_registry_refuses_a_deprecated_tool_that_still_has_code(self):
        from sentinel_harness.registry import RegistryError, ToolRegistry
        fm = {"good_tool": lambda: {"type": "x", "name": "good_tool"}}
        d = tempfile.mkdtemp()
        y = os.path.join(d, "tools.yaml")
        with open(y, "w", encoding="utf-8") as fh:
            fh.write("tools:\n  - name: good_tool\n    owner: platform\n    status: deprecated\n")
        reg = ToolRegistry(fm).load_yaml(y)
        with pytest.raises(RegistryError):
            reg.resolve("good_tool")
        report = reg.governance_check()
        assert report.ok is False
        assert "good_tool" in report.deprecated_with_code

    def test_registry_dual_gate_is_case_sensitive_both_ways(self):
        """A case mismatch must fail on BOTH sides and be reported as drift —
        never resolved by a lenient comparison."""
        from sentinel_harness.registry import RegistryError, ToolRegistry
        fm = {"good_tool": lambda: {"type": "x", "name": "good_tool"}}
        d = tempfile.mkdtemp()
        y = os.path.join(d, "tools.yaml")
        with open(y, "w", encoding="utf-8") as fh:
            fh.write("tools:\n  - name: Good_Tool\n    owner: platform\n    status: approved\n")
        reg = ToolRegistry(fm).load_yaml(y)
        for probe in ("good_tool", "Good_Tool", "GOOD_TOOL"):
            with pytest.raises(RegistryError):
                reg.resolve(probe)
        assert reg.governance_check().ok is False

    @pytest.mark.parametrize("status", ["APPROVED", "approvedd", "Approved", ""])
    def test_registry_invalid_status_fails_loudly_not_silently(self, status):
        """A typo'd status must NOT quietly degrade to "not approved" — that would
        hide a governance misconfiguration."""
        from sentinel_harness.registry import RegistryError, ToolRegistry
        d = tempfile.mkdtemp()
        y = os.path.join(d, "tools.yaml")
        with open(y, "w", encoding="utf-8") as fh:
            fh.write(f"tools:\n  - name: good_tool\n    owner: p\n    status: {status!r}\n")
        with pytest.raises(RegistryError, match="status"):
            ToolRegistry({}).load_yaml(y)

    def test_true_positive_indicator_is_never_proposed_for_suppression(self):
        """The load-bearing feedback guarantee: allowlisting an indicator seen on a
        real detection would blind that detection."""
        events = [
            _ev("Q", "f1", "false_positive", ["5.5.5.5", "9.9.9.9"]),
            _ev("Q", "f2", "false_positive", ["5.5.5.5"]),
            _ev("Q", "f3", "false_positive", ["5.5.5.5"]),
            _ev("Q", "t1", "true_positive", ["9.9.9.9"]),
        ]
        tasks = F.detect_triggers(F.record_disposition(events, tenant="t"))
        wl = [t for t in tasks if t["type"] == "whitelist_optimization"]
        assert wl, "a genuinely suppressable rule must still emit a task"
        assert "9.9.9.9" not in wl[0]["fp_indicators"]
        assert "9.9.9.9" in wl[0]["withheld_tp_indicators"]

    def test_policy_engine_mode_rejects_anything_but_the_two_valid_modes(self):
        """`ENFORCE` is the default and an invalid mode raises — a guardrail that
        silently degraded to observe-only would be a false sense of protection."""
        arn = "arn:aws:bedrock:us-east-1:000000000000:guardrail/g"
        assert G.policy_engine_config(arn)["mode"] == "ENFORCE"
        for bad in ("DISABLED", "", "OFF", "log only"):
            with pytest.raises(ValueError):
                G.policy_engine_config(arn, mode=bad)
