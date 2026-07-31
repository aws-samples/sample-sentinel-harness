"""
Round-11 semantic-gap regression suite — detection-suite fidelity.
==================================================================
R10 asked "is this well-formed output semantically right?" of the translators.
R11 put the same question to the rest of the detection suite, where the failure
mode is subtler: these tools produce *governance numbers* a SOC acts on. A wrong
number is worse than a crash, because nobody investigates a green dashboard.

Two findings, both of which make a blind spot look covered:

1. **`detection_coverage` counted a rule that can NEVER FIRE as coverage.** A tag
   is a statement of INTENT; only a rule that can fire is CAPABILITY. A rule with
   no `detection` block — or a `condition` naming a selection that does not exist
   — produces exactly zero alerts, yet its `attack.t1059` tag was enough to move
   T1059 out of `uncovered`. The module's own docstring names this failure ("a
   false 'covered' hides a real blind spot"); it just never checked.

2. **`sigma_match` treated Sigma wildcards as literal characters.** `Image: 'cmd*'`
   reported NO match against `cmd.exe`. Because `longrunning/bas-runner` uses this
   matcher to decide whether a technique is detected, an under-match publishes a
   FALSE BLIND SPOT: the team is told to build coverage it already has, and the
   noise hides the real gaps. Field names were also compared case-sensitively, so
   a rule written `Image:` missed an event carrying `image:`.

`detection_dedup` was probed with the same intent and found SOLID — it performs a
real match-set containment proof (not text similarity), refuses to claim a subset
it cannot prove, and records non-provable rules in `not_analyzed`. Tripwire tests
for that are kept at the bottom so a future "optimisation" cannot quietly turn it
into fuzzy matching.

Zero network, zero AWS, zero LLM.
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


cov = _load("detection_coverage_r11", "tools/detection_coverage/handler.py")
sm = _load("sigma_match_r11", "tools/sigma_match/handler.py")
dd = _load("detection_dedup_r11", "tools/detection_dedup/handler.py")
audit = _load("detection_audit_r11", "tools/detection_audit/handler.py")


def _coverage(rules, techniques=None):
    payload = {"rules": rules}
    if techniques is not None:
        payload["techniques"] = techniques
    return cov.handler(payload, None)


def _match(selection_body: str, log_event: dict, condition: str = "selection"):
    rule = (
        "title: T\nlogsource:\n    category: proxy\ndetection:\n    selection:\n"
        f"{selection_body}    condition: {condition}\n"
    )
    return sm.handler({"rule": rule, "log_event": log_event}, None)


def _value_match(pattern, text, modifier=""):
    """Exercise the value comparison directly, bypassing the YAML layer.

    Wildcard/escape behaviour is about the RAW value the parser produced, and going
    through a YAML string literal in the test source obscures which backslashes are
    the test author's and which are Sigma's. Passing the value straight in keeps
    each case unambiguous.
    """
    return sm._match_one_value(text, modifier, pattern, False, "f", [])


def _tagged_rule(detection_block: str, tag: str = "attack.t1059", title: str = "R") -> str:
    return f"title: {title}\ntags:\n    - {tag}\n{detection_block}"


# ========================================================================== #
# INV-COVERAGE-1 — a tag is intent; only a rule that can FIRE is capability   #
# ========================================================================== #
class TestNonActionableRulesDoNotCountAsCoverage:
    """PRE-R11: coverage was computed purely from `tags`, so a structurally dead
    rule moved its technique out of `uncovered`. The ATT&CK matrix showed green
    while an attacker using that technique walked in unseen."""

    @pytest.mark.parametrize("detection_block,label", [
        ("", "no detection block at all"),
        ("detection: {}\n", "empty detection block"),
        ("detection:\n    selection:\n        a: 'x'\n", "no condition"),
        ("detection:\n    selection:\n        a: 'x'\n    condition: nonexistent\n",
         "condition names an undefined selection"),
        ("detection:\n    condition: selection\n", "condition but no selection"),
    ])
    def test_a_rule_that_cannot_fire_never_covers(self, detection_block, label):
        out = _coverage([_tagged_rule(detection_block)], ["T1059"])
        assert out["covered"] == [], f"{label}: dead rule counted as coverage"
        assert out["uncovered"] == ["T1059"], f"{label}: technique hidden from uncovered"
        assert len(out["non_actionable_rules"]) == 1

    def test_the_exclusion_is_recorded_with_the_claim_it_made(self):
        """A withheld rule must be actionable, not silently dropped: the report has
        to say WHICH technique it falsely claimed, or the gap is unfixable."""
        out = _coverage(
            [_tagged_rule("detection:\n    selection:\n        a: 'x'\n    condition: typo\n")],
            ["T1059"],
        )
        entry = out["non_actionable_rules"][0]
        assert entry["claimed_techniques"] == ["T1059"]
        assert "can never fire" in entry["reason"]

    def test_summary_surfaces_the_exclusion(self):
        """A reader who only reads the one-line summary must still see it."""
        out = _coverage(
            [_tagged_rule("detection:\n    selection:\n        a: 'x'\n    condition: typo\n")],
            ["T1059"],
        )
        assert "non-actionable" in out["summary"]

    def test_a_live_rule_still_covers(self):
        out = _coverage(
            [_tagged_rule("detection:\n    selection:\n        a: 'x'\n    condition: selection\n")],
            ["T1059"],
        )
        assert [c["technique"] for c in out["covered"]] == ["T1059"]
        assert out["non_actionable_rules"] == []

    def test_coverage_is_credited_only_to_the_rule_that_can_fire(self):
        """The mixed case that matters in a real rule library: one good rule, one
        dead one, both claiming the same technique. Coverage is real (the good rule
        exists) but the dead rule is still reported."""
        good = _tagged_rule(
            "detection:\n    selection:\n        a: 'x'\n    condition: selection\n", title="Good")
        dead = _tagged_rule(
            "detection:\n    selection:\n        a: 'x'\n    condition: typo\n", title="Dead")
        out = _coverage([good, dead], ["T1059"])
        assert len(out["covered"]) == 1
        assert all("Good" in r for r in out["covered"][0]["rules"])
        assert len(out["non_actionable_rules"]) == 1

    @pytest.mark.parametrize("condition", [
        "selection",
        "selection and not filter",
        "selection or filter",
        "1 of selection_*",
        "all of them",
        "all of selection_*",
    ])
    def test_valid_condition_shapes_are_not_falsely_excluded(self, condition):
        """ZERO false positives on real Sigma condition grammar — an actionability
        check that rejects valid rules would silently DELETE real coverage, which is
        the opposite failure and just as bad."""
        rule = (
            "title: R\ntags:\n    - attack.t1059\ndetection:\n"
            "    selection:\n        a: 'x'\n"
            "    selection_b:\n        b: 'y'\n"
            "    filter:\n        c: 'z'\n"
            f"    condition: {condition}\n"
        )
        out = _coverage([rule], ["T1059"])
        assert out["non_actionable_rules"] == [], f"{condition!r} wrongly excluded"
        assert [c["technique"] for c in out["covered"]] == ["T1059"]

    def test_sub_technique_reasoning_still_holds(self):
        """Regression on the pre-existing sound sub-technique logic: a sub covers its
        parent, a parent does NOT cover a specific sub."""
        sub = _tagged_rule(
            "detection:\n    selection:\n        a: 'x'\n    condition: selection\n",
            tag="attack.t1059.001")
        out = _coverage([sub], ["T1059", "T1059.001", "T1059.002"])
        covered = {c["technique"] for c in out["covered"]}
        assert covered == {"T1059", "T1059.001"}
        assert out["uncovered"] == ["T1059.002"]

        parent = _tagged_rule(
            "detection:\n    selection:\n        a: 'x'\n    condition: selection\n",
            tag="attack.t1059")
        out2 = _coverage([parent], ["T1059.001"])
        assert out2["covered"] == []


class TestAuditPenalisesNonActionableRules:
    """A non-actionable rule is a governance defect in its own right — and a WORSE
    one than an untagged rule. An untagged rule UNDER-reports its own coverage
    (conservative, harmless); this one OVER-reports it, turning the matrix green
    over a real gap. The audit score has to reflect that asymmetry."""

    def _audit(self, rules, techniques):
        return audit.handler({"rules": rules, "techniques": techniques}, None)

    def test_non_actionable_count_reaches_the_audit_totals(self):
        dead = _tagged_rule(
            "detection:\n    selection:\n        a: 'x'\n    condition: typo\n")
        out = self._audit([dead], ["T1059"])
        assert out["totals"]["non_actionable_rules"] == 1

    def test_non_actionable_rules_lower_the_health_score(self):
        live = _tagged_rule(
            "logsource:\n    product: windows\n    category: ps_script\n"
            "detection:\n    selection:\n        a: 'x'\n    condition: selection\n",
            title="Live")
        dead = _tagged_rule(
            "logsource:\n    product: windows\n    category: ps_script\n"
            "detection:\n    selection:\n        a: 'x'\n    condition: typo\n",
            title="Dead")
        healthy = self._audit([live], ["T1059"])["health_score"]
        degraded = self._audit([live, dead], ["T1059"])["health_score"]
        assert degraded < healthy, (
            "a rule that claims coverage it cannot deliver did not cost any score"
        )


# ========================================================================== #
# INV-MATCH-1/2 — the matcher agrees with Sigma on wildcards and field case   #
# ========================================================================== #
class TestSigmaWildcardsAreHonoured:
    """PRE-R11: `*` and `?` in a value were compared as literal characters, so
    `Image: 'cmd*'` did not match `cmd.exe`. In this tool that is not just a wrong
    boolean — bas-runner reads it as "technique NOT detected" and publishes a false
    blind spot."""

    @pytest.mark.parametrize("pattern,text", [
        ("cmd*", "cmd.exe"),
        ("*cmd.exe", r"C:\Windows\cmd.exe"),
        ("*powershell*", r"C:\WinSxS\powershell.exe"),
        ("cm?", "cmd"),
        ("x*z", "xyz"),
        ("a*b*c", "aXXbYYc"),
    ])
    def test_wildcards_match(self, pattern, text):
        assert _value_match(pattern, text) is True

    @pytest.mark.parametrize("pattern,text", [
        ("cmd*", "notcmd.exe"),      # * does not float to the middle
        ("cm?", "cmdd"),             # ? is exactly one character
        ("x*z", "xy"),               # the trailing literal must still be present
    ])
    def test_wildcards_do_not_over_match(self, pattern, text):
        assert _value_match(pattern, text) is False

    @pytest.mark.parametrize("pattern,text,expected", [
        (r"a\*b", "a*b", True),      # \* is an escape -> literal asterisk
        (r"a\*b", "aXXb", False),    # ...and therefore NOT a wildcard
        (r"a\?b", "a?b", True),
        (r"a\?b", "aXb", False),
    ])
    def test_escaped_wildcards_stay_literal(self, pattern, text, expected):
        """Per the Sigma spec only `\\*`, `\\?` and `\\\\` are escapes. The literal
        spelling has to WORK: before this fix the escape was honoured on the wildcard
        path and ignored on the literal path, so `a\\*b` matched nothing at all — the
        one spelling that exists to match a literal asterisk was the one that could
        never match."""
        assert _value_match(pattern, text) is expected

    def test_a_lone_backslash_stays_literal(self):
        """Windows paths depend on this: only \\* \\? \\\\ are escapes, so `\\W` is
        just a backslash followed by W."""
        assert _value_match(r"C:\Windows\cmd.exe", r"C:\Windows\cmd.exe") is True
        assert _value_match(r"a\nb", r"a\nb") is True

    def test_escaped_backslash_then_wildcard(self):
        r"""`a\\*b` = literal backslash, then a live wildcard."""
        assert _value_match(r"a\\*b", r"a\XXb") is True

    @pytest.mark.parametrize("modifier,pattern,text", [
        ("contains", "x*y", "aaxbbycc"),
        ("startswith", "c*d", "cXXdYY"),
        ("endswith", "x*z", "AAxQQz"),
    ])
    def test_wildcards_compose_with_a_modifier(self, modifier, pattern, text):
        """The modifier still decides WHERE the pattern sits: `|contains: 'x*y'` means
        "some substring matches x*y", not "the whole field does"."""
        assert _value_match(pattern, text, modifier) is True

    def test_end_to_end_through_the_handler(self):
        out = _match("        Image: 'cmd*'\n", {"Image": "cmd.exe"})
        assert out["matched"] is True
        assert not out.get("caveats")


class TestFieldNamesAreCaseInsensitive:
    """PRE-R11: field lookup was exact, so a rule written `Image:` missed an event
    carrying `image:` — a routine mismatch between a rule author's reference and a
    shipped log schema, and another source of false blind spots."""

    def test_rule_case_differs_from_event_case(self):
        assert _match("        Image: 'x'\n", {"image": "x"})["matched"] is True
        assert _match("        image: 'x'\n", {"IMAGE": "x"})["matched"] is True

    def test_an_exact_hit_always_wins(self):
        """A well-formed event must be unaffected by the fallback."""
        assert _match("        a: 'exact'\n", {"a": "exact", "A": "other"})["matched"] is True

    def test_ambiguous_case_is_refused_with_a_caveat(self):
        """Two keys differing only by case: either choice could flip the verdict, so
        the matcher refuses rather than guessing — and says so."""
        out = _match("        Image: 'x'\n", {"IMAGE": "x", "image": "x"})
        assert out["matched"] is False
        assert any(c.get("reason") == "ambiguous_field_case" for c in out["caveats"])

    def test_exists_modifier_uses_the_same_resolution(self):
        assert _match("        Image|exists: true\n", {"image": "v"})["matched"] is True
        assert _match("        Zzz|exists: false\n", {"image": "v"})["matched"] is True

    def test_a_genuinely_absent_field_still_does_not_match(self):
        assert _match("        totally_absent: 'x'\n", {"a": "1"})["matched"] is False


class TestMatcherRegressions:
    """The pre-existing evaluation semantics must survive both fixes."""

    @pytest.mark.parametrize("body,event,expected", [
        ("        a: 'cmd.exe'\n", {"a": "CMD.EXE"}, True),        # value case-insensitive
        ("        a|contains: 'jndi'\n", {"a": "x jndi y"}, True),
        ("        a|re: '^cm.*'\n", {"a": "cmd"}, True),
        ("        ip|cidr: '10.0.0.0/8'\n", {"ip": "10.1.2.3"}, True),
        ("        n|gt: 100\n", {"n": 200}, True),
        ("        n|gt: 100\n", {"n": 50}, False),
        ("        a|cased: 'CMD'\n", {"a": "cmd"}, False),          # cased is strict
        ("        a: null\n", {}, True),                            # null == absent
        ("        zzz: 'x'\n", {"a": "1"}, False),
    ])
    def test_existing_modifiers_unchanged(self, body, event, expected):
        assert _match(body, event)["matched"] is expected

    def test_unknown_modifier_still_caveats_and_fails(self):
        out = _match("        a|frobnicate: 'x'\n", {"a": "x"})
        assert out["matched"] is False
        assert any(c.get("reason") == "unsupported_modifier" for c in out["caveats"])

    def test_negation_condition_unchanged(self):
        rule = ("title: T\nlogsource:\n    category: proxy\ndetection:\n"
                "    selection:\n        a: 'x'\n"
                "    filter:\n        b: 'y'\n    condition: selection and not filter\n")
        hit = sm.handler({"rule": rule, "log_event": {"a": "x", "b": "y"}}, None)
        miss = sm.handler({"rule": rule, "log_event": {"a": "x", "b": "other"}}, None)
        assert hit["matched"] is False      # filter excluded it
        assert miss["matched"] is True

    def test_all_aggregator_unchanged(self):
        rule = ("title: T\nlogsource:\n    category: proxy\ndetection:\n"
                "    selection:\n        a|contains|all:\n            - 'x'\n            - 'y'\n"
                "    condition: selection\n")
        assert sm.handler({"rule": rule, "log_event": {"a": "xy"}}, None)["matched"] is True
        assert sm.handler({"rule": rule, "log_event": {"a": "xq"}}, None)["matched"] is False


# ========================================================================== #
# detection_dedup — probed and found SOLID; tripwires so it stays that way    #
# ========================================================================== #
class TestDedupRemainsAMatchSetProof:
    """`detection_dedup` does a real match-set containment PROOF, not text
    similarity. These tripwires exist because the tempting "optimisation" — compare
    normalised rule text — would silently start reporting false duplicates, and a
    false duplicate gets a REAL rule deleted."""

    @staticmethod
    def _rule(title, body, category="proxy"):
        return (f"title: {title}\nlogsource:\n    category: {category}\n"
                f"detection:\n    selection:\n{body}    condition: selection\n")

    def _run(self, rules):
        return dd.handler({"rules": rules}, None)

    def test_same_match_set_different_field_order_is_a_duplicate(self):
        out = self._run([
            self._rule("A", "        a: 'x'\n        b: 'y'\n"),
            self._rule("B", "        b: 'y'\n        a: 'x'\n"),
        ])
        assert len(out["duplicates"]) == 1

    def test_a_stricter_rule_is_a_subsumption_not_a_duplicate(self):
        """THE case that must never be called a duplicate: deleting the narrow rule
        as 'redundant' loses a detection the broad one does not make."""
        out = self._run([
            self._rule("Broad", "        a: 'x'\n"),
            self._rule("Narrow", "        a: 'x'\n        b: 'y'\n"),
        ])
        assert out["duplicates"] == []
        assert len(out["subsumptions"]) == 1

    def test_case_differences_are_still_duplicates(self):
        out = self._run([
            self._rule("A", "        Image: 'CMD.EXE'\n"),
            self._rule("B", "        image: 'cmd.exe'\n"),
        ])
        assert len(out["duplicates"]) == 1

    def test_different_logsource_is_never_a_duplicate(self):
        """Same predicate over a different data source is a different detection."""
        out = self._run([
            self._rule("A", "        a: 'x'\n", category="proxy"),
            self._rule("B", "        a: 'x'\n", category="process_creation"),
        ])
        assert out["duplicates"] == []

    def test_non_provable_rules_are_recorded_not_silently_cleared(self):
        """Two identical `|re` rules ARE duplicates in reality, but the tool cannot
        prove it — so it must say "not analyzed" rather than report zero duplicates
        as if it had checked."""
        out = self._run([
            self._rule("A", "        a|re: '^x'\n"),
            self._rule("B", "        a|re: '^x'\n"),
        ])
        assert out["duplicates"] == []
        assert len(out["not_analyzed"]) == 2
