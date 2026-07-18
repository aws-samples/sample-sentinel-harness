"""
Offline unit tests for the Splunk SPL + Elastic EQL targets of detection_translate.
================================================================================
H1 adds two FIELD-AWARE query targets (unlike the byte-content YARA/Suricata ones):
a Sigma ``field|modifier: value`` predicate maps to a real field term. These tests
pin the faithful modifier→syntax mapping, injection-safe value/field escaping (the
round-3 output-injection lesson), the OR-flatten honesty note, and back-compat.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_spleql", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tr = _load("detection_translate")


def translate(sigma: str, targets):
    return tr.handler({"sigma": sigma, "targets": targets}, None)


def _rule(selection: dict, condition="selection") -> str:
    sel = "\n".join(f"        {k}: {v!r}" for k, v in selection.items())
    return (f"title: t\nlogsource:\n    category: proxy\n"
            f"detection:\n    selection:\n{sel}\n    condition: {condition}\n")


# --------------------------------------------------------------------------- #
# faithful modifier -> SPL / EQL syntax                                       #
# --------------------------------------------------------------------------- #
def test_splunk_contains_startswith_endswith_equals():
    out = translate(_rule({
        "CommandLine|contains": "-enc",
        "Image|endswith": "ps.exe",
        "User|startswith": "adm",
        "EventID": "4688",
    }), ["splunk"])
    spl = out["translations"]["splunk"]
    assert 'CommandLine="*-enc*"' in spl
    assert 'Image="*ps.exe"' in spl
    assert 'User="adm*"' in spl
    assert 'EventID="4688"' in spl          # plain equality, no wildcard
    assert spl.startswith("search ")


def test_elastic_contains_startswith_endswith_equals():
    out = translate(_rule({
        "CommandLine|contains": "-enc",
        "Image|endswith": "ps.exe",
        "User|startswith": "adm",
        "EventID": "4688",
    }), ["elastic"])
    eql = out["translations"]["elastic"]
    assert 'CommandLine like~ "*-enc*"' in eql
    assert 'Image like~ "*ps.exe"' in eql
    assert 'User like~ "adm*"' in eql
    # plain equality now uses case-insensitive like~ (matches Sigma's default), not ==
    assert 'EventID like~ "4688"' in eql
    assert "==" not in eql
    assert eql.startswith("any where ")


def test_splunk_terms_and_joined():
    out = translate(_rule({"a|contains": "x", "b|contains": "y"}), ["splunk"])
    # both terms present, space-joined (implicit AND in SPL)
    spl = out["translations"]["splunk"]
    assert 'a="*x*"' in spl and 'b="*y*"' in spl


def test_elastic_conditions_and_joined():
    out = translate(_rule({"a|contains": "x", "b|contains": "y"}), ["elastic"])
    assert " and " in out["translations"]["elastic"]


# --------------------------------------------------------------------------- #
# injection-safe escaping (round-3 lesson)                                    #
# --------------------------------------------------------------------------- #
def test_splunk_value_quote_and_backslash_escaped():
    out = translate(_rule({"CommandLine|contains": 'a" OR x=1'}), ["splunk"])
    spl = out["translations"]["splunk"]
    # the double-quote must be backslash-escaped so it cannot close the literal
    assert '\\"' in spl
    assert 'OR x=1' in spl  # content preserved, just neutralized


def test_splunk_value_wildcard_neutralized():
    # a literal '*' in the value must not become an unintended SPL wildcard
    out = translate(_rule({"CommandLine|contains": "a*b"}), ["splunk"])
    spl = out["translations"]["splunk"]
    assert "a\\*b" in spl          # value-borne star escaped
    assert spl.count("*") >= 2     # our own contains-wildcards remain


def test_value_newline_stripped_keeps_single_line():
    out = translate(_rule({"CommandLine|contains": "line1\nline2"}), ["splunk", "elastic"])
    for tgt in ("splunk", "elastic"):
        body = out["translations"][tgt]
        # the emitted query is a single logical line (no raw newline inside the value)
        assert "line1" in body and "line2" in body
        # no bare newline splitting the query (the trailing \n terminator aside)
        assert "\n" not in body.rstrip("\n")


def test_field_name_sanitized_against_injection():
    # a crafted dotted field with injection chars is reduced to a safe token
    assert tr._spl_field("winlog.event_data.Image; DROP TABLE") == "winlog.event_data.ImageDROPTABLE"
    assert tr._spl_field("a b|c=d") == "abcd"
    assert tr._spl_field("!!!") == "UNKNOWN_FIELD"
    assert tr._spl_field("CommandLine") == "CommandLine"


# --------------------------------------------------------------------------- #
# honesty ledger + boolean caveat carry over                                  #
# --------------------------------------------------------------------------- #
def test_negation_condition_untranslatable_for_spl():
    sigma = ("title: t\nlogsource:\n    category: proxy\n"
             "detection:\n    selection:\n        a: 'b'\n"
             "    filter:\n        c: 'd'\n    condition: selection and not filter\n")
    out = translate(sigma, ["splunk"])
    assert any("NEGATION" in u for u in out["untranslatable"])


def test_lossy_modifier_flagged_for_eql():
    out = translate(_rule({"CommandLine|re": ".*enc.*"}), ["elastic"])
    assert any("re" in u for u in out["untranslatable"])
    # a best-effort term is still emitted (regex value escaped as a literal)
    assert out["translations"]["elastic"].startswith("any where ")


def test_or_flatten_note_present():
    out = translate(_rule({"a|contains": "x"}), ["splunk", "elastic"])
    joined = " ".join(out["notes"])
    assert "Splunk" in joined and "EQL" in joined


# --------------------------------------------------------------------------- #
# targets: back-compat, all-four, validation                                  #
# --------------------------------------------------------------------------- #
def test_default_targets_unchanged_yara_suricata():
    out = tr.handler({"sigma": _rule({"a|contains": "x"})}, None)  # no targets
    assert set(out["translations"]) == {"yara", "suricata"}


def test_all_four_targets_emitted():
    out = translate(_rule({"a|contains": "x"}), ["yara", "suricata", "splunk", "elastic"])
    assert set(out["translations"]) == {"yara", "suricata", "splunk", "elastic"}


def test_splunk_only_does_not_emit_others():
    out = translate(_rule({"a|contains": "x"}), ["splunk"])
    assert set(out["translations"]) == {"splunk"}


def test_unknown_target_rejected():
    out = translate(_rule({"a|contains": "x"}), ["kibana"])
    assert out["ok"] is False and out["error"] == "validation_error"


def test_no_predicate_emits_placeholder_not_crash():
    # a rule whose only predicate is lossy-null still emits a placeholder query
    sigma = ("title: t\nlogsource:\n    category: proxy\n"
             "detection:\n    selection:\n        f:\n    condition: selection\n")
    out = translate(sigma, ["splunk", "elastic"])
    assert "REPLACE_ME" in out["translations"]["splunk"]
    assert "REPLACE_ME" in out["translations"]["elastic"]


# --------------------------------------------------------------------------- #
# SPL/EQL injection-audit fixes (spl-eql-injection-audit workflow)            #
# --------------------------------------------------------------------------- #
def test_spl_title_backtick_cannot_break_out_of_comment():
    """A Sigma title with the SPL triple-backtick comment delimiter must NOT close
    the provenance comment and inject a live command (audited output-injection)."""
    sigma = ('title: "x``` | delete ```y"\nlogsource:\n    category: proxy\n'
             "detection:\n    selection:\n        f: 'v'\n    condition: selection\n")
    spl = translate(sigma, ["splunk"])["translations"]["splunk"]
    # the title's own backticks are stripped, so ` | delete ` is inert text inside
    # the tool's OWN comment — there is exactly ONE comment (two ``` delimiters).
    assert spl.count("```") == 2
    assert "| delete" in spl        # present, but as inert comment text
    # and it sits AFTER the comment opener (never before it as a live pipe)
    body, _, comment = spl.partition("```")
    assert "delete" not in body     # nothing injected into the executable portion


def test_spl_value_backtick_removed():
    """A backtick in a VALUE (SPL macro trigger) is removed, not passed through."""
    out = translate(_rule({"CommandLine|contains": "`some_macro`"}), ["splunk"])
    spl = out["translations"]["splunk"]
    # the value's backticks are gone; the term is a plain literal match
    assert 'CommandLine="*some_macro*"' in spl


def test_eql_plain_equality_is_case_insensitive():
    """EQL plain equality uses like~ (case-insensitive), matching Sigma's default;
    the case-sensitive == would silently miss CMD.EXE for cmd.exe (false negative)."""
    out = translate(_rule({"Image": "cmd.exe"}), ["elastic"])
    eql = out["translations"]["elastic"]
    assert "like~" in eql and "==" not in eql
    assert 'Image like~ "cmd.exe"' in eql


def test_eql_value_wildcard_neutralized_like_spl():
    """A value-borne '*' must be a LITERAL in EQL (as in SPL), so the same Sigma
    value matches identically across both targets (no silent cross-target drift)."""
    out = translate(_rule({"field|contains": "a*b"}), ["splunk", "elastic"])
    spl = out["translations"]["splunk"]
    eql = out["translations"]["elastic"]
    # both neutralize the value star to a literal `\*` (single backslash), identically
    assert "a\\*b" in spl
    assert "a\\*b" in eql
    # and the two targets agree byte-for-byte on the neutralized value fragment
    assert "a\\*b" in spl and "a\\*b" in eql
    # the wrapping contains-wildcards remain live in both
    assert spl.count("*") > spl.count("\\*")
    assert eql.count("*") > eql.count("\\*")


def test_eql_and_spl_escape_backslash_identically():
    """SPL and EQL must escape a value-borne backslash the SAME way (no ordering
    double-escape divergence). Use a YAML DOUBLE-quoted scalar with a single escaped
    backslash so exactly ONE backslash reaches the emitter."""
    # In a YAML double-quoted scalar, "\\" is ONE backslash — unambiguous input.
    sigma = ('title: t\nlogsource:\n    category: proxy\n'
             'detection:\n    selection:\n        Image|endswith: "C:\\\\ps"\n'
             '    condition: selection\n')
    out = translate(sigma, ["splunk", "elastic"])
    eql_frag = out["translations"]["elastic"].split('"')[1]
    spl_frag = out["translations"]["splunk"].split('"')[1]
    # one input backslash -> exactly one escaped '\\' (two chars), in BOTH targets
    assert eql_frag.count("\\") == 2, eql_frag
    assert spl_frag.count("\\") == 2, spl_frag
    # and the value fragments are byte-identical between the two targets
    assert eql_frag.lstrip("*") == spl_frag.lstrip("*")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
