"""
Offline unit tests for the sigma_match tool handler
===================================================
``tools/sigma_match`` is the *real, deterministic, LLM-free* core of the M3
BAS detection-replay loop: it decides whether a log EVENT is caught by a Sigma
RULE (the sibling ``sigma_yara_lint`` only lints rule syntax; it never matches
events). Because blind-spot enumeration depends entirely on this matcher being
correct, its every branch — each modifier, each condition combinator, and the
missing-field / malformed-input edges — needs regression protection.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. The tool is pure Python by
design, so every case runs fully offline with no mocking.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# The tool handlers live under tools/<name>/handler.py — a scripts tree, not an
# installed package. Load the module directly by path so the tests don't depend
# on tools/ being importable.
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sigma_match", "handler.py",
)
_spec = importlib.util.spec_from_file_location("sigma_match_handler", _HANDLER_PATH)
sm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sm)


def match(rule, log_event) -> dict:
    return sm.handler({"rule": rule, "log_event": log_event}, None)


# --------------------------------------------------------------------------- #
# A rule that MATCHES an event, and one that does NOT                          #
# --------------------------------------------------------------------------- #
POWERSHELL_RULE = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""


def test_rule_matches_event():
    ev = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
    }
    r = match(POWERSHELL_RULE, ev)
    assert r["ok"] is True
    assert r["matched"] is True
    assert r["matched_selections"] == ["selection"]
    assert r["condition"] == "selection"


def test_rule_does_not_match_event():
    # Same rule, but CommandLine lacks '-enc' so the selection cannot fire.
    ev = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -File setup.ps1",
    }
    r = match(POWERSHELL_RULE, ev)
    assert r["ok"] is True
    assert r["matched"] is False
    assert r["matched_selections"] == []


def test_rule_accepts_already_parsed_dict():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4688},
            "condition": "selection",
        },
    }
    assert match(rule, {"EventID": 4688})["matched"] is True
    assert match(rule, {"EventID": 4624})["matched"] is False


# --------------------------------------------------------------------------- #
# Each value modifier                                                         #
# --------------------------------------------------------------------------- #
def _rule_with_selection(sel_body: str) -> str:
    return f"""
title: x
logsource:
    product: windows
detection:
    selection:
{sel_body}
    condition: selection
"""


def test_modifier_contains():
    rule = _rule_with_selection("        CommandLine|contains: 'mimikatz'")
    assert match(rule, {"CommandLine": "run MIMIKATZ.exe now"})["matched"] is True
    assert match(rule, {"CommandLine": "run notepad"})["matched"] is False


def test_modifier_startswith():
    # Use a forward-slash path so backslash escaping doesn't muddy the fixture;
    # the modifier logic is identical regardless of separator.
    rule = _rule_with_selection("        Image|startswith: '/usr/tmp'")
    assert match(rule, {"Image": "/USR/TMP/evil.bin"})["matched"] is True
    assert match(rule, {"Image": "/usr/bin/evil.bin"})["matched"] is False


def test_modifier_endswith():
    rule = _rule_with_selection("        Image|endswith: '.exe'")
    assert match(rule, {"Image": "C:\\a\\PAYLOAD.EXE"})["matched"] is True
    assert match(rule, {"Image": "C:\\a\\payload.dll"})["matched"] is False


def test_modifier_regex():
    rule = _rule_with_selection("        CommandLine|re: 'iex\\s*\\('")
    assert match(rule, {"CommandLine": "IEX ( new-object net.webclient )"})["matched"] is True
    assert match(rule, {"CommandLine": "echo hello"})["matched"] is False


def test_modifier_all_list_and():
    # |contains|all: every listed substring must be present (AND).
    rule = _rule_with_selection(
        "        CommandLine|contains|all:\n"
        "            - '-enc'\n"
        "            - 'hidden'\n"
    )
    assert match(rule, {"CommandLine": "pwsh -enc AAAA -windowstyle hidden"})["matched"] is True
    # Missing 'hidden' -> all() fails.
    assert match(rule, {"CommandLine": "pwsh -enc AAAA"})["matched"] is False


def test_plain_equality_case_insensitive():
    rule = _rule_with_selection("        User: 'Administrator'")
    assert match(rule, {"User": "administrator"})["matched"] is True
    assert match(rule, {"User": "guest"})["matched"] is False


def test_list_of_values_is_or():
    # A plain list value = OR (any element matches).
    rule = _rule_with_selection(
        "        Image|endswith:\n"
        "            - 'cmd.exe'\n"
        "            - 'powershell.exe'\n"
    )
    assert match(rule, {"Image": "C:/w/CMD.EXE"})["matched"] is True
    assert match(rule, {"Image": "C:/w/powershell.exe"})["matched"] is True
    assert match(rule, {"Image": "C:/w/explorer.exe"})["matched"] is False


# --------------------------------------------------------------------------- #
# Condition combinators                                                       #
# --------------------------------------------------------------------------- #
MULTI_SELECTION_RULE = """
title: x
logsource:
    product: windows
detection:
    selection_a:
        EventID: 4688
    selection_b:
        User: 'admin'
    condition: {cond}
"""


def _multi(cond: str, log_event) -> dict:
    return match(MULTI_SELECTION_RULE.format(cond=cond), log_event)


def test_condition_1_of_them():
    # Only selection_a fires.
    r = _multi("1 of them", {"EventID": 4688, "User": "guest"})
    assert r["matched"] is True
    assert r["matched_selections"] == ["selection_a"]
    # Neither fires.
    assert _multi("1 of them", {"EventID": 1, "User": "guest"})["matched"] is False


def test_condition_all_of_them():
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("all of them", both)["matched"] is True
    # Only one fires -> all of them is False.
    assert _multi("all of them", {"EventID": 4688, "User": "guest"})["matched"] is False


def test_condition_wildcard_1_of_prefix():
    # '1 of selection_*' resolves both selections by prefix.
    r = _multi("1 of selection_*", {"EventID": 4688, "User": "guest"})
    assert r["matched"] is True
    assert _multi("1 of selection_*", {"EventID": 0, "User": "guest"})["matched"] is False


def test_condition_all_of_wildcard_prefix():
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("all of selection_*", both)["matched"] is True
    assert _multi("all of selection_*", {"EventID": 4688, "User": "x"})["matched"] is False


def test_condition_and_or_combinators():
    both = {"EventID": 4688, "User": "admin"}
    only_a = {"EventID": 4688, "User": "guest"}
    assert _multi("selection_a and selection_b", both)["matched"] is True
    assert _multi("selection_a and selection_b", only_a)["matched"] is False
    assert _multi("selection_a or selection_b", only_a)["matched"] is True


def test_condition_not_combinator():
    # 'selection_a and not selection_b' — a fires, b must NOT.
    only_a = {"EventID": 4688, "User": "guest"}
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("selection_a and not selection_b", only_a)["matched"] is True
    assert _multi("selection_a and not selection_b", both)["matched"] is False


def test_condition_parentheses_precedence():
    # (a or b) and not b  — with only b firing, inner is True but 'not b' kills it.
    only_b = {"EventID": 0, "User": "admin"}
    assert _multi("(selection_a or selection_b) and not selection_b", only_b)["matched"] is False
    only_a = {"EventID": 4688, "User": "guest"}
    assert _multi("(selection_a or selection_b) and not selection_b", only_a)["matched"] is True


# --------------------------------------------------------------------------- #
# Missing field — no match, no crash                                          #
# --------------------------------------------------------------------------- #
def test_missing_field_does_not_match_and_does_not_crash():
    rule = _rule_with_selection("        CommandLine|contains: '-enc'")
    # log_event has no 'CommandLine' key at all.
    r = match(rule, {"Image": "powershell.exe"})
    assert r["ok"] is True
    assert r["matched"] is False
    assert r["matched_selections"] == []


def test_partial_selection_absent_key_fails_the_and():
    # selection needs BOTH keys; one key's field is absent -> selection fails.
    rule = _rule_with_selection(
        "        Image|endswith: '\\\\powershell.exe'\n"
        "        CommandLine|contains: '-enc'"
    )
    r = match(rule, {"Image": "x\\powershell.exe"})  # no CommandLine
    assert r["matched"] is False


# --------------------------------------------------------------------------- #
# List-of-maps selection (implicit OR across sub-maps)                        #
# --------------------------------------------------------------------------- #
def test_selection_list_of_maps_is_or():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": [
                {"Image|endswith": "\\cmd.exe"},
                {"Image|endswith": "\\powershell.exe"},
            ],
            "condition": "selection",
        },
    }
    assert match(rule, {"Image": "a\\CMD.EXE"})["matched"] is True
    assert match(rule, {"Image": "a\\explorer.exe"})["matched"] is False


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_determinism_same_input_same_output():
    ev = {"Image": "x\\powershell.exe", "CommandLine": "p -enc AA"}
    a = match(POWERSHELL_RULE, ev)
    b = match(POWERSHELL_RULE, ev)
    assert a == b


# --------------------------------------------------------------------------- #
# Malformed input -> validation_error                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("event", [
    {},                                                    # nothing
    {"rule": POWERSHELL_RULE},                             # no log_event
    {"rule": POWERSHELL_RULE, "log_event": "not-a-dict"},  # bad log_event type
    {"rule": 123, "log_event": {}},                        # rule wrong type
    {"rule": "   ", "log_event": {}},                      # empty rule string
    {"rule": "title: x\nlogsource: {}", "log_event": {}},  # no detection block
])
def test_malformed_input_is_validation_error(event):
    r = sm.handler(event, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_event_not_a_dict_is_validation_error():
    # The top-level event itself is not a mapping (handler line ~225-226).
    r = sm.handler("not-a-dict", None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "event must be a dict" in r["message"]


def test_condition_with_trailing_token_is_validation_error():
    # Two bare names with no combinator -> unexpected trailing token (handler ~403-404).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "selection_a selection_a"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "trailing token" in r["message"]


def test_quantifier_exact_name_target_resolves():
    # "1 of selection_a" uses an exact (non-wildcard, non-'them') target that IS
    # defined -> handler line ~495-496 (target in self._names).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "1 of selection_a"},
    }
    assert match(rule, {"EventID": 1})["matched"] is True
    assert match(rule, {"EventID": 0})["matched"] is False


def test_detection_without_condition_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}},  # no 'condition'
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "condition" in r["message"]


def test_detection_without_selection_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"condition": "selection"},  # no selection defined
    }
    r = sm.handler({"rule": rule, "log_event": {}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_condition_referencing_undefined_selection_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_a": {"EventID": 1},
            "condition": "selection_a and ghost",  # 'ghost' undefined
        },
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "undefined selection" in r["message"]


def test_malformed_condition_unbalanced_parens_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 1},
            "condition": "(selection and",  # unbalanced / dangling
        },
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# List-of-conditions is OR-joined                                             #
# --------------------------------------------------------------------------- #
def test_list_condition_is_or_joined():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_a": {"EventID": 4688},
            "selection_b": {"User": "admin"},
            "condition": ["selection_a", "selection_b"],  # list => OR
        },
    }
    # Only selection_b fires; OR-join still matches.
    r = sm.handler({"rule": rule, "log_event": {"EventID": 0, "User": "admin"}}, None)
    assert r["matched"] is True
    assert r["condition"] == "(selection_a) or (selection_b)"


# --------------------------------------------------------------------------- #
# Dependency-free minimal-YAML FALLBACK parser                                #
# --------------------------------------------------------------------------- #
# The handler prefers the sibling sigma_yara_lint parser (which uses PyYAML if
# present). The whole minimal fallback parser (_parse_yaml_minimal, ~lines
# 130-212) is only exercised when the sibling is unavailable — which never
# happens in the other tests because PyYAML is installed. We force that path by
# monkeypatching _load_sibling_parse_yaml to return None, so _parse_yaml falls
# through to _parse_yaml_minimal, then assert the parser is CORRECT on the full
# Sigma-subset syntax AND drives a correct match/no-match end to end.
@pytest.fixture()
def force_minimal_yaml(monkeypatch):
    """Make _parse_yaml use the dependency-free minimal parser, not PyYAML."""
    monkeypatch.setattr(sm, "_load_sibling_parse_yaml", lambda: None)
    return sm


def test_fallback_parser_scalar_types(force_minimal_yaml):
    # ints, floats, bools, null (both spellings), quoted scalars, comments,
    # and an empty scalar (bare "key:") — every scalar() branch.
    text = (
        "# a leading comment line, ignored\n"
        "an_int: 4688\n"
        "a_float: 1.5\n"
        "bool_true: true\n"
        "bool_false: False\n"       # case-insensitive bool
        "null_word: null\n"
        "null_tilde: ~\n"
        "dquoted: \"hello world\"\n"
        "squoted: 'quoted:with:colons'\n"   # colon inside quotes kept as value
        "  # an indented comment, ignored\n"
        "plain: bareword\n"
    )
    parsed = force_minimal_yaml._parse_yaml(text)
    assert parsed["an_int"] == 4688 and isinstance(parsed["an_int"], int)
    assert parsed["a_float"] == 1.5 and isinstance(parsed["a_float"], float)
    assert parsed["bool_true"] is True
    assert parsed["bool_false"] is False
    assert parsed["null_word"] is None
    assert parsed["null_tilde"] is None
    assert parsed["dquoted"] == "hello world"
    # partition(":") splits on the first colon; the quoted remainder is kept.
    assert parsed["squoted"] == "quoted:with:colons"
    assert parsed["plain"] == "bareword"


def test_fallback_parser_inline_and_block_lists(force_minimal_yaml):
    # Inline "[a, b]" list, an empty inline "[]" list, and a block "- item" list.
    text = (
        "inline: [cmd.exe, powershell.exe]\n"
        "empty_inline: []\n"
        "block:\n"
        "    - first\n"
        "    - second\n"
    )
    parsed = force_minimal_yaml._parse_yaml(text)
    assert parsed["inline"] == ["cmd.exe", "powershell.exe"]
    assert parsed["empty_inline"] == []
    assert parsed["block"] == ["first", "second"]


def test_fallback_parser_inline_list_with_empty_element(force_minimal_yaml):
    # An empty element between commas -> scalar("") -> None (handler line ~145-146).
    parsed = force_minimal_yaml._parse_yaml("k: [a, , b]\n")
    assert parsed["k"] == ["a", None, "b"]


def test_fallback_parser_nested_maps(force_minimal_yaml):
    # Nested mappings resolved purely by indentation depth.
    text = (
        "logsource:\n"
        "    product: windows\n"
        "    category: process_creation\n"
        "detection:\n"
        "    selection:\n"
        "        EventID: 4688\n"
        "    condition: selection\n"
    )
    parsed = force_minimal_yaml._parse_yaml(text)
    assert parsed["logsource"] == {
        "product": "windows",
        "category": "process_creation",
    }
    assert parsed["detection"]["selection"] == {"EventID": 4688}
    assert parsed["detection"]["condition"] == "selection"


def test_fallback_parser_skips_lines_without_colon(force_minimal_yaml):
    # A non-list, non-"key: value" content line inside a mapping is skipped
    # (handler line ~194-196) rather than crashing the parser.
    text = (
        "title: x\n"
        "this_line_has_no_colon_and_is_skipped\n"
        "detection:\n"
        "    selection:\n"
        "        EventID: 1\n"
        "    condition: selection\n"
    )
    parsed = force_minimal_yaml._parse_yaml(text)
    assert parsed["title"] == "x"
    assert "this_line_has_no_colon_and_is_skipped" not in parsed
    assert parsed["detection"]["condition"] == "selection"


def test_fallback_parser_drives_correct_match(force_minimal_yaml):
    # End-to-end proof: with ONLY the minimal parser, a YAML-string rule still
    # parses into a structure the matcher evaluates correctly (match + no-match).
    rule = """
title: Encoded PowerShell
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: 'powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""
    hit = match(rule, {
        "Image": "C:/w/PowerShell.exe",
        "CommandLine": "powershell -enc AAAA",
    })
    assert hit["ok"] is True
    assert hit["matched"] is True
    assert hit["matched_selections"] == ["selection"]

    miss = match(rule, {
        "Image": "C:/w/powershell.exe",
        "CommandLine": "powershell -File s.ps1",  # no '-enc'
    })
    assert miss["matched"] is False


def test_fallback_parser_block_list_of_values_is_or(force_minimal_yaml):
    # Block list under a field|modifier key -> OR semantics, via the minimal parser.
    rule = """
title: x
logsource:
    product: windows
detection:
    selection:
        Image|endswith:
            - cmd.exe
            - powershell.exe
    condition: selection
"""
    assert match(rule, {"Image": "a/CMD.EXE"})["matched"] is True
    assert match(rule, {"Image": "a/explorer.exe"})["matched"] is False


def test_minimal_parser_callable_directly():
    # The minimal parser is also exercisable directly (no monkeypatch needed),
    # documenting it as a self-contained, dependency-free function.
    parsed = sm._parse_yaml_minimal("a: 1\nb:\n    c: two\n")
    assert parsed == {"a": 1, "b": {"c": "two"}}


# --------------------------------------------------------------------------- #
# YAML-string rule that parses to a NON-mapping top level                     #
# --------------------------------------------------------------------------- #
def test_rule_yaml_resolving_to_non_mapping_is_validation_error():
    # A YAML scalar string parses to a str, not a dict -> handler line ~241-242.
    r = sm.handler({"rule": "just a bare scalar", "log_event": {}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "mapping at the top level" in r["message"]


def test_rule_yaml_parse_failure_is_validation_error():
    # Structurally broken YAML makes the parser raise; the handler wraps it as a
    # validation_error (handler line ~234-235) instead of swallowing it.
    broken = "a: [1, 2\n  b: : :\n"
    r = sm.handler({"rule": broken, "log_event": {}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "could not parse 'rule' YAML" in r["message"]


# --------------------------------------------------------------------------- #
# Boolean field values (case-insensitive true/false rendering)                #
# --------------------------------------------------------------------------- #
def test_boolean_field_value_matches():
    # _as_text renders bools as 'true'/'false' (handler line ~269-271) so a
    # YAML bool in the rule matches a Python bool in the log event.
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"Elevated": True},
            "condition": "selection",
        },
    }
    assert match(rule, {"Elevated": True})["matched"] is True
    assert match(rule, {"Elevated": False})["matched"] is False


# --------------------------------------------------------------------------- #
# Selection shapes that cannot match (return False, never raise)              #
# --------------------------------------------------------------------------- #
def test_scalar_selection_cannot_match():
    # A selection that is a scalar (not a dict/list) -> handler line ~353-354.
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": "not-a-mapping", "condition": "selection"},
    }
    r = match(rule, {"anything": 1})
    assert r["ok"] is True
    assert r["matched"] is False
    assert r["matched_selections"] == []


def test_empty_dict_selection_cannot_match():
    # An empty mapping selection also cannot match (handler line ~353-354).
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {}, "condition": "selection"},
    }
    assert match(rule, {"x": 1})["matched"] is False


# --------------------------------------------------------------------------- #
# Empty condition string                                                      #
# --------------------------------------------------------------------------- #
def test_empty_condition_is_validation_error():
    # An empty condition tokenizes to nothing (handler line ~400-401).
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}, "condition": "   "},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "empty condition" in r["message"]


# --------------------------------------------------------------------------- #
# Malformed quantifier variants                                               #
# --------------------------------------------------------------------------- #
def test_quantifier_missing_of_is_validation_error():
    # "1 them" — quantifier not followed by 'of' (handler line ~458-459).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "1 them"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "expected 'of'" in r["message"]


def test_quantifier_missing_target_is_validation_error():
    # "1 of" — nothing after 'of' (handler line ~462-463).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "1 of"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "expected target" in r["message"]


def test_quantifier_undefined_exact_target_is_validation_error():
    # "1 of ghost" — exact target is not a defined selection (handler ~497).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "1 of ghost"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "undefined selection" in r["message"]


def test_quantifier_wildcard_matching_nothing_does_not_fire():
    # "1 of ghost_*" — the prefix matches NO selection, so the group is empty
    # and the quantifier is treated as False (handler line ~467-472), NOT an
    # error and NOT vacuously true.
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "1 of ghost_*"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is True
    assert r["matched"] is False
    # selection_a itself still evaluated as matched, but the condition is False.
    assert r["matched_selections"] == ["selection_a"]


def test_all_of_wildcard_matching_nothing_does_not_fire():
    # Same empty-group rule applies to "all of <empty>" -> False, not vacuous True.
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "all of ghost_*"},
    }
    assert match(rule, {"EventID": 1})["matched"] is False


# --------------------------------------------------------------------------- #
# 'any of them' spelling of the quantifier                                    #
# --------------------------------------------------------------------------- #
def test_condition_any_of_them():
    # 'any of them' is the alias for '1 of them' (handler _QUANTIFIERS/'any').
    rule = MULTI_SELECTION_RULE.format(cond="any of them")
    assert match(rule, {"EventID": 4688, "User": "guest"})["matched"] is True
    assert match(rule, {"EventID": 0, "User": "guest"})["matched"] is False


# --------------------------------------------------------------------------- #
# Unbalanced parentheses opened but never closed                              #
# --------------------------------------------------------------------------- #
def test_unclosed_parenthesis_is_validation_error():
    # "(selection_a" reaches end-of-tokens while expecting ')' (handler ~444-445).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {"selection_a": {"EventID": 1}, "condition": "(selection_a"},
    }
    r = match(rule, {"EventID": 1})
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "unbalanced parentheses" in r["message"]
