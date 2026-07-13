"""
Offline unit tests for the sigma_yara_lint tool handler
=======================================================
``tools/sigma_yara_lint`` is the one *functional, deterministic, LLM-free* tool in
the repo — it is meant to run as a mandatory structural gate in a detection pipeline
(an LLM drafts a rule; this linter, not another LLM, decides if it is well-formed).
That makes its logic exactly the thing that needs regression protection, yet it had
none: the registry tests only used its *name* as a fixture, never exercising the
lint logic. These tests close that gap.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — the tool is pure Python by design,
so every case runs fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# The tool handlers live under tools/<name>/handler.py — a scripts tree, not an
# installed package. Load the module directly by path so the tests don't depend on
# tools/ being importable.
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sigma_yara_lint", "handler.py",
)
_spec = importlib.util.spec_from_file_location("sigma_yara_lint_handler", _HANDLER_PATH)
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)


def lint(rule_type: str, content: str) -> dict:
    return sl.handler({"rule_type": rule_type, "content": content}, None)


# --------------------------------------------------------------------------- #
# A well-formed Sigma rule passes                                             #
# --------------------------------------------------------------------------- #
GOOD_SIGMA = """
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


def test_valid_sigma_passes_clean():
    r = lint("sigma", GOOD_SIGMA)
    assert r["ok"] is True
    assert r["rule_type"] == "sigma"
    assert r["valid"] is True
    assert r["errors"] == []


# --------------------------------------------------------------------------- #
# Hard failures (rule is structurally invalid)                                #
# --------------------------------------------------------------------------- #
def test_missing_required_top_level_keys_are_errors():
    # No title / logsource / detection.
    r = lint("sigma", "id: abc\nstatus: stable\nlevel: low\n")
    assert r["valid"] is False
    joined = " ".join(r["errors"])
    for key in ("title", "logsource", "detection"):
        assert f"'{key}'" in joined


def test_invalid_level_is_error():
    rule = GOOD_SIGMA.replace("level: high", "level: catastrophic")
    r = lint("sigma", rule)
    assert r["valid"] is False
    assert any("invalid 'level'" in e for e in r["errors"])


def test_detection_without_condition_is_error():
    rule = """
title: X
logsource:
    product: windows
detection:
    selection:
        Image: '\\evil.exe'
"""
    r = lint("sigma", rule)
    assert r["valid"] is False
    assert any("must contain a 'condition'" in e for e in r["errors"])


def test_detection_with_only_condition_no_selection_is_error():
    rule = """
title: X
logsource:
    product: windows
detection:
    condition: selection
"""
    r = lint("sigma", rule)
    assert r["valid"] is False
    assert any("at least one selection" in e for e in r["errors"])


def test_condition_referencing_undefined_selection_is_error():
    # condition names 'selection' but the only defined selection is 'sel_a'.
    rule = """
title: X
logsource:
    product: windows
detection:
    sel_a:
        Image: '\\evil.exe'
    condition: selection and sel_a
"""
    r = lint("sigma", rule)
    assert r["valid"] is False
    assert any("undefined selection: 'selection'" in e for e in r["errors"])


def test_condition_keywords_and_aggregates_are_not_flagged():
    # 'all', 'of', 'them', '1', 'and', 'or', 'not' are grammar, not selections.
    rule = """
title: X
logsource:
    product: windows
detection:
    selection_a:
        Image: '\\a.exe'
    selection_b:
        Image: '\\b.exe'
    condition: all of them and not 1 of selection_a
"""
    r = lint("sigma", rule)
    # No "undefined selection" errors — every bare identifier resolves.
    assert not any("undefined selection" in e for e in r["errors"])


def test_wildcard_selection_reference_matches_by_prefix():
    rule = """
title: X
logsource:
    product: windows
detection:
    selection_net:
        Image: '\\a.exe'
    condition: 1 of selection_*
"""
    r = lint("sigma", rule)
    assert not any("undefined selection pattern" in e for e in r["errors"])


def test_wildcard_selection_with_no_match_is_error():
    rule = """
title: X
logsource:
    product: windows
detection:
    selection_net:
        Image: '\\a.exe'
    condition: 1 of filter_*
"""
    r = lint("sigma", rule)
    assert r["valid"] is False
    assert any("undefined selection pattern: 'filter_*'" in e for e in r["errors"])


# --------------------------------------------------------------------------- #
# Non-fatal warnings                                                          #
# --------------------------------------------------------------------------- #
def test_missing_recommended_keys_warn_not_error():
    rule = """
title: X
logsource:
    product: windows
detection:
    selection:
        Image: '\\a.exe'
    condition: selection
"""
    r = lint("sigma", rule)
    # Missing id/level/status are warnings; the rule is still valid.
    assert r["valid"] is True
    joined = " ".join(r["warnings"])
    for key in ("id", "level", "status"):
        assert f"'{key}'" in joined


def test_logsource_without_product_category_service_warns():
    rule = """
title: X
id: abc
level: low
status: stable
logsource:
    definition: something
detection:
    selection:
        Image: '\\a.exe'
    condition: selection
"""
    r = lint("sigma", rule)
    assert any("product/category/service" in w for w in r["warnings"])


# --------------------------------------------------------------------------- #
# YARA structural checks                                                      #
# --------------------------------------------------------------------------- #
GOOD_YARA = """
rule ExampleRule
{
    strings:
        $a = "malicious"
    condition:
        $a
}
"""


def test_valid_yara_passes():
    r = lint("yara", GOOD_YARA)
    assert r["ok"] is True
    assert r["rule_type"] == "yara"
    assert r["valid"] is True
    assert r["errors"] == []


def test_yara_unbalanced_braces_is_error():
    broken = GOOD_YARA.replace("}", "", 1)  # drop one closing brace
    r = lint("yara", broken)
    assert r["valid"] is False
    assert any("unbalanced braces" in e for e in r["errors"])


def test_yara_without_rule_block_is_error():
    r = lint("yara", "not a rule at all")
    assert r["valid"] is False
    assert any("no 'rule <name>" in e for e in r["errors"])


def test_yara_missing_condition_is_error():
    rule = """
rule NoCond
{
    strings:
        $a = "x"
}
"""
    r = lint("yara", rule)
    assert r["valid"] is False
    assert any("missing a 'condition:'" in e for e in r["errors"])


def test_yara_string_ref_without_strings_section_warns():
    rule = """
rule Refs
{
    condition:
        $a
}
"""
    r = lint("yara", rule)
    # Uses $ but has no strings: section -> warning, not a hard error.
    # Assert on stable tokens only (not internal line-wrapping of the message).
    assert any("strings:" in w and "$" in w for w in r["warnings"])


# --------------------------------------------------------------------------- #
# Input validation                                                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("event", [
    {},                                        # nothing
    {"rule_type": "sigma"},                    # no content
    {"rule_type": "sigma", "content": "  "},   # blank content
    {"rule_type": "snort", "content": "x"},    # unsupported rule_type
    {"content": "x"},                          # no rule_type
])
def test_bad_input_is_validation_error(event):
    r = sl.handler(event, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_rule_type_is_case_insensitive():
    r = lint("SIGMA", GOOD_SIGMA)
    assert r["ok"] is True
    assert r["rule_type"] == "sigma"


# --------------------------------------------------------------------------- #
# Minimal YAML fallback parser (the offline, dependency-free path)            #
# --------------------------------------------------------------------------- #
def test_minimal_yaml_parser_handles_sigma_shape():
    """Exercise the built-in parser directly so we don't depend on whether PyYAML
    is installed — this is the zero-dependency offline guarantee."""
    doc = sl._parse_yaml_minimal(GOOD_SIGMA)
    assert doc["title"].startswith("Suspicious")
    assert doc["logsource"]["product"] == "windows"
    assert doc["detection"]["condition"] == "selection"
    assert "Image|endswith" in doc["detection"]["selection"]


def test_determinism_same_input_same_output():
    """A gate must be deterministic: identical input yields identical output."""
    a = lint("sigma", GOOD_SIGMA)
    b = lint("sigma", GOOD_SIGMA)
    assert a == b
