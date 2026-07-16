"""
Offline unit tests for the detection_translate tool.

``tools/detection_translate`` deterministically translates a Sigma rule into YARA
and Suricata SKELETONS for human review. These tests pin: the faithful subset
(contains/startswith/endswith → content matches), the honest surfacing of lossy
predicates (regex/numeric → untranslatable notes, never silently dropped), and —
the load-bearing integration — that the emitted skeletons LINT CLEAN through
sigma_yara_lint (the two tools compose).

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_undertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tr = _load("detection_translate")
lint = _load("sigma_yara_lint")


def translate(sigma: str, targets=None) -> dict:
    ev = {"sigma": sigma}
    if targets is not None:
        ev["targets"] = targets
    return tr.handler(ev, None)


GOOD_SIGMA = """
title: Log4Shell JNDI Exploit Attempt
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '${jndi:ldap'
        cs-user-agent|startswith: 'curl'
    condition: selection
"""


# --------------------------------------------------------------------------- #
# basic translation                                                           #
# --------------------------------------------------------------------------- #
def test_translates_to_both_targets_by_default():
    out = translate(GOOD_SIGMA)
    assert out["ok"] is True
    assert out["title"] == "Log4Shell JNDI Exploit Attempt"
    assert set(out["translations"]) == {"yara", "suricata"}


def test_target_subset_respected():
    out = translate(GOOD_SIGMA, targets=["yara"])
    assert set(out["translations"]) == {"yara"}


def test_yara_contains_the_string_values():
    y = translate(GOOD_SIGMA, targets=["yara"])["translations"]["yara"]
    assert "${jndi:ldap" in y
    assert "curl" in y
    assert y.strip().startswith("rule ")


def test_suricata_contains_content_and_placeholder_sid():
    s = translate(GOOD_SIGMA, targets=["suricata"])["translations"]["suricata"]
    assert 'content:"${jndi:ldap"' in s
    assert "startswith" in s  # cs-user-agent|startswith
    assert "sid:1000000" in s  # placeholder


# --------------------------------------------------------------------------- #
# the load-bearing integration: emitted skeletons LINT CLEAN                  #
# --------------------------------------------------------------------------- #
def test_emitted_yara_lints_clean():
    y = translate(GOOD_SIGMA, targets=["yara"])["translations"]["yara"]
    res = lint.handler({"rule_type": "yara", "content": y}, None)
    assert res["valid"] is True, res["errors"]


def test_emitted_suricata_lints_clean():
    s = translate(GOOD_SIGMA, targets=["suricata"])["translations"]["suricata"]
    res = lint.handler({"rule_type": "suricata", "content": s}, None)
    assert res["valid"] is True, res["errors"]


# --------------------------------------------------------------------------- #
# honesty: lossy predicates are surfaced, never silently dropped              #
# --------------------------------------------------------------------------- #
def test_regex_modifier_is_untranslatable():
    out = translate("title: T\ndetection:\n  sel:\n    field|re: 'a.*b'\n  condition: sel")
    assert any("re" in u and "faithful" in u for u in out["untranslatable"])


def test_numeric_comparison_untranslatable():
    out = translate("title: T\ndetection:\n  sel:\n    port|gt: 1024\n  condition: sel")
    assert out["untranslatable"]


def test_notes_warn_about_review():
    out = translate(GOOD_SIGMA)
    assert any("review" in n.lower() for n in out["notes"])


def test_list_value_yields_multiple_predicates():
    sigma = ("title: T\ndetection:\n  sel:\n    cmd|contains:\n      - 'foo'\n"
             "      - 'bar'\n  condition: sel")
    y = translate(sigma, targets=["yara"])["translations"]["yara"]
    assert "foo" in y and "bar" in y


# --------------------------------------------------------------------------- #
# validation + determinism                                                    #
# --------------------------------------------------------------------------- #
def test_empty_sigma_rejected():
    r = tr.handler({"sigma": ""}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_unknown_target_rejected():
    r = tr.handler({"sigma": GOOD_SIGMA, "targets": ["snort"]}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_sigma_without_detection_is_translation_error():
    r = tr.handler({"sigma": "title: X\nlogsource:\n  product: windows"}, None)
    assert r["ok"] is False and r["error"] == "translation_error"


def test_translation_is_deterministic():
    assert translate(GOOD_SIGMA) == translate(GOOD_SIGMA)


# --------------------------------------------------------------------------- #
# regression: YARA linter must not miscount braces inside strings/comments    #
# (surfaced by translating a Log4Shell '${jndi' pattern — a real case)        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("content,valid", [
    ('rule X {\n strings:\n  $a = "${jndi:ldap"\n condition:\n  $a\n}\n', True),
    ('rule Y {\n strings:\n  $a = "}greedy{"\n condition:\n  $a\n}\n', True),
    ('rule Z {\n // a { brace } comment\n strings:\n  $a = "x"\n condition:\n  $a\n}\n', True),
    ('rule W {\n /* a } { */\n strings:\n  $a = "x"\n condition:\n  $a\n}\n', True),
    ('rule U {\n condition:\n  true\n', False),   # genuinely unbalanced
    ('rule V {\n strings:\n  $a = "x"\n}\n', False),  # missing condition
])
def test_yara_brace_counting_ignores_strings_and_comments(content, valid):
    assert lint.handler({"rule_type": "yara", "content": content}, None)["valid"] is valid
