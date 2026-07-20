"""
Offline unit tests for sigma_match value modifiers (M17 detection depth)
========================================================================
``tools/sigma_match`` is the deterministic, LLM-free core of the BAS
detection-replay blind-spot loop. Before M17 several widely-used Sigma value
modifiers silently misbehaved: ``|cidr`` string-compared an IP to a network,
``|base64offset`` was wrong at both encode and match time, ``|gte`` degraded to
equality, and null semantics were inverted — all silently, letting a rule be
scored "covered" when it could never actually fire. These tests pin the fixed
behaviour with table-driven positive/negative pairs for every modifier, plus
the caveat contract that forces an un-evaluable rule OUT of the coverage
verdict instead of counting it as a match.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. Pure Python, fully offline.
"""
from __future__ import annotations

import base64
import importlib.util
import os

import pytest

# The tool handlers live under tools/<name>/handler.py — a scripts tree, not an
# installed package. Load the module directly by a unique path-based name.
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sigma_match", "handler.py",
)
_spec = importlib.util.spec_from_file_location("sigma_match_handler__mod", _HANDLER_PATH)
sm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sm)


def match(rule, log_event) -> dict:
    return sm.handler({"rule": rule, "log_event": log_event}, None)


def _rule(field_spec: str, value) -> dict:
    """Build a minimal single-key rule as an already-parsed dict.

    Using a dict (not YAML) keeps the fixtures readable and avoids indentation
    fragility while exercising the exact same matching path the YAML rules hit.
    """
    return {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {field_spec: value}, "condition": "selection"},
    }


def _matches(field_spec: str, value, log_event) -> bool:
    r = match(_rule(field_spec, value), log_event)
    assert r["ok"] is True, r
    return r["matched"]


# --------------------------------------------------------------------------- #
# cidr                                                                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field_ip,network,expected", [
    ("10.1.2.3", "10.0.0.0/8", True),        # inside the /8
    ("10.255.255.255", "10.0.0.0/8", True),  # last address in range
    ("11.0.0.1", "10.0.0.0/8", False),       # just outside
    ("192.168.1.5", "192.168.1.0/24", True),
    ("192.168.2.5", "192.168.1.0/24", False),
    ("::1", "::/0", True),                   # IPv6 supported too
])
def test_cidr_membership(field_ip, network, expected):
    assert _matches("SourceIp|cidr", network, {"SourceIp": field_ip}) is expected


def test_cidr_non_ip_field_no_match_no_crash():
    # A field that is not an IP must NOT match and must NOT crash (the old bug
    # string-compared it to the network literal).
    assert _matches("SourceIp|cidr", "10.0.0.0/8", {"SourceIp": "not-an-ip"}) is False
    assert _matches("SourceIp|cidr", "10.0.0.0/8", {"SourceIp": ""}) is False


def test_cidr_invalid_network_records_caveat():
    r = match(_rule("SourceIp|cidr", "not-a-network"), {"SourceIp": "10.1.2.3"})
    assert r["matched"] is False
    assert r["caveats"] == [
        {"field": "SourceIp", "modifier": "cidr", "reason": "invalid_cidr_value"}
    ]


# --------------------------------------------------------------------------- #
# base64 / base64offset                                                       #
# --------------------------------------------------------------------------- #
def test_base64_straight_encode_and_match():
    # The field holds the base64 of the decoded command; the rule pattern is the
    # PLAINTEXT and the engine encodes it before substring-matching.
    payload = "whoami /all"
    field = base64.b64encode(payload.encode()).decode()
    assert _matches("CommandLine|base64", payload, {"CommandLine": field}) is True
    # A different plaintext must not match the same field.
    assert _matches("CommandLine|base64", "netstat -ano", {"CommandLine": field}) is False


def test_base64offset_matches_pattern_embedded_midstream():
    # The pattern appears in the MIDDLE of a larger base64 blob, so its byte
    # alignment is not 0; the 3-offset expansion must still find it.
    pattern = "cmd.exe /c"
    for prefix in ("", "run ", "x ", "yy "):  # shift the alignment 0..3
        blob = base64.b64encode((prefix + pattern + " tail").encode()).decode()
        assert _matches("CommandLine|base64offset", pattern, {"CommandLine": blob}) is True


def test_base64offset_negative():
    blob = base64.b64encode(b"totally unrelated content here").decode()
    assert _matches("CommandLine|base64offset", "mimikatz", {"CommandLine": blob}) is False


# --------------------------------------------------------------------------- #
# windash                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cmdline,expected", [
    ("powershell -enc AAAA", True),   # rule written with '-', field uses '-'
    ("powershell /enc AAAA", True),   # field uses '/' — must still match
    ("powershell -noprofile", False),  # a genuinely different flag token
])
def test_windash_flag_variants(cmdline, expected):
    # Rule pattern uses the '-' spelling; windash must also catch the '/' form.
    assert _matches("CommandLine|windash", "-enc", {"CommandLine": cmdline}) is expected


def test_windash_rule_written_with_slash_matches_dash_field():
    assert _matches("CommandLine|windash", "/enc", {"CommandLine": "pwsh -enc AA"}) is True


# --------------------------------------------------------------------------- #
# gt / gte / lt / lte                                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("modifier,threshold,value,expected", [
    ("gt", 100, 101, True),
    ("gt", 100, 100, False),      # gt is strict — the old bug degraded to ==
    ("gte", 100, 100, True),
    ("gte", 100, 99, False),
    ("lt", 100, 99, True),
    ("lt", 100, 100, False),
    ("lte", 100, 100, True),
    ("lte", 100, 101, False),
    ("gt", 100, "150", True),     # numeric string field coerces
    ("gte", 5, 5.0, True),        # float field
])
def test_numeric_comparison(modifier, threshold, value, expected):
    assert _matches(f"Count|{modifier}", threshold, {"Count": value}) is expected


def test_numeric_non_numeric_field_records_caveat():
    r = match(_rule("Count|gt", 100), {"Count": "not-a-number"})
    assert r["matched"] is False
    assert r["caveats"] == [
        {"field": "Count", "modifier": "gt", "reason": "non_numeric_value"}
    ]


def test_numeric_bool_field_is_non_numeric_caveat():
    # A boolean is deliberately NOT treated as 0/1 for a numeric comparison.
    r = match(_rule("Count|gte", 1), {"Count": True})
    assert r["matched"] is False
    assert r["caveats"][0]["reason"] == "non_numeric_value"


# --------------------------------------------------------------------------- #
# exists                                                                      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("exists_value,event,expected", [
    (True, {"TargetFilename": "x.dll"}, True),    # present, want present
    (True, {"TargetFilename": None}, True),       # present-but-None still exists
    (True, {"Other": 1}, False),                  # absent, want present
    (False, {"Other": 1}, True),                  # absent, want absent
    (False, {"TargetFilename": "x"}, False),      # present, want absent
])
def test_exists_presence(exists_value, event, expected):
    assert _matches("TargetFilename|exists", exists_value, event) is expected


# --------------------------------------------------------------------------- #
# cased                                                                       #
# --------------------------------------------------------------------------- #
def test_cased_exact_is_case_sensitive():
    # Default matching is case-insensitive; |cased must require an exact case.
    assert _matches("User|cased", "Administrator", {"User": "Administrator"}) is True
    assert _matches("User|cased", "Administrator", {"User": "administrator"}) is False


def test_cased_composes_with_contains():
    assert _matches("CommandLine|contains|cased", "Invoke", {"CommandLine": "x Invoke-Mimikatz"}) is True
    assert _matches("CommandLine|contains|cased", "Invoke", {"CommandLine": "x invoke-mimikatz"}) is False


def test_default_contains_is_case_insensitive():
    # Sanity anchor: without |cased the comparison stays case-insensitive.
    assert _matches("CommandLine|contains", "invoke", {"CommandLine": "x INVOKE-y"}) is True


# --------------------------------------------------------------------------- #
# null semantics                                                              #
# --------------------------------------------------------------------------- #
def test_null_matches_absent_field():
    assert _matches("TargetObject", None, {"Other": 1}) is True


def test_null_matches_present_none_value():
    assert _matches("TargetObject", None, {"TargetObject": None}) is True


def test_null_does_not_match_present_value():
    assert _matches("TargetObject", None, {"TargetObject": "something"}) is False


def test_absent_field_still_fails_for_non_null_value():
    # Regression guard: only null should match on absence; a real value must not.
    assert _matches("TargetObject", "x", {"Other": 1}) is False


# --------------------------------------------------------------------------- #
# unsupported modifier -> caveat + excluded from verdict                      #
# --------------------------------------------------------------------------- #
def test_unknown_modifier_records_caveat_and_forces_no_match():
    r = match(_rule("CommandLine|frobnicate", "x"), {"CommandLine": "x"})
    assert r["ok"] is True
    assert r["matched"] is False  # inconclusive, never a silent equality match
    assert r["caveats"] == [
        {"field": "CommandLine", "modifier": "frobnicate", "reason": "unsupported_modifier"}
    ]


def test_unknown_modifier_forces_no_match_even_when_other_keys_match():
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {
            "selection": {
                "User": "admin",                    # this would match
                "CommandLine|frobnicate": "x",      # this is un-evaluable
            },
            "condition": "selection",
        },
    }
    r = match(rule, {"User": "admin", "CommandLine": "x"})
    assert r["matched"] is False
    assert any(c["reason"] == "unsupported_modifier" for c in r["caveats"])


def test_fully_supported_rule_has_empty_caveats():
    # A normal rule must report an explicit empty caveats list (stable shape).
    r = match(_rule("CommandLine|contains", "enc"), {"CommandLine": "p -enc AA"})
    assert r["matched"] is True
    assert r["caveats"] == []


def test_caveat_recorded_even_when_earlier_key_fails():
    # The failing 'User' key comes first; the engine must still evaluate the
    # later un-evaluable key and record its caveat (no short-circuit hiding it).
    rule = {
        "title": "x",
        "logsource": {},
        "detection": {
            "selection": {
                "User": "nobody",                 # fails
                "Count|gt": 5,                     # non-numeric field -> caveat
            },
            "condition": "selection",
        },
    }
    r = match(rule, {"User": "admin", "Count": "abc"})
    assert r["matched"] is False
    assert any(c["reason"] == "non_numeric_value" for c in r["caveats"])
