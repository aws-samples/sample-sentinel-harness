"""
Offline unit tests for longrunning/bas-runner/bas_cases.py
==========================================================
``bas_cases`` is the real, deterministic, LLM-free heart of the M3 BAS
detection-replay loop: it generates SIMULATED attack telemetry from a built-in
ATT&CK case library and replays it against a set of Sigma rules via the sibling
``tools/sigma_match`` matcher to enumerate **detection blind spots** (techniques
no rule catches). Because the blind-spot verdict a detection program acts on
depends on this being correct, every branch — case shape, filtering, the
DETECTED vs BLIND-SPOT decision, coverage arithmetic, and the empty-rules edge —
gets regression protection.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS, no LLM. Both ``bas_cases`` and
``sigma_match`` are pure Python by design, so every case runs fully offline with
no mocking.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# bas_cases lives under longrunning/bas-runner/ (a flat scripts tree with a
# hyphen in the dir name, so it is not importable as a package). Load it by
# absolute path, the same way the matcher's own tests load sigma_match.
_MODULE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "longrunning", "bas-runner", "bas_cases.py",
)
_spec = importlib.util.spec_from_file_location("bas_cases", _MODULE_PATH)
bas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bas)


# --------------------------------------------------------------------------- #
# Rules used across the replay tests                                          #
# --------------------------------------------------------------------------- #
# Catches the T1059.001 PowerShell case (Image endswith powershell.exe +
# CommandLine contains -enc). Matches the built-in PowerShell telemetry.
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

# Catches the T1547.001 run-key persistence case via the registry TargetObject.
RUNKEY_RULE = """
title: Registry Run Key Persistence
id: aaaabbbb-cccc-dddd-eeee-ffff00001111
status: experimental
level: medium
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\\CurrentVersion\\Run'
    condition: selection
"""

# A rule that matches NOTHING in the library (a fabricated field/value).
NEVER_MATCH_RULE = """
title: Never Matches Anything
id: 99999999-0000-0000-0000-000000000000
status: experimental
level: low
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\definitely_not_present_binary.exe'
    condition: selection
"""


# --------------------------------------------------------------------------- #
# generate_cases                                                              #
# --------------------------------------------------------------------------- #
def test_generate_all_cases_are_well_formed():
    cases = bas.generate_cases()
    assert len(cases) == len(bas.BAS_CASES)
    assert len(cases) >= 4  # PowerShell, LSASS, network scan, run-key at minimum

    seen_ids = set()
    for case in cases:
        # shape
        assert set(case) == {"technique_id", "name", "simulated_events"}
        assert isinstance(case["technique_id"], str) and case["technique_id"]
        assert isinstance(case["name"], str) and case["name"]
        assert isinstance(case["simulated_events"], list)
        assert case["simulated_events"], "each case must carry >=1 event"
        for event in case["simulated_events"]:
            assert isinstance(event, dict) and event
            # SIMULATED telemetry uses string field values (Sigma-style fields).
            assert all(isinstance(k, str) for k in event)
        # unique techniques
        assert case["technique_id"] not in seen_ids
        seen_ids.add(case["technique_id"])

    # The techniques named in the task brief are present.
    assert {"T1059.001", "T1003.001", "T1046", "T1547.001"} <= seen_ids


def test_generated_cases_are_defensive_copies():
    # Mutating a returned case must not corrupt the library or later calls.
    first = bas.generate_cases(["T1059.001"])[0]
    first["simulated_events"][0]["CommandLine"] = "TAMPERED"
    fresh = bas.generate_cases(["T1059.001"])[0]
    assert fresh["simulated_events"][0]["CommandLine"] != "TAMPERED"


def test_filter_by_technique_id_subset_and_order():
    cases = bas.generate_cases(["T1547.001", "T1046"])
    assert [c["technique_id"] for c in cases] == ["T1547.001", "T1046"]


def test_filter_is_case_insensitive_and_deduplicates():
    cases = bas.generate_cases(["t1059.001", "T1059.001"])
    assert [c["technique_id"] for c in cases] == ["T1059.001"]


def test_filter_accepts_bare_string():
    cases = bas.generate_cases("T1046")
    assert [c["technique_id"] for c in cases] == ["T1046"]


def test_unknown_technique_id_raises():
    with pytest.raises(ValueError):
        bas.generate_cases(["T9999"])


def test_empty_technique_id_raises():
    with pytest.raises(ValueError):
        bas.generate_cases([""])


# --------------------------------------------------------------------------- #
# replay — DETECTED vs BLIND SPOT                                             #
# --------------------------------------------------------------------------- #
def test_replay_marks_technique_detected_when_matching_rule_present():
    cases = bas.generate_cases(["T1059.001"])
    report = bas.replay(cases, [POWERSHELL_RULE])

    assert report["total_cases"] == 1
    assert report["detected_count"] == 1
    assert report["blind_spots"] == []
    assert report["coverage"] == 1.0

    result = report["results"][0]
    assert result["technique_id"] == "T1059.001"
    assert result["detected"] is True
    # The firing rule is labeled by its Sigma title.
    assert result["matched_rules"] == ["Suspicious PowerShell Encoded Command"]


def test_replay_marks_technique_blind_spot_when_no_rule_matches():
    cases = bas.generate_cases(["T1059.001"])
    report = bas.replay(cases, [NEVER_MATCH_RULE])

    assert report["detected_count"] == 0
    assert report["blind_spots"] == ["T1059.001"]
    assert report["coverage"] == 0.0
    result = report["results"][0]
    assert result["detected"] is False
    assert result["matched_rules"] == []


def test_replay_mixed_detected_and_blind_spot():
    # One rule catches PowerShell only; LSASS + network-scan stay blind spots.
    cases = bas.generate_cases(["T1059.001", "T1003.001", "T1046"])
    report = bas.replay(cases, [POWERSHELL_RULE])

    assert report["total_cases"] == 3
    assert report["detected_count"] == 1
    # blind_spots follow input case order.
    assert report["blind_spots"] == ["T1003.001", "T1046"]
    assert report["coverage"] == pytest.approx(1 / 3)

    by_id = {r["technique_id"]: r for r in report["results"]}
    assert by_id["T1059.001"]["detected"] is True
    assert by_id["T1003.001"]["detected"] is False
    assert by_id["T1046"]["detected"] is False


def test_replay_two_rules_cover_two_techniques():
    cases = bas.generate_cases(["T1059.001", "T1547.001"])
    report = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])

    assert report["detected_count"] == 2
    assert report["blind_spots"] == []
    assert report["coverage"] == 1.0

    by_id = {r["technique_id"]: r for r in report["results"]}
    assert by_id["T1059.001"]["matched_rules"] == [
        "Suspicious PowerShell Encoded Command"
    ]
    assert by_id["T1547.001"]["matched_rules"] == ["Registry Run Key Persistence"]


# --------------------------------------------------------------------------- #
# replay — coverage math + empty-rules edge                                   #
# --------------------------------------------------------------------------- #
def test_empty_rules_makes_everything_a_blind_spot():
    cases = bas.generate_cases()
    report = bas.replay(cases, [])

    assert report["total_cases"] == len(cases)
    assert report["detected_count"] == 0
    assert report["coverage"] == 0.0
    assert report["blind_spots"] == [c["technique_id"] for c in cases]
    assert all(r["detected"] is False for r in report["results"])
    assert all(r["matched_rules"] == [] for r in report["results"])


def test_coverage_ratio_math_full_and_partial():
    cases = bas.generate_cases()  # 4 built-in cases
    # A single PowerShell rule covers exactly one of them.
    partial = bas.replay(cases, [POWERSHELL_RULE])
    assert partial["coverage"] == pytest.approx(
        partial["detected_count"] / partial["total_cases"]
    )
    assert partial["detected_count"] == 1

    # Zero cases -> coverage is defined as 0.0 (no ZeroDivisionError).
    empty = bas.replay([], [POWERSHELL_RULE])
    assert empty["total_cases"] == 0
    assert empty["coverage"] == 0.0
    assert empty["blind_spots"] == []


def test_replay_determinism():
    cases = bas.generate_cases()
    r1 = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])
    r2 = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])
    assert r1 == r2


# --------------------------------------------------------------------------- #
# replay — accepts parsed-dict rules and surfaces bad rules                   #
# --------------------------------------------------------------------------- #
def test_replay_accepts_parsed_dict_rule():
    dict_rule = {
        "title": "PowerShell Encoded (dict form)",
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    report = bas.replay(bas.generate_cases(["T1059.001"]), [dict_rule])
    assert report["detected_count"] == 1
    assert report["results"][0]["matched_rules"] == ["PowerShell Encoded (dict form)"]


def test_replay_surfaces_matcher_validation_error():
    # A rule with no 'detection' block is rejected by sigma_match; replay must
    # surface that rather than silently marking the technique a blind spot.
    bad_rule = {"title": "no detection block"}
    with pytest.raises(ValueError):
        bas.replay(bas.generate_cases(["T1059.001"]), [bad_rule])


def test_replay_rejects_malformed_case():
    with pytest.raises(ValueError):
        bas.replay([{"name": "missing technique id"}], [POWERSHELL_RULE])


# --------------------------------------------------------------------------- #
# generate_cases — unknown / empty / whitespace filters                       #
# --------------------------------------------------------------------------- #
def test_generate_empty_sequence_returns_no_cases():
    # An empty (but not None) filter selects nothing — distinct from None which
    # returns the whole library.
    assert bas.generate_cases([]) == []


def test_whitespace_only_technique_id_raises():
    # A whitespace-only string is "empty" after strip and must be rejected
    # (same branch as the empty-string case, exercised via .strip()).
    with pytest.raises(ValueError):
        bas.generate_cases(["   "])


def test_non_string_technique_id_raises():
    with pytest.raises(ValueError):
        bas.generate_cases([12345])  # type: ignore[list-item]


def test_unknown_id_mixed_with_known_still_raises():
    # A single unknown id anywhere in the request fails the whole call rather
    # than silently dropping it (would hide a real gap in the case set).
    with pytest.raises(ValueError):
        bas.generate_cases(["T1059.001", "T0000.999"])


# --------------------------------------------------------------------------- #
# replay — multiple simulated events, only some of which match                #
# --------------------------------------------------------------------------- #
def test_replay_case_with_multiple_events_only_one_matches():
    # A case carrying several simulated events where only ONE event trips the
    # rule must still be DETECTED (a case fires if *any* event matches). This
    # exercises the inner event loop's "keep scanning until a match" path.
    case = {
        "technique_id": "T1059.001",
        "name": "PowerShell (multi-event)",
        "simulated_events": [
            # First event: benign, does NOT match the encoded-command rule.
            {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -Command Get-Date",
            },
            # Second event: the malicious one the rule catches (-enc).
            {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            },
        ],
    }
    report = bas.replay([case], [POWERSHELL_RULE])
    assert report["detected_count"] == 1
    assert report["blind_spots"] == []
    assert report["coverage"] == 1.0
    assert report["results"][0]["matched_rules"] == [
        "Suspicious PowerShell Encoded Command"
    ]


def test_replay_case_with_multiple_events_none_match_is_blind_spot():
    # Same shape, but NO event trips the rule -> the technique is a blind spot.
    case = {
        "technique_id": "T1059.001",
        "name": "PowerShell (multi-event, benign only)",
        "simulated_events": [
            {"Image": "C:\\powershell.exe", "CommandLine": "powershell -Command ls"},
            {"Image": "C:\\powershell.exe", "CommandLine": "powershell -Command pwd"},
        ],
    }
    report = bas.replay([case], [POWERSHELL_RULE])
    assert report["detected_count"] == 0
    assert report["blind_spots"] == ["T1059.001"]
    assert report["coverage"] == 0.0


# --------------------------------------------------------------------------- #
# replay — coverage ratio at the exact extremes (0.0 and 1.0)                 #
# --------------------------------------------------------------------------- #
def test_coverage_ratio_exactly_zero():
    # Every technique in the library is a blind spot -> coverage is exactly 0.0.
    cases = bas.generate_cases()
    report = bas.replay(cases, [NEVER_MATCH_RULE])
    assert report["detected_count"] == 0
    assert report["coverage"] == 0.0
    assert report["blind_spots"] == [c["technique_id"] for c in cases]


def test_coverage_ratio_exactly_one():
    # Two rules that between them cover both requested techniques -> coverage 1.0.
    cases = bas.generate_cases(["T1059.001", "T1547.001"])
    report = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])
    assert report["detected_count"] == report["total_cases"] == 2
    assert report["coverage"] == 1.0
    assert report["blind_spots"] == []


# --------------------------------------------------------------------------- #
# replay — rule labeling: title / id fallback / positional fallback           #
# --------------------------------------------------------------------------- #
def test_rule_label_falls_back_to_id_when_no_title():
    # A dict rule with no 'title' but an 'id' is labeled by its id.
    dict_rule = {
        "id": "no-title-but-has-id-0001",
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    report = bas.replay(bas.generate_cases(["T1059.001"]), [dict_rule])
    assert report["results"][0]["matched_rules"] == ["no-title-but-has-id-0001"]


def test_rule_label_falls_back_to_positional_when_no_title_or_id():
    # A rule carrying neither title nor id gets a positional "rule[<index>]"
    # label so it stays identifiable in the report.
    dict_rule = {
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    report = bas.replay(bas.generate_cases(["T1059.001"]), [dict_rule])
    assert report["results"][0]["matched_rules"] == ["rule[0]"]


def test_rule_label_blank_title_falls_through_to_id():
    # A whitespace-only title is treated as absent; labeling falls to 'id'.
    dict_rule = {
        "title": "   ",
        "id": "blank-title-id-0002",
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    report = bas.replay(bas.generate_cases(["T1059.001"]), [dict_rule])
    assert report["results"][0]["matched_rules"] == ["blank-title-id-0002"]


def test_yaml_string_rule_label_uses_title():
    # A YAML *string* rule is parsed via the matcher's own parser for labeling.
    report = bas.replay(bas.generate_cases(["T1059.001"]), [POWERSHELL_RULE])
    assert report["results"][0]["matched_rules"] == [
        "Suspicious PowerShell Encoded Command"
    ]


def test_parse_rule_for_label_swallows_parser_error_returns_none(monkeypatch):
    # The cosmetic label parser must NEVER propagate a parse error: when the
    # matcher's _parse_yaml raises, _parse_rule_for_label returns None so the
    # caller can fall back to a positional label. Patching only affects labeling
    # here because we call the helper directly (no matcher evaluation involved).
    def _boom(_text):
        raise RuntimeError("boom")

    monkeypatch.setattr(bas._SIGMA_MATCH_MODULE, "_parse_yaml", _boom)
    assert bas._parse_rule_for_label("title: whatever") is None


def test_rule_id_falls_back_to_positional_on_unparseable_string(monkeypatch):
    # When labeling a YAML *string* whose parse fails, _rule_id must fall back to
    # the positional "rule[<index>]" label rather than raising.
    def _boom(_text):
        raise RuntimeError("boom")

    monkeypatch.setattr(bas._SIGMA_MATCH_MODULE, "_parse_yaml", _boom)
    assert bas._rule_id("title: broken", 3) == "rule[3]"


def test_rule_id_string_without_title_or_id_is_positional():
    # A parseable YAML string carrying neither title nor id -> positional label.
    yaml_no_meta = (
        "detection:\n"
        "    selection:\n"
        "        CommandLine|contains: '-enc'\n"
        "    condition: selection\n"
    )
    assert bas._rule_id(yaml_no_meta, 5) == "rule[5]"


# --------------------------------------------------------------------------- #
# replay — malformed-case edge branches                                       #
# --------------------------------------------------------------------------- #
def test_replay_rejects_non_dict_case():
    # A non-dict entry in the case list is a hard error.
    with pytest.raises(ValueError):
        bas.replay(["not-a-dict"], [POWERSHELL_RULE])  # type: ignore[list-item]


def test_replay_rejects_non_list_simulated_events():
    # 'simulated_events' must be a list; a string (or any non-list) is rejected.
    bad_case = {"technique_id": "T1059.001", "name": "bad", "simulated_events": "nope"}
    with pytest.raises(ValueError):
        bas.replay([bad_case], [POWERSHELL_RULE])


def test_replay_rejects_blank_technique_id():
    bad_case = {"technique_id": "   ", "name": "blank id", "simulated_events": []}
    with pytest.raises(ValueError):
        bas.replay([bad_case], [POWERSHELL_RULE])


# --------------------------------------------------------------------------- #
# module loader — error branches                                              #
# --------------------------------------------------------------------------- #
def test_load_sigma_match_missing_handler_path_raises(monkeypatch):
    # If the matcher file is absent, the loader raises rather than degrading.
    monkeypatch.setattr(bas, "_sigma_match_handler_path", lambda: "/no/such/handler.py")
    with pytest.raises(ImportError):
        bas._load_sigma_match_module()


def test_load_sigma_match_spec_none_raises(monkeypatch):
    # A real, existing path but a None spec (importlib can't build one) raises.
    monkeypatch.setattr(bas.importlib.util, "spec_from_file_location", lambda *a, **k: None)
    with pytest.raises(ImportError):
        bas._load_sigma_match_module()


def test_load_sigma_match_no_handler_attr_raises(monkeypatch):
    # A module that loads fine but exposes no 'handler' callable is rejected.
    class _FakeSpec:
        loader = type("L", (), {"exec_module": staticmethod(lambda mod: None)})()

    monkeypatch.setattr(
        bas.importlib.util, "spec_from_file_location", lambda *a, **k: _FakeSpec()
    )
    monkeypatch.setattr(
        bas.importlib.util,
        "module_from_spec",
        lambda spec: type("M", (), {})(),  # bare module object, no 'handler'
    )
    with pytest.raises(ImportError):
        bas._load_sigma_match_module()


# --------------------------------------------------------------------------- #
# __main__ demo block — importable & runnable offline, prints a valid report  #
# --------------------------------------------------------------------------- #
def test_main_demo_block_runs_and_prints_report(capfd):
    # Execute the module as __main__ so the demo/CLI block (its json.dumps of a
    # real replay) is exercised end-to-end, fully offline. runpy runs the file
    # under run_name="__main__", tripping the `if __name__ == "__main__":` guard
    # without clobbering the module-level `bas` import above.
    import json
    import runpy

    runpy.run_path(_MODULE_PATH, run_name="__main__")

    out, _ = capfd.readouterr()
    report = json.loads(out)
    # The demo rule only catches PowerShell -> every other technique is blind.
    assert report["total_cases"] == len(bas.BAS_CASES)
    assert report["detected_count"] == 1
    assert "T1059.001" not in report["blind_spots"]
    assert set(report["blind_spots"]) == {
        c["technique_id"] for c in bas.BAS_CASES if c["technique_id"] != "T1059.001"
    }
