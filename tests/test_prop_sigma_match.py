"""
Property-based tests for the sigma_match deterministic matcher
==============================================================
``tools/sigma_match`` is a REAL, deterministic, LLM-free gate: given a Sigma
rule + a normalized log event it decides whether the rule fires. Example-based
regression tests already cover the fixed cases; these Hypothesis tests attack
the *invariants* that must hold for arbitrary rules/events — the properties the
BAS detection-replay blind-spot analysis silently relies on.

Invariants exercised (all real, none tautological):
  * the matcher NEVER raises on an absent/odd field — it returns a result dict;
  * a selection referencing a field that is absent from the event can never be
    satisfied, so a rule whose condition is that selection never fires;
  * the contains / startswith / endswith / regex modifiers round-trip: a value
    substring/prefix/suffix/pattern derived from the event's own value matches;
  * ``all of them`` / ``1 of them`` / ``all of selection_*`` (wildcard) quantifier
    grammar behaves like the explicit AND/OR expansion;
  * De Morgan + boolean-algebra condition equivalences hold
    (``not (a and b)`` == ``not a or not b``, commutativity, double-negation).

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. Pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os
import re

from hypothesis import given, settings
from hypothesis import strategies as st

# Load the handler by a UNIQUE path-based module name so it never collides with
# a sibling ``handler`` module in sys.modules (tools/ is a flat scripts tree).
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sigma_match", "handler.py",
)
_spec = importlib.util.spec_from_file_location("sigma_match_handler__prop", _HANDLER_PATH)
sm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sm)

# Keep the suite fast + deterministic: modest example budget, generous deadline
# (import-time module load can be slow on a cold cache; matching itself is
# microseconds).
_SETTINGS = settings(max_examples=150, deadline=None)


def _match(rule, log_event) -> dict:
    return sm.handler({"rule": rule, "log_event": log_event}, None)


# Identifiers used for field + selection names: safe, condition-tokenizable.
_names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8).filter(
    lambda s: s not in ("and", "or", "not", "of", "them", "all", "any")
)
# Field VALUES: printable-ish text that never contains YAML/condition metachars.
_values = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/ ",
    min_size=1,
    max_size=20,
)
# A log event: a mapping of distinct field names -> values.
_log_events = st.dictionaries(_names, _values, min_size=0, max_size=6)


# --------------------------------------------------------------------------- #
# 1. Never crashes: arbitrary rule dict + arbitrary event => a result dict.    #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    sel_field=_names,
    modifier=st.sampled_from(["", "contains", "startswith", "endswith", "re"]),
    expected=st.one_of(_values, st.lists(_values, min_size=1, max_size=3)),
    log_event=_log_events,
)
def test_never_crashes_on_absent_or_arbitrary_field(sel_field, modifier, expected, log_event):
    """The matcher returns a well-formed dict for any field/modifier/event.

    In particular an ABSENT field (the sel_field need not be present in the
    event) must never raise — it simply fails to match.
    """
    key = sel_field if not modifier else f"{sel_field}|{modifier}"
    rule = {"detection": {"selection": {key: expected}, "condition": "selection"}}
    result = _match(rule, log_event)
    assert isinstance(result, dict)
    assert result.get("ok") is True
    assert isinstance(result["matched"], bool)


# --------------------------------------------------------------------------- #
# 2. A selection over an absent field can never be satisfied.                  #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(
    log_event=_log_events,
    absent_field=_names,
    modifier=st.sampled_from(["", "contains", "startswith", "endswith"]),
    expected=_values,
)
def test_unsatisfiable_selection_never_fires(log_event, absent_field, modifier, expected):
    """A rule whose only selection keys off a field missing from the event
    never fires — regardless of the expected value or modifier."""
    # Force the field to be absent.
    log_event = {k: v for k, v in log_event.items() if k != absent_field}
    key = absent_field if not modifier else f"{absent_field}|{modifier}"
    rule = {"detection": {"selection": {key: expected}, "condition": "selection"}}
    result = _match(rule, log_event)
    assert result["ok"] is True
    assert result["matched"] is False
    assert result["matched_selections"] == []


# --------------------------------------------------------------------------- #
# 3. Modifier round-trips: a fragment of the event's own value matches.        #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(field=_names, value=_values, data=st.data())
def test_contains_startswith_endswith_roundtrip(field, value, data):
    """contains(substring), startswith(prefix), endswith(suffix) derived from
    the event's own value all match that event (case-insensitive)."""
    n = len(value)
    i = data.draw(st.integers(min_value=0, max_value=n - 1))
    j = data.draw(st.integers(min_value=i + 1, max_value=n))
    substring = value[i:j]
    prefix = value[:j]
    suffix = value[i:]

    for modifier, fragment in (
        ("contains", substring),
        ("startswith", prefix),
        ("endswith", suffix),
    ):
        rule = {
            "detection": {
                "selection": {f"{field}|{modifier}": fragment},
                "condition": "selection",
            }
        }
        result = _match(rule, {field: value})
        assert result["ok"] is True, (modifier, fragment, value)
        assert result["matched"] is True, (modifier, fragment, value)


@_SETTINGS
@given(field=_names, value=_values)
def test_regex_modifier_roundtrip(field, value):
    """An anchored regex built from the escaped value matches that value."""
    pattern = re.escape(value)
    rule = {
        "detection": {
            "selection": {f"{field}|re": pattern},
            "condition": "selection",
        }
    }
    result = _match(rule, {field: value})
    assert result["ok"] is True
    assert result["matched"] is True


# --------------------------------------------------------------------------- #
# 4. all|contains round-trip and list-OR semantics.                            #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(field=_names, values=st.lists(_values, min_size=2, max_size=4, unique=True))
def test_all_modifier_requires_every_element(field, values):
    """``field|contains|all: [a, b, ...]`` matches iff EVERY element is present
    in the concatenated field value, and fails if a novel element is added."""
    joined = "-x-".join(values)
    rule_all = {
        "detection": {
            "selection": {f"{field}|contains|all": values},
            "condition": "selection",
        }
    }
    assert _match(rule_all, {field: joined})["matched"] is True

    # Add an element that cannot appear (contains a metachar not in the alphabet).
    rule_missing = {
        "detection": {
            "selection": {f"{field}|contains|all": [*values, "@@absent@@"]},
            "condition": "selection",
        }
    }
    assert _match(rule_missing, {field: joined})["matched"] is False


@_SETTINGS
@given(field=_names, values=st.lists(_values, min_size=2, max_size=4, unique=True), data=st.data())
def test_plain_list_is_or(field, values, data):
    """A plain list value is OR: the event matching ANY one element fires."""
    pick = data.draw(st.sampled_from(values))
    rule = {
        "detection": {
            "selection": {field: values},
            "condition": "selection",
        }
    }
    assert _match(rule, {field: pick})["matched"] is True


# --------------------------------------------------------------------------- #
# 5. Quantifier grammar: them / 1 of / all of / wildcard prefix.               #
# --------------------------------------------------------------------------- #
def _rule_with_selections(matched_flags):
    """Build a rule with selections ``selection_0..n-1``; ``matched_flags[i]``
    decides whether selection_i matches the (fixed) event. Returns (rule, event).

    Matching selections key off a present field with its exact value; failing
    ones key off a guaranteed-absent field.
    """
    event = {"present": "value"}
    detection = {}
    for i, flag in enumerate(matched_flags):
        name = f"selection_{i}"
        if flag:
            detection[name] = {"present": "value"}
        else:
            detection[name] = {"absent_field": "value"}  # field not in event
    return event, detection


@_SETTINGS
@given(flags=st.lists(st.booleans(), min_size=1, max_size=5))
def test_quantifiers_match_explicit_expansion(flags):
    """``all of them`` == AND of all selections; ``1 of them`` / ``any of them``
    == OR of all selections; the ``selection_*`` wildcard covers the same set."""
    event, detection = _rule_with_selections(flags)
    names = [f"selection_{i}" for i in range(len(flags))]

    def run(condition):
        rule = {"detection": {**detection, "condition": condition}}
        r = _match(rule, event)
        assert r["ok"] is True, condition
        return r["matched"]

    expected_all = all(flags)
    expected_any = any(flags)

    assert run("all of them") == expected_all
    assert run("1 of them") == expected_any
    assert run("any of them") == expected_any
    # Wildcard by prefix must cover exactly the same selection_* set.
    assert run("all of selection_*") == expected_all
    assert run("1 of selection_*") == expected_any
    # Explicit AND / OR expansions agree with the quantifiers.
    assert run(" and ".join(names)) == expected_all
    assert run(" or ".join(names)) == expected_any


@_SETTINGS
@given(flags=st.lists(st.booleans(), min_size=1, max_size=4))
def test_wildcard_over_nonexistent_group_never_fires(flags):
    """A quantifier over a prefix that matches NO selection never fires
    (empty group is treated as False, not vacuously True)."""
    event, detection = _rule_with_selections(flags)
    for cond in ("all of nomatch_*", "1 of nomatch_*", "any of nomatch_*"):
        rule = {"detection": {**detection, "condition": cond}}
        r = _match(rule, event)
        assert r["ok"] is True
        assert r["matched"] is False


# --------------------------------------------------------------------------- #
# 6. De Morgan + boolean equivalences over the condition grammar.              #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(a=st.booleans(), b=st.booleans())
def test_de_morgan_and_boolean_equivalences(a, b):
    """Condition expressions that are logically equivalent evaluate equally for
    every truth assignment of the two selections."""
    event, detection = _rule_with_selections([a, b])
    detection = {"selection_a": detection["selection_0"], "selection_b": detection["selection_1"]}

    def run(condition):
        rule = {"detection": {**detection, "condition": condition}}
        r = _match(rule, event)
        assert r["ok"] is True, condition
        return r["matched"]

    # De Morgan.
    assert run("not (selection_a and selection_b)") == run("not selection_a or not selection_b")
    assert run("not (selection_a or selection_b)") == run("not selection_a and not selection_b")
    # Commutativity.
    assert run("selection_a and selection_b") == run("selection_b and selection_a")
    assert run("selection_a or selection_b") == run("selection_b or selection_a")
    # Double negation.
    assert run("not not selection_a") == run("selection_a")


# --------------------------------------------------------------------------- #
# 7. Determinism: same (rule, event) always yields the same verdict.           #
# --------------------------------------------------------------------------- #
@_SETTINGS
@given(field=_names, value=_values, log_event=_log_events)
def test_determinism(field, value, log_event):
    rule = {
        "detection": {
            "selection": {f"{field}|contains": value},
            "condition": "selection",
        }
    }
    r1 = _match(rule, log_event)
    r2 = _match(rule, log_event)
    assert r1 == r2
