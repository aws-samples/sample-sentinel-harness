"""Edge-case & negative-path tests for the M2 building blocks
=============================================================
The M2 self-improvement loop rests on two deterministic pieces: the
``run_evaluation`` scoring gate (a pure verdict parser + a single judge invoke)
and the ``sentinel_harness.core`` endpoint wrappers (the promote-to-production
mechanism). The happy-path suites (``tests/test_run_evaluation.py`` and
``tests/test_core_endpoint.py``) pin the mainline; THIS file drills the branches
they skip:

  * ``parse_verdict`` / ``_extract_json_object`` — nested verdict objects, braces
    inside string literals, MULTIPLE candidate objects (the right one wins), a
    fenced block winning over surrounding prose braces, fractional out-of-range
    scores clamped to [0, 1], a parseable string-number score, the subtle
    truthy/falsy ``pass`` variants (a non-empty ``"false"`` string is TRUTHY),
    ``reasons``/``suggestions`` given as a bare string vs a list vs missing, and a
    pure-prose reply with no JSON.
  * ``score_answer`` validation — each missing required param, criteria as list vs
    string, and an EMPTY judge reply that must still yield a usable verdict (not a
    crash) after the retry loop.
  * the endpoint wrappers — the PARTIAL-optional create cases (only
    ``target_version``, only ``description``) that the happy path (which only tests
    both-set and both-omitted) misses, plus id/name plumbing and kw passthrough.

HARD RULE: ZERO network / ZERO AWS. ``core.invoke`` / ``core.new_session`` and
``core._control`` are monkeypatched to recording fakes; no boto client is ever
constructed. ``parse_verdict`` is pure and needs no patching. The judge-invoke
retry backoff is zeroed (autouse fixture) so the retry path never sleeps on real
wall-clock. No real 12-digit account id sits literally in this file — the one
ARN placeholder is built at runtime from ``"0" * 12``.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_m2_edge.py -q
"""
from __future__ import annotations

import importlib
import importlib.util
import os

import pytest

# --- Hermetic import: dummy env before anything builds a boto3 client. ---
# The account id is concatenated at runtime so no literal iam::<12 digits>:
# pattern sits in the file for the CI secret-scan to flag.
_ACCT = "0" * 12
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", f"arn:aws:iam::{_ACCT}:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core  # noqa: E402

_TOOLS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
)


def _load(tool_name: str):
    """Load tools/<tool_name>/handler.py by path (tools/ is a scripts tree)."""
    path = os.path.join(_TOOLS_DIR, tool_name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{tool_name}_handler_edge", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("run_evaluation")


@pytest.fixture(autouse=True)
def _pristine_core():
    """Guarantee the GENUINE ``sentinel_harness.core`` wrappers are in place before
    each test, then restore them afterward.

    WHY this is required: ``demo/m2_self_improving_demo.py::_install_offline_stubs``
    rebinds ``core.create_harness_endpoint`` (and its siblings) to in-memory fakes as
    a *module-level* mutation and does not capture/restore the originals. When the
    demo suite (``tests/test_m2_demo.py``) exercises that installer directly, those
    fakes LEAK into the shared pytest process and bypass ``core._control`` entirely —
    so this file's ``fake_control`` recorder would never see a call. Reloading the
    module rebinds the real wrappers regardless of prior pollution; the offline reload
    is safe because dummy creds/region are set above and boto3 client construction
    makes no network call. This fixture edits only this test file (no change to the
    demo or any shared file)."""
    importlib.reload(core)
    yield
    importlib.reload(core)


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the judge-invoke retry backoff so any retry path never sleeps on real
    wall-clock (mirrors the happy-path suite's autouse fixture)."""
    monkeypatch.setattr(ev, "_JUDGE_BACKOFF_SECONDS", 0)


def _pv(text):
    """Shorthand: run the parse_verdict action and return the result dict."""
    return ev.handler({"action": "parse_verdict", "params": {"text": text}}, None)


# --------------------------------------------------------------------------- #
# _extract_json_object — nested / string-braces / multiple / fence-vs-prose   #
# --------------------------------------------------------------------------- #
def test_parse_verdict_nested_object_is_parsed_whole():
    # A verdict object that CONTAINS a nested object: the brace scanner must not
    # stop at the inner '}'; the whole outer object parses and the extra key is
    # simply ignored by the coercers.
    text = ('prose {"score": 0.5, "pass": true, "reasons": ["r"], '
            '"suggestions": [], "meta": {"model": "judge", "nested": {"deep": 1}}} tail')
    r = _pv(text)
    assert r["ok"] is True
    assert r["score"] == 0.5
    assert r["passed"] is True
    assert r["reasons"] == ["r"]


def test_parse_verdict_braces_inside_string_values():
    # A '}' living inside a JSON string literal must NOT terminate the object —
    # the brace scanner is string-literal aware.
    text = ('{"score": 0.4, "pass": false, '
            '"reasons": ["use the {placeholder} token", "close with }"], '
            '"suggestions": ["wrap {x} in braces"]}')
    r = _pv(text)
    assert r["ok"] is True
    assert r["score"] == 0.4
    assert r["passed"] is False
    assert r["reasons"] == ["use the {placeholder} token", "close with }"]
    assert r["suggestions"] == ["wrap {x} in braces"]


def test_parse_verdict_multiple_objects_takes_first_brace_span():
    # Two standalone objects in prose. The whole trimmed string is not valid JSON,
    # so the brace scanner returns the FIRST balanced {...} span — that verdict
    # (score 0.1 / fail) is the one that must win, not the later 0.9 / pass one.
    text = ('First cut: {"score": 0.1, "pass": false, "reasons": ["thin"]} '
            'Revised: {"score": 0.9, "pass": true, "reasons": ["good"]}')
    r = _pv(text)
    assert r["ok"] is True
    assert r["score"] == 0.1
    assert r["passed"] is False
    assert r["reasons"] == ["thin"]


def test_parse_verdict_fenced_block_wins_over_surrounding_prose_braces():
    # A ```json fence is tried BEFORE the brace scan, so the fenced verdict wins
    # even when unrelated {...} spans sit before/after it in the prose.
    text = ('Context {"noise": 1} and more.\n'
            '```json\n{"score": 0.33, "pass": false, "suggestions": ["cite sources"]}\n```\n'
            'Trailing {"garbage": 2}.')
    r = _pv(text)
    assert r["ok"] is True
    assert r["score"] == 0.33
    assert r["passed"] is False
    assert r["suggestions"] == ["cite sources"]


# --------------------------------------------------------------------------- #
# score coercion — fractional out-of-range, string number                     #
# --------------------------------------------------------------------------- #
def test_parse_verdict_fractional_score_above_one_clamps():
    # 1.7 (a plausible mis-scale, not an integer) clamps to the [0, 1] ceiling.
    r = _pv('{"score": 1.7, "pass": true}')
    assert r["score"] == 1.0
    assert r["passed"] is True


def test_parse_verdict_fractional_negative_score_clamps_to_zero():
    # -0.3 clamps to the floor; pass flag is independent of the clamp.
    r = _pv('{"score": -0.3, "pass": false}')
    assert r["score"] == 0.0
    assert r["passed"] is False


def test_parse_verdict_string_number_score_is_parsed():
    # A parseable numeric STRING is coerced via float(), not treated as unparseable
    # (unlike the "N/A" case pinned in the happy-path suite).
    r = _pv('{"score": "0.55", "pass": true}')
    assert r["score"] == 0.55
    assert r["passed"] is True


# --------------------------------------------------------------------------- #
# pass coercion — truthy / falsy variants (bool(...) semantics)               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pass_val, expected", [
    (0, False),          # falsy int
    (0.0, False),        # falsy float
    ("", False),         # empty string is falsy
    (None, False),       # null is falsy
    ([], False),         # empty list is falsy
    ("false", True),     # GOTCHA: a NON-EMPTY string is TRUTHY, even "false"
    ("no", True),        # any non-empty string is truthy under bool()
    (["x"], True),       # non-empty list is truthy
])
def test_parse_verdict_pass_truthy_falsy_variants(pass_val, expected):
    import json
    text = json.dumps({"score": 0.5, "pass": pass_val})
    r = _pv(text)
    assert r["passed"] is expected


def test_parse_verdict_missing_pass_defaults_false_and_score_zero():
    # No "pass" key at all → obj.get("pass") is None → passed False → score
    # defaults to 0.0 (the fail default) when score is also absent.
    r = _pv('{"reasons": ["some note"]}')
    assert r["ok"] is True
    assert r["passed"] is False
    assert r["score"] == 0.0
    assert r["reasons"] == ["some note"]


# --------------------------------------------------------------------------- #
# reasons / suggestions coercion — bare string vs list vs missing             #
# --------------------------------------------------------------------------- #
def test_parse_verdict_reasons_bare_string_suggestions_list():
    # A bare-string reasons becomes a one-item list; a list stays element-wise.
    r = _pv('{"score": 0.6, "pass": true, "reasons": "single reason", '
            '"suggestions": ["a", "b"]}')
    assert r["reasons"] == ["single reason"]
    assert r["suggestions"] == ["a", "b"]


def test_parse_verdict_reasons_and_suggestions_missing_become_empty_lists():
    # Both fields absent → empty lists, never a crash and never a None.
    r = _pv('{"score": 0.6, "pass": true}')
    assert r["reasons"] == []
    assert r["suggestions"] == []


def test_parse_verdict_list_fields_stringify_non_string_elements():
    # Non-string list elements are stringified element-wise (str(x)).
    r = _pv('{"score": 0.6, "pass": true, "reasons": [1, 2.5, true], '
            '"suggestions": [null]}')
    assert r["reasons"] == ["1", "2.5", "True"]
    assert r["suggestions"] == ["None"]


def test_parse_verdict_empty_string_reasons_becomes_empty_list():
    # A whitespace-only bare string is NOT a reason → empty list (the _coerce_list
    # str.strip() guard), distinct from a non-empty bare string.
    r = _pv('{"score": 0.6, "pass": true, "reasons": "   "}')
    assert r["reasons"] == []


# --------------------------------------------------------------------------- #
# pure-prose replies with no JSON at all — prose-scan fallback                 #
# --------------------------------------------------------------------------- #
def test_parse_verdict_prose_no_pass_no_fail_is_not_passed():
    # Neither "pass" nor "fail" present → prose scan yields not-passed, score 0.0.
    r = _pv("The response was thorough and well organized overall.")
    assert r["ok"] is True
    assert r["passed"] is False
    assert r["score"] == 0.0


def test_parse_verdict_prose_pass_substring_is_case_insensitive():
    # The scan lowercases, so "PASS" (uppercase) still counts as pass.
    r = _pv("VERDICT: PASS. Meets every criterion.")
    assert r["passed"] is True
    assert r["score"] == 1.0


def test_parse_verdict_empty_text_via_action_is_validation_error():
    # An empty text string fails _require_str BEFORE the parser runs — the
    # parse_verdict ACTION requires a non-empty string.
    r = ev.handler({"action": "parse_verdict", "params": {"text": "   "}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# score_answer validation — each missing param is its own validation_error    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def stub_invoke(monkeypatch):
    """Recorder for core.invoke returning a mutable canned reply; new_session is
    a deterministic stub. Mirrors the happy-path suite's fixture shape."""
    state: dict = {
        "calls": [],
        "reply": '{"score": 0.7, "pass": true, "reasons": ["ok"], "suggestions": []}',
        "error": None,
    }

    def fake_invoke(*args, **kw):
        state["calls"].append({"args": args, "kwargs": kw})
        return {"text": state["reply"], "error": state["error"],
                "stop_reason": "end_turn", "tools_used": [], "tool_use": None,
                "events": [], "metadata": {}}

    monkeypatch.setattr(core, "invoke", fake_invoke)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    return state


def test_score_answer_missing_judge_arn_never_invokes(stub_invoke):
    r = ev.handler(
        {"action": "score_answer",
         "params": {"agent_answer": "a", "criteria": "c"}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "judge_arn" in r["message"]
    assert stub_invoke["calls"] == []  # a validation failure never reaches the model


def test_score_answer_missing_agent_answer_never_invokes(stub_invoke):
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "criteria": "c"}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "agent_answer" in r["message"]
    assert stub_invoke["calls"] == []


def test_score_answer_missing_criteria_never_invokes(stub_invoke):
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "agent_answer": "a"}}, None)
    assert r["ok"] is False and r["error"] == "validation_error"
    assert "criteria" in r["message"]
    assert stub_invoke["calls"] == []


def test_score_answer_criteria_as_string_reaches_judge_verbatim(stub_invoke):
    # A bare-string criteria passes through _as_text unchanged (no numbering).
    ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "agent_answer": "a",
                    "criteria": "Answer must cite a source."}}, None)
    prompt = stub_invoke["calls"][0]["args"][2]
    assert "Answer must cite a source." in prompt
    assert "1. Answer must cite a source." not in prompt  # a string is NOT numbered


def test_score_answer_criteria_as_list_is_numbered(stub_invoke):
    # A list criteria becomes a 1-based numbered block (distinct list content from
    # the happy-path suite's case so this is not a duplicate).
    ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "agent_answer": "a",
                    "criteria": ["mentions MITRE technique", "no hallucinated CVE"]}},
        None)
    prompt = stub_invoke["calls"][0]["args"][2]
    assert "1. mentions MITRE technique" in prompt
    assert "2. no hallucinated CVE" in prompt


def test_score_answer_empty_judge_reply_yields_usable_verdict(stub_invoke):
    # An EMPTY judge reply must not crash: the retry loop exhausts (no exception
    # raised because last_exc is None), then the prose fallback over "" yields a
    # usable fail verdict. This is the key robustness branch.
    stub_invoke["reply"] = ""
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "agent_answer": "a", "criteria": "c"}}, None)
    assert r["ok"] is True
    assert r["passed"] is False
    assert r["score"] == 0.0
    assert r["reasons"] == [] and r["suggestions"] == []
    assert r["raw"] == ""
    # Empty-reply attempts are retried up to the policy limit (not a single shot).
    assert len(stub_invoke["calls"]) == ev._JUDGE_RETRIES


def test_score_answer_whitespace_only_reply_also_falls_back(stub_invoke):
    # A whitespace-only reply (never .strip()-truthy) behaves like empty: retried
    # then a usable fail verdict from the prose fallback.
    stub_invoke["reply"] = "   \n\t  "
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:j", "agent_answer": "a", "criteria": "c"}}, None)
    assert r["ok"] is True
    assert r["passed"] is False
    assert r["score"] == 0.0
    assert len(stub_invoke["calls"]) == ev._JUDGE_RETRIES


# --------------------------------------------------------------------------- #
# core endpoint wrappers — PARTIAL optionals + id/name plumbing + kw           #
# --------------------------------------------------------------------------- #
class _CapturingControl:
    """Captures endpoint/version call kwargs; returns canned envelopes. Any other
    attribute access is a loud failure so an accidental real path is caught."""

    def __init__(self):
        self.create_calls: list[dict] = []
        self.get_calls: list[dict] = []
        self.versions_calls: list[dict] = []
        self.delete_calls: list[dict] = []

    def create_harness_endpoint(self, **kwargs):
        self.create_calls.append(kwargs)
        return {"endpoint": {"endpointName": kwargs.get("endpointName"),
                             "status": "CREATING"}}

    def get_harness_endpoint(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"endpoint": {"endpointName": kwargs.get("endpointName"),
                             "status": "READY"}}

    def list_harness_versions(self, **kwargs):
        self.versions_calls.append(kwargs)
        return {"harnessVersions": [{"version": "7"}, {"version": "8"}]}

    def delete_harness_endpoint(self, **kwargs):
        self.delete_calls.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def __getattr__(self, item):  # pragma: no cover - defensive
        raise AssertionError(f"endpoint edge test must not touch _control.{item}")


@pytest.fixture()
def fake_control(monkeypatch):
    ctrl = _CapturingControl()
    monkeypatch.setattr(core, "_control", ctrl)
    return ctrl


def test_create_includes_only_target_version_when_description_none(fake_control):
    # PARTIAL optional: target_version set, description omitted → only targetVersion
    # leaks (the happy-path suite only covers both-set and both-omitted).
    core.create_harness_endpoint("hid-7", "prod", target_version="8")
    call = fake_control.create_calls[0]
    assert set(call) == {"harnessId", "endpointName", "targetVersion"}
    assert call["targetVersion"] == "8"
    assert "description" not in call


def test_create_includes_only_description_when_target_version_none(fake_control):
    # PARTIAL optional: description set, target_version omitted → only description.
    core.create_harness_endpoint("hid-7", "prod", description="promote candidate")
    call = fake_control.create_calls[0]
    assert set(call) == {"harnessId", "endpointName", "description"}
    assert call["description"] == "promote candidate"
    assert "targetVersion" not in call


def test_create_kw_alongside_partial_optional_passes_through(fake_control):
    # kw + a partial optional together: both land, no None optional leaks.
    core.create_harness_endpoint(
        "hid-7", "prod", target_version="8", clientToken="tok-123")
    call = fake_control.create_calls[0]
    assert call["targetVersion"] == "8"
    assert call["clientToken"] == "tok-123"
    assert "description" not in call


def test_list_harness_versions_returns_the_list(fake_control):
    out = core.list_harness_versions("hid-7")
    assert fake_control.versions_calls[0] == {"harnessId": "hid-7"}
    assert out == [{"version": "7"}, {"version": "8"}]


def test_get_endpoint_passes_harness_id_and_name(fake_control):
    out = core.get_harness_endpoint("hid-9", "staging")
    assert fake_control.get_calls[0] == {"harnessId": "hid-9", "endpointName": "staging"}
    assert out["endpointName"] == "staging"
    assert out["status"] == "READY"


def test_delete_endpoint_passes_harness_id_and_name(fake_control):
    out = core.delete_harness_endpoint("hid-9", "staging")
    assert fake_control.delete_calls[0] == {"harnessId": "hid-9", "endpointName": "staging"}
    assert out == {"ResponseMetadata": {"HTTPStatusCode": 200}}
