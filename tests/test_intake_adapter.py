"""
Offline tests for the intake adapter (ROADMAP §4 M1 item 4)
===========================================================
The intake adapter is a pure, deterministic normalizer — no AWS, no network, no
LLM. These tests assert each of the three channels (``nl`` / ``notes`` / ``error``)
produces the expected normalized request text, that a blank payload and an unknown
source_type both raise loudly, and that an error traceback becomes a fix-request.

HARD RULE: ZERO AWS / network calls. The module imports nothing that touches boto3
or the wire, so no monkeypatching is needed — importing it must stay cheap.
"""
from __future__ import annotations

import pytest

from intake import IntakeResult, normalize
from intake.adapter import SOURCE_TYPES, normalize_detailed


# --------------------------------------------------------------------------- nl
def test_nl_passthrough_stripped():
    """A plain request is passed through with surrounding whitespace stripped."""
    assert normalize("nl", "  Build a phishing-triage harness.  ") == (
        "Build a phishing-triage harness."
    )


def test_nl_collapses_internal_whitespace():
    """Internal newlines / runs of whitespace collapse to single spaces (stable text)."""
    out = normalize("nl", "Triage the alert\n   then   summarize\tfindings")
    assert out == "Triage the alert then summarize findings"


# ------------------------------------------------------------------------ notes
def test_notes_extracts_after_marker():
    """A `request:` marker line yields its inline remainder as the request."""
    notes = (
        "Attendees: A, B, C\n"
        "Context: quarterly detection review\n"
        "Request: build a harness that triages EDR alerts by MITRE technique\n"
        "Next steps: schedule follow-up\n"
    )
    res = normalize_detailed("notes", notes)
    assert res.request_text == (
        "build a harness that triages EDR alerts by MITRE technique"
    )
    assert res.meta["strategy"] == "marker"
    assert res.meta["marker"] == "request"


def test_notes_marker_with_bullet_and_alt_keyword():
    """Markers work after list bullets and with alternate keywords (`ask:`)."""
    notes = "- discussion notes...\n* Ask: add EPSS enrichment to CVE triage\n"
    assert normalize("notes", notes) == "add EPSS enrichment to CVE triage"


def test_notes_marker_without_inline_uses_next_line():
    """A bare marker line pulls the following non-empty line as the request."""
    notes = "Need:\n   create a detection-eng harness for Sigma rules\nother\n"
    res = normalize_detailed("notes", notes)
    assert res.request_text == "create a detection-eng harness for Sigma rules"
    assert res.meta["strategy"] == "marker_nextline"


def test_notes_falls_back_to_first_imperative():
    """With no marker, the first imperative-verb line is taken."""
    notes = (
        "Some rambling context about the team.\n"
        "Implement an alert-triage variant tuned for cloud audit logs.\n"
        "More context.\n"
    )
    res = normalize_detailed("notes", notes)
    assert res.request_text == (
        "Implement an alert-triage variant tuned for cloud audit logs."
    )
    assert res.meta["strategy"] == "imperative"
    assert res.meta["verb"] == "implement"


def test_notes_final_fallback_first_line():
    """No marker and no imperative -> best-effort first non-empty line (never empty)."""
    notes = "\n\n   the SOC wants faster CVE turnaround\nblah\n"
    res = normalize_detailed("notes", notes)
    assert res.request_text == "the SOC wants faster CVE turnaround"
    assert res.meta["strategy"] == "first_line"


# ------------------------------------------------------------------------ error
def test_error_traceback_becomes_fix_request():
    """A Python traceback → a deterministic fix-request template using the tail line."""
    tb = (
        "Traceback (most recent call last):\n"
        '  File "loader.py", line 200, in load_harness_config\n'
        "    system_prompt = _resolve_system_prompt(cfg['systemPrompt'], harness_dir)\n"
        "KeyError: 'systemPrompt'\n"
    )
    res = normalize_detailed("error", tb)
    assert res.request_text == (
        "Investigate and fix: KeyError: 'systemPrompt'; add a regression test."
    )
    assert res.meta["error_summary"] == "KeyError: 'systemPrompt'"


def test_error_non_traceback_uses_first_line():
    """A non-traceback error string uses its first non-empty line."""
    err = "ValidationException: allowedTools must not be '*'\n(request id abc)\n"
    assert normalize("error", err) == (
        "Investigate and fix: ValidationException: allowedTools must not be '*'; "
        "add a regression test."
    )


def test_error_summary_truncated():
    """A giant error line is truncated so it can't bloat the request."""
    err = "RuntimeError: " + "x" * 1000
    out = normalize("error", err)
    # Fits inside the template with an ellipsis; the raw 1000-char blob is gone.
    assert "…" in out
    assert len(out) < 400
    assert out.startswith("Investigate and fix: RuntimeError: ")


# ------------------------------------------------------------------- error paths
def test_unknown_source_type_raises():
    with pytest.raises(ValueError, match="unknown source_type"):
        normalize("slack", "anything")


@pytest.mark.parametrize("src", SOURCE_TYPES)
def test_blank_payload_raises(src):
    """A whitespace-only payload raises for every channel (no actionable request)."""
    with pytest.raises(ValueError, match="empty payload"):
        normalize(src, "   \n\t  ")


def test_non_string_payload_raises():
    with pytest.raises(ValueError, match="empty payload"):
        normalize("nl", None)  # type: ignore[arg-type]


# ------------------------------------------------------------------- result type
def test_normalize_detailed_returns_intake_result():
    res = normalize_detailed("nl", "do a thing")
    assert isinstance(res, IntakeResult)
    assert res.source_type == "nl"
    assert res.request_text == "do a thing"
    assert isinstance(res.meta, dict)
