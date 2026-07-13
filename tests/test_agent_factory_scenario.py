"""
Offline tests for the agent-factory-loop scenario (M1 north star)
=================================================================
The scenario itself is live (it builds real harnesses); these tests cover its
OFFLINE-checkable logic — spec extraction from a model reply and the model alias
map — plus the new core._consume_stream ``error`` field that makes a failed invoke
diagnosable instead of silently empty (the bug that a haiku model-id typo caused).

HARD RULE: ZERO AWS. The scenario module imports boto3 clients at import time
(offline construction), so we set dummy env before importing it.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from scenarios import scenario_agent_factory_loop as afl  # noqa: E402
from sentinel_harness import core  # noqa: E402


# --------------------------------------------------------------------------- #
# _extract_spec — tolerant JSON extraction from a model reply                 #
# --------------------------------------------------------------------------- #
def test_extract_spec_from_fenced_json():
    reply = ('Sure!\n```json\n{"harnessName": "cve_fast", '
             '"system_prompt": "triage", "model": "haiku"}\n```\ndone')
    spec = afl._extract_spec(reply)
    assert spec["harnessName"] == "cve_fast"
    assert spec["model"] == "haiku"


def test_extract_spec_from_bare_json_with_prose():
    spec = afl._extract_spec('Here: {"harnessName": "x1", "system_prompt": "p"} ok')
    assert spec["harnessName"] == "x1"


@pytest.mark.parametrize("reply", [
    "no json at all here",
    '{"foo": 1}',                                  # missing required keys
    '{"harnessName": "x"}',                         # missing system_prompt
    '{"system_prompt": "p"}',                       # missing harnessName
])
def test_extract_spec_rejects_bad_replies(reply):
    with pytest.raises(ValueError):
        afl._extract_spec(reply)


def test_model_alias_map_covers_three_tiers():
    assert set(afl._MODEL_ALIAS) == {"haiku", "sonnet", "opus"}
    # The alias must resolve to the real, version-pinned ids from core (regression:
    # a bare 'claude-haiku-4-5' without the -20251001-v1:0 suffix is an INVALID model
    # id that only fails at invoke time — keep these pointing at core's verified ids).
    assert afl._MODEL_ALIAS["haiku"] == core.MODEL_HAIKU
    assert afl._MODEL_ALIAS["sonnet"] == core.MODEL_SONNET
    assert afl._MODEL_ALIAS["opus"] == core.MODEL_OPUS


def test_haiku_model_id_is_version_pinned():
    """Regression for the live bug: MODEL_HAIKU must carry the full version suffix,
    or CreateHarness succeeds but the first invoke raises a ConverseStream
    'model identifier is invalid' ValidationException."""
    assert core.MODEL_HAIKU.startswith("global.anthropic.claude-haiku-4-5-")
    assert core.MODEL_HAIKU.endswith("-v1:0")


# --------------------------------------------------------------------------- #
# core._consume_stream surfaces stream errors explicitly (observability)      #
# --------------------------------------------------------------------------- #
def test_consume_stream_surfaces_error_field():
    """A runtimeClientError in the stream must set result['error'] (not just be
    buried in text) so a failed invoke is diagnosable."""
    stream = [
        {"messageStart": {"role": "assistant"}},
        {"runtimeClientError": {"message": "ConverseStream: model identifier is invalid"}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    r = core._consume_stream(iter(stream))
    assert r["error"] is not None
    assert "runtimeClientError" in r["error"]


def test_consume_stream_clean_run_has_no_error():
    stream = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"delta": {"text": "hello"}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    r = core._consume_stream(iter(stream))
    assert r["error"] is None
    assert r["text"] == "hello"
