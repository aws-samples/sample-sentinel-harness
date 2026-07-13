"""
Offline tests for the detection-gen scenario (roadmap item #6)
==============================================================
These validate the two fixes without any AWS calls:

  * the adversarial-reviewer verdict parser is robust (case-insensitive, uses the
    LAST 'verdict:' line, approve wins only if 'revise' is absent);
  * the reviewer submits a STRUCTURED verdict via the submit_review_verdict tool
    (deterministic), reconstructed from the event stream by core._consume_stream;
  * the reviewer harness is built with a bigger budget (maxIterations>=8 + maxTokens);
  * the publisher harness is scoped with allowedTools to ONLY the inline gate so a
    stray built-in 'shell' tool can't fire.

HARD RULE: ZERO AWS calls. We set dummy env before import (client construction is
offline) and monkeypatch the control-plane client so create_harness never leaves
the process — we only inspect the request kwargs it *would* have sent.
"""
from __future__ import annotations

import os
import sys

import pytest

# Repo root on path so `scenarios` (a scripts dir, not an installed package) imports.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Make the import hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402
from scenarios import scenario_detection_gen as dg  # noqa: E402


# --------------------------------------------------------------------------- #
# Verdict parser robustness                                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text, expected", [
    ("...analysis...\nVERDICT: approve", True),
    ("...analysis...\nVERDICT: revise", False),
    ("lots of text\nverdict: approve", True),            # lowercase
    ("junk\nVERDICT: APPROVE", True),                    # uppercase value
    ("VERDICT: revise\nVERDICT: approve", True),         # LAST line wins (approve)
    ("VERDICT: approve\nVERDICT: revise", False),        # LAST line wins (revise)
    ("Verdict: Approve — reason here", True),            # trailing reason on the line
    ("Verdict: revise, needs a filter", False),
    # No explicit verdict line -> whole-text fallback (approve and not revise).
    ("I think this rule is fine, approve it.", True),
    ("This should be revised before approve.", False),   # both present -> not approved
])
def test_parse_verdict(text, expected):
    assert dg.parse_verdict(text) is expected


def test_parse_verdict_uses_last_verdict_line_not_body():
    """A body full of the word 'revise' must not flip an approving final line."""
    text = ("Consider whether to revise. You might revise the selection. revise revise.\n"
            "VERDICT: approve")
    assert dg.parse_verdict(text) is True


def test_parse_verdict_ignores_leading_whitespace_lines():
    text = "   VERDICT: revise   "
    assert dg.parse_verdict(text) is False


# --------------------------------------------------------------------------- #
# Reviewer system prompt mandates the structured verdict tool                 #
# --------------------------------------------------------------------------- #
def test_rev_sys_mandates_verdict_tool():
    s = dg.REV_SYS.lower()
    # The reviewer must be told to record its decision via the tool, not prose.
    assert "submit_review_verdict" in s
    assert "approve" in s and "revise" in s


# --------------------------------------------------------------------------- #
# Budget knobs                                                                #
# --------------------------------------------------------------------------- #
def test_review_budget_defaults():
    assert dg.REVIEW_MAX_ITERATIONS >= 8
    assert dg.REVIEW_MAX_TOKENS >= 2000


# --------------------------------------------------------------------------- #
# build() emits the right harness configs (no AWS)                            #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def captured_harnesses(monkeypatch):
    """Capture every create_harness kwargs, keyed by harnessName, and stub wait_ready."""
    seen: dict = {}

    class _FakeControl:
        def create_harness(self, **kwargs):
            seen[kwargs["harnessName"]] = kwargs
            return {"harness": {"harnessId": f"hid-{kwargs['harnessName']}",
                                "arn": f"arn:aws:test:harness/{kwargs['harnessName']}", **kwargs}}

    monkeypatch.setattr(sh, "_control", _FakeControl())
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    monkeypatch.setattr(sh, "wait_ready", lambda *a, **k: None)
    monkeypatch.setattr(dg.sh, "_control", sh._control)  # dg uses the same module object
    dg.build()
    return seen


def test_reviewer_harness_has_larger_budget(captured_harnesses):
    rev = captured_harnesses["sentinel_detect_reviewer"]
    assert rev["maxIterations"] >= 8
    assert rev["maxTokens"] >= 2000


def test_publisher_scoped_to_inline_gate_only(captured_harnesses):
    """allowedTools must restrict the publisher to the inline gate only, so the
    model cannot invoke a stray built-in 'shell' tool."""
    pub = captured_harnesses["sentinel_detect_publisher"]
    assert pub["allowedTools"] == ["request_publish_approval"]
    # The only declared tool is the inline HITL gate.
    assert [t["name"] for t in pub["tools"]] == ["request_publish_approval"]
    assert pub["tools"][0]["type"] == "inline_function"
    assert "shell" not in pub["allowedTools"]


def test_publish_gate_is_inline_function():
    assert dg.PUBLISH_GATE["type"] == "inline_function"
    assert dg.PUBLISH_GATE["name"] == "request_publish_approval"


def test_all_scenario_harness_names_valid(captured_harnesses):
    import re
    name_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")
    for name in captured_harnesses:
        assert name_re.match(name), f"{name!r} violates the harness naming rule"


# --------------------------------------------------------------------------- #
# Reviewer submits a STRUCTURED verdict via a tool (deterministic)            #
# --------------------------------------------------------------------------- #
def test_verdict_tool_shape():
    t = dg.VERDICT_TOOL
    assert t["type"] == "inline_function"
    assert t["name"] == "submit_review_verdict"
    schema = t["config"]["inlineFunction"]["inputSchema"]
    assert schema["properties"]["verdict"]["enum"] == ["approve", "revise"]


def test_reviewer_scoped_to_verdict_tool(captured_harnesses):
    rev = captured_harnesses["sentinel_detect_reviewer"]
    assert rev["allowedTools"] == ["submit_review_verdict"]
    assert [t["name"] for t in rev["tools"]] == ["submit_review_verdict"]


def test_structured_verdict_reconstructed_from_stream():
    """core._consume_stream must deterministically reassemble a submit_review_verdict
    tool call (verdict + issues) from streamed toolUse.input deltas — this is what makes
    the reviewer verdict parseable regardless of the model's free-text behavior."""
    from sentinel_harness import core
    stream = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockStart": {"start": {"toolUse": {"toolUseId": "tu-9", "name": "submit_review_verdict"}}}},
        {"contentBlockDelta": {"delta": {"toolUse": {"input": '{"verdict":"revise",'}}}},
        {"contentBlockDelta": {"delta": {"toolUse": {"input": '"issues":["selection too broad"]}'}}}},
        {"contentBlockStop": {}},
        {"messageStop": {"stopReason": "tool_use"}},
    ]
    r = core._consume_stream(iter(stream))
    assert r["stop_reason"] == "tool_use"
    assert r["tool_use"]["name"] == "submit_review_verdict"
    assert r["tool_use"]["input"] == {"verdict": "revise", "issues": ["selection too broad"]}
