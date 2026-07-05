"""
Offline INTEGRATION tests for the M2 self-improvement loop
==========================================================
The M2 unit tests (``test_run_evaluation.py``, ``test_harness_ops.py``,
``test_core_endpoint.py``) each pin ONE component in isolation. These tests
instead exercise the M2 components *together across their real contracts* —
the real handler + the real ``parse_verdict`` extractor run end to end, and we
mock ONLY at the AWS boundary (``core.invoke`` / ``core._control.create_harness_endpoint``
/ ``core.new_session``). This proves the wiring the loop actually depends on:

  A) score_answer  ->  prompt-build  ->  core.invoke(judge)  ->  parse_verdict
     as one unit: a realistic FENCED-JSON judge verdict round-trips to a parsed
     ``{score, passed, reasons, suggestions}`` AND the judge PROMPT embeds the
     agent answer + every criterion (we inspect the prompt the stub received).
  B) harness_ops ``create_endpoint`` (the promote path) integrated with a stubbed
     ``core._control.create_harness_endpoint`` — the {harnessId, endpointName, ...}
     envelope is forwarded and the structured result comes back.
  C) a scoring ROUND-TRIP against the real ``eval/criteria.yaml`` pass bar: a WEAK
     answer scored low fails the gate and a STRONG answer scored high passes it —
     the pass/fail decision FLIPS across ``pass_threshold``. This proves the
     scoring gate + the caller-defined criteria integrate.

HARD RULE: ZERO network / ZERO AWS. Dummy env is set before importing anything
that builds a boto3 client; ``core.invoke`` / ``core.new_session`` / ``core._control``
are monkeypatched to recording stubs, so no boto client is ever called. The
judge-invoke retry backoff is zeroed (autouse) so no test sleeps on wall-clock.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_m2_integration.py -q
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. The
# all-zeros account id is an explicit placeholder (never a real 12-digit id). ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOLS_DIR = os.path.join(_REPO_ROOT, "tools")


def _load(tool_name: str):
    """Load tools/<tool_name>/handler.py by path (tools/ is a scripts tree, loaded
    the same way the existing tool tests and the live scenario load it)."""
    path = os.path.join(_TOOLS_DIR, tool_name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{tool_name}_handler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("run_evaluation")
ops = _load("harness_ops")


def _load_criteria() -> dict:
    """Load the real eval/criteria.yaml (the loop's pass bar). PyYAML is a hard
    dep of the project, but guard the import so a missing wheel skips rather than
    errors the whole integration module."""
    yaml = pytest.importorskip("yaml")
    path = os.path.join(_REPO_ROOT, "eval", "criteria.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# The four SecOps criteria the live self-improve scenario scores against — used so
# the integration prompt-embedding assertion mirrors the real caller contract.
_CRITERIA = [
    "Names the vulnerability class (JNDI/LDAP remote code execution in Log4j2).",
    "States severity is critical (CVSS ~10) and that it is exploited in the wild / in CISA KEV.",
    "Gives at least one concrete recommended action (patch/upgrade Log4j, mitigate JNDI lookups).",
    "Is specific and actionable, not a yes/no or a single vague sentence.",
]


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the judge-invoke retry backoff so any test that hits the retry path
    never sleeps on real wall-clock (mirrors test_run_evaluation._no_backoff)."""
    monkeypatch.setattr(ev, "_JUDGE_BACKOFF_SECONDS", 0)


@pytest.fixture
def judge_stub(monkeypatch):
    """Stub the AWS boundary for score_answer: core.invoke records each call and
    returns a canned judge reply; core.new_session is deterministic.

    Returns a state dict — ``calls`` captures each (args, kwargs) so a test can
    inspect the exact prompt/session forwarded to the judge, and ``reply`` is
    mutable so a test can set the judge text (fenced JSON, prose, ...) before
    invoking. Everything above the AWS boundary — prompt build, retry loop,
    parse_verdict — is the REAL handler code."""
    state: dict = {"calls": [], "reply": ""}

    def fake_invoke(*args, **kw):
        state["calls"].append({"args": args, "kwargs": kw})
        return {"text": state["reply"], "stop_reason": "end_turn",
                "tools_used": [], "tool_use": None, "events": [], "metadata": {}}

    monkeypatch.setattr(core, "invoke", fake_invoke)
    monkeypatch.setattr(core, "new_session", lambda *a, **k: "judge-" + "0" * 33)
    return state


# =========================================================================== #
# A) score_answer -> prompt-build -> core.invoke -> parse_verdict, as a unit    #
# =========================================================================== #
def test_score_answer_chain_parses_fenced_verdict_and_embeds_full_prompt(judge_stub):
    """The whole score_answer chain, integrated: a realistic FENCED-JSON judge
    verdict (the shape a real Sonnet judge emits — prose + ```json fence) must
    round-trip to the correctly parsed structured verdict, AND the prompt the
    handler built and handed to core.invoke must embed the agent answer plus
    EVERY criterion. This is the score_answer -> prompt -> invoke -> parse chain."""
    agent_answer = (
        "Log4Shell (CVE-2021-44228) is a JNDI/LDAP remote code execution flaw in "
        "Log4j2, CVSS 10.0, actively exploited and in CISA KEV. Upgrade Log4j to "
        "2.17.1+ and disable JNDI lookups as an interim mitigation."
    )
    judge_stub["reply"] = (
        "Here is my assessment of the answer against the criteria.\n\n"
        "```json\n"
        "{\n"
        '  "score": 0.92,\n'
        '  "pass": true,\n'
        '  "reasons": ["names JNDI/LDAP RCE", "cites CVSS 10 + KEV", "gives concrete patch"],\n'
        '  "suggestions": ["mention affected version range explicitly"]\n'
        "}\n"
        "```\n"
        "Overall a strong, actionable triage."
    )

    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": agent_answer,
                    "criteria": _CRITERIA}},
        None)

    # --- the parsed verdict came back through the real parse_verdict extractor ---
    assert r["ok"] is True and r["action"] == "score_answer"
    assert r["score"] == 0.92
    assert r["passed"] is True
    assert r["reasons"] == [
        "names JNDI/LDAP RCE", "cites CVSS 10 + KEV", "gives concrete patch"]
    assert r["suggestions"] == ["mention affected version range explicitly"]
    assert r["judge_error"] is None
    assert "0.92" in r["raw"]  # the raw fenced reply is surfaced, not swallowed

    # --- exactly one model call, to the judge arn, with the minted judge session ---
    assert len(judge_stub["calls"]) == 1
    call = judge_stub["calls"][0]
    assert call["args"][0] == "arn:judge"
    assert call["args"][1] == "judge-" + "0" * 33

    # --- the prompt embeds the agent answer AND every single criterion ---
    prompt = call["args"][2]
    assert agent_answer in prompt
    for idx, criterion in enumerate(_CRITERIA, 1):
        assert criterion in prompt          # each criterion text is present
        assert f"{idx}. {criterion}" in prompt  # rendered as its numbered line
    # the judge instruction + section headers are actually spliced in (real builder)
    assert "impartial evaluation judge" in prompt
    assert "CRITERIA:" in prompt
    assert "AGENT ANSWER:" in prompt


def test_score_answer_chain_recovers_from_prose_only_reply(judge_stub):
    """Integration of the parse_verdict prose fallback into the score_answer chain:
    a judge that ignores the JSON instruction and replies in prose still yields a
    usable decision (the scoring gate must never hang on a non-JSON reply)."""
    judge_stub["reply"] = "This triage is thorough and correct. I pass it."
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "ans",
                    "criteria": _CRITERIA}},
        None)
    assert r["ok"] is True
    assert r["passed"] is True
    assert r["score"] == 1.0  # prose "pass" (and no "fail") -> 1.0 by the fallback


# =========================================================================== #
# B) harness_ops create_endpoint integrated with core._control (promote path)   #
# =========================================================================== #
class _FakeControl:
    """Stubs the AWS control-plane boundary for the promote path: records each
    create_harness_endpoint envelope and returns a realistic CREATING response.

    Any other attribute access raises so an accidental real code path is loud —
    the promote integration must touch ONLY create_harness_endpoint."""

    def __init__(self):
        self.create_calls: list[dict] = []

    def create_harness_endpoint(self, **kwargs):
        self.create_calls.append(kwargs)
        return {
            "endpointName": kwargs["endpointName"],
            "status": "CREATING",
            "targetVersion": kwargs.get("targetVersion"),
        }

    def __getattr__(self, item):  # pragma: no cover - defensive
        raise AssertionError(f"promote integration must not touch _control.{item}")


@pytest.fixture
def fake_control(monkeypatch):
    ctrl = _FakeControl()
    monkeypatch.setattr(core, "_control", ctrl)
    return ctrl


def test_create_endpoint_promote_path_forwards_envelope_and_returns_result(fake_control):
    """The harness_ops create_endpoint action (the promote path M2 exposes) wired
    to the control-plane boundary: the {harnessId, endpointName, targetVersion,
    description} envelope must be forwarded verbatim to create_harness_endpoint and
    the structured result must come back through the handler's success envelope."""
    r = ops.handler(
        {"action": "create_endpoint",
         "params": {"harness_id": "hid-promoted", "endpoint_name": "prod",
                    "target_version": "3",
                    "description": "promoted after passing eval"}},
        None)

    assert r["ok"] is True and r["action"] == "create_endpoint"
    assert r["endpointName"] == "prod"
    assert r["harnessId"] == "hid-promoted"
    assert r["status"] == "CREATING"
    assert r["targetVersion"] == "3"

    # the envelope reached the control plane exactly as the API expects it
    assert len(fake_control.create_calls) == 1
    kw = fake_control.create_calls[0]
    assert kw["harnessId"] == "hid-promoted"
    assert kw["endpointName"] == "prod"
    assert kw["targetVersion"] == "3"
    assert kw["description"] == "promoted after passing eval"


def test_create_endpoint_promote_path_omits_unset_optionals(fake_control):
    """A bare promote (no version pin / description) must send ONLY the two required
    fields — no None optionals leak into the boto call (would be a ParamValidationError
    against the real control plane)."""
    r = ops.handler(
        {"action": "create_endpoint",
         "params": {"harness_id": "hid-promoted", "endpoint_name": "prod"}},
        None)
    assert r["ok"] is True
    kw = fake_control.create_calls[0]
    assert set(kw) == {"harnessId", "endpointName"}


# =========================================================================== #
# C) scoring round-trip: pass/fail decision FLIPS across the criteria bar       #
# =========================================================================== #
def _gate(verdict: dict, threshold: float) -> bool:
    """The scoring gate the self-improve loop applies: an answer passes when the
    judge marked it passed OR its score reaches the criteria pass_threshold (mirrors
    scenario_self_improve_loop.run: ``bool(passed) or score >= threshold``)."""
    return bool(verdict.get("passed")) or (verdict.get("score") or 0) >= threshold


def test_scoring_gate_flips_across_criteria_threshold(judge_stub):
    """End-to-end scoring gate integrated with the REAL eval/criteria.yaml bar: a
    WEAK answer ("noted") scored low by the judge must FAIL the gate, and a STRONG
    answer scored high must PASS it — the decision flips across pass_threshold. This
    proves the scoring gate + the caller-defined criteria integrate as the loop uses
    them."""
    criteria = _load_criteria()
    threshold = criteria["pass_threshold"]
    assert 0.0 < threshold <= 1.0  # sanity: a real fractional bar (0.7 in the file)

    # --- WEAK answer: the deliberately underspecified agent replies "noted"; the
    #     judge scores it well below the bar and marks it not-passed. ---
    judge_stub["reply"] = (
        '{"score": 0.15, "pass": false, '
        '"reasons": ["single vague word, names nothing, no action"], '
        '"suggestions": ["identify the CVE class", "state severity", "give a fix"]}'
    )
    weak = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "noted",
                    "criteria": _CRITERIA}},
        None)
    assert weak["ok"] is True
    assert weak["score"] < threshold
    assert _gate(weak, threshold) is False   # below bar -> loop does NOT promote
    assert weak["suggestions"]               # concrete suggestions feed the retry

    # --- STRONG answer: a complete, actionable triage; the judge scores it above
    #     the bar and marks it passed. Same code path, opposite decision. ---
    judge_stub["reply"] = (
        '{"score": 0.9, "pass": true, '
        '"reasons": ["names JNDI/LDAP RCE", "CVSS 10 + KEV", "concrete patch"], '
        '"suggestions": []}'
    )
    strong = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge",
                    "agent_answer": (
                        "Log4Shell (CVE-2021-44228): JNDI/LDAP RCE in Log4j2, CVSS 10.0, "
                        "in CISA KEV and exploited in the wild. Upgrade to Log4j 2.17.1+ "
                        "and disable JNDI lookups."),
                    "criteria": _CRITERIA}},
        None)
    assert strong["ok"] is True
    assert strong["score"] >= threshold
    assert _gate(strong, threshold) is True   # at/above bar -> eligible to promote

    # the gate decision genuinely FLIPPED across the same criteria bar
    assert _gate(weak, threshold) != _gate(strong, threshold)


def test_scoring_gate_score_only_pass_still_promotes(judge_stub):
    """The gate is score-OR-passed: a judge that returns a high score but forgets
    (or omits) the ``pass`` flag still clears the bar via score >= threshold — the
    loop must not withhold promotion on a technicality. Integrates the coerce +
    gate logic against the real threshold."""
    criteria = _load_criteria()
    threshold = criteria["pass_threshold"]
    # no "pass" key -> parse_verdict coerces passed=False, but score is above bar.
    judge_stub["reply"] = '{"score": 0.85, "reasons": ["strong"], "suggestions": []}'
    r = ev.handler(
        {"action": "score_answer",
         "params": {"judge_arn": "arn:judge", "agent_answer": "a solid answer",
                    "criteria": _CRITERIA}},
        None)
    assert r["ok"] is True
    assert r["passed"] is False           # judge omitted the flag
    assert r["score"] >= threshold
    assert _gate(r, threshold) is True    # score alone clears the bar
