"""run_evaluation — deterministic evaluation-scoring MCP tool (M2 scoring gate).

SecOps / platform purpose
-------------------------
M2 is the *soul* of the self-iteration engine (ROADMAP §4 layer ③, §5.3): after
``harnesses/agent-ops`` builds a harness, the ``harnesses/self-improving`` loop
must SCORE that agent's answers against caller-defined criteria, retry-with-
reasoning below bar, and promote only at/above bar. This tool is that scoring
gate.

Why a self-built LLM-judge harness (not the managed Evaluate API)
-----------------------------------------------------------------
The managed Evaluate API scores *live traces* (OTEL sessionSpans / CloudWatch
Logs) — that telemetry pipeline is M4 infrastructure, out of scope for M2. So
M2 uses the ROADMAP-sanctioned fallback: an **offline fixed dataset + a
self-built LLM-judge harness** (a Sonnet harness whose system prompt is "score
this agent answer against these criteria and return a structured verdict"). The
judge harness is provisioned like any other harness (``harness_ops`` /
``core.create_harness``); THIS tool only *invokes* it and parses the verdict.
``CreateEvaluator`` remains available as an OPTIONAL governance record, but it
is not the scoring path here.

Why a thin deterministic router (not a smart tool)
--------------------------------------------------
Like its M1 sibling ``harness_ops``, this handler is DETERMINISTIC: it validates
structured ``params`` and performs exactly ONE model call — ``core.invoke`` to
the judge harness — then parses the reply deterministically. There is NO other
LLM reasoning and NO business logic beyond validation and parsing. Determinism
is the whole point: the self-improvement loop must be reproducible. The verdict
parser (``parse_verdict``) is a PURE function — no I/O, no AWS — so it can be
unit-tested and reused wherever a judge reply must be scored.

Input contract
--------------
event = {"action": <str>, "params": {...}}
    action ∈ {score_answer, parse_verdict}

Output contract
---------------
Success: {"ok": True, "action": <str>, ...action-specific result}
Failure: {"ok": False, "action": <str>, "error": <code>, "message": <str>}
    error ∈ {validation_error, upstream_error}

Configuration / secrets posture
-------------------------------
No account ids, ARNs, or secrets are hardcoded. The execution role, region and
model come from ``core`` (env: ``SENTINEL_EXECUTION_ROLE_ARN``,
``SENTINEL_REGION``, ``AWS_PROFILE``). The judge harness ARN is supplied by the
caller (``judge_arn``) — this tool never provisions or names a harness itself.
The single model call goes through ``core.invoke`` so the one region/credential
resolution path is shared.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from sentinel_harness import core
# The repo's authoritative truthiness coercion. Imported rather than reimplemented:
# `bool(obj.get("pass"))` made the JSON string "false" read as a PASS, which is the
# defect INV-BOUNDARY-1 pinned in asset_lookup. It recurred here because that
# invariant was a documented convention rather than an enforced mechanism, so this
# import is the mechanism.
from sentinel_harness.connectors.base import _coerce_bool

_ACTIONS = frozenset({"score_answer", "parse_verdict"})

# Judge-invoke retry policy. A fresh harness's first call, or a burst of invokes
# against one judge, can hit a transient stream error or a 403/throttle from the
# control plane; a short exponential backoff lets the rate window recover. Kept as a
# module constant so tests can zero it out (no real sleeps in unit tests).
_JUDGE_RETRIES = 3
_JUDGE_BACKOFF_SECONDS = 3.0

# A ```json ... ``` (or plain ``` ... ```) fenced code block. The judge is asked
# to return ONLY a JSON verdict, but models often wrap it in a fence and/or add
# surrounding prose — so we tolerate both. DOTALL so the body may span lines.
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

# The judge prompt: a clear instruction to score the agent answer against the
# criteria and return ONLY a JSON verdict. Kept as a builder so score_answer can
# splice in the (optional) expected answer without duplicating the schema text.
_JUDGE_INSTRUCTION = (
    "You are an impartial evaluation judge. Score the AGENT ANSWER below against "
    "the CRITERIA. Be strict and specific.\n\n"
    "Return ONLY a JSON object (no prose, no markdown fences) with EXACTLY these keys:\n"
    '  "score":       a float in [0, 1] (1 = fully meets every criterion),\n'
    '  "pass":        a boolean (true iff the answer is acceptable overall),\n'
    '  "reasons":     a list of short strings justifying the score,\n'
    '  "suggestions": a list of short, concrete improvement suggestions.\n'
)


class _ValidationError(ValueError):
    """Raised for a malformed request. Kept distinct from upstream/boto errors so
    the handler labels the two differently (fix-your-input vs retry-AWS) — we
    never collapse them by swallowing one into the other."""


# --------------------------------------------------------------------------- #
# Prose-verdict vocabulary (INV-GATE-1)                                        #
# --------------------------------------------------------------------------- #
# The prose fallback used to test `"pass" in text`, a SUBSTRING scan. That let
# ordinary English words containing the letters p-a-s-s approve a promotion:
# "passable at best", "shows compassion", "expectations were surpassed" all read
# as a pass at score 1.0. Word-boundary matching is the fix; the vocabulary is
# explicit so the judgement is auditable rather than emergent.
#
# Note "passable"/"compassion"/"surpassed" are NOT in the pass list — they are
# exactly the words the substring scan mis-fired on.
_PASS_WORDS = ("pass", "passes", "passed", "passing", "acceptable", "approved",
               "satisfactory", "meets", "met")
_FAIL_WORDS = ("fail", "fails", "failed", "failing", "unacceptable", "rejected",
               "unsatisfactory", "insufficient", "inadequate")
# A judge that declines to answer is NOT a pass. A refusal is the absence of a
# verdict, and the absence of a verdict must never promote — the fail-closed rule
# this whole invariant family exists to enforce. Phrased as substrings on purpose:
# these are multi-word markers, not single tokens.
_REFUSAL_MARKERS = ("cannot evaluate", "can't evaluate", "cannot assess",
                    "unable to evaluate", "unable to assess", "i cannot help",
                    "i can't help", "not able to evaluate", "declining to",
                    "i must decline", "cannot provide an evaluation")

# Below this score, `pass: true` is treated as a self-contradicting verdict and
# resolved to fail. Not a tunable policy bar — the loop's own bar is the caller's
# business. This only catches a judge whose two output channels disagree, where the
# conservative reading of a contradiction is "did not clear it".
_CONTRADICTION_FLOOR = 0.5


def _has_word(text: str, words: tuple) -> bool:
    """True iff any of ``words`` occurs in ``text`` as a WHOLE word.

    ``\\bpass\\b`` distinguishes "I pass it" from "passable"/"compassion"/
    "surpassed" — the three words the old substring scan approved at score 1.0."""
    return any(re.search(r"\b" + re.escape(w) + r"\b", text) for w in words)


def _carries_verdict(obj: Dict[str, Any]) -> bool:
    """True if a parsed object actually contains a verdict field.

    Guards the brace-span path in :func:`_extract_verdict_objects`. Only ``pass``
    and ``score`` qualify — ``reasons``/``suggestions`` alone are commentary, not a
    decision, and an empty ``{}`` is neither.
    """
    return "pass" in obj or "score" in obj


def _coerce_pass(raw: Any) -> bool:
    """Coerce a judge ``pass`` field to bool, refusing structured values.

    Delegates scalars to the repo's authoritative ``_coerce_bool`` (INV-BOUNDARY-1
    — the ``bool("false") is True`` trap). A dict/list value, however, is not a
    boolean at all: ``_coerce_bool`` falls back to Python truthiness for
    non-strings, so a non-empty ``{"pass": {"nested": true}}`` promoted. A
    structured value where a boolean belongs means the reply is not the verdict
    schema we asked for, and an unparseable decision is a FAIL.
    """
    if isinstance(raw, (dict, list, tuple, set)):
        return False
    return _coerce_bool(raw)


def _looks_like_attempted_json(text: str) -> bool:
    """True if the reply was clearly TRYING to be a JSON verdict.

    Used to route a failed parse to a hard fail instead of the prose scan. A judge
    aiming at JSON and getting cut off mid-object is a malformed verdict; treating
    it as English lets the JSON key ``"pass"`` act as an approval word.

    Deliberately conservative — it must not swallow a genuine prose verdict that
    merely mentions a brace. The markers are: the reply starts with ``{`` (after
    stripping), or it opens a code fence, or it contains a quoted ``"pass"`` /
    ``"score"`` key with the colon a JSON object would have.
    """
    if not isinstance(text, str):
        return False
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("{") or stripped.startswith("```"):
        return True
    return bool(re.search(r'"(?:pass|passed|score)"\s*:?', stripped))


# --------------------------------------------------------------------------- #
# param helpers (mirror harness_ops)                                          #
# --------------------------------------------------------------------------- #
def _require(params: Dict[str, Any], key: str) -> Any:
    """Return ``params[key]`` or raise a clear validation error if missing/empty.

    ``0`` / ``False`` are legitimate values, so we test presence, not truthiness."""
    if key not in params or params[key] in (None, ""):
        raise _ValidationError(f"missing required param {key!r} for this action")
    return params[key]


def _require_str(params: Dict[str, Any], key: str) -> str:
    val = _require(params, key)
    if not isinstance(val, str) or not val.strip():
        raise _ValidationError(f"param {key!r} must be a non-empty string")
    return val


def _as_text(value: Any) -> str:
    """Normalize criteria (a str or a list of criterion strings) to prompt text.

    A list becomes a numbered block so each criterion is individually visible to
    the judge; a bare string passes through. Anything else is a validation error
    — we never silently coerce an unexpected type into a confusing prompt."""
    if isinstance(value, str):
        if not value.strip():
            raise _ValidationError("'criteria' must be a non-empty string or list")
        return value
    if isinstance(value, list):
        items = [str(c).strip() for c in value if str(c).strip()]
        if not items:
            raise _ValidationError("'criteria' list must contain at least one criterion")
        return "\n".join(f"{i}. {c}" for i, c in enumerate(items, 1))
    raise _ValidationError("'criteria' must be a string or a list of strings")


# --------------------------------------------------------------------------- #
# verdict parsing — a PURE function (no I/O, no AWS)                           #
# --------------------------------------------------------------------------- #
def _coerce_score(raw: Any, *, default: float) -> float:
    """Coerce a judge ``score`` to a float clamped to [0, 1].

    Tolerant of ints / numeric strings; an unparseable value falls back to
    ``default`` rather than raising, because a judge that emits a valid pass/fail
    but a malformed number should still yield a usable verdict."""
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return default
    if val < 0.0:
        return 0.0
    if val > 1.0:
        return 1.0
    return val


def _coerce_list(raw: Any) -> List[str]:
    """Coerce a ``reasons``/``suggestions`` field to a list of strings.

    A list is stringified element-wise; a bare string becomes a one-item list;
    anything else (incl. missing) becomes an empty list. Never raises — a missing
    justification is not a reason to fail the whole parse."""
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str) and raw.strip():
        return [raw]
    return []


def parse_verdict(text: str) -> Dict[str, Any]:
    """Extract a structured verdict from a judge reply. PURE — no I/O, no AWS.

    Tolerant of (a) a bare JSON object, (b) a ```json fenced block, and (c) JSON
    embedded in surrounding prose. The extracted object is coerced: ``score`` to a
    float clamped to [0, 1], ``pass`` to a bool, ``reasons``/``suggestions`` to
    lists of strings.

    If NO JSON object can be parsed we fall back to a prose scan (the same robust
    approach ``scenario_detection_gen.py`` uses for verdict recovery): ``passed``
    is true iff a pass WORD appears and no fail word does; ``score`` then defaults
    to 1.0 (pass) or 0.0 (fail). This guarantees a usable verdict even when the
    judge ignores the JSON instruction.

    Four audited fail-open defects, all of which promoted on a verdict the judge
    did not give (INV-GATE-1..6):

    - **The prose scan was a SUBSTRING scan** (``"pass" in low``), so "passable at
      best", "shows compassion" and "expectations were surpassed" each approved at
      score 1.0. Now word-boundary matched against an explicit vocabulary.
    - **A judge REFUSAL read as a pass** when its wording happened to contain the
      letters p-a-s-s: "I cannot evaluate this; please pass it to a human" scored
      1.0. A refusal is the ABSENCE of a verdict and can never promote.
    - **``bool(obj.get("pass"))``** made the JSON strings ``"false"``/``"no"``/
      ``"0"`` read as a pass, because ``bool("false") is True``. Delegates to the
      repo's authoritative ``_coerce_bool`` — the same defect INV-BOUNDARY-1
      pinned in asset_lookup, recurring here because that invariant was a
      convention rather than a mechanism.
    - **First-JSON-wins let the EVALUATED AGENT score itself.** A real judge reply
      routinely quotes the answer under review; if that answer embedded
      ``{"pass": true, "score": 1.0}``, the parser returned the agent's own
      fabricated verdict and discarded the judge's. That directly breaks
      ``agent_loop``'s stated invariant — "the agent cannot claim a score" — and is
      a self-promoting loop. We now take the LAST parseable object (a judge states
      its verdict after quoting the material) and, more importantly, refuse when
      two candidate objects DISAGREE, because at that point which one is the
      judge's is unknowable and guessing favours the attacker.

    Returns ``{score, passed, reasons, suggestions}`` — never raises on a bad
    reply, so the deterministic scoring loop always gets a decision. When the
    verdict cannot be established the decision is FAIL, never pass."""
    objs = _extract_verdict_objects(text)
    if objs:
        chosen = objs[-1]
        # Two candidate verdicts that disagree on the pass/fail decision: we cannot
        # tell the judge's from one quoted out of the evaluated answer. Fail closed.
        decisions = {_coerce_pass(o.get("pass")) for o in objs if "pass" in o}
        if len(decisions) > 1:
            return {
                "score": 0.0,
                "passed": False,
                "reasons": [
                    "ambiguous judge reply: it contains multiple verdict objects "
                    "that disagree on pass/fail, so the judge's own verdict cannot "
                    "be identified — failing closed rather than guessing."
                ],
                "suggestions": [],
            }
        passed = _coerce_pass(chosen.get("pass"))
        score = _coerce_score(chosen.get("score"), default=1.0 if passed else 0.0)
        reasons = _coerce_list(chosen.get("reasons"))
        # INV-GATE-5: a verdict whose score CONTRADICTS its pass flag is not a
        # usable decision.
        # `passed=True` with score 0.05 (or `passed=False` with 0.95) means the
        # judge's two channels disagree; the conservative reading of a contradiction
        # is that the bar was not cleared.
        if passed and score < _CONTRADICTION_FLOOR:
            passed = False
            reasons = reasons + [
                f"verdict contradicted itself: pass=true with score {score} below "
                f"{_CONTRADICTION_FLOOR}; resolved to fail (a contradiction is not "
                f"a pass)."
            ]
        return {
            "score": score,
            "passed": passed,
            "reasons": reasons,
            "suggestions": _coerce_list(chosen.get("suggestions")),
        }

    # Prose fallback. Word-boundary matched, and a refusal is never a pass.
    low = (text or "").lower()
    if any(marker in low for marker in _REFUSAL_MARKERS):
        return {
            "score": 0.0,
            "passed": False,
            "reasons": ["judge declined to evaluate — no verdict was given, so the "
                        "answer does not clear the bar"],
            "suggestions": [],
        }
    # INV-GATE-6: a reply that was ATTEMPTING JSON and failed is a malformed
    # verdict, not natural-language prose, and must not be word-scanned. A judge
    # reply truncated mid-object (a stream cut, a token limit) leaves the JSON KEY
    # `"pass"` in the text — which a word-boundary scan reads as a pass, scoring
    # 1.0. `{"passed": fals`, `{"score": 0.9, "pass"` and a truncated fenced block
    # all promoted this way. The prose path exists for a judge that answered in
    # sentences; applying it to broken JSON confuses "malformed" with "approved".
    if _looks_like_attempted_json(text):
        return {
            "score": 0.0,
            "passed": False,
            "reasons": ["judge reply appears to be malformed/truncated JSON — no "
                        "verdict could be parsed, so the answer does not clear the "
                        "bar (a parse failure is not an approval)"],
            "suggestions": [],
        }
    passed = _has_word(low, _PASS_WORDS) and not _has_word(low, _FAIL_WORDS)
    return {
        "score": 1.0 if passed else 0.0,
        "passed": passed,
        "reasons": [],
        "suggestions": [],
    }


def _extract_json_object(text: str):
    """Return the first parseable JSON object dict from ``text`` or ``None``.

    Tries, in order: a ```json fenced block, the whole trimmed string, then the
    first ``{...}`` span found by a brace scan (handles JSON embedded in prose).
    Only a dict result counts — a bare list/number is not a verdict."""
    if not isinstance(text, str) or not text.strip():
        return None

    candidates: List[str] = []
    fence = _FENCE_RE.search(text)
    if fence:
        candidates.append(fence.group(1))
    candidates.append(text.strip())
    brace = _first_brace_span(text)
    if brace is not None:
        candidates.append(brace)

    for cand in candidates:
        try:
            parsed = json.loads(cand)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _extract_verdict_objects(text: str) -> List[Dict[str, Any]]:
    """Return EVERY parseable top-level JSON object in ``text``, in order.

    ``_extract_json_object`` returns only the FIRST one, which was the
    self-promotion hole (INV-GATE-4): a judge reply that quotes the answer under
    review — which real judges do routinely — puts the AGENT's text before the
    judge's verdict, so an answer embedding ``{"pass": true, "score": 1.0}`` was
    read as the verdict and the judge's real decision was discarded.

    Returning all of them lets ``parse_verdict`` prefer the last (a judge states
    its verdict after quoting the material) *and* detect the case where two
    candidates disagree, which is the only honest response to an ambiguous reply.

    A fenced block is preferred when present: an explicit ```json fence is the
    judge following the instruction, and is stronger evidence than a brace span
    scraped out of prose. Only dicts count — a bare list or number is not a
    verdict.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    # A fence is the judge complying with the output instruction. If one parses,
    # it is authoritative and quoted material outside it is irrelevant.
    fence = _FENCE_RE.search(text)
    if fence:
        try:
            parsed = json.loads(fence.group(1))
            if isinstance(parsed, dict):
                return [parsed]
        except (ValueError, TypeError):
            pass

    # The whole reply being one JSON object is the clean case.
    try:
        parsed = json.loads(text.strip())
        if isinstance(parsed, dict):
            return [parsed]
    except (ValueError, TypeError):
        pass

    out: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(text):
        span = _brace_span_indices(text, pos)
        if span is None:
            break
        start, end = span
        try:
            parsed = json.loads(text[start:end])
            # A brace span scraped out of PROSE only counts as a verdict if it
            # actually carries a verdict field. Without this, a judge writing
            # "it uses {} incorrectly. I pass it." had its `{}` accepted as an
            # empty verdict — pass absent, so the prose verdict was overridden
            # into a fail. An object with no verdict key is punctuation, not a
            # decision.
            if isinstance(parsed, dict) and _carries_verdict(parsed):
                out.append(parsed)
        except (ValueError, TypeError):
            pass
        pos = end
    return out


def _brace_span_indices(text: str, offset: int = 0):
    """Return ``(start, end)`` of the first brace-balanced ``{...}`` at/after
    ``offset``, or ``None``. String-literal aware, so a ``{`` inside a JSON string
    value (a judge writing ``"reason": "avoid using {} here"``) does not break the
    balance. ``end`` is exclusive, so callers can resume the scan from it.
    """
    start = text.find("{", offset)
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (start, i + 1)
    return None


def _first_brace_span(text: str):
    """Substring form of :func:`_brace_span_indices`, for the single-object caller."""
    span = _brace_span_indices(text)
    return None if span is None else text[span[0]:span[1]]


# --------------------------------------------------------------------------- #
# action implementations — each validates then delegates                       #
# --------------------------------------------------------------------------- #
def _score_answer(params: Dict[str, Any]) -> Dict[str, Any]:
    """score_answer → build a judge prompt → core.invoke(judge) → parse verdict.

    Required params: ``judge_arn``, ``agent_answer``, ``criteria`` (str or list).
    Optional: ``expected`` (a reference answer the judge may compare against),
    ``session_id`` (auto-minted with a ``judge`` prefix if absent), ``actor_id``,
    and any ``core.invoke`` override (model/tools/maxIterations/...). The single
    model call is the ONLY non-deterministic step; the reply is parsed by the same
    pure extractor as the ``parse_verdict`` action."""
    judge_arn = _require_str(params, "judge_arn")
    agent_answer = _require_str(params, "agent_answer")
    criteria_text = _as_text(_require(params, "criteria"))

    rest = dict(params)  # copy: never mutate the caller's dict
    for consumed in ("judge_arn", "agent_answer", "criteria", "expected", "session_id"):
        rest.pop(consumed, None)
    session_id = params.get("session_id") or core.new_session("judge")

    prompt_parts = [_JUDGE_INSTRUCTION, f"\nCRITERIA:\n{criteria_text}"]
    expected = params.get("expected")
    if isinstance(expected, str) and expected.strip():
        prompt_parts.append(f"\nEXPECTED / REFERENCE ANSWER:\n{expected}")
    prompt_parts.append(f"\nAGENT ANSWER:\n{agent_answer}")
    prompt = "\n".join(prompt_parts)

    # The judge is a real harness invoke: a fresh harness's first call can return a
    # transient stream error / empty reply (cold start). A scoring gate must be robust
    # to that, so retry a couple of times on an empty-or-errored reply with a fresh
    # session each time. Deterministic otherwise — same reply always parses the same.
    text = ""
    last_error = None
    last_exc = None
    for attempt in range(_JUDGE_RETRIES):
        if attempt > 0 and _JUDGE_BACKOFF_SECONDS:
            time.sleep(_JUDGE_BACKOFF_SECONDS * attempt)  # nosemgrep: arbitrary-sleep -- intentional exponential backoff between judge retries; bounded by _JUDGE_RETRIES
        sid = session_id if attempt == 0 else core.new_session("judge")
        try:
            result = core.invoke(judge_arn, sid, prompt, **rest)
        except TypeError:
            # A bad invoke override (e.g. an unknown kwarg) is the CALLER's malformed
            # request, not a transient fault — do not retry; let the handler classify
            # it as a validation_error.
            raise
        except Exception as exc:  # noqa: BLE001 — a transient stream/upstream fault; retry
            last_exc = exc
            last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
            continue
        text = result.get("text") or ""
        last_error = result.get("error")
        if text.strip() and last_error is None:
            break
    else:
        # Every attempt raised a (non-TypeError) fault and none succeeded — surface it
        # as a real upstream error rather than returning a fabricated 0.0 verdict.
        if last_exc is not None and not text.strip():
            raise last_exc
    verdict = parse_verdict(text)
    return {
        "score": verdict["score"],
        "passed": verdict["passed"],
        "reasons": verdict["reasons"],
        "suggestions": verdict["suggestions"],
        "raw": text,
        "judge_error": last_error,   # surfaced (not swallowed) if all retries stayed errored
    }


def _parse_verdict(params: Dict[str, Any]) -> Dict[str, Any]:
    """parse_verdict → run the pure extractor over ``params['text']``.

    A pure, offline action: no model call, no AWS. Exposed as its own action so a
    caller that already has a judge reply (e.g. from a batch invoke) can score it
    without re-invoking the judge."""
    text = _require_str(params, "text")
    verdict = parse_verdict(text)
    return {
        "score": verdict["score"],
        "passed": verdict["passed"],
        "reasons": verdict["reasons"],
        "suggestions": verdict["suggestions"],
    }


_DISPATCH = {
    "score_answer": _score_answer,
    "parse_verdict": _parse_verdict,
}


# --------------------------------------------------------------------------- #
# entrypoint                                                                   #
# --------------------------------------------------------------------------- #
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Route a structured evaluation request to the right scoring path.

    Deterministic: the agent supplies ``{"action", "params"}``; we validate and
    delegate. The only model call is ``core.invoke`` to the judge harness (in
    ``score_answer``); ``parse_verdict`` is fully offline. Exceptions are never
    allowed to escape unlabeled — a bad request is a ``validation_error`` and any
    model/control-plane/boto failure is an ``upstream_error`` — but the underlying
    message is always surfaced, never swallowed."""
    if not isinstance(event, dict):
        return {
            "ok": False,
            "action": None,
            "error": "validation_error",
            "message": "event must be a dict of {'action', 'params'}",
        }

    action = event.get("action")
    if action not in _ACTIONS:
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": (
                f"unknown action {action!r}; expected one of {sorted(_ACTIONS)}"
            ),
        }

    params = event.get("params", {})
    if not isinstance(params, dict):
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": "'params' must be a dict",
        }

    try:
        result = _DISPATCH[action](params)
    except _ValidationError as exc:
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": str(exc),
        }
    except TypeError as exc:
        # Bad kwargs handed to core.invoke (e.g. an unexpected override name)
        # surface as a validation error — the caller's request is malformed,
        # not AWS.
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": str(exc),
        }
    except Exception as exc:  # noqa: BLE001 — model/control-plane failure; surfaced, not swallowed
        return {
            "ok": False,
            "action": action,
            "error": "upstream_error",
            "message": str(exc),
        }

    return {"ok": True, "action": action, **result}


if __name__ == "__main__":
    # Offline smoke: parse_verdict is pure and never touches AWS.
    print(
        json.dumps(
            handler(
                {
                    "action": "parse_verdict",
                    "params": {"text": '```json\n{"score": 0.9, "pass": true, '
                                       '"reasons": ["clear"], "suggestions": []}\n```'},
                },
                None,
            ),
            indent=2,
        )
    )
