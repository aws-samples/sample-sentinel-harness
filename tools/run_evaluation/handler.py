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
    is true iff the word "pass" appears and the word "fail" does NOT; ``score``
    then defaults to 1.0 (pass) or 0.0 (fail). This guarantees a usable verdict
    even when the judge ignores the JSON instruction.

    Returns ``{score, passed, reasons, suggestions}`` — never raises on a bad
    reply, so the deterministic scoring loop always gets a decision."""
    obj = _extract_json_object(text)
    if obj is not None:
        passed = bool(obj.get("pass"))
        return {
            "score": _coerce_score(obj.get("score"), default=1.0 if passed else 0.0),
            "passed": passed,
            "reasons": _coerce_list(obj.get("reasons")),
            "suggestions": _coerce_list(obj.get("suggestions")),
        }

    # Prose fallback: approve iff "pass" present and "fail" absent (case-insensitive).
    low = (text or "").lower()
    passed = "pass" in low and "fail" not in low
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


def _first_brace_span(text: str):
    """Return the substring from the first ``{`` to its matching ``}`` (brace-
    balanced, string-literal aware) or ``None``. Lets us pull a JSON object out of
    surrounding prose without a greedy regex that would over-match nested braces."""
    start = text.find("{")
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
                return text[start : i + 1]
    return None


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
            time.sleep(_JUDGE_BACKOFF_SECONDS * attempt)   # exponential backoff on retry
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
