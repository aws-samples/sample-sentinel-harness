"""
sentinel-harness · intake adapter (diverse intake → meta-agent input)
=====================================================================
Normalizes the three intake channels the roadmap calls out (ROADMAP §3 key #4,
§4 M1 item 4) into a single natural-language request string for the meta-agent:

    - ``"nl"``     a plain natural-language request  → passed through, cleaned.
    - ``"notes"``  free-form meeting/spec notes       → the actionable ask, extracted.
    - ``"error"``  a framework error / traceback      → a "fix it + add a test" request.

Why deterministic (no LLM)
--------------------------
The meta-agent (an Opus harness) is where the *reasoning* lives; this adapter is a
cheap, reproducible front door. A given payload MUST always normalize to the same
request text so the self-iteration loop is testable offline and its inputs are
auditable. So every rule here is a documented, deterministic heuristic — never a
model call and never a network call.

The result is a small :class:`IntakeResult` carrying the normalized
``request_text`` plus the ``source_type`` and a ``meta`` dict (how the text was
derived), so a caller can log/trace the provenance of a request. ``normalize`` is
a thin convenience that returns just the ``request_text``.

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# The three intake channels the roadmap defines. An unknown source_type is a
# programming error at the call site, so we fail loudly (ValueError) rather than
# silently guessing a channel.
SOURCE_TYPES = ("nl", "notes", "error")

# Markers that, in free-form notes, introduce the actionable request. Matched
# case-insensitively at the start of a line (after optional list bullet / markdown
# heading punctuation). Ordered by how explicit the intent is.
_NOTES_MARKERS = ("request", "ask", "need", "action item", "todo", "to-do")

# Leading list/heading punctuation to strip from a notes line before matching a
# marker or reading the imperative (e.g. "- ", "* ", "1. ", "#", ">").
_BULLET_RE = re.compile(r"^\s*(?:[-*+>#]+|\d+[.)])\s*")

# A rough "imperative" opener set: if no explicit marker is present we fall back to
# the first line that reads like an instruction. Kept small + deterministic.
_IMPERATIVE_VERBS = (
    "add", "build", "create", "fix", "implement", "investigate", "make",
    "update", "write", "generate", "triage", "detect", "harden", "review",
    "enable", "support", "extend", "refactor", "remove", "improve", "wire",
)

# How much of an error string to keep in the summary — a traceback can be huge and
# the meta-agent only needs the actionable head, not the full stack.
_ERROR_SUMMARY_MAX = 300


@dataclass
class IntakeResult:
    """A normalized intake request plus the provenance of how it was derived.

    ``request_text`` is the clean natural-language request handed to the meta-agent;
    ``source_type`` is the originating channel; ``meta`` records the derivation
    (e.g. which notes marker fired, or the extracted error summary) so a request's
    origin stays auditable through the self-iteration loop."""

    request_text: str
    source_type: str
    meta: dict = field(default_factory=dict)


def normalize(source_type: str, payload: str) -> str:
    """Normalize an intake ``payload`` from ``source_type`` into a request string.

    ``source_type`` must be one of :data:`SOURCE_TYPES`; anything else raises
    ``ValueError`` (loud — an unknown channel is a caller bug, not something to
    guess around). A blank/whitespace-only payload also raises ``ValueError`` (there
    is no actionable request to build). Returns just the ``request_text``; use
    :func:`normalize_detailed` when you want the full :class:`IntakeResult` with
    provenance.
    """
    return normalize_detailed(source_type, payload).request_text


def normalize_detailed(source_type: str, payload: str) -> IntakeResult:
    """Like :func:`normalize` but returns the full :class:`IntakeResult`.

    Kept separate so the common path (``normalize`` → str) stays terse while
    callers that trace request provenance can reach the ``meta`` dict."""
    if source_type not in SOURCE_TYPES:
        raise ValueError(
            f"unknown source_type {source_type!r}; expected one of {SOURCE_TYPES}"
        )
    if not isinstance(payload, str) or not payload.strip():
        # No text = no request. Fail loudly rather than emit an empty spec target.
        raise ValueError(f"empty payload for source_type {source_type!r}")

    if source_type == "nl":
        return _from_nl(payload)
    if source_type == "notes":
        return _from_notes(payload)
    return _from_error(payload)


# --------------------------------------------------------------------- nl channel
def _from_nl(payload: str) -> IntakeResult:
    """A plain request: collapse surrounding/internal whitespace and pass through.

    We intentionally do NOT rewrite the operator's wording — the meta-agent owns
    interpretation; here we only strip and normalize whitespace so downstream
    hashing/logging is stable."""
    text = _collapse_ws(payload)
    return IntakeResult(request_text=text, source_type="nl", meta={"cleaned": True})


# ------------------------------------------------------------------ notes channel
def _from_notes(payload: str) -> IntakeResult:
    """Extract the actionable request from free-form meeting/spec notes.

    Deterministic heuristic (documented so it stays predictable):
      1. Scan lines for an explicit marker (``request:`` / ``ask:`` / ``need:`` /
         ``action item:`` / ``todo:``), case-insensitive, after stripping any list
         bullet or markdown heading punctuation. The FIRST marker hit wins; its
         inline remainder (text after the colon) is the request, or — if the marker
         line has no inline text — the next non-empty line.
      2. Else fall back to the first line that opens with an imperative verb
         (:data:`_IMPERATIVE_VERBS`) — a "summarize by first imperative" rule.
      3. Else fall back to the first non-empty line (best-effort; never silently
         return nothing).
    """
    lines = [ln for ln in payload.splitlines()]

    # 1) explicit marker.
    for i, raw in enumerate(lines):
        stripped = _BULLET_RE.sub("", raw).strip()
        if not stripped:
            continue
        marker, remainder = _split_marker(stripped)
        if marker is None:
            continue
        if remainder:
            return IntakeResult(
                request_text=_collapse_ws(remainder),
                source_type="notes",
                meta={"strategy": "marker", "marker": marker},
            )
        # Marker with no inline text -> take the next non-empty line.
        follow = _next_nonempty(lines, i + 1)
        if follow:
            return IntakeResult(
                request_text=_collapse_ws(follow),
                source_type="notes",
                meta={"strategy": "marker_nextline", "marker": marker},
            )

    # 2) first imperative line.
    for raw in lines:
        stripped = _BULLET_RE.sub("", raw).strip()
        if not stripped:
            continue
        first_word = re.split(r"[\s:,.]", stripped, maxsplit=1)[0].lower()
        if first_word in _IMPERATIVE_VERBS:
            return IntakeResult(
                request_text=_collapse_ws(stripped),
                source_type="notes",
                meta={"strategy": "imperative", "verb": first_word},
            )

    # 3) first non-empty line (guaranteed to exist: payload is non-blank).
    first = _next_nonempty(lines, 0)
    return IntakeResult(
        request_text=_collapse_ws(_BULLET_RE.sub("", first or "").strip()),
        source_type="notes",
        meta={"strategy": "first_line"},
    )


def _split_marker(line: str) -> tuple[str | None, str]:
    """If ``line`` starts with a known notes marker followed by ``:``, return
    ``(marker, remainder_after_colon)``; else ``(None, "")``. Case-insensitive."""
    head, sep, rest = line.partition(":")
    if not sep:
        return None, ""
    key = head.strip().lower()
    if key in _NOTES_MARKERS:
        return key, rest.strip()
    return None, ""


def _next_nonempty(lines: list[str], start: int) -> str | None:
    """First line at/after ``start`` that is non-empty once bullets are stripped."""
    for raw in lines[start:]:
        if _BULLET_RE.sub("", raw).strip():
            return raw
    return None


# ------------------------------------------------------------------ error channel
def _from_error(payload: str) -> IntakeResult:
    """Turn a framework error / traceback into a developer fix-request.

    Deterministic template (ROADMAP §3: "an error auto-becomes a dev request"):
    extract the most actionable single line of the error — the LAST non-empty line
    of a Python traceback is the exception type + message (``KeyError: 'foo'``);
    for a non-traceback error string we use its first non-empty line. That summary
    is dropped into a fixed template so the meta-agent gets a concrete dev task
    rather than a raw stack dump."""
    summary = _error_summary(payload)
    request = (
        f"Investigate and fix: {summary}; add a regression test."
    )
    return IntakeResult(
        request_text=request,
        source_type="error",
        meta={"strategy": "traceback_tail", "error_summary": summary},
    )


def _error_summary(payload: str) -> str:
    """The single most actionable line of an error blob.

    A Python traceback ends with ``ExceptionType: message``; that last non-empty
    line is what a developer acts on, so prefer it. If the payload isn't a
    traceback (no ``Traceback (most recent call last):`` header) fall back to the
    first non-empty line. Truncate to :data:`_ERROR_SUMMARY_MAX` chars so a giant
    message can't bloat the request."""
    nonempty = [ln.strip() for ln in payload.splitlines() if ln.strip()]
    if not nonempty:  # pragma: no cover - guarded by the blank-payload check
        return _collapse_ws(payload)[:_ERROR_SUMMARY_MAX]

    is_traceback = any(ln.startswith("Traceback (most recent call last)") for ln in nonempty)
    line = nonempty[-1] if is_traceback else nonempty[0]
    line = _collapse_ws(line)
    if len(line) > _ERROR_SUMMARY_MAX:
        line = line[: _ERROR_SUMMARY_MAX - 1].rstrip() + "…"
    return line


# ------------------------------------------------------------------------ helpers
def _collapse_ws(text: str) -> str:
    """Collapse runs of whitespace (incl. newlines) to single spaces and strip
    the ends — stable, single-line request text for logging/hashing."""
    return re.sub(r"\s+", " ", text).strip()
