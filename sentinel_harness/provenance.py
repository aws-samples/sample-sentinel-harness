"""
sentinel-harness · provenance ledger (append-only, offline, deterministic)
===========================================================================
ROADMAP §4b M12: the north-star self-improving loop must leave an **auditable
trail** — for every autonomous run we record *where the request came from*, *what
spec the meta-agent emitted*, *how the candidate scored over its retry rounds*,
*whether it was promoted and by whom*, and *which endpoint / evidence artifact
resulted*. That trail is this ledger.

Why append-only + hash-chained
-------------------------------
A promotion decision is a governance record: a reviewer (or an auditor after an
incident) must be able to trust that the ledger was not silently rewritten to
hide a bad promotion. So each record carries:

  - ``seq``        — its 0-based position (monotonic, gap-free), and
  - ``prev_hash``  — the ``record_hash`` of the record before it, and
  - ``record_hash``— a SHA-256 over the record's *content* (every field except
                     ``record_hash`` itself, including ``seq`` and ``prev_hash``).

This turns the file into a tamper-evident chain: editing any field of any record,
inserting/deleting a record, or reordering records all break either a
``record_hash`` or the ``prev_hash`` linkage, and :func:`verify_ledger` will
raise. Appending a new valid record is the *only* mutation that keeps the chain
consistent — hence "append-only".

Why deterministic + offline
----------------------------
No real clock, no network, no AWS, no LLM. The timestamp is supplied by the
caller (``timestamp=``) or defaults to a fixed placeholder, so a given sequence
of ``record_run`` calls always produces byte-identical ledger lines and identical
hashes. That is what lets the self-iteration loop be replayed and asserted
offline.

Storage format
--------------
JSON Lines (one compact JSON object per line), which is append-friendly (a new
record is a single ``open(..., "a")`` + one ``write``) and diff-friendly. Nothing
here is customer- or company-specific.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The genesis link for the first record — a fixed all-zero digest, so an empty
# ledger's first record always chains from the same known value (deterministic).
GENESIS_HASH = "0" * 64

# A fixed, non-real timestamp placeholder. The module NEVER reads the wall clock;
# callers that want real time must pass ``timestamp=`` explicitly. Keeping a
# placeholder (rather than ``datetime.now``) is what makes the ledger replayable
# and its hashes stable in tests. ROADMAP labels wall-clock stamping as a live
# concern; offline the placeholder stands in.
TS_PLACEHOLDER = "1970-01-01T00:00:00Z"

# The promotion decisions the loop can record. ``promoted`` = a human cleared the
# HITL gate and CreateHarnessEndpoint ran; ``rejected`` = the candidate was
# refused (below bar, regressed, or safety-vetoed); ``held`` = passed the bar but
# is still awaiting the human approval gate. An unknown decision is a caller bug.
PROMOTION_DECISIONS = ("promoted", "rejected", "held")

# The content fields a caller must supply in an entry. ``approver``,
# ``endpoint_version`` and ``evidence_path`` are optional (default ``None``):
# a rejected/held run has no approver or endpoint yet.
REQUIRED_FIELDS = (
    "intake_source",
    "normalized_request",
    "emitted_spec_summary",
    "score_trajectory",
    "promotion_decision",
)
OPTIONAL_FIELDS = ("approver", "endpoint_version", "evidence_path")

# The full, ordered set of content fields written per record (before the ledger
# adds ``seq`` / ``prev_hash`` / ``record_hash``). ``ts_placeholder`` leads so a
# human scanning the raw JSONL sees the stamp first.
_CONTENT_FIELDS = ("ts_placeholder",) + REQUIRED_FIELDS + OPTIONAL_FIELDS

# Default ledger location: evidence/ (tracked, alongside the other run artifacts).
# Callers — and every test — should pass an explicit ``ledger_path`` to avoid
# writing to the repo; this default only serves an unconfigured production caller.
DEFAULT_LEDGER_PATH = (
    Path(__file__).resolve().parent.parent / "evidence" / "provenance_ledger.jsonl"
)


class ProvenanceError(Exception):
    """Raised on an invalid entry or a ledger that fails its consistency checks
    (tampered field, broken hash chain, non-monotonic ``seq``, malformed line)."""


@dataclass
class LedgerEntry:
    """A typed convenience wrapper for one provenance record's *content*.

    Callers may pass either a plain ``dict`` or this dataclass to
    :func:`record_run`. ``score_trajectory`` is the per-round score history (each
    element is a number, or a small dict like ``{"round": 1, "score": 0.62}``) so
    the ledger captures *how* a candidate reached its final score, not just the
    final value."""

    intake_source: str
    normalized_request: str
    emitted_spec_summary: str
    score_trajectory: list[Any]
    promotion_decision: str
    approver: str | None = None
    endpoint_version: str | None = None
    evidence_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "intake_source": self.intake_source,
            "normalized_request": self.normalized_request,
            "emitted_spec_summary": self.emitted_spec_summary,
            "score_trajectory": list(self.score_trajectory),
            "promotion_decision": self.promotion_decision,
            "approver": self.approver,
            "endpoint_version": self.endpoint_version,
            "evidence_path": self.evidence_path,
        }


# --------------------------------------------------------------------------- #
# hashing                                                                     #
# --------------------------------------------------------------------------- #
def _canonical(content: dict[str, Any]) -> str:
    """Canonical JSON for hashing: keys sorted, no incidental whitespace, so the
    digest depends only on the *values*, never on dict ordering or spacing."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over a record's content — every key except ``record_hash`` itself
    (which includes ``seq`` and ``prev_hash``, binding each record to its position
    and predecessor)."""
    content = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(_canonical(content).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# entry normalization                                                         #
# --------------------------------------------------------------------------- #
def _entry_to_content(entry: LedgerEntry | dict[str, Any], timestamp: str) -> dict[str, Any]:
    """Validate an entry and project it onto the fixed content shape.

    Raises :class:`ProvenanceError` on a missing required field, an unknown
    ``promotion_decision``, or a ``score_trajectory`` that is not a list — loud,
    because a malformed governance record is worse than none."""
    if isinstance(entry, LedgerEntry):
        data = entry.to_dict()
    elif isinstance(entry, dict):
        data = dict(entry)
    else:
        raise ProvenanceError(
            f"entry must be a LedgerEntry or dict, got {type(entry).__name__}"
        )

    missing = [k for k in REQUIRED_FIELDS if k not in data or data[k] is None]
    if missing:
        raise ProvenanceError(f"entry missing required field(s): {sorted(missing)}")

    decision = data["promotion_decision"]
    if decision not in PROMOTION_DECISIONS:
        raise ProvenanceError(
            f"promotion_decision {decision!r} not in {PROMOTION_DECISIONS}"
        )

    if not isinstance(data["score_trajectory"], list):
        raise ProvenanceError("score_trajectory must be a list")

    for f in ("intake_source", "normalized_request", "emitted_spec_summary"):
        if not isinstance(data[f], str) or not data[f].strip():
            raise ProvenanceError(f"{f} must be a non-empty string")

    content: dict[str, Any] = {"ts_placeholder": timestamp}
    for f in REQUIRED_FIELDS:
        content[f] = data[f]
    for f in OPTIONAL_FIELDS:
        content[f] = data.get(f)
    # score_trajectory is copied so a caller mutating their list later can't
    # retroactively change what we hashed/wrote.
    content["score_trajectory"] = list(content["score_trajectory"])
    return content


# --------------------------------------------------------------------------- #
# write path                                                                  #
# --------------------------------------------------------------------------- #
def record_run(
    entry: LedgerEntry | dict[str, Any],
    *,
    ledger_path: str | os.PathLike[str] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Append one provenance record to the ledger and return the stored record.

    The record is chained onto the current tail: its ``seq`` is the next index,
    its ``prev_hash`` is the tail's ``record_hash`` (or :data:`GENESIS_HASH` for
    an empty ledger), and its ``record_hash`` seals the whole thing. Writing is a
    single append of one JSON line — the file is only ever grown, never rewritten.

    ``timestamp`` defaults to :data:`TS_PLACEHOLDER` (no wall-clock read, so the
    result is deterministic). ``ledger_path`` defaults to
    :data:`DEFAULT_LEDGER_PATH`; tests should always pass an explicit path.
    """
    path = Path(ledger_path) if ledger_path is not None else DEFAULT_LEDGER_PATH
    ts = timestamp if timestamp is not None else TS_PLACEHOLDER

    content = _entry_to_content(entry, ts)

    # Read the existing tail to chain onto it. We verify as we load so we never
    # extend an already-corrupt ledger (fail loudly instead of masking tamper).
    existing = load_ledger(path) if path.exists() else []
    seq = len(existing)
    prev_hash = existing[-1]["record_hash"] if existing else GENESIS_HASH

    record: dict[str, Any] = {}
    for f in _CONTENT_FIELDS:
        record[f] = content[f]
    record["seq"] = seq
    record["prev_hash"] = prev_hash
    record["record_hash"] = compute_record_hash(record)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(_canonical(record) + "\n")
    return record


# --------------------------------------------------------------------------- #
# read + verify path                                                          #
# --------------------------------------------------------------------------- #
def load_ledger(
    ledger_path: str | os.PathLike[str] | None = None,
    *,
    verify: bool = True,
) -> list[dict[str, Any]]:
    """Load every record from the ledger in file order.

    A missing file is an empty ledger (``[]``) — not an error. Each non-empty line
    must be a JSON object; a malformed line raises :class:`ProvenanceError`. When
    ``verify`` is true (default) the loaded chain is checked via
    :func:`verify_ledger` before it is returned, so callers can't act on a
    tampered ledger by accident."""
    path = Path(ledger_path) if ledger_path is not None else DEFAULT_LEDGER_PATH
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ProvenanceError(
                    f"ledger line {lineno} is not valid JSON: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ProvenanceError(f"ledger line {lineno} is not a JSON object")
            records.append(obj)

    if verify:
        _verify_records(records)
    return records


def verify_ledger(ledger_path: str | os.PathLike[str] | None = None) -> int:
    """Verify the on-disk ledger is a consistent append-only chain.

    Returns the number of records on success; raises :class:`ProvenanceError` on
    the first inconsistency (missing chain field, non-monotonic ``seq``, broken
    ``prev_hash`` linkage, or a ``record_hash`` that doesn't match the content —
    i.e. a tampered field)."""
    records = load_ledger(ledger_path, verify=False)
    _verify_records(records)
    return len(records)


def _verify_records(records: list[dict[str, Any]]) -> None:
    """Core chain check shared by :func:`load_ledger` and :func:`verify_ledger`."""
    prev_hash = GENESIS_HASH
    for i, rec in enumerate(records):
        for key in ("seq", "prev_hash", "record_hash"):
            if key not in rec:
                raise ProvenanceError(f"record at index {i} missing chain field {key!r}")

        if rec["seq"] != i:
            raise ProvenanceError(
                f"record at index {i} has seq={rec['seq']!r} "
                f"(expected {i}) — records reordered or a record was removed/inserted"
            )

        if rec["prev_hash"] != prev_hash:
            raise ProvenanceError(
                f"record seq={i} prev_hash does not match the previous record's "
                f"record_hash — the chain is broken (tamper or reorder)"
            )

        expected = compute_record_hash(rec)
        if rec["record_hash"] != expected:
            raise ProvenanceError(
                f"record seq={i} record_hash mismatch — a field was tampered "
                f"(stored {rec['record_hash']!r}, recomputed {expected!r})"
            )

        prev_hash = rec["record_hash"]
