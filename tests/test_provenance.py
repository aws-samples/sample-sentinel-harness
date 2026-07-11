"""
Offline tests for the M12 provenance ledger (sentinel_harness/provenance.py)
============================================================================
The provenance ledger is the auditable trail of the north-star self-improving
loop (ROADMAP §4b M12): for each autonomous run it records where the request
came from, the emitted spec, the score trajectory, the promotion decision +
approver, and the resulting endpoint / evidence artifact.

What these tests pin:
  - ``record_run`` appends and preserves order (seq is monotonic + gap-free);
  - the ledger round-trips (load reproduces exactly what was written);
  - it is deterministic (same inputs + fixed timestamp => byte-identical file +
    identical hashes across two independent builds);
  - it is tamper-evident: editing a field, reordering, inserting, deleting, or
    truncating a record makes ``verify_ledger`` raise;
  - required-field / decision validation is loud.

HARD RULE: ZERO AWS / ZERO network. The module is pure stdlib (hashlib/json);
importing + exercising it touches no boto3, no wire, no wall clock. Every test
writes to a pytest ``tmp_path`` — never the repo's evidence/ dir. The module is
loaded under a UNIQUE importlib name so it can't collide with a sibling test.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
    AWS_DEFAULT_REGION=us-east-1 \
        python -m pytest tests/test_provenance.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODULE_PATH = os.path.join(REPO_ROOT, "sentinel_harness", "provenance.py")


def _load():
    """Load provenance.py under a unique name (import-safe, offline)."""
    unique = "sentinel_provenance__test"
    spec = importlib.util.spec_from_file_location(unique, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)  # must not touch AWS/network/clock
    return mod


prov = _load()


def _entry(**over):
    """A valid entry dict; override any field via kwargs."""
    base = {
        "intake_source": "nl",
        "normalized_request": "Build a phishing-triage harness.",
        "emitted_spec_summary": "sonnet harness + code-interpreter + phishing skill",
        "score_trajectory": [0.55, 0.68, 0.82],
        "promotion_decision": "held",
    }
    base.update(over)
    return base


# ========================================================================== #
# (1) append + order preservation                                            #
# ========================================================================== #
def test_record_run_appends_and_assigns_monotonic_seq(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    r0 = prov.record_run(_entry(normalized_request="first"), ledger_path=ledger)
    r1 = prov.record_run(_entry(normalized_request="second"), ledger_path=ledger)
    r2 = prov.record_run(_entry(normalized_request="third"), ledger_path=ledger)

    assert [r0["seq"], r1["seq"], r2["seq"]] == [0, 1, 2]
    # prev_hash chains: r0 from genesis, each next from the prior record_hash.
    assert r0["prev_hash"] == prov.GENESIS_HASH
    assert r1["prev_hash"] == r0["record_hash"]
    assert r2["prev_hash"] == r1["record_hash"]

    loaded = prov.load_ledger(ledger)
    assert [x["normalized_request"] for x in loaded] == ["first", "second", "third"]
    assert len(loaded) == 3


def test_record_run_is_append_only_file_grows(tmp_path):
    """Each record is a single appended line; earlier lines are never rewritten."""
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(), ledger_path=ledger)
    first_bytes = ledger.read_bytes()
    prov.record_run(_entry(normalized_request="another"), ledger_path=ledger)
    grown = ledger.read_bytes()
    # The original content is an exact prefix of the grown file (append-only).
    assert grown.startswith(first_bytes)
    assert len(grown) > len(first_bytes)
    assert grown.count(b"\n") == 2


def test_record_run_accepts_dataclass_entry(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    entry = prov.LedgerEntry(
        intake_source="error",
        normalized_request="Investigate and fix: KeyError; add a regression test.",
        emitted_spec_summary="patch loader + add test",
        score_trajectory=[{"round": 1, "score": 0.9}],
        promotion_decision="promoted",
        approver="analyst-1",
        endpoint_version="v3",
        evidence_path="evidence/run.json",
    )
    rec = prov.record_run(entry, ledger_path=ledger)
    assert rec["promotion_decision"] == "promoted"
    assert rec["approver"] == "analyst-1"
    assert rec["endpoint_version"] == "v3"


# ========================================================================== #
# (2) round-trip + full-field fidelity                                       #
# ========================================================================== #
def test_ledger_round_trips_all_fields(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    entry = _entry(
        promotion_decision="promoted",
        approver="reviewer-x",
        endpoint_version="v7",
        evidence_path="evidence/foo.json",
        score_trajectory=[0.4, 0.6, 0.75],
    )
    written = prov.record_run(entry, ledger_path=ledger, timestamp="2026-07-11T00:00:00Z")
    (loaded,) = prov.load_ledger(ledger)

    assert loaded == written  # exact round-trip, chain fields included
    assert loaded["ts_placeholder"] == "2026-07-11T00:00:00Z"
    assert loaded["intake_source"] == "nl"
    assert loaded["score_trajectory"] == [0.4, 0.6, 0.75]
    assert loaded["approver"] == "reviewer-x"
    assert loaded["endpoint_version"] == "v7"
    assert loaded["evidence_path"] == "evidence/foo.json"


def test_optional_fields_default_to_none(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    rec = prov.record_run(_entry(), ledger_path=ledger)
    for f in prov.OPTIONAL_FIELDS:
        assert rec[f] is None


def test_default_timestamp_is_placeholder_no_clock(tmp_path):
    """No wall-clock read — a run with no explicit timestamp uses the placeholder."""
    ledger = tmp_path / "ledger.jsonl"
    rec = prov.record_run(_entry(), ledger_path=ledger)
    assert rec["ts_placeholder"] == prov.TS_PLACEHOLDER


def test_score_trajectory_copied_not_aliased(tmp_path):
    """Mutating the caller's list after recording must not change the ledger."""
    ledger = tmp_path / "ledger.jsonl"
    traj = [0.1, 0.2]
    prov.record_run(_entry(score_trajectory=traj), ledger_path=ledger)
    traj.append(0.99)  # caller mutates their own list afterwards
    (loaded,) = prov.load_ledger(ledger)
    assert loaded["score_trajectory"] == [0.1, 0.2]


# ========================================================================== #
# (3) determinism                                                            #
# ========================================================================== #
def test_deterministic_identical_across_builds(tmp_path):
    """Same entries + same fixed timestamps => byte-identical files + equal hashes."""
    entries = [
        _entry(normalized_request="a", promotion_decision="held"),
        _entry(normalized_request="b", promotion_decision="rejected"),
        _entry(normalized_request="c", promotion_decision="promoted",
               approver="p", endpoint_version="v1"),
    ]
    ts = "2026-01-02T03:04:05Z"

    p1 = tmp_path / "l1.jsonl"
    p2 = tmp_path / "l2.jsonl"
    h1 = [prov.record_run(e, ledger_path=p1, timestamp=ts)["record_hash"] for e in entries]
    h2 = [prov.record_run(e, ledger_path=p2, timestamp=ts)["record_hash"] for e in entries]

    assert h1 == h2
    assert p1.read_bytes() == p2.read_bytes()


# ========================================================================== #
# (4) verify: consistent chain, and tamper/ordering detection                #
# ========================================================================== #
def test_verify_ledger_ok_and_counts(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    for i in range(4):
        prov.record_run(_entry(normalized_request=f"r{i}"), ledger_path=ledger)
    assert prov.verify_ledger(ledger) == 4


def test_missing_ledger_is_empty_not_error(tmp_path):
    ledger = tmp_path / "nope.jsonl"
    assert prov.load_ledger(ledger) == []
    assert prov.verify_ledger(ledger) == 0


def test_tamper_field_breaks_record_hash(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(promotion_decision="rejected"), ledger_path=ledger)
    # Flip the decision to 'promoted' but leave the stored record_hash — chain breaks.
    rec = json.loads(ledger.read_text().strip())
    rec["promotion_decision"] = "promoted"
    ledger.write_text(json.dumps(rec) + "\n")
    with pytest.raises(prov.ProvenanceError, match="record_hash mismatch"):
        prov.verify_ledger(ledger)


def test_reordering_records_breaks_chain(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(normalized_request="one"), ledger_path=ledger)
    prov.record_run(_entry(normalized_request="two"), ledger_path=ledger)
    lines = ledger.read_text().splitlines()
    # Swap the two records — seq no longer matches position and prev_hash breaks.
    ledger.write_text(lines[1] + "\n" + lines[0] + "\n")
    with pytest.raises(prov.ProvenanceError):
        prov.verify_ledger(ledger)


def test_deleting_middle_record_breaks_chain(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    for i in range(3):
        prov.record_run(_entry(normalized_request=f"r{i}"), ledger_path=ledger)
    lines = ledger.read_text().splitlines()
    # Drop the middle record: the third now has seq=2 at index 1, and its
    # prev_hash points at the deleted record — either check fires.
    ledger.write_text(lines[0] + "\n" + lines[2] + "\n")
    with pytest.raises(prov.ProvenanceError):
        prov.verify_ledger(ledger)


def test_inserting_forged_record_breaks_chain(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(normalized_request="real"), ledger_path=ledger)
    real = json.loads(ledger.read_text().strip())
    # A forged second record with a plausible seq but a bogus prev_hash.
    forged = dict(real)
    forged["seq"] = 1
    forged["normalized_request"] = "forged"
    # recompute a self-consistent record_hash so ONLY the prev_hash linkage is wrong
    forged["prev_hash"] = prov.GENESIS_HASH
    forged["record_hash"] = prov.compute_record_hash(forged)
    with open(ledger, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged) + "\n")
    with pytest.raises(prov.ProvenanceError, match="chain is broken|prev_hash"):
        prov.verify_ledger(ledger)


def test_load_ledger_verifies_by_default(tmp_path):
    """load_ledger(verify=True) refuses to hand back a tampered chain."""
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(), ledger_path=ledger)
    rec = json.loads(ledger.read_text().strip())
    rec["normalized_request"] = "silently changed"
    ledger.write_text(json.dumps(rec) + "\n")
    with pytest.raises(prov.ProvenanceError):
        prov.load_ledger(ledger)  # verify defaults True
    # verify=False still returns the raw (tampered) rows without raising.
    assert prov.load_ledger(ledger, verify=False)[0]["normalized_request"] == "silently changed"


def test_record_run_refuses_to_extend_corrupt_ledger(tmp_path):
    """Appending onto an already-tampered ledger fails loudly (never masks tamper)."""
    ledger = tmp_path / "ledger.jsonl"
    prov.record_run(_entry(), ledger_path=ledger)
    rec = json.loads(ledger.read_text().strip())
    rec["emitted_spec_summary"] = "tampered"
    ledger.write_text(json.dumps(rec) + "\n")
    with pytest.raises(prov.ProvenanceError):
        prov.record_run(_entry(normalized_request="next"), ledger_path=ledger)


def test_malformed_line_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("{not json}\n")
    with pytest.raises(prov.ProvenanceError, match="not valid JSON"):
        prov.load_ledger(ledger, verify=False)


# ========================================================================== #
# (5) entry validation is loud                                               #
# ========================================================================== #
@pytest.mark.parametrize("missing", list(prov.REQUIRED_FIELDS))
def test_missing_required_field_raises(tmp_path, missing):
    ledger = tmp_path / "ledger.jsonl"
    entry = _entry()
    del entry[missing]
    with pytest.raises(prov.ProvenanceError, match="missing required field"):
        prov.record_run(entry, ledger_path=ledger)
    # nothing was written
    assert not ledger.exists() or ledger.read_text() == ""


def test_unknown_promotion_decision_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    with pytest.raises(prov.ProvenanceError, match="promotion_decision"):
        prov.record_run(_entry(promotion_decision="yolo"), ledger_path=ledger)


def test_non_list_score_trajectory_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    with pytest.raises(prov.ProvenanceError, match="score_trajectory must be a list"):
        prov.record_run(_entry(score_trajectory="0.9"), ledger_path=ledger)


def test_blank_string_field_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    with pytest.raises(prov.ProvenanceError, match="non-empty string"):
        prov.record_run(_entry(normalized_request="   "), ledger_path=ledger)


def test_non_entry_type_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    with pytest.raises(prov.ProvenanceError, match="LedgerEntry or dict"):
        prov.record_run(["not", "an", "entry"], ledger_path=ledger)  # type: ignore[arg-type]


def test_all_promotion_decisions_accepted(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    for d in prov.PROMOTION_DECISIONS:
        prov.record_run(_entry(promotion_decision=d), ledger_path=ledger)
    assert prov.verify_ledger(ledger) == len(prov.PROMOTION_DECISIONS)
