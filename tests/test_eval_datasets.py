"""
Offline tests for the EXPANDED M12 eval datasets (eval/datasets/*_expanded.jsonl)
=================================================================================
M12 (ROADMAP §4b) expands the toy 6-line ``cve_triage`` / ``detection_gen``
criteria into dozens of cases carrying the extra labels the regression guard +
safety veto need to *bite*:

  - ``id``           — a stable case id.
  - ``category``     — one of clear / ambiguous_severity / ambiguous /
                       hard_negative / safety_trap.
  - ``input`` / ``expected`` / ``assertions`` — the same holistic-target + must-have
    rubric the existing toy datasets use (see tests/test_eval_assets.py).
  - ``disposition``  — the expected verdict a judge/harness should reach.
  - ``safety_flag``  — True iff a fluent-but-unsafe answer MUST be failed here.
  - ``safety_trap``  — for safety_flag cases: ``{unsafe_answer, veto_reason}`` — the
                       material that lets a judge see *what* to veto and *why*, so
                       the safety veto is testable, not aspirational.

These tests pin the *shape* + label discipline of the expanded datasets so a
malformed line, a mislabeled disposition, or a safety trap missing its veto
material fails in CI instead of silently weakening the loop's evaluation bar.

HARD RULE: ZERO network / ZERO AWS. These assets are plain files; we only read +
parse them (json.loads per line). No boto3, no ``sentinel_harness.core`` import,
nothing that reaches a service. Deterministic and fast.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
    AWS_DEFAULT_REGION=us-east-1 \
        python -m pytest tests/test_eval_datasets.py -q
"""
from __future__ import annotations

import json
import os
import re

import pytest

_EVAL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval"
)
_DATASETS_DIR = os.path.join(_EVAL_DIR, "datasets")

# The expanded datasets M12 ships. Kept separate from the toy 5-8 line datasets
# (cve_triage.jsonl / detection_gen.jsonl) that tests/test_eval_assets.py pins.
_CVE_FILE = "cve_triage_expanded.jsonl"
_DET_FILE = "detection_gen_expanded.jsonl"
_DATASET_FILES = [_CVE_FILE, _DET_FILE]

# Category vocabulary shared by both datasets.
_CATEGORIES = {"clear", "ambiguous_severity", "ambiguous", "hard_negative", "safety_trap"}

# Per-dataset disposition vocabularies. A CVE-triage verdict and a
# detection-generation verdict draw from different action spaces; both include
# ``refuse_unsafe`` for the safety traps.
_CVE_DISPOSITIONS = {
    "escalate_critical", "patch_now", "page_oncall", "monitor",
    "risk_accept", "reject_finding", "refuse_unsafe",
}
_DET_DISPOSITIONS = {"emit_rule", "refine_rule", "reject_task", "refuse_unsafe"}

_ALLOWED_DISPOSITIONS = {
    _CVE_FILE: _CVE_DISPOSITIONS,
    _DET_FILE: _DET_DISPOSITIONS,
}

# Required keys on every dataset row.
_REQUIRED_KEYS = ("id", "category", "input", "expected", "assertions",
                  "disposition", "safety_flag")

# RFC-5737 documentation ranges — the only IP literals allowed to appear.
_RFC5737 = ("192.0.2.", "198.51.100.", "203.0.113.")
# Anything that looks like a dotted quad but is NOT in an RFC-5737 range is a leak.
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _load_jsonl(path: str) -> list[dict]:
    """Parse a JSON Lines file: json.loads each NON-EMPTY line. A malformed line
    surfaces as an AssertionError (never silently skipped)."""
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"{os.path.basename(path)}:{lineno} is not valid JSON: {exc}"
                ) from exc
    return rows


def _rows(fname: str) -> list[dict]:
    return _load_jsonl(os.path.join(_DATASETS_DIR, fname))


# --------------------------------------------------------------------------- #
# existence + non-trivial counts                                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_file_exists(fname):
    path = os.path.join(_DATASETS_DIR, fname)
    assert os.path.isfile(path), f"expected expanded dataset {fname} under eval/datasets/"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_counts_are_nontrivial(fname):
    """'Dozens of cases' — each expanded dataset carries at least 20 rows."""
    rows = _rows(fname)
    assert len(rows) >= 20, (
        f"{fname} should carry dozens of cases (>=20), got {len(rows)}"
    )


def test_combined_count_is_dozens():
    total = sum(len(_rows(f)) for f in _DATASET_FILES)
    assert total >= 45, f"expanded datasets combined should be dozens of cases, got {total}"


# --------------------------------------------------------------------------- #
# every row parses + has the required non-empty fields                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_rows_have_required_fields(fname):
    rows = _rows(fname)
    for i, row in enumerate(rows):
        assert isinstance(row, dict), f"{fname} row {i} is not a JSON object"
        for key in _REQUIRED_KEYS:
            assert key in row, f"{fname} row {i} ({row.get('id')}) missing '{key}'"

        # id: non-empty string
        assert isinstance(row["id"], str) and row["id"].strip(), (
            f"{fname} row {i} 'id' must be a non-empty string"
        )
        # input / expected: non-empty strings
        for k in ("input", "expected"):
            assert isinstance(row[k], str) and row[k].strip(), (
                f"{fname} {row['id']} '{k}' must be a non-empty string"
            )
        # assertions: non-empty list of non-empty strings
        assertions = row["assertions"]
        assert isinstance(assertions, list) and assertions, (
            f"{fname} {row['id']} 'assertions' must be a non-empty list"
        )
        for j, a in enumerate(assertions):
            assert isinstance(a, str) and a.strip(), (
                f"{fname} {row['id']} assertion {j} must be a non-empty string"
            )
        # safety_flag: strict bool (not a truthy int)
        assert isinstance(row["safety_flag"], bool), (
            f"{fname} {row['id']} 'safety_flag' must be a bool"
        )


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_ids_are_unique(fname):
    rows = _rows(fname)
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), f"{fname} has duplicate case ids"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_category_and_disposition_are_from_vocab(fname):
    rows = _rows(fname)
    allowed_dispo = _ALLOWED_DISPOSITIONS[fname]
    for row in rows:
        assert row["category"] in _CATEGORIES, (
            f"{fname} {row['id']} category {row['category']!r} not in {_CATEGORIES}"
        )
        assert row["disposition"] in allowed_dispo, (
            f"{fname} {row['id']} disposition {row['disposition']!r} not in {allowed_dispo}"
        )


# --------------------------------------------------------------------------- #
# the three ingredients the regression guard + safety veto need               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_has_hard_negatives(fname):
    """Hard negatives (findings/tasks that must be REJECTED, not answered) exist —
    they're what stop a fluent agent from confabulating a rule/severity."""
    rows = _rows(fname)
    hard = [r for r in rows if r["category"] == "hard_negative"]
    assert len(hard) >= 3, f"{fname} needs several hard negatives, got {len(hard)}"
    # A hard negative must NOT resolve to a normal 'do it' disposition.
    for r in hard:
        assert r["disposition"] in {"reject_finding", "reject_task"}, (
            f"{fname} {r['id']} is a hard_negative but disposition is {r['disposition']!r}"
        )


def test_cve_dataset_has_ambiguous_severity():
    """The CVE dataset carries ambiguous-severity cases (CVSS vs KEV/EPSS vs
    reachability tension) — the material a naive severity call gets wrong."""
    rows = _rows(_CVE_FILE)
    amb = [r for r in rows if r["category"] == "ambiguous_severity"]
    assert len(amb) >= 4, f"cve dataset needs ambiguous-severity cases, got {len(amb)}"


def test_detection_dataset_has_ambiguous_cases():
    """The detection dataset carries ambiguous / too-broad cases that must be
    refined rather than emitted as-is."""
    rows = _rows(_DET_FILE)
    amb = [r for r in rows if r["category"] == "ambiguous"]
    assert len(amb) >= 3, f"detection dataset needs ambiguous cases, got {len(amb)}"


# --------------------------------------------------------------------------- #
# safety traps: labeled so a judge could veto them                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_safety_traps_present_and_labeled(fname):
    """Every safety trap is labeled so a judge/veto can bite:
      - category == 'safety_trap' <=> safety_flag is True,
      - disposition is 'refuse_unsafe',
      - a 'safety_trap' block carries a non-empty tempting `unsafe_answer` and a
        non-empty `veto_reason` (why the fluent answer must be failed)."""
    rows = _rows(fname)
    traps = [r for r in rows if r["category"] == "safety_trap"]
    assert len(traps) >= 4, f"{fname} needs several safety traps, got {len(traps)}"

    for r in rows:
        is_trap = r["category"] == "safety_trap"
        # category and safety_flag must agree — no unflagged trap, no flagged non-trap.
        assert r["safety_flag"] is is_trap, (
            f"{fname} {r['id']}: safety_flag ({r['safety_flag']}) must match "
            f"category=={r['category']!r}"
        )
        if not is_trap:
            assert "safety_trap" not in r, (
                f"{fname} {r['id']} is not a trap but carries a safety_trap block"
            )
            continue

        assert r["disposition"] == "refuse_unsafe", (
            f"{fname} {r['id']} is a safety_trap; disposition must be 'refuse_unsafe'"
        )
        block = r.get("safety_trap")
        assert isinstance(block, dict), (
            f"{fname} {r['id']} safety_trap must carry a 'safety_trap' object"
        )
        for k in ("unsafe_answer", "veto_reason"):
            assert k in block and isinstance(block[k], str) and block[k].strip(), (
                f"{fname} {r['id']} safety_trap.{k} must be a non-empty string"
            )
        # The unsafe_answer must read as a compliance (the fluent-but-unsafe answer
        # a judge has to fail), distinct from the expected refusal.
        assert block["unsafe_answer"].strip() != r["expected"].strip(), (
            f"{fname} {r['id']} unsafe_answer must differ from the expected refusal"
        )


# --------------------------------------------------------------------------- #
# public hygiene: RFC-5737 IPs only, no obvious secrets/accounts              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_any_ip_is_rfc5737(fname):
    """The only IP literals allowed are RFC-5737 documentation ranges."""
    text = open(os.path.join(_DATASETS_DIR, fname), encoding="utf-8").read()
    for ip in _IP_RE.findall(text):
        assert any(ip.startswith(p) for p in _RFC5737), (
            f"{fname} contains a non-RFC-5737 IP literal: {ip}"
        )


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_no_real_account_ids_or_secret_prefixes(fname):
    """No real 12-digit AWS account ids (only 000000000000) and no obvious secret
    prefixes leak into the public dataset."""
    text = open(os.path.join(_DATASETS_DIR, fname), encoding="utf-8").read()
    for acct in re.findall(r"\b\d{12}\b", text):
        assert acct == "000000000000", f"{fname} contains a non-placeholder 12-digit id: {acct}"
    for token in ("AKIA", "ghp_", "xoxb-"):
        assert token not in text, f"{fname} contains a secret-looking prefix: {token}"
