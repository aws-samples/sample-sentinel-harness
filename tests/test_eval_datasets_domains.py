"""
Offline schema/hygiene tests for the NEW-DOMAIN golden eval datasets
====================================================================
Track A (world-class) extends the self-improving loop's evaluation from two
domains (cve_triage / detection_gen, pinned by tests/test_eval_datasets.py) to
every domain with a runnable scenario. Each new domain ships a golden JSONL under
``eval/datasets/<domain>_golden.jsonl`` following the SAME rich M12 schema so the
regression guard + safety veto can bite in that domain too.

This is the generic, registry-driven validator: add a domain to ``_DOMAINS`` and
its dataset is auto-checked for schema, label discipline, category mix, and public
hygiene — the same bar the cve/detection expanded datasets already pass.

HARD RULE: ZERO network / ZERO AWS. Plain-file read + json.loads per line only.
"""
from __future__ import annotations

import json
import os
import re

import pytest

_EVAL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval")
_DATASETS_DIR = os.path.join(_EVAL_DIR, "datasets")

# Registry of new-domain golden datasets: filename -> allowed disposition vocab.
# Each vocab includes the domain's reject verdict (for hard_negative rows) and
# "refuse_unsafe" (for safety_trap rows). Kept in lockstep with the authored files.
_DOMAINS = {
    "alert_triage_golden.jsonl": {
        "dispositions": {
            "true_positive_escalate", "false_positive_close", "needs_more_context",
            "contain_with_approval", "refuse_unsafe",
        },
        "reject": {"false_positive_close"},
    },
    "attack_path_golden.jsonl": {
        "dispositions": {
            "high_risk_path", "low_risk_path", "needs_more_context",
            "reject_finding", "refuse_unsafe",
        },
        "reject": {"reject_finding"},
    },
    "feedback_loop_golden.jsonl": {
        "dispositions": {
            "whitelist_optimization", "rule_regeneration", "no_action",
            "reject_task", "refuse_unsafe",
        },
        "reject": {"reject_task"},
    },
}

_CATEGORIES = {"clear", "ambiguous_severity", "ambiguous", "hard_negative", "safety_trap"}
_REQUIRED_KEYS = ("id", "category", "input", "expected", "assertions", "disposition", "safety_flag")

_RFC5737 = ("192.0.2.", "198.51.100.", "203.0.113.")
# Non-routable / wildcard notations that are standard SecOps shorthand, NOT a
# leaked real host: 0.0.0.0 (unspecified / "0.0.0.0/0" = open-to-world) and
# 127.0.0.1 (loopback). scenario_egress_control.py uses "0.0.0.0/0" the same way.
_ALLOWED_NONROUTABLE = {"0.0.0.0", "127.0.0.1"}
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

_DATASET_FILES = sorted(_DOMAINS)


def _load_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{os.path.basename(path)}:{lineno} invalid JSON: {exc}") from exc
    return rows


def _rows(fname: str) -> list[dict]:
    return _load_jsonl(os.path.join(_DATASETS_DIR, fname))


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_file_exists(fname):
    assert os.path.isfile(os.path.join(_DATASETS_DIR, fname)), f"missing {fname}"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_counts_nontrivial(fname):
    assert len(_rows(fname)) >= 22, f"{fname} should carry >=22 golden cases"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_required_fields_and_types(fname):
    for i, row in enumerate(_rows(fname)):
        assert isinstance(row, dict), f"{fname} row {i} not an object"
        for key in _REQUIRED_KEYS:
            assert key in row, f"{fname} row {i} ({row.get('id')}) missing '{key}'"
        assert isinstance(row["id"], str) and row["id"].strip()
        for k in ("input", "expected"):
            assert isinstance(row[k], str) and row[k].strip(), f"{fname} {row['id']} '{k}' empty"
        assert isinstance(row["assertions"], list) and row["assertions"], f"{fname} {row['id']} assertions"
        for a in row["assertions"]:
            assert isinstance(a, str) and a.strip()
        assert isinstance(row["safety_flag"], bool), f"{fname} {row['id']} safety_flag not bool"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_ids_unique(fname):
    ids = [r["id"] for r in _rows(fname)]
    assert len(ids) == len(set(ids)), f"{fname} duplicate ids"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_category_and_disposition_vocab(fname):
    allowed = _DOMAINS[fname]["dispositions"]
    for row in _rows(fname):
        assert row["category"] in _CATEGORIES, f"{fname} {row['id']} bad category {row['category']!r}"
        assert row["disposition"] in allowed, f"{fname} {row['id']} bad disposition {row['disposition']!r}"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_hard_negatives_reject(fname):
    reject = _DOMAINS[fname]["reject"]
    hard = [r for r in _rows(fname) if r["category"] == "hard_negative"]
    assert len(hard) >= 3, f"{fname} needs >=3 hard negatives, got {len(hard)}"
    for r in hard:
        assert r["disposition"] in reject, (
            f"{fname} {r['id']} hard_negative disposition {r['disposition']!r} not a reject verdict {reject}"
        )


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_safety_traps_labeled(fname):
    traps = [r for r in _rows(fname) if r["category"] == "safety_trap"]
    assert len(traps) >= 4, f"{fname} needs >=4 safety traps, got {len(traps)}"
    for r in _rows(fname):
        is_trap = r["category"] == "safety_trap"
        assert r["safety_flag"] is is_trap, f"{fname} {r['id']} safety_flag must match category==safety_trap"
        if not is_trap:
            assert "safety_trap" not in r, f"{fname} {r['id']} non-trap carries safety_trap block"
            continue
        assert r["disposition"] == "refuse_unsafe", f"{fname} {r['id']} trap must refuse_unsafe"
        block = r.get("safety_trap")
        assert isinstance(block, dict), f"{fname} {r['id']} missing safety_trap block"
        for k in ("unsafe_answer", "veto_reason"):
            assert k in block and isinstance(block[k], str) and block[k].strip(), (
                f"{fname} {r['id']} safety_trap.{k} empty"
            )
        assert block["unsafe_answer"].strip() != r["expected"].strip(), (
            f"{fname} {r['id']} unsafe_answer must differ from expected"
        )


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_has_clear_cases(fname):
    clear = [r for r in _rows(fname) if r["category"] == "clear"]
    assert len(clear) >= 4, f"{fname} needs a spread of clear cases, got {len(clear)}"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_ip_hygiene(fname):
    text = open(os.path.join(_DATASETS_DIR, fname), encoding="utf-8").read()
    for ip in _IP_RE.findall(text):
        if ip in _ALLOWED_NONROUTABLE:
            continue  # 0.0.0.0/0 wildcard, 127.0.0.1 loopback — notation, not a leak
        assert any(ip.startswith(p) for p in _RFC5737), f"{fname} non-RFC-5737 IP: {ip}"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_no_secrets_or_accounts(fname):
    text = open(os.path.join(_DATASETS_DIR, fname), encoding="utf-8").read()
    for acct in re.findall(r"\b\d{12}\b", text):
        assert acct == "000000000000", f"{fname} non-placeholder account id: {acct}"
    for token in ("AKIA", "ghp_", "xoxb-"):
        assert token not in text, f"{fname} secret-looking prefix: {token}"
