"""
Offline tests for the M2 evaluation assets (eval/)
==================================================
The fixed evaluation datasets (``eval/datasets/*.jsonl``) and the caller-defined
pass bar (``eval/criteria.yaml``) are the offline baseline the self-improving
loop scores against (ROADMAP M2 / §3 key #2 / §5.3). These tests pin the *shape*
of those assets so a malformed dataset line or a nonsensical pass bar fails in CI
instead of at loop time.

HARD RULE: ZERO network / ZERO AWS. These assets are plain files; we only read
and parse them (json.loads per line, yaml.safe_load for the criteria). No boto3,
no ``sentinel_harness.core`` import, nothing that reaches a service.

Run:
    SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
        /tmp/sentinel_test_venv/bin/python -m pytest tests/test_eval_assets.py -q
"""
from __future__ import annotations

import json
import os

import pytest

_EVAL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval"
)
_DATASETS_DIR = os.path.join(_EVAL_DIR, "datasets")
_CRITERIA_PATH = os.path.join(_EVAL_DIR, "criteria.yaml")

# The datasets the self-improving loop ships with. Keep in sync with eval/README.md.
_DATASET_FILES = ["cve_triage.jsonl", "detection_gen.jsonl"]


def _load_jsonl(path: str) -> list[dict]:
    """Parse a JSON Lines file: json.loads each NON-EMPTY line. A malformed line
    surfaces as a JSONDecodeError (never silently skipped) so a broken dataset
    fails loudly."""
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


# --------------------------------------------------------------------------- #
# datasets: each line has non-empty input / expected / assertions             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_file_exists(fname):
    path = os.path.join(_DATASETS_DIR, fname)
    assert os.path.isfile(path), f"expected dataset file {fname} under eval/datasets/"


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_has_between_5_and_8_lines(fname):
    rows = _load_jsonl(os.path.join(_DATASETS_DIR, fname))
    assert 5 <= len(rows) <= 8, (
        f"{fname} should carry 5-8 dataset lines, got {len(rows)}"
    )


@pytest.mark.parametrize("fname", _DATASET_FILES)
def test_dataset_lines_have_required_nonempty_fields(fname):
    rows = _load_jsonl(os.path.join(_DATASETS_DIR, fname))
    for i, row in enumerate(rows):
        assert isinstance(row, dict), f"{fname} line {i} is not a JSON object"

        # input: non-empty string
        assert "input" in row, f"{fname} line {i} missing 'input'"
        assert isinstance(row["input"], str) and row["input"].strip(), (
            f"{fname} line {i} 'input' must be a non-empty string"
        )

        # expected: non-empty string (the holistic judge target)
        assert "expected" in row, f"{fname} line {i} missing 'expected'"
        assert isinstance(row["expected"], str) and row["expected"].strip(), (
            f"{fname} line {i} 'expected' must be a non-empty string"
        )

        # assertions: non-empty list of non-empty strings (the must-haves)
        assert "assertions" in row, f"{fname} line {i} missing 'assertions'"
        assertions = row["assertions"]
        assert isinstance(assertions, list) and assertions, (
            f"{fname} line {i} 'assertions' must be a non-empty list"
        )
        for j, a in enumerate(assertions):
            assert isinstance(a, str) and a.strip(), (
                f"{fname} line {i} assertion {j} must be a non-empty string"
            )


# --------------------------------------------------------------------------- #
# criteria.yaml: the caller-defined pass bar has a sane shape                  #
# --------------------------------------------------------------------------- #
def _load_criteria() -> dict:
    """Load eval/criteria.yaml, guarding the PyYAML import so the test skips
    cleanly (rather than erroring) in an environment without PyYAML."""
    try:
        import yaml  # type: ignore
    except ImportError:
        pytest.skip("PyYAML not installed; skipping criteria.yaml shape checks")
    assert os.path.isfile(_CRITERIA_PATH), "eval/criteria.yaml is missing"
    with open(_CRITERIA_PATH, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict), "criteria.yaml must parse to a mapping"
    return data


def test_criteria_pass_threshold_is_float_in_unit_interval():
    data = _load_criteria()
    assert "pass_threshold" in data, "criteria.yaml missing 'pass_threshold'"
    pt = data["pass_threshold"]
    # bool is a subclass of int/float — reject it explicitly; a threshold is numeric.
    assert isinstance(pt, float) and not isinstance(pt, bool), (
        "pass_threshold must be a float"
    )
    assert 0.0 <= pt <= 1.0, f"pass_threshold must be within 0..1, got {pt}"


def test_criteria_max_retries_is_int_ge_1():
    data = _load_criteria()
    assert "max_retries" in data, "criteria.yaml missing 'max_retries'"
    mr = data["max_retries"]
    assert isinstance(mr, int) and not isinstance(mr, bool), (
        "max_retries must be an int"
    )
    assert mr >= 1, f"max_retries must be >= 1 (loop must run at least once), got {mr}"


def test_criteria_dimensions_present_and_nonempty():
    data = _load_criteria()
    dims = data.get("dimensions")
    assert isinstance(dims, list) and dims, "dimensions must be a non-empty list"
    for d in dims:
        assert isinstance(d, str) and d.strip(), "each dimension must be a non-empty string"


def test_criteria_require_human_promotion_is_true():
    """Promotion is HITL-gated: passing the bar is necessary, not sufficient."""
    data = _load_criteria()
    assert data.get("require_human_promotion") is True, (
        "require_human_promotion must be true — never auto-promote to production"
    )
