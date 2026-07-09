"""
Offline guard tests for the delivery/onboarding doc (``docs/QUICKSTART.md``)
============================================================================
QUICKSTART.md is the "get running in 5 minutes" promise a newcomer reads first,
so its claims must stay true to the repo: the make targets it advertises have to
be the canonical ones (and, once a Makefile exists as a sibling deliverable, must
actually be defined there), the offline test count it quotes must match the real
suite size (1475), and — this being a PUBLIC repo — it must never leak a customer
name or a real 12-digit AWS account id.

These tests read files as text only. They run no make target, no deploy, no AWS
call, and no subprocess — they are hermetic and deterministic.
"""
from __future__ import annotations

import os
import re

import pytest

# Repo layout: tests/ is a sibling of docs/ and (when present) the Makefile.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUICKSTART = os.path.join(_REPO_ROOT, "docs", "QUICKSTART.md")
MAKEFILE = os.path.join(_REPO_ROOT, "Makefile")

# The canonical Makefile target names the delivery story is built around. These
# are the contract the QUICKSTART advertises and (when the Makefile lands) the
# targets it must define.
CANONICAL_TARGETS = [
    "test",
    "lint",
    "synth",
    "deploy",
    "seed-registry",
    "create-harnesses",
    "smoke",
    "demo",
    "reset",
    "destroy",
]

# The offline suite size the doc must quote accurately.
EXPECTED_TEST_COUNT = "1475"

# The one customer/company name that must never appear in this public repo. Built
# from a char class so the literal string never sits in this source file (mirrors
# the CI secret-and-name gate in .github/workflows/ci.yml).
_CUSTOMER_NAME_RE = re.compile(r"[Aa][Vv][Ee][Nn][Ii][Rr]")

# A bare 12-digit run is an AWS account id. The all-zeros placeholder 000000000000
# is the ONLY 12-digit run tolerated; anything else is a hard failure.
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def quickstart_text() -> str:
    return _read(QUICKSTART)


# --------------------------------------------------------------------------- #
# Existence
# --------------------------------------------------------------------------- #
def test_quickstart_exists() -> None:
    assert os.path.isfile(QUICKSTART), "docs/QUICKSTART.md must exist"
    assert _read(QUICKSTART).strip(), "docs/QUICKSTART.md must not be empty"


# --------------------------------------------------------------------------- #
# Make target references
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target", CANONICAL_TARGETS)
def test_quickstart_references_canonical_target(quickstart_text: str, target: str) -> None:
    """Every canonical target must be advertised as ``make <target>`` in the doc."""
    assert f"make {target}" in quickstart_text, (
        f"QUICKSTART.md must reference the canonical target `make {target}`"
    )


def test_quickstart_targets_match_makefile_when_present(quickstart_text: str) -> None:
    """Cross-check the doc against the Makefile.

    The Makefile is a sibling deliverable that may not exist yet. When it is
    absent, we still assert the doc references the canonical target names (done by
    the parametrized test above) and quotes the right offline test count. When it
    IS present, every canonical target the doc advertises must be a real target
    defined in the Makefile — no advertising a target that does not exist.
    """
    if not os.path.isfile(MAKEFILE):
        pytest.skip("Makefile is a sibling deliverable not yet present; doc-name check covered elsewhere")

    makefile_text = _read(MAKEFILE)
    # A target definition line looks like `name:` at column 0 (optionally with deps).
    defined = set(re.findall(r"(?m)^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:", makefile_text))
    for target in CANONICAL_TARGETS:
        if f"make {target}" in quickstart_text:
            assert target in defined, (
                f"QUICKSTART.md advertises `make {target}` but the Makefile does not define it"
            )


# --------------------------------------------------------------------------- #
# Offline test count accuracy
# --------------------------------------------------------------------------- #
def test_quickstart_quotes_offline_test_count(quickstart_text: str) -> None:
    assert EXPECTED_TEST_COUNT in quickstart_text, (
        f"QUICKSTART.md must quote the offline test count {EXPECTED_TEST_COUNT}"
    )


# --------------------------------------------------------------------------- #
# Public-repo hygiene: no customer names, no real account ids
# --------------------------------------------------------------------------- #
def test_quickstart_has_no_customer_name(quickstart_text: str) -> None:
    assert not _CUSTOMER_NAME_RE.search(quickstart_text), (
        "QUICKSTART.md must not contain any customer/company name (public repo)"
    )


def test_quickstart_has_no_real_account_id(quickstart_text: str) -> None:
    offenders = [m for m in _TWELVE_DIGITS.findall(quickstart_text) if m != "000000000000"]
    assert not offenders, (
        f"QUICKSTART.md must not hardcode a real 12-digit AWS account id; found {offenders}. "
        "Use the 000000000000 placeholder or env vars."
    )
