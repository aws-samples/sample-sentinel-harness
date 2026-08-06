"""
Offline guard tests for the delivery/onboarding doc (``docs/QUICKSTART.md``)
============================================================================
QUICKSTART.md is the "get running in 5 minutes" promise a newcomer reads first,
so its claims must stay true to the repo: the make targets it advertises have to
be the canonical ones (and, once a Makefile exists as a sibling deliverable, must
actually be defined there), the offline test count it quotes must match the real
suite size (1698), and — this being a PUBLIC repo — it must never leak a customer
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

# The canonical Makefile target names the delivery story is built around. These are the contract
# the QUICKSTART advertises and the targets it must define.
#
# This list named 10 while QUICKSTART advertised 11 `make X` commands: `deploy-endpoints` was
# missing, so neither check below covered it — not "the doc mentions it" and not "the doc agrees
# with the Makefile". Fourth instance of the same shape in four rounds (INV-SKILL-1 five-of-nine,
# INV-HARNESS-1's reference side, INV-MAKE-1 thirteen-of-sixteen), so the fix is the same: keep it
# explicit so a REMOVED target fails loudly, and reconcile against the document by
# `test_the_canonical_list_covers_every_advertised_target` so an ADDED one cannot go unchecked.
CANONICAL_TARGETS = [
    "test",
    "lint",
    "synth",
    "deploy",
    "deploy-endpoints",
    "seed-registry",
    "create-harnesses",
    "smoke",
    "demo",
    "reset",
    "destroy",
]

# The offline suite size the doc must quote accurately. Update this together with
# QUICKSTART.md / TESTING.md whenever the suite size changes (it is a deliberate
# tripwire: a doc that quotes a stale count fails here).
EXPECTED_TEST_COUNT = "2365"

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

# --------------------------------------------------------------------------- #
# The canonical list itself (INV-DOC-10)                                      #
# --------------------------------------------------------------------------- #
def _advertised_targets(text: str) -> set:
    """Every `make <target>` the QUICKSTART tells a reader to run."""
    return set(re.findall(r"\bmake\s+([a-z][a-z0-9-]*)", text))


def test_the_canonical_list_covers_every_advertised_target(quickstart_text: str) -> None:
    """A `make X` in the doc that the list omits is a command nothing checks.

    Measured: QUICKSTART advertised 11 commands and this list named 10 — `deploy-endpoints` was
    missing, so neither "the doc mentions it" nor "the doc agrees with the Makefile" covered it.

    The list is a deliberate SUBSET of the Makefile (the delivery story's contract, not every
    target), so it is reconciled against the DOCUMENT rather than against the Makefile — the
    Makefile-wide inventory is INV-MAKE-1's job. Getting that distinction wrong would demand this
    list grow to all 16 targets, which is the subset-vs-total trap INV-DOC-9 records.
    """
    advertised = _advertised_targets(quickstart_text)
    assert advertised, (
        "no `make <target>` found in QUICKSTART.md — either the doc stopped showing commands or "
        "this parser is blind; both must fail rather than pass vacuously."
    )
    uncovered = sorted(advertised - set(CANONICAL_TARGETS))
    assert not uncovered, (
        f"QUICKSTART advertises `make {'`, `make '.join(uncovered)}` but CANONICAL_TARGETS omits "
        f"{uncovered}, so every check parametrised over that list silently skips them."
    )


def test_no_canonical_target_is_unadvertised(quickstart_text: str) -> None:
    """The other direction: a listed target the doc no longer shows.

    That means either the doc dropped a command it should still teach, or the entry is stale. Both
    are worth a failure — a list entry nobody exercises is the "exemption nobody uses" shape.
    """
    advertised = _advertised_targets(quickstart_text)
    orphans = sorted(set(CANONICAL_TARGETS) - advertised)
    assert not orphans, (
        f"CANONICAL_TARGETS names {orphans}, which QUICKSTART.md no longer shows as `make <t>`. "
        "Either restore the command in the doc or drop the entry."
    )


def test_every_canonical_target_exists_in_the_makefile() -> None:
    """The doc must not teach a command that does not exist.

    Complements INV-MAKE-1, which asserts the Makefile's own inventory is fully covered; this
    asserts the direction that matters to a READER — every command QUICKSTART shows is real.
    """
    with open(MAKEFILE, encoding="utf-8") as handle:
        declared = set(re.findall(r"^([a-z][a-z0-9-]*):", handle.read(), re.M))
    assert len(declared) >= 15, f"the Makefile parse found only {len(declared)} targets"
    missing = sorted(set(CANONICAL_TARGETS) - declared)
    assert not missing, (
        f"QUICKSTART teaches `make {'`, `make '.join(missing)}` but the Makefile declares no such "
        f"target: {missing}. A reader following the doc gets 'No rule to make target'."
    )
