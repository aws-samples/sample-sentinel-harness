"""Offline guard tests for the top-level Makefile + deploy/ helper wrappers.

WHY this file exists
--------------------
The M7 delivery form is a single ergonomic entry point: one ``Makefile`` at the
repo root plus three thin ``deploy/*.sh`` wrappers (seed_registry / create_harnesses
/ smoke). Those files are the human-facing "clone -> deploy/seed/create/smoke"
path, so their contract must not silently regress. These tests assert that
contract as TEXT + ``bash -n`` — they do NOT execute the wrappers' bodies, so
there is ZERO AWS / network / subprocess-into-AWS risk. The only subprocess is
``bash -n`` (a pure syntax check that neither runs the body nor touches the net).

What we verify (all statically):
  * the Makefile exists and declares every key target (grep),
  * each of the 3 new wrappers is ``bash -n``-clean,
  * no wrapper (nor the Makefile) embeds a real 12-digit AWS account id — the only
    12-digit run allowed is the scrubbed placeholder ``000000000000``.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

# Repo layout: tests/ is a sibling of deploy/ and of the root Makefile.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEPLOY_DIR = os.path.join(_REPO_ROOT, "deploy")

MAKEFILE = os.path.join(_REPO_ROOT, "Makefile")
SEED_SH = os.path.join(_DEPLOY_DIR, "seed_registry.sh")
CREATE_SH = os.path.join(_DEPLOY_DIR, "create_harnesses.sh")
SMOKE_SH = os.path.join(_DEPLOY_DIR, "smoke.sh")

WRAPPERS = [SEED_SH, CREATE_SH, SMOKE_SH]

# Every target the delivery story promises. Declared as ``name:`` at column 0.
#
# This list drifted: it named 13 targets while the Makefile declared 16, so `ci`, `typecheck` and
# `dist` — the local gate entry point, the two mypy gates, and the clean-tree build added a few
# rounds ago — were covered by NOTHING here, including `test_makefile_targets_are_phony`. Same shape
# as INV-SKILL-1 (five listed, nine on disk) one round earlier: a hand-written inventory that stops
# tracking what it mirrors.
#
# Kept explicit so a REMOVED target fails loudly, and reconciled against the Makefile by
# `test_the_target_inventory_matches_the_makefile` so an ADDED one cannot go unchecked.
KEY_TARGETS = [
    "help", "ci", "typecheck", "test", "lint", "synth", "deploy", "deploy-endpoints",
    "seed-registry", "create-harnesses", "smoke", "reset", "destroy",
    "demo", "clean", "dist", "sync-action-pins",
]

# A 12-digit run that is NOT the scrubbed placeholder is a leaked account id.
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PLACEHOLDER = "000000000000"


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Makefile exists + declares the key targets.                                 #
# --------------------------------------------------------------------------- #
def test_makefile_exists():
    assert os.path.isfile(MAKEFILE), "top-level Makefile must exist at the repo root"


@pytest.mark.parametrize("target", KEY_TARGETS)
def test_makefile_declares_target(target):
    text = _read(MAKEFILE)
    # A GNU-make target declaration is ``<name>:`` at the start of a line.
    assert re.search(rf"(?m)^{re.escape(target)}:", text), (
        f"Makefile must declare a '{target}' target"
    )


def test_makefile_default_goal_is_help():
    text = _read(MAKEFILE)
    assert ".DEFAULT_GOAL := help" in text


def test_makefile_targets_are_phony():
    """Every key target must be .PHONY so a same-named file never shadows it."""
    # Join backslash line-continuations first, then collect every .PHONY line.
    text = _read(MAKEFILE).replace("\\\n", " ")
    declared: set[str] = set()
    for line in text.splitlines():
        if line.startswith(".PHONY:"):
            declared.update(line[len(".PHONY:"):].split())
    for target in KEY_TARGETS:
        assert target in declared, f"{target} should be listed under .PHONY"


def test_makefile_uses_canonical_offline_pytest():
    """`make test` must use the hermetic uv invocation (no /tmp venv)."""
    text = _read(MAKEFILE)
    assert "uv run --no-project --python 3.13" in text
    assert "python -m pytest" in text


def test_makefile_calls_existing_deploy_scripts_not_reimplemented():
    """deploy/destroy must delegate to the existing M4 scripts, not `cdk deploy`."""
    text = _read(MAKEFILE)
    assert "deploy/deploy.sh" in text
    assert "deploy/deploy.sh --with-endpoints" in text
    assert "deploy/destroy.sh" in text
    assert "deploy/seed_registry.sh" in text
    assert "deploy/create_harnesses.sh" in text
    assert "deploy/smoke.sh" in text


# --------------------------------------------------------------------------- #
# The 3 wrappers exist, are executable, and pass `bash -n`.                    #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", WRAPPERS)
def test_wrapper_exists_and_executable(path):
    assert os.path.isfile(path), f"{path} must exist"
    assert os.access(path, os.X_OK), f"{path} must be executable (chmod +x)"


@pytest.mark.parametrize("path", WRAPPERS)
def test_wrapper_bash_n_clean(path):
    """`bash -n` is a syntax-only check: it never runs the body or hits the net."""
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is present in CI
        pytest.skip("bash not available")
    result = subprocess.run([bash, "-n", path], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed for {path}:\n{result.stderr}"


@pytest.mark.parametrize("path", WRAPPERS)
def test_wrapper_has_strict_mode_and_shebang(path):
    text = _read(path)
    assert text.startswith("#!/usr/bin/env bash"), f"{path} must start with a bash shebang"
    assert "set -euo pipefail" in text, f"{path} must use strict mode"


@pytest.mark.parametrize("path", WRAPPERS)
def test_wrapper_is_documented(path):
    """Each wrapper must carry a WHY/USAGE header — it is human-facing runbook."""
    text = _read(path)
    assert "WHY this script exists" in text, f"{path} must document WHY it exists"
    assert "USAGE:" in text, f"{path} must document USAGE"


# --------------------------------------------------------------------------- #
# No hardcoded account id anywhere in the delivery surface.                    #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", WRAPPERS + [MAKEFILE])
def test_no_hardcoded_account_id(path):
    text = _read(path)
    leaked = [m for m in _TWELVE_DIGITS.findall(text) if m != _PLACEHOLDER]
    assert not leaked, f"{path} embeds a non-placeholder 12-digit account id: {leaked}"


# --------------------------------------------------------------------------- #
# Safe-by-default behaviour is expressed in the wrapper text.                  #
# --------------------------------------------------------------------------- #
def test_create_harnesses_defaults_to_dry_run():
    text = _read(CREATE_SH)
    assert 'DRY_RUN="${DRY_RUN:-1}"' in text, "create_harnesses.sh must default DRY_RUN=1 (offline safe)"
    assert "dry_run=" in text or "dry_run =" in text or "provision_fleet" in text


def test_smoke_defaults_to_offline():
    text = _read(SMOKE_SH)
    assert "SENTINEL_SMOKE_LIVE" in text
    assert 'SENTINEL_SMOKE_LIVE:-0' in text, "smoke.sh must default to offline (LIVE opt-in)"


def test_seed_registry_is_offline_governance():
    text = _read(SEED_SH)
    assert "load_registry" in text
    assert "governance_check" in text
    assert "OFFLINE" in text or "offline" in text

# --------------------------------------------------------------------------- #
# The target inventory (INV-MAKE-1)                                           #
# --------------------------------------------------------------------------- #
def _makefile_text() -> str:
    """The Makefile's contents.

    `MAKEFILE` is a `str` path (this module uses `os.path`, not `pathlib`). My first version called
    `MAKEFILE.read_text()` — importing a second file-access idiom into a module that already had
    one, and getting an AttributeError for it. Matching the surrounding style is cheaper than
    mixing.
    """
    with open(MAKEFILE, encoding="utf-8") as handle:
        return handle.read()


def _declared_targets() -> set:
    """Every `name:` target declared at column 0 in the Makefile."""
    return set(re.findall(r"^([a-z][a-z0-9-]*):", _makefile_text(), re.M))


def test_the_target_inventory_matches_the_makefile():
    """KEY_TARGETS must mirror the Makefile, or checks silently stop covering targets.

    It had drifted to 13 of 16. The three missing were `ci` (the local gate everyone runs),
    `typecheck` (both mypy gates) and `dist` (the clean-tree build) — so
    `test_makefile_targets_are_phony` never covered them, and `dist` was in fact **missing from
    `.PHONY`**. Extending the list made that check fail immediately, which is the whole argument for
    reconciling inventories: the drift was not the defect, it was the thing hiding one.

    Same shape as INV-SKILL-1 (five listed, nine on disk) one round earlier.

    Both directions fail, so an added target gets covered and a removed one is noticed.
    """
    declared = _declared_targets()
    listed = set(KEY_TARGETS)
    uncovered = sorted(declared - listed)
    assert not uncovered, (
        f"Makefile declares target(s) {uncovered} that KEY_TARGETS omits, so every check "
        "parametrised over that list silently skips them — including the .PHONY check, which is "
        "how `dist` came to be undeclared."
    )
    stale = sorted(listed - declared)
    assert not stale, (
        f"KEY_TARGETS names target(s) {stale} that the Makefile no longer declares. Either they "
        "were renamed (update both) or removed (drop them here)."
    )


def test_the_inventory_is_non_trivial():
    """Positive control. Every parametrised check in this module iterates KEY_TARGETS; a truncated
    list makes them vanish rather than fail — exactly how three targets went unchecked."""
    assert len(KEY_TARGETS) >= 15, (
        f"only {len(KEY_TARGETS)} targets listed: {KEY_TARGETS}. The checks below cover only what "
        "this list contains."
    )
    assert len(KEY_TARGETS) == len(set(KEY_TARGETS)), f"duplicates: {KEY_TARGETS}"
    assert len(_declared_targets()) >= 15, "the Makefile parse found too few targets to trust"


def test_every_declared_target_is_phony():
    """`.PHONY` over the FULL declared set, not just the listed subset.

    None of these targets produces a file of its own name, so all of them must be phony: otherwise a
    same-named file or directory in the repo root can make `make <target>` a no-op. `dist` was the
    one missing.

    Measured honestly: with a same-named file planted, these targets still ran (they have no
    prerequisites, so make runs the recipe anyway), so the omission was not causing a live failure.
    The declaration is still required — it states the intent that these are commands, not artifacts,
    and `demo` and `dist` are names that DO exist as directories in this repo at times.
    """
    # LINE CONTINUATIONS are joined first. `.PHONY` here spans two lines with a trailing `\`, and
    # my first version matched `^\.PHONY:(.*)$` per line — capturing only the first half and a
    # literal `\` token, then reporting the six names on the continuation line as missing. The
    # Makefile was correct; the parser was not. Reading a line-continued declaration line-by-line is
    # the same class of error as substring-matching a structure.
    text = re.sub(r"\\\n\s*", " ", _makefile_text())
    phony: set = set()
    for match in re.finditer(r"^\.PHONY:(.*)$", text, re.M):
        phony |= set(match.group(1).split())
    missing = sorted(_declared_targets() - phony)
    assert not missing, (
        f"target(s) {missing} are declared but not in .PHONY. A file or directory of that name in "
        "the repo root could turn the target into a no-op — and `demo`/`dist` are exactly such "
        "names here."
    )
