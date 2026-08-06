"""INV-COV-1 — every SHIPPED Python package is inside the coverage gate's view.

`.coveragerc` deliberately uses `include` globs rather than `source`, and the reason is written down
at length: the suite path-loads flat trees via `spec_from_file_location` under fabricated module
names, and coverage's `source` option turns on import-time interception that fights that pattern.
`include` is a pure post-hoc path filter, so the whole suite stays green. That decision is sound.

Its cost is that the glob list is HAND-MAINTAINED, and it had drifted. It named four trees —
`tools`, `longrunning`, `specialists`, `sentinel_harness` — while `pyproject.toml` ships five
packages. Two carrying real Python were outside the gate entirely:

    intake/     2 files, ~195 lines   (the deterministic intake normaliser)
    mockdata/   5 files, ~1478 lines  (the ONLY source of the mock threat intelligence)

Measured, and the demonstration is the point rather than the percentage. Appending seven
never-executed statements to `intake/adapter.py`:

    before the fix:   TOTAL 8644 statements, 92%, `coverage report --fail-under=88` -> rc=0
                      intake/adapter.py does not appear in the report AT ALL
    after the fix:    TOTAL 8864, intake/adapter.py 86 statements 89%, missing 247-253

So this was not "a number could look better". Code in two shipped packages could rot arbitrarily and
the gate would not notice — the "lint-exempt directory = never cleaned" rule, applied to a coverage
gate. `mockdata` matters most of the three: at 1478 lines it is seven times `intake`, it is the sole
source of the fictional threat intelligence every tool returns, and SecOps output is only as
trustworthy as the shape of that data.

`harnesses/` is deliberately NOT added
--------------------------------------
It is the fifth shipped package and it contains **zero** `.py` files — it is YAML harness configs.
Adding it to the include globs would create a rule that can never match anything, i.e. configuration
whose only function is to make a checklist look complete. The guard below therefore keys on "ships
Python", not on "is listed in pyproject", and asserts that distinction rather than leaving the
omission to look like the same drift being fixed here.

Adding the two trees moved TOTAL from 8644 to 8856 statements and coverage stayed at 92%, so the
88% gate still passes — verified before committing, because a fix that lands red is not a fix.

ZERO network, ZERO AWS: reads two config files and the filesystem.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COVERAGERC = os.path.join(REPO_ROOT, ".coveragerc")
PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    tomllib = pytest.importorskip(
        "tomli", reason="TOML parsing on 3.10 needs the `tomli` marker-gated dep"
    )

# Trees that ship but carry no Python, so a coverage glob for them could never match. Recorded with
# the reason so the exemption is a decision rather than an oversight — and checked below, because an
# exemption without its own guard is a hole.
_SHIPS_NO_PYTHON = {
    "harnesses": "YAML harness configs only; a coverage glob would match nothing",
}


def _shipped_packages() -> list:
    """Top-level package names `pyproject.toml` ships, with the `*` suffix stripped."""
    with open(PYPROJECT, "rb") as fh:
        data = tomllib.load(fh)
    patterns = data["tool"]["setuptools"]["packages"]["find"]["include"]
    return sorted({pattern.rstrip("*").rstrip(".") for pattern in patterns})


def _coverage_included_trees() -> set:
    """Top-level directory names the `[run] include` globs cover.

    Parsed from the `include =` block only. Reading the whole file and grepping for `*/name/*` would
    also pick up the `omit =` entries (`node_modules`, `build`, `.venv`), which are the opposite of
    included — a scan that cannot tell include from omit would report `build` as covered.
    """
    with open(COVERAGERC, encoding="utf-8") as fh:
        text = fh.read()
    block = re.search(r"^include\s*=\s*\n((?:[ \t]+\S+\n)+)", text, re.M)
    assert block, "could not locate the `include =` block in .coveragerc"
    return set(re.findall(r"\*/([A-Za-z0-9_]+)/\*", block.group(1)))


def _python_files_in(tree: str) -> list:
    """Every non-cache `.py` file under a top-level tree."""
    root = os.path.join(REPO_ROOT, tree)
    if not os.path.isdir(root):
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        found.extend(
            os.path.join(dirpath, name) for name in filenames if name.endswith(".py")
        )
    return sorted(found)


def test_the_scan_reads_both_configs():
    """Positive control. Both sides of the comparison are parsed; either coming back empty would make
    the assertion below pass while checking nothing — the vacuous-pass shape this repo records most."""
    shipped = _shipped_packages()
    assert len(shipped) >= 4, f"only {len(shipped)} shipped packages parsed: {shipped}"
    included = _coverage_included_trees()
    assert len(included) >= 4, f"only {len(included)} include globs parsed: {sorted(included)}"
    # And the omit entries must NOT have leaked in, or the comparison would count `build` as covered.
    for omitted in ("node_modules", "build"):
        assert omitted not in included, (
            f"{omitted!r} was parsed as an include glob; the parser is reading the `omit =` block "
            "too, which would report excluded trees as covered"
        )


def test_every_shipped_package_with_python_is_in_the_coverage_include():
    """THE defect: `intake/` and `mockdata/` shipped but sat outside the gate's view.

    Demonstrated rather than argued — seven never-executed statements appended to
    `intake/adapter.py` left `coverage report --fail-under=88` at rc=0 and TOTAL unchanged at 8644,
    with the file absent from the report entirely.
    """
    shipped = _shipped_packages()
    included = _coverage_included_trees()

    missing = []
    for package in shipped:
        if package in _SHIPS_NO_PYTHON:
            continue
        if not _python_files_in(package):
            continue
        if package not in included:
            count = len(_python_files_in(package))
            missing.append(f"{package}/ ({count} .py files) ships but is not in .coveragerc include")

    assert not missing, (
        "shipped Python package(s) are outside the coverage gate, so their code can rot arbitrarily "
        "without the 88% gate noticing:\n  " + "\n  ".join(missing)
        + "\n\nAdd `*/<name>/*` to the `include =` block in .coveragerc. This is the "
        "'lint-exempt directory = never cleaned' rule applied to a coverage gate: a tree the gate "
        "cannot see is a tree the gate does not protect."
    )


def test_the_no_python_exemption_is_accurate():
    """Guard the exemption in both directions.

    `harnesses/` is exempt because it ships zero `.py` files, so a glob for it could never match — a
    rule whose only function would be to make a checklist look complete. But if it ever GAINS Python,
    the exemption silently hides that code from the gate, so the premise is asserted rather than
    trusted.
    """
    for tree, reason in sorted(_SHIPS_NO_PYTHON.items()):
        files = _python_files_in(tree)
        assert not files, (
            f"{tree}/ is exempted from the coverage include on the grounds that it ships no Python "
            f"({reason}), but it now contains {len(files)} .py file(s): "
            f"{[os.path.relpath(f, REPO_ROOT) for f in files[:3]]}\n\n"
            "Either add it to the include globs or drop it from _SHIPS_NO_PYTHON — an exemption "
            "whose premise expired hides real code from the gate."
        )
        assert os.path.isdir(os.path.join(REPO_ROOT, tree)), (
            f"{tree}/ no longer exists; remove it from _SHIPS_NO_PYTHON rather than leaving a "
            "dead exemption"
        )


def test_no_include_glob_points_at_a_tree_that_does_not_exist():
    """The reverse direction: a glob for a moved or renamed tree covers nothing.

    Coverage does not warn about an include pattern that matches no files — it simply reports less,
    which reads identically to "that code is fully covered". Same failure shape as a Dependabot
    directory that no longer exists (INV-SUPPLY-1).
    """
    stale = []
    for tree in sorted(_coverage_included_trees()):
        path = os.path.join(REPO_ROOT, tree)
        if not os.path.isdir(path):
            stale.append(f"{tree}/ is in the include globs but does not exist")
        elif not _python_files_in(tree):
            stale.append(f"{tree}/ is in the include globs but contains no .py files")
    assert not stale, (
        "coverage include glob(s) match nothing, so they silently narrow the gate:\n  "
        + "\n  ".join(stale)
    )


def test_the_gate_threshold_is_stated_in_both_places_it_is_enforced():
    """`.coveragerc` and the Makefile must agree on the number.

    `.coveragerc`'s own comment says "Quality gate — MUST match ci.yml's
    `coverage report --fail-under`". Two copies of one threshold drift, and the direction that
    matters is the silent one: a Makefile at 88 and a config at 80 means `make ci` is stricter than
    the file people read.
    """
    with open(COVERAGERC, encoding="utf-8") as fh:
        config_text = fh.read()
    config_match = re.search(r"^fail_under\s*=\s*(\d+)", config_text, re.M)
    assert config_match, ".coveragerc declares no `fail_under`"
    config_value = int(config_match.group(1))

    makefile_path = os.path.join(REPO_ROOT, "Makefile")
    with open(makefile_path, encoding="utf-8") as fh:
        makefile_text = fh.read()
    make_values = {int(v) for v in re.findall(r"--fail-under=(\d+)", makefile_text)}
    assert make_values, "the Makefile does not pass --fail-under anywhere"
    assert make_values == {config_value}, (
        f".coveragerc sets fail_under={config_value} but the Makefile passes "
        f"--fail-under={sorted(make_values)}. One threshold, two copies — they agree today and "
        "will not after the next edit."
    )
