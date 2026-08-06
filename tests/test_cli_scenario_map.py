"""INV-CLI-4 — every scenario the CLI advertises resolves to a file that exists.

`sentinel run-scenario <name>` is driven by a hand-written map in `sentinel_harness/cli.py`:

    _SCENARIOS = {
        "cve_triage":    "scenario_cve_triage.py",
        "multi_harness": "scenario_multi_harness.py",
        "detection_gen": "scenario_detection_gen.py",
    }

Nothing referenced it. Measured, by pointing one entry at a filename that does not exist and running
everything:

    _SCENARIOS["cve_triage"] = "scenario_typo_gone.py"   ->  4113 passed, 20 skipped

The whole suite stayed green while `sentinel run-scenario cve_triage` — a name argparse offers in
`--help` — would print `scenario file not found: …` and exit 2. A user-visible CLI failure with zero
test coverage.

Note what DID get caught, because the distinction matters: deleting `scenarios/scenario_cve_triage.py`
outright fails three tests in `test_scenarios_execute.py`. That module guards the scenario INVENTORY
(every scenario on disk is classified and runnable), not the CLI's map INTO it. So the file existing
is checked, and the CLI pointing at the right file is not — two halves of one contract with only the
first guarded. My first hypothesis was that a rename would go unnoticed entirely; that was wrong, and
narrowing the probe to the mapping alone is what isolated the real gap.

A recorded dead branch
----------------------
`cmd_run_scenario` opens with:

    if name not in _SCENARIOS:
        _eprint(f"unknown scenario {name!r}. available: …")
        return 2

That is UNREACHABLE through the CLI: the parser declares `choices=sorted(_SCENARIOS)`, so argparse
rejects an unknown name first — verified, `parse_args(["run-scenario", "does_not_exist"])` raises
SystemExit(2) with argparse's own message. The branch is kept as defence for direct calls to
`cmd_run_scenario(...)`, and it is asserted below so its unreachability is a recorded decision rather
than something the next reader has to re-derive from a coverage report. (`test_cli.py` already had a
comment saying argparse enforces the choices list; this makes the consequence explicit.)

Why the map is a SUBSET, stated
-------------------------------
The repo has 23 scenarios and the CLI advertises 3. That is deliberate — all three drive real
AgentCore APIs, so they are the live-demo selection rather than the offline set — but the code said
only "scenario name -> module file" and gave no reason, which is indistinguishable from a list that
drifted. The subset is asserted to stay a subset of what exists, and its size is bounded so silently
dropping to one entry fails.

ZERO network, ZERO AWS: this reads the map and the filesystem.
"""
from __future__ import annotations

import ast
import os

from sentinel_harness import cli

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS_DIR = os.path.join(REPO_ROOT, "scenarios")
CLI_SOURCE = os.path.join(REPO_ROOT, "sentinel_harness", "cli.py")


def _scenarios_on_disk() -> set:
    return {
        name for name in os.listdir(SCENARIOS_DIR)
        if name.startswith("scenario_") and name.endswith(".py")
    }


def test_the_map_is_non_empty_and_the_scenarios_dir_is_populated():
    """Positive control. Every assertion below iterates the map or the directory; either coming back
    empty would make them all pass while checking nothing — the vacuous-pass shape this repo records
    most."""
    assert len(cli._SCENARIOS) >= 3, (
        f"the CLI advertises only {len(cli._SCENARIOS)} scenario(s): {sorted(cli._SCENARIOS)}. "
        "Either entries were dropped or this import is reading the wrong object; both must fail "
        "loudly rather than shrink the check."
    )
    assert len(_scenarios_on_disk()) >= 20, (
        f"only {len(_scenarios_on_disk())} scenario files found under scenarios/ — the comparison "
        "below would be blind."
    )


def test_every_advertised_scenario_resolves_to_a_file_that_exists():
    """THE defect: nothing checked this, and a broken mapping left the suite fully green.

    `cmd_run_scenario` builds `os.path.join(SCENARIOS_DIR, _SCENARIOS[name])` and refuses with exit 2
    when the file is absent. So a rename in `scenarios/` — or a typo in this map — turns a
    `--help`-advertised command into a runtime error, and the only signal is a user hitting it.

    Resolved through the CLI's own constants rather than a re-typed path, so this cannot pass while
    the CLI looks somewhere else.
    """
    missing = {}
    for name, filename in sorted(cli._SCENARIOS.items()):
        path = os.path.join(cli.SCENARIOS_DIR, filename)
        if not os.path.isfile(path):
            missing[name] = filename
    assert not missing, (
        "the CLI advertises scenario(s) whose file does not exist, so "
        f"`sentinel run-scenario <name>` exits 2 for them: {missing}\n\n"
        "Either a scenario was renamed without updating `_SCENARIOS` in sentinel_harness/cli.py, or "
        "the map has a typo. Verified reachable: pointing one entry at a nonexistent filename left "
        "the entire suite green (4113 passed) while the command was broken."
    )


def test_the_cli_and_this_guard_agree_on_where_scenarios_live():
    """Guard the premise of the check above.

    If `cli.SCENARIOS_DIR` ever pointed somewhere other than the repo's `scenarios/`, the resolution
    test would still pass — against the wrong tree — while the shipped CLI failed. So the two are
    asserted to be the same directory, by inode rather than by string, since either could be an
    equivalent-but-differently-spelled path.
    """
    assert os.path.isdir(cli.SCENARIOS_DIR), (
        f"cli.SCENARIOS_DIR ({cli.SCENARIOS_DIR!r}) is not a directory, so every "
        "`run-scenario` invocation fails"
    )
    assert os.path.samefile(cli.SCENARIOS_DIR, SCENARIOS_DIR), (
        f"cli.SCENARIOS_DIR resolves to {cli.SCENARIOS_DIR!r}, not the repo's "
        f"{SCENARIOS_DIR!r} — this guard would be checking a different tree than the CLI uses."
    )


def test_the_advertised_set_is_a_subset_of_what_exists():
    """The map is deliberately a SUBSET (3 of 23), so it is checked as one rather than for equality.

    All three advertised scenarios drive real AgentCore APIs — they are the live-demo selection, not
    the offline set — so demanding all 23 be advertised would be wrong. What must hold is that every
    advertised filename is a real scenario file (not, say, a helper module that happens to sit in
    that directory).
    """
    on_disk = _scenarios_on_disk()
    advertised = set(cli._SCENARIOS.values())
    stray = sorted(advertised - on_disk)
    assert not stray, (
        f"the CLI advertises {stray}, which are not `scenario_*.py` files under scenarios/. Either "
        "the filename is wrong or the target is not a scenario."
    )


def test_the_argparse_choices_come_from_the_map_itself():
    """The `--help` list and the dispatch map must be ONE fact.

    `choices=sorted(_SCENARIOS)` is what makes them agree. If someone re-typed the list as a literal,
    `--help` could offer a name the dispatch map lacks (a confusing exit 2) or omit one it has (an
    invisible feature). Asserted from the AST rather than by substring, since `_SCENARIOS` appearing
    somewhere in the file proves nothing about the `choices=` argument.
    """
    with open(CLI_SOURCE, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    choices_nodes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "choices":
                choices_nodes.append(keyword.value)

    # Find the one whose value derives from _SCENARIOS.
    derived = [
        value for value in choices_nodes
        if any(isinstance(n, ast.Name) and n.id == "_SCENARIOS" for n in ast.walk(value))
    ]
    assert derived, (
        "no `choices=` argument in cli.py derives from `_SCENARIOS`. The run-scenario parser must "
        "build its choices FROM the dispatch map, or `--help` and the dispatcher can disagree — "
        "offering a name that exits 2, or hiding one that works."
    )


def test_the_unknown_name_branch_is_unreachable_through_the_cli():
    """A recorded dead branch, so the next reader does not mistake it for a coverage gap.

    `cmd_run_scenario` refuses an unknown name with exit 2, but argparse's `choices=` rejects it
    first — verified here rather than asserted from reading. The branch stays as defence for direct
    `cmd_run_scenario(...)` calls; this test pins WHY it never shows up as covered.
    """
    import argparse

    import pytest

    parser = cli.build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["run-scenario", "definitely_not_a_scenario"])
    assert excinfo.value.code == 2, (
        f"argparse exited {excinfo.value.code}, expected 2 for an invalid choice. If it now ACCEPTS "
        "an unknown name, the in-function check is live code and needs a behavioural test of its "
        "own rather than this reachability note."
    )

    # And the branch itself still works when called directly, since that is the path it defends.
    namespace = argparse.Namespace(name="definitely_not_a_scenario")
    assert cli.cmd_run_scenario(namespace) == 2, (
        "cmd_run_scenario no longer returns 2 for an unknown scenario name. It is the last line of "
        "defence for direct calls that bypass the parser."
    )
