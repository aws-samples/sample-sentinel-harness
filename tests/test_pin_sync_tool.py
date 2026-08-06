"""INV-CI-5 — a guard that demands a machine-derived table ships a working way to derive it.

INV-CI-3 asserts that every SHA-pinned Action's version comment names the version the SHA really is,
by comparing each pin against an `_AUTHORITATIVE` table. The guard works: it blocked Dependabot
PR #61, which bumped the three `github/codeql-action` sub-actions to a SHA the table did not know.

It was not, however, **actionable**. Its failure message said to resolve each SHA against GitHub and
noted "SENTINEL_VERIFY_ACTION_PINS=1 does this". That was false. Measured by reproducing PR #61 in
the working tree:

    offline layer                          2 failed   (SHA not in the authoritative table)
    online layer (VERIFY_ACTION_PINS=1)    PASSED     (it iterates only entries already in the
                                                       table, so a brand-new SHA is never seen)

So the only remaining route was for a human to hand-copy a 40-hex SHA and hand-resolve it against
the GitHub API — precisely the manual work INV-CI-3 exists to eliminate. Dependabot bumps Actions
weekly, so this was a recurring red CI whose only supported fix was the ritual the guard replaced.
A guard that converts the labour it prevents into a mandatory ceremony has traded one defect for
another, and "the guards are code too, so they get invariants" (round 18) is why this one is here.

The fix is `scripts/sync_action_pins.py` + `make sync-action-pins`, which re-derives the table and
the comments from the authoritative direction (SHA -> the tag pointing at it). Verified end to end
against PR #61's exact state: guard fails -> one command -> guard passes, table gained
`d1ba80a13dd9 = v4.37.5` and dropped the superseded entry, three comments rewritten.

What this module asserts
------------------------
* the tool exists, is syntactically valid, and is reachable from the Makefile
* every failure message that tells a reader to fix the table names the tool — the specific defect
  was a message pointing at something that could not do the job
* the tool resolves SHA -> tag, not comment -> table (deriving the version from the neighbouring
  comment would launder a stale label into the "authoritative" source, which IS the defect INV-CI-3
  records: `setup-python` claimed v6.3.0 while pinned to v7.0.0)
* it refuses to write a PARTIAL table when any SHA is unresolvable
* it does not pick a moving major alias or a historical re-tag over the real release

Recorded because it nearly shipped: the tool's first version ranked candidate tags by counting
dot-separated components, and `actions/deploy-pages` has three tags on one commit — `v5.0.0`, `v5`,
and `v3.0.2-node.24`. The component count picked `v3.0.2-node.24`, so the tool proposed rewriting a
CORRECT `v5.0.0` comment into a misleading one: the guard's own defect class, reintroduced by its
remediation tool. Now ranked semantically (plain releases beat suffixed ones, then most-qualified,
then highest), and asserted below.

ZERO network, ZERO AWS: this reads the tool as source and as an AST. The tool itself needs `gh`, so
its live behaviour is covered by INV-CI-3's opt-in online layer rather than duplicated here.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys

import pytest

from repo_infra import require_git_checkout

# Repository-scoped, module-level. `scripts/` is deliberately NOT in the sdist — it is maintainer
# tooling in the same category as `.github/` (see test_sdist_contents.py's _DELIBERATELY_ABSENT) —
# so in an unpacked sdist this whole module is inapplicable and skips with a reason. Inside a git
# checkout its absence is a FAILURE, which is the asymmetry `repo_infra` defines once: a guard that
# skips where it matters has verified nothing.
require_git_checkout("the pin-sync tool guard (scripts/ ships only in the repository)")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(REPO_ROOT, "scripts", "sync_action_pins.py")
GUARD = os.path.join(REPO_ROOT, "tests", "test_action_pin_comments.py")
MAKEFILE = os.path.join(REPO_ROOT, "Makefile")

# The command the guard must point at. A reader who hits the failure has to be able to copy this.
_TOOL_INVOCATION = "scripts/sync_action_pins.py"
_MAKE_TARGET = "sync-action-pins"


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _tool_ast() -> ast.Module:
    return ast.parse(_read(TOOL))


def test_the_remediation_tool_exists_and_parses():
    """Positive control for everything below: a missing or unparseable tool must fail loudly rather
    than make the assertions vacuous."""
    assert os.path.isfile(TOOL), (
        f"{_TOOL_INVOCATION} does not exist, but test_action_pin_comments.py's failure messages "
        "tell the reader to run it. A guard whose remediation does not exist is worse than one "
        "with no advice: the reader follows the instruction, gets nothing, and hand-edits the table."
    )
    tree = _tool_ast()
    functions = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for required in ("resolve_sha_to_version", "collect_pins", "render_table", "main"):
        assert required in functions, (
            f"{_TOOL_INVOCATION} has no `{required}` — it is not the pin-sync tool this module "
            f"describes. Functions found: {sorted(functions)}"
        )


def test_the_tool_is_reachable_from_the_makefile():
    """A script nobody can find is a script nobody runs.

    INV-MAKE-1 records the Makefile as the discoverable entry point for every routine task, and
    `make help` lists them. A remediation reachable only by remembering a path under `scripts/`
    fails the person who needs it most: someone reading a red CI log for the first time.
    """
    makefile = _read(MAKEFILE)
    assert f"{_MAKE_TARGET}:" in makefile, (
        f"the Makefile has no `{_MAKE_TARGET}` target, so the fix for a failing pin guard is not "
        "discoverable from `make help`."
    )
    assert _TOOL_INVOCATION in makefile, (
        f"the `{_MAKE_TARGET}` target does not invoke {_TOOL_INVOCATION}"
    )
    # It must be .PHONY, or a same-named file would shadow it. INV-MAKE-1 exists because `dist`
    # was added as a target and left out of .PHONY for several rounds.
    phony = re.search(r"^\.PHONY:(.*?)(?=^\S|\Z)", makefile, re.M | re.S)
    assert phony, "the Makefile declares no .PHONY block"
    declared = re.sub(r"\\\s*\n\s*", " ", phony.group(1)).split()
    assert _MAKE_TARGET in declared, (
        f"`{_MAKE_TARGET}` is not in .PHONY, so a file of that name would silently shadow the "
        f"target. Declared: {declared}"
    )


def test_the_dry_run_is_the_default():
    """The tool rewrites a TEST MODULE. Writing by default would mean a mistyped command edits the
    guard's own source before anyone reads the diff.

    Checked structurally: the `--write` flag must exist and default to off (`store_true`), so the
    no-argument invocation cannot mutate anything.
    """
    tree = _tool_ast()
    write_flags = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and any(isinstance(a, ast.Constant) and a.value == "--write" for a in node.args)
    ]
    assert write_flags, f"{_TOOL_INVOCATION} declares no `--write` flag"
    for call in write_flags:
        actions = [kw.value for kw in call.keywords if kw.arg == "action"]
        assert actions and all(
            isinstance(v, ast.Constant) and v.value == "store_true" for v in actions
        ), (
            "`--write` is not a `store_true` flag, so it may not default to off. This tool "
            "rewrites tests/test_action_pin_comments.py; the default must be a dry run."
        )


def test_every_table_failure_message_names_the_tool():
    """The actual defect: the messages pointed at `SENTINEL_VERIFY_ACTION_PINS=1`, which cannot
    regenerate the table (it only validates entries already in it, so a new SHA is never seen).

    Any assertion whose remedy is "update the table" must name the tool that does it. Found by
    walking the AST for the three assertions that mention `_AUTHORITATIVE`, rather than by grepping
    the file — a substring standing in for a structural question is the defect class this repo
    records most, and it has already bitten a guard I wrote this month.
    """
    tree = ast.parse(_read(GUARD))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert) or node.msg is None:
            continue
        # The message is a concatenation of literals; collect every string in it.
        literals = [
            child.value for child in ast.walk(node.msg)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        ]
        message = " ".join(literals)
        if "_AUTHORITATIVE" not in message and "authoritative table" not in message:
            continue
        if _TOOL_INVOCATION not in message and _MAKE_TARGET not in message:
            offenders.append(f"line {node.lineno}: {message[:120]}")
    assert not offenders, (
        "assertion(s) in test_action_pin_comments.py tell the reader the authoritative table is "
        "wrong without naming the tool that fixes it:\n  " + "\n  ".join(offenders)
        + f"\n\nEach must name `{_TOOL_INVOCATION}` or `make {_MAKE_TARGET}`. The original message "
        "pointed at SENTINEL_VERIFY_ACTION_PINS=1, which PASSES in exactly the situation the "
        "reader is in, leaving hand-copying a 40-hex SHA as the only route."
    )


def test_the_stale_verify_pointer_is_gone():
    """Guard the specific false claim so it cannot come back by copy-paste.

    `SENTINEL_VERIFY_ACTION_PINS=1` is a real and useful flag — it keeps the table honest against
    GitHub — so this does not ban mentioning it. What it bans is presenting it as the way to
    REGENERATE the table, which it is not.
    """
    guard = _read(GUARD)
    assert "SENTINEL_VERIFY_ACTION_PINS" in guard, (
        "the online verification flag is gone entirely; INV-CI-3's second layer relies on it"
    )
    bad_phrasings = [
        "SENTINEL_VERIFY_ACTION_PINS=1 does this",
        "SENTINEL_VERIFY_ACTION_PINS=1 to regenerate",
    ]
    present = [phrase for phrase in bad_phrasings if phrase in guard]
    assert not present, (
        f"test_action_pin_comments.py again claims {present} regenerates the table. It does not: "
        "the online layer iterates only SHAs already in the table, so it passes on a new pin while "
        f"the offline layer fails. Point at `{_TOOL_INVOCATION} --write` instead."
    )


def test_the_tool_resolves_shas_authoritatively_not_from_comments():
    """The tool must derive the version from GitHub, never from the comment it is fixing.

    If it read the neighbouring comment it would launder a stale label into the "authoritative"
    table, which is INV-CI-3's defect verbatim (`setup-python` said v6.3.0 while pinned to v7.0.0;
    `codeql-action` said v3.37.0 while pinned to v4.37.4). Then the guard would pass and the repo
    would still be lying about what runs in CI.

    Asserted from the AST: the resolver must query the tags API and compare commit SHAs.
    """
    tree = _tool_ast()
    resolver = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "resolve_sha_to_version"),
        None,
    )
    assert resolver is not None, "no resolve_sha_to_version function"

    # The endpoint must appear in a CALL argument, not merely somewhere in the function.
    #
    # A first version joined every string constant in the resolver and asked `"/tags" in joined`.
    # The mutation "query /commits instead of /tags" SURVIVED it, because the resolver's own
    # DOCSTRING discusses `/tags` — documentation satisfying a check about implementation. That is
    # the substring-for-structure defect class again, inside the guard written to prevent it, so the
    # docstring is excluded and only call arguments count.
    docstring = ast.get_docstring(resolver)
    call_strings = []
    for node in ast.walk(resolver):
        if not isinstance(node, ast.Call):
            continue
        for argument in node.args:
            for child in ast.walk(argument):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    if docstring is None or child.value != docstring:
                        call_strings.append(child.value)
    joined = " ".join(call_strings)
    assert "/tags" in joined, (
        "resolve_sha_to_version does not pass a `/tags` endpoint to any call, so it cannot map a "
        "SHA to the version that actually points at it. A `/commits` or `/releases` lookup answers "
        "a different question and would let a wrong label into the authoritative table.\n"
        f"Call-argument strings found: {call_strings}"
    )
    # It must compare against the passed-in sha, i.e. resolve in the SHA -> tag direction.
    names = {n.id for n in ast.walk(resolver) if isinstance(n, ast.Name)}
    assert "sha" in names, "resolve_sha_to_version never references the sha it is resolving"


def test_the_tool_refuses_to_write_a_partial_table():
    """A partial table is worse than a stale one.

    If one SHA cannot be resolved and the tool wrote the rest, the guard would pass on the resolved
    entries while the UNRESOLVABLE pin — the suspicious one — stayed unrecorded. That is exactly
    "a check that no-ops must not look like a check that passed" (INV-CI-1 / INV-DOC-5), applied to
    a code generator.

    Verified live during the round: planting a nonexistent SHA gave `rc=1`, an explicit UNRESOLVED
    line, and zero writes to either the table or any comment.
    """
    tree = _tool_ast()
    main = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "main"), None)
    assert main is not None, "no main() in the tool"

    # The gate must be `if unresolved:` — a bare truth test on the collected failures, guarding the
    # WRITE. Located structurally, and its condition checked for exactness.
    #
    # Two mutations survived weaker versions of this and both are worth recording:
    #
    #  * `assert "refusing to write" in <every string in main()>` SURVIVED deleting the refusal
    #    message, because main() has a SECOND refuse-to-write path (the empty-table guard) whose
    #    message also matches. One phrase, two call sites — the check could not tell which was gone.
    #  * Finding the branch with `any(Name id == "unresolved")` SURVIVED `if False and unresolved:`.
    #    The name is still present, the branch is still found, its `return 1` is still non-zero, and
    #    the gate is dead. A guard has to test whether the gate can FIRE, not whether it exists.
    refusal_branches = [
        node for node in ast.walk(main)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "unresolved"
    ]
    assert refusal_branches, (
        "main() has no `if unresolved:` gate whose condition is exactly that name, so nothing "
        "reliably gates writing on every SHA having resolved.\n\n"
        "If the condition was rewritten (`if False and unresolved`, `if unresolved and DEBUG`, a "
        "flag, …) the gate may never fire, and the tool would write the partial table it is "
        "supposed to refuse — a guard that no-ops must not look like a guard that passed."
    )
    for branch in refusal_branches:
        # Its own message, scoped to this branch rather than to all of main().
        branch_strings = " ".join(
            node.value for node in ast.walk(branch)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ).lower()
        assert "refus" in branch_strings, (
            "the unresolvable-SHA branch does not say it is refusing to write, so its output is "
            "indistinguishable from a successful sync in a CI log."
        )
        codes = [
            node.value.value for node in ast.walk(branch)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, int)
        ]
        assert codes, (
            "the unresolvable-SHA branch does not return an exit code at all, so execution falls "
            "through and the tool writes the partial table it just refused to write."
        )
        assert all(code != 0 for code in codes), (
            f"the unresolvable-SHA branch returns {codes}. A refusal that exits 0 reads as SUCCESS "
            "to a shell, to `make`, and to CI — the caller would believe the table was synced."
        )


def test_the_tool_prefers_a_real_release_over_an_alias_or_a_retag():
    """The near-miss, made permanent.

    `actions/deploy-pages` has THREE tags on one commit:

        v5.0.0            the release
        v5                a moving major alias
        v3.0.2-node.24    a historical re-tag under the old major

    The tool's first ranking counted dot-separated components, so `v3.0.2-node.24` won and it
    proposed rewriting a CORRECT `v5.0.0` comment into a misleading one — the guard's own defect
    class, reintroduced by its remediation. Ranking is now semantic, and this pins that behaviour by
    running the real ranking function over the real ambiguous case.
    """
    # Import the tool's ranking by executing it in a namespace, WITHOUT running main(): the module
    # is a script, and `scripts/` is not an importable package.
    # `__file__` must be seeded: the tool computes REPO_ROOT from it at module scope, and an exec
    # namespace has no `__file__` by default (NameError). `__name__` is set to something other than
    # "__main__" so the `if __name__ == "__main__"` guard does not run main().
    namespace: dict = {"__file__": TOOL, "__name__": "sync_action_pins_under_test"}
    source = _read(TOOL)
    exec(compile(source, TOOL, "exec"), namespace)  # noqa: S102 - reading our own repo's tool

    resolve = namespace["resolve_sha_to_version"]
    # Feed the real ambiguous tag set through the resolver with the network stubbed out, so the
    # RANKING is what gets tested rather than the API call.
    sha = "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128"
    namespace["gh_api"] = lambda path: [
        {"name": "v3.0.2-node.24", "commit": {"sha": sha}},
        {"name": "v5", "commit": {"sha": sha}},
        {"name": "v5.0.0", "commit": {"sha": sha}},
        {"name": "v4.9.9", "commit": {"sha": "0" * 40}},  # different commit: must be ignored
    ]
    chosen = resolve("actions/deploy-pages", sha)
    assert chosen == "v5.0.0", (
        f"the resolver picked {chosen!r} for a commit tagged v5.0.0 / v5 / v3.0.2-node.24. It must "
        "pick the real release: `v5` is a moving alias (recording it defeats SHA pinning) and "
        "`v3.0.2-node.24` is a historical re-tag under an older major. Picking either would "
        "rewrite a correct comment into a misleading one."
    )


def test_the_tool_passes_the_repo_lint():
    """The tool is shipped code in a security reference; it holds to the same bar as the rest.

    Run as its own subprocess rather than trusting the suite-wide lint job to cover `scripts/`,
    since a new top-level directory silently outside the linter's reach is the "lint-exempt
    directory = never cleaned" trap.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", TOOL],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    if proc.returncode == 127 or "No module named ruff" in (proc.stderr or ""):
        pytest.skip("ruff is not installed in this interpreter; the CI lint job covers it")
    assert proc.returncode == 0, (
        f"ruff reports problems in {_TOOL_INVOCATION}:\n{proc.stdout}\n{proc.stderr}"
    )
