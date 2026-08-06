"""INV-TEST-2 — the suite leaves no in-process state behind, and its fake module names are unique.

`test_zz_process_isolation.py` guards four SPECIFIC leaks found by earlier rounds: the promotion
witness, a stacked metric handler, a redirected registry path. This module guards the general
properties those were instances of — the ones that make `pytest -p randomly` meaningful at all.

Four properties measured across all 168 test files. All four hold; none was checked.

1. **No test writes `os.environ` without restoring it.** An AST scan found 10 real writes (as
   opposed to reads, which a grep for `os.environ[` cannot distinguish — 15 of those 25 hits were
   assertions). Every one is either a deliberate module-level `pop("*_LIVE")` — a safety measure
   keeping the live path off — or wrapped in `try/finally`.

2. **No `sys.modules` injection shadows a real importable module.** 48 bare assignments, all
   registering path-loaded modules under fabricated names. Zero collide with something importable.
   A shadowing entry would silently replace a real package for every LATER test in the process.

3. **The 19 fabricated names are unique across files.** Two files reusing one "unique" name means
   whichever imports second silently wins the cache, and the first file's tests then exercise the
   wrong module — passing, while testing something else.

4. **`conftest.py`'s credential fallback uses `setdefault`, never assignment**, so a test that
   sets its own region/role keeps it.

Why this file is named `test_zz_*`
----------------------------------
Alphabetically last, like its sibling, so in a fixed-order run it observes the process after
everything else has had its turn. Under `pytest-randomly` that ordering is not guaranteed — which
is the point of the AST checks: they are static and hold regardless of when they run.

ZERO network, ZERO AWS: parses test sources and inspects the live process.
"""
from __future__ import annotations

import ast
import collections
import os
import pathlib
import sys

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent


# The three un-normalised `sys.path.insert` sites present when this guard was written. Recorded
# rather than hidden: the guard fails on a NEW one, and this list shows the debt so it can shrink.
# The wider duplication (repo root 19x, tests/ 24x in a full run) mostly comes from pytest's own
# rootdir handling and from `if X not in sys.path` guards comparing STRINGS — `/repo` and
# `/repo/tests/..` are the same directory and different strings. Fixing that spans ~26 files and
# is its own change.
_KNOWN_UNNORMALISED_INSERTS = (
    ("test_bas_replay_scenario.py", 26),
    ("test_detonation_scenario.py", 31),
    ("test_egress_control.py", 28),
)


def _test_sources() -> list:
    return sorted(TESTS_DIR.rglob("test_*.py"))


def _parse(path: pathlib.Path):
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:  # pragma: no cover - the suite would not import either
        return None


def _string_constants(tree) -> dict:
    """Module-level `NAME = "literal"` bindings, for resolving variable subscript keys."""
    found = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            found[node.targets[0].id] = node.value.value
    return found


def _subscript_writes(tree, attribute: str) -> list:
    """`(lineno, key_node)` for every `<x>.<attribute>[...] = ...` assignment.

    Structural, not textual. A grep for `os.environ[` cannot tell an assignment from an
    assertion — 15 of 25 such hits in this suite are reads — and reporting reads as leaks
    would be a false alarm that trains people to ignore the guard.
    """
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == attribute):
                out.append((node.lineno, target.slice))
    return out


def _mutating_calls(tree, attribute: str) -> list:
    """`(lineno, method)` for `<x>.<attribute>.pop/update/clear(...)` — mutations, not reads."""
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in ("pop", "update", "clear"):
            continue
        owner = node.func.value
        if isinstance(owner, ast.Attribute) and owner.attr == attribute:
            out.append((node.lineno, node.func.attr))
    return out


def _is_importable_from_disk(name: str) -> bool:
    """Could Python import `name` from the filesystem, ignoring `sys.modules`?

    `importlib.util.find_spec` returns the spec of an ALREADY-REGISTERED module, so calling it
    directly made this check order-dependent: run alone it passed, run after the suite it reported
    47 "shadowing" names — every fabricated name the earlier tests had registered themselves.
    A check that answers differently depending on when it runs is the exact class of problem this
    module exists to detect, so it must not have that property itself.
    """
    for finder in sys.meta_path:
        find_spec = getattr(finder, "find_spec", None)
        if find_spec is None:
            continue
        # Skip the finder that answers from the sys.modules cache.
        if type(finder).__name__ == "BuiltinImporter":
            if name in sys.builtin_module_names:
                return True
            continue
        try:
            spec = find_spec(name, None)
        except (ImportError, AttributeError, ValueError):
            continue
        if spec is not None and getattr(spec, "origin", None) not in (None, "frozen"):
            return True
    return name in sys.builtin_module_names


def _enclosing_function(tree, lineno: int):
    """The innermost function containing `lineno`, or None if module scope."""
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        if node.lineno <= lineno <= end:
            if best is None or node.lineno > best.lineno:
                best = node
    return best


def _inside_try_finally(function, lineno: int) -> bool:
    """Is `lineno` inside the `try:` body of a `try/finally` within `function`?

    Structural containment, NOT `ast.dump()` + substring. My first version was
    `"Try(" in ast.dump(function) and "finalbody" in ...`, which `test_r18_guard_the_guards.py::
    test_no_test_substring_matches_an_ast_dump` failed — correctly, and it is the third time I
    have made this mistake. `ast.dump()` embeds every node's type name, so that test matches when
    the function contains ANY try/finally, including one that has nothing to do with the env write
    being judged. A protection check that cannot tell WHICH statement is protected is not a
    protection check.
    """
    for node in ast.walk(function):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        # The write may sit inside the `try:` body OR on a line just before it. The idiomatic
        # form is
        #     os.environ[KEY] = value
        #     try:
        #         ...
        #     finally:
        #         os.environ.pop(KEY, None)
        # and it is idiomatic for a reason: putting the assignment INSIDE the try means a failure
        # during the assignment still runs the finally, which would then clear a variable this
        # test never set. My first containment check only looked inside the body and flagged three
        # correctly-written tests in test_coverage_doc_runs_in_ci.py.
        #
        # So the window starts a few lines before the `try:` — enough for the setup line(s) — and
        # ends at the end of the try body. Bounded deliberately: a write 50 lines earlier is NOT
        # protected by this try, and treating it as protected would be the fail-open.
        # A mutation inside `finalbody` IS the restoration — flagging it as an unprotected write
        # was my next false positive after widening the window: the guard reported the cleanup
        # code as the leak.
        for stmt in node.finalbody:
            start = stmt.lineno
            end = getattr(stmt, "end_lineno", None) or start
            if start <= lineno <= end:
                return True

        body_end = max(
            (getattr(stmt, "end_lineno", None) or stmt.lineno) for stmt in node.body
        )
        if node.lineno - 3 <= lineno <= body_end:
            return True
    return False


def _asserts_absent(function, key) -> bool:
    """Does `function` assert `<key> not in os.environ`?

    That assertion is what makes a bare `pop` safe: the test proves the variable is still absent
    when it finishes, so the process is left as it was found.
    """
    for node in ast.walk(function):
        if not isinstance(node, ast.Assert):
            continue
        for compare in ast.walk(node.test):
            if not isinstance(compare, ast.Compare):
                continue
            if not any(isinstance(op, ast.NotIn) for op in compare.ops):
                continue
            left = compare.left
            left_name = left.id if isinstance(left, ast.Name) else (
                left.value if isinstance(left, ast.Constant) else None)
            right = compare.comparators[0] if compare.comparators else None
            if (left_name == key and isinstance(right, ast.Attribute)
                    and right.attr == "environ"):
                return True
    return False


def test_the_scan_sees_the_whole_suite():
    """Positive control. Every check below iterates the parsed sources; an empty list would make
    them all hold vacuously — the failure mode this repo records more than any other."""
    sources = _test_sources()
    assert len(sources) >= 150, (
        f"only found {len(sources)} test files under {TESTS_DIR}; this scan is now blind."
    )
    parsed = [p for p in sources if _parse(p) is not None]
    assert len(parsed) == len(sources), (
        f"{len(sources) - len(parsed)} test file(s) failed to parse — the scan silently skipped "
        "them, so its verdict covers less than it appears to."
    )


def test_every_env_write_inside_a_test_is_restored():
    """A test that sets an env var and leaves it changes the world for every LATER test.

    `pytest.MonkeyPatch` exists for this and most of the suite uses it. The exceptions are allowed
    only when the write is wrapped in `try/finally`, or is a module-level `pop` of a `*_LIVE`
    flag — a deliberate safety measure that must NOT be undone (restoring it would re-arm a live
    path mid-suite).
    """
    offenders = []
    for path in _test_sources():
        tree = _parse(path)
        if tree is None:
            continue
        source_lines = path.read_text(encoding="utf-8").splitlines()

        events = [(ln, "assign") for ln, _ in _subscript_writes(tree, "environ")]
        events += [(ln, method) for ln, method in _mutating_calls(tree, "environ")]

        for lineno, kind in events:
            function = _enclosing_function(tree, lineno)
            if function is None:
                # Module scope. Only a `pop` of an opt-in live flag is acceptable there.
                line = source_lines[lineno - 1] if lineno <= len(source_lines) else ""
                if kind == "pop" and "_LIVE" in line:
                    continue
                offenders.append(f"{path.name}:{lineno} (module scope, {kind})")
                continue
            if _inside_try_finally(function, lineno):
                continue

            # A `pop` that the test itself ASSERTS stayed popped is not a leak: it establishes a
            # precondition ("this var is absent") and then proves the code under test left it
            # absent. Net effect on the process is zero, so try/finally would add nothing.
            #
            # My first rule was "any env mutation needs try/finally", and it flagged two such
            # tests in test_r21_promotion_gate.py — the ones proving the promotion witness does
            # not outlive its call. Reporting a leak-proving test as a leak is the kind of false
            # alarm that teaches people to ignore a guard, so the question is NET EFFECT, not
            # whether a mutation appeared.
            if kind == "pop":
                key = None
                for node in ast.walk(function):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "pop"
                            and isinstance(node.func.value, ast.Attribute)
                            and node.func.value.attr == "environ" and node.args):
                        arg = node.args[0]
                        key = arg.id if isinstance(arg, ast.Name) else (
                            arg.value if isinstance(arg, ast.Constant) else None)
                        break
                if key is not None and _asserts_absent(function, key):
                    continue

            # A monkeypatch-based test never reaches here (it does not subscript os.environ).
            offenders.append(f"{path.name}:{lineno} ({function.name}, {kind})")

    assert not offenders, (
        "test(s) mutate os.environ without a try/finally and without monkeypatch:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse the `monkeypatch` fixture, or wrap in try/finally. An env var left set "
        "changes behaviour for every later test in the process, and only in some orders."
    )


def test_no_sys_modules_injection_shadows_a_real_module():
    """Registering a fake module under a REAL importable name replaces it for the whole process.

    48 bare `sys.modules[...] = ...` assignments exist, all deliberate: path-loaded tool and
    specialist modules registered under fabricated names, because two different
    `bedrock_entrypoint.py` files exist and a bare import would collide. This asserts none of the
    names is one Python could really import.
    """
    offenders = []
    for path in _test_sources():
        tree = _parse(path)
        if tree is None:
            continue
        constants = _string_constants(tree)
        for lineno, key in _subscript_writes(tree, "modules"):
            name = None
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                name = key.value
            elif isinstance(key, ast.Name):
                name = constants.get(key.id)
            if not name:
                continue  # an f-string or computed key: covered by the uniqueness test below
            root = name.split(".")[0]
            if _is_importable_from_disk(root):
                offenders.append(f"{path.name}:{lineno} -> {name!r} shadows a real module")
    assert not offenders, (
        "sys.modules injection(s) shadow an importable module:\n  " + "\n  ".join(offenders)
        + "\n\nEvery later test in the process would get the fake. Use a fabricated name."
    )


def test_the_fabricated_module_names_are_unique_across_files():
    """Two files reusing one "unique" name means the second import silently wins the cache.

    The first file's tests then exercise a module loaded from a different path — passing, while
    testing something else. That is worse than a failure: it is a green test with no subject.
    """
    owners: dict = collections.defaultdict(set)
    for path in _test_sources():
        tree = _parse(path)
        if tree is None:
            continue
        constants = _string_constants(tree)
        for _lineno, key in _subscript_writes(tree, "modules"):
            name = None
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                name = key.value
            elif isinstance(key, ast.Name):
                name = constants.get(key.id)
            if name:
                owners[name].add(path.name)

    assert owners, (
        "no sys.modules registrations found at all. The path-loading convention is central to "
        "this suite, so finding none means this scan is broken rather than the suite being clean."
    )
    shared = {name: sorted(files) for name, files in owners.items() if len(files) > 1}
    assert not shared, (
        f"fabricated module name(s) reused across files: {shared}. Whichever imports second wins "
        "`sys.modules`, so the other file's tests silently exercise a module loaded from a "
        "different path."
    )


def test_the_conftest_credential_fallback_never_clobbers_an_explicit_value():
    """`conftest.py` seeds fake AWS credentials so no test can touch a real account.

    It must use `setdefault`: a plain assignment would overwrite a region or role a test set on
    purpose, and the test would then assert against the wrong configuration while passing. The
    file says so in prose; this checks the code.
    """
    conftest = TESTS_DIR / "conftest.py"
    assert conftest.is_file(), "tests/conftest.py is missing"
    tree = _parse(conftest)
    assert tree is not None, "tests/conftest.py does not parse"

    bad = [lineno for lineno, _ in _subscript_writes(tree, "environ")]
    assert not bad, (
        f"tests/conftest.py assigns os.environ[...] directly at line(s) {bad}. Use "
        "`setdefault` so a test that sets its own region/role keeps it — otherwise the fallback "
        "silently overrides deliberate configuration."
    )
    # And that it really does seed credentials, or the isolation claim is empty.
    source = conftest.read_text(encoding="utf-8")
    for required in ("AWS_ACCESS_KEY_ID", "SENTINEL_EXECUTION_ROLE_ARN"):
        assert required in source, (
            f"conftest.py no longer seeds {required}; a test could reach a real account."
        )


def test_no_live_opt_in_flag_is_set_in_this_process():
    """Runtime check, complementing the static ones: no `*_LIVE` flag may be set as the suite runs.

    Every live path in this repo is gated behind an opt-in env flag. If any test set one and left
    it, a LATER test could make a real AWS or network call — the single worst leak this suite can
    have, and one no static scan can see because the value may arrive from the environment.
    """
    live = sorted(
        key for key in os.environ
        if key.startswith("SENTINEL_") and key.endswith("_LIVE")
        and os.environ[key].strip().lower() in ("1", "true", "yes", "on")
    )
    assert not live, (
        f"live opt-in flag(s) are set in this process: {live}. Either a test set one and did not "
        "restore it, or the suite is being run with them exported — both mean a later test may "
        "make a real call."
    )


def test_no_new_unnormalised_sys_path_insert_is_added():
    """`sys.path` insertions must be normalised, so the `if X not in sys.path` guards work.

    Measured in a full run: the repo root appears **19 times** on `sys.path` and `tests/` **24
    times**, plus four un-normalised equivalents of the same directories (`tests/..`,
    `scenarios/..`, `tests/../scenarios/..`). 38 insertions carry an
    `if REPO_ROOT not in sys.path` guard and 26 do not — and the guarded ones do not help, because
    the comparison is STRING equality: `/repo` and `/repo/tests/..` are the same directory and
    different strings, so the guard lets the duplicate through.

    That is real (import resolution order becomes collection-order dependent, and every import
    walks a longer path), and it is PRE-EXISTING technical debt across ~26 files. Cleaning it up is
    its own change; this assertion is deliberately scoped to what it can enforce today: **no new
    un-normalised insert**. An insert built from `os.path.join(..., "..")` without
    `os.path.realpath`/`abspath` is what creates a fresh alias of an existing entry.

    Stating the current count honestly rather than widening a threshold until it passes: a guard
    tuned to accept the status quo teaches nothing, and INV-DOC-2 records what happens when a
    number is adjusted to match reality instead of the reverse.
    """
    offenders = []
    for path in _test_sources():
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "insert":
                continue
            owner = node.func.value
            if not (isinstance(owner, ast.Attribute) and owner.attr == "path"):
                continue
            if len(node.args) < 2:
                continue
            # Inspected by NODE TYPE, never by substring-matching `ast.dump()`. This is the
            # FOURTH time in this repo I have reached for the dump-and-grep shortcut, and
            # `test_r18_guard_the_guards.py::test_no_test_substring_matches_an_ast_dump` caught it
            # every time: `ast.dump()` embeds each node's type name, so a marker can match
            # something structurally unrelated. Here it would also have been wrong in a specific
            # way — `"realpath"` appearing anywhere in the dumped subtree would excuse an
            # unrelated `..` segment.
            expression = node.args[1]
            has_dotdot = any(
                isinstance(child, ast.Constant) and child.value == ".."
                for child in ast.walk(expression)
            )
            if not has_dotdot:
                continue
            normalised = any(
                isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                and child.func.attr in ("realpath", "abspath", "resolve", "normpath")
                for child in ast.walk(expression)
            )
            if normalised:
                continue
            offenders.append(f"{path.name}:{node.lineno}")

    # The known-bad set at the time this guard was written. New entries fail; these are recorded
    # rather than hidden, so the debt is visible and shrinkable.
    known = {
        f"{name}:{line}" for name, line in _KNOWN_UNNORMALISED_INSERTS
    }
    new = sorted(set(offenders) - known)
    assert not new, (
        f"new un-normalised `sys.path.insert` call(s): {new}. Wrap the path in "
        "`os.path.realpath(...)` so the `if X not in sys.path` guards can actually match — "
        "otherwise this adds another alias of a directory already on the path, and import "
        "resolution order starts depending on collection order."
    )
    # Positive control: if the scan stops finding the known set, it has gone blind.
    stale = sorted(known - set(offenders))
    assert len(stale) < len(known), (
        f"this scan no longer finds ANY of the known un-normalised inserts ({sorted(known)}). "
        "Either they were all fixed — delete them from _KNOWN_UNNORMALISED_INSERTS and say so — "
        "or the detection broke."
    )

def _insert_sites() -> list:
    """`(file, lineno, guarded)` for every `sys.path.insert` in the suite.

    `guarded` is judged PER STATEMENT — is this call inside an `if <x> not in sys.path:` body —
    not by asking whether the file mentions that phrase anywhere. The round that first documented
    these figures used the file-level test and reported "38 guards"; the statement-level answer is
    37 guarded / 26 unguarded. A file-level substring test standing in for a statement-level
    structural question, committed while documenting a guard against exactly that.
    """
    sites = []
    for path in _test_sources():
        tree = _parse(path)
        if tree is None:
            continue

        guard_ranges = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            tests_sys_path = False
            for compare in ast.walk(node.test):
                if not isinstance(compare, ast.Compare):
                    continue
                if not any(isinstance(op, ast.NotIn) for op in compare.ops):
                    continue
                right = compare.comparators[0] if compare.comparators else None
                if isinstance(right, ast.Attribute) and right.attr == "path":
                    tests_sys_path = True
            if not tests_sys_path:
                continue
            for stmt in node.body:
                guard_ranges.append(
                    (stmt.lineno, getattr(stmt, "end_lineno", None) or stmt.lineno)
                )

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "insert":
                continue
            owner = node.func.value
            if not (isinstance(owner, ast.Attribute) and owner.attr == "path"):
                continue
            guarded = any(start <= node.lineno <= end for start, end in guard_ranges)
            sites.append((path.name, node.lineno, guarded))
    return sites


def test_the_documented_sys_path_figures_are_current():
    """INV-TEST-2 quotes counts for the `sys.path` debt. Numbers in a doc drift; this re-derives
    them.

    The first version of that invariant entry had three wrong figures — "38 guards" (37), "tests/
    24x" (25), and it omitted that the repo root appears 27x once aliases are resolved, which is the
    number that actually matters. Hand-written counts in a document describing a guard is the same
    shape as INV-DOC-2's stale coverage table, so the doc now states them and this checks them.
    """
    doc = (REPO_ROOT / "docs" / "INVARIANTS.md").read_text(encoding="utf-8")
    entry_start = doc.find("| **INV-TEST-2**")
    assert entry_start != -1, "INV-TEST-2 is gone from docs/INVARIANTS.md"
    entry = doc[entry_start:doc.find("\n", entry_start)]

    sites = _insert_sites()
    guarded = sum(1 for _f, _l, g in sites if g)
    unguarded = len(sites) - guarded

    # Tolerance of 0: these are exact counts derived from the same tree the doc describes.
    # BOTH spellings, not either. My first version used `or`, and the mutation "drop the
    # `63 sys.path entries` phrase" survived because the doc also says `63 insert sites` further
    # along — one claim going stale while an unrelated sentence kept the assertion satisfied. An
    # `or` across two independent statements of the same fact means neither is actually pinned.
    for phrase in (f"{len(sites)} `sys.path`", f"{len(sites)} insert sites"):
        assert phrase in entry, (
            f"INV-TEST-2 no longer states {phrase!r}. Both phrasings describe the same count "
            f"(total entries carried, and total insert sites), so both must track it — otherwise "
            f"one can go stale while the other keeps this check green.\n{entry[:400]}"
        )
    assert f"{unguarded} of the {len(sites)}" in entry, (
        f"INV-TEST-2 does not state that {unguarded} of {len(sites)} sites are unguarded "
        f"(it must, or the diagnosis reads as a guard problem rather than a missing-guard "
        f"problem):\n{entry[:400]}"
    )
    assert f"{guarded} that do" in entry, (
        f"INV-TEST-2 does not state the current guarded count of {guarded}:\n{entry[:400]}"
    )


def test_the_statement_level_guard_split_is_what_the_doc_claims():
    """Positive control for the scan above, and the correction it encodes.

    Asserts the split is non-trivial in BOTH directions: a scan reporting 0 unguarded would mean it
    stopped recognising bare inserts, and one reporting 0 guarded would mean it stopped recognising
    the `if ... not in sys.path` idiom. Either failure would make the figures above meaningless
    while still producing a number.
    """
    sites = _insert_sites()
    guarded = sum(1 for _f, _l, g in sites if g)
    unguarded = len(sites) - guarded
    assert len(sites) >= 50, f"only found {len(sites)} sys.path.insert sites — the scan is blind"
    assert guarded > 0, "the scan recognises no guarded inserts; the `if ... not in` detection broke"
    assert unguarded > 0, (
        "the scan recognises no UNGUARDED inserts. Either they were all fixed — a real "
        "improvement that must be reflected in INV-TEST-2 — or the detection broke."
    )
