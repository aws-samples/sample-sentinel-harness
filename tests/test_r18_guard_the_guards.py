"""
Round-18 — the guards are code too, so they get invariants.
===========================================================
Round 17 shipped three structural guards and **all three were broken on arrival**, each
caught by a positive control rather than by review:

1. ``_ALLOWED_BARE_BOOL`` was keyed by FILE, so it exempted a whole file forever — a
   fresh violation injected into ``feedback.py`` was not caught, because that file
   already held one legitimate ``bool()``. A fail-open, built into a mechanism whose
   only purpose is to prevent fail-open.
2. The provenance matcher substring-matched ``ast.dump()``, and every variable
   reference carries ``ctx=Load()`` — so the marker ``"load"`` matched *everything*.
   All 24 expressions were classified external, and it looked clean only because the
   allowlist covered them all.
3. The connector-injection assertion substring-matched a quote-then-operator sequence
   and flagged all seven **correctly escaped** backends; then, rewritten, it measured
   ``str(request)`` and so counted Python's repr escaping instead of the DSL's.

Three for three. A guard is as likely to be wrong as the code it guards, and nothing
was checking the guards — so this module does.

What the evidence actually supports
-----------------------------------
I proposed this round believing six control-less scanning tests were at risk. Measuring
it said otherwise, and the narrowing matters:

- ``test_exporter``-style tests assert a violation IS present (``assert "X" in code``).
  A broken search makes those FAIL, loudly. They cannot pass vacuously and are out of
  scope.
- The simple negative scans — one AST node type, one grepped word — were tested by
  INJECTION (a ``subprocess`` call added to ``simulation.py``; the grepped word removed
  from ``epss_kev``). **Both fired.** They are not blind.
- What went blind in round 17 both times was a scan carrying an **exemption
  mechanism**. An allowlist is the part that can swallow a real violation while the
  test still reports clean.

So the invariant is scoped to exemptions, not to scans. Today that is two files and both
already comply — this module is a ratchet, not a bug report, and the positive control at
the bottom is what makes a zero-violation guard worth having.

    INV-GUARD-1  an exemption is keyed to an EXPRESSION, never to a whole file
    INV-GUARD-2  a scan with an exemption mechanism has a positive control
    INV-GUARD-3  a scan with an exemption mechanism rejects stale entries
    INV-GUARD-4  a structural question is asked of the tree, not of a substring

Zero network, zero AWS: this reads ``tests/`` with ``ast``.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
THIS_FILE = pathlib.Path(__file__).name

# Calls that read source or walk a tree — the raw material of a structural scan.
_SCAN_CALLS = frozenset({"read_text", "getsource", "parse", "walk", "rglob", "glob"})

# Identifier fragments that mean "these findings are excused". An exemption is the
# component that can hide a real violation, which is why it — and not scanning in
# general — is what these invariants govern.
_EXEMPTION_HINTS = ("allow", "exempt", "skip", "ignore", "waive", "argued",
                    "known", "whitelist", "expected_offenders")

# Markers a positive control announces itself with. Kept as an explicit list so adding
# a control is a deliberate act rather than an accident of naming.
_CONTROL_MARKERS = ("POSITIVE CONTROL", "positive control", "CanActuallyDetect",
                    "can_actually_detect", "can_detect", "_can_see",
                    "proves nothing", "vacuous")


def _test_files() -> list[pathlib.Path]:
    return [p for p in sorted(TESTS_DIR.glob("test_*.py")) if p.name != THIS_FILE]


class _Analysis:
    """What one test module does, structurally."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.source = path.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.scans = False
        self.exemptions: list[tuple[str, ast.AST]] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = (getattr(node.func, "attr", None)
                        or getattr(node.func, "id", None))
                if name in _SCAN_CALLS:
                    self.scans = True
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    ident = (getattr(target, "id", None)
                             or getattr(target, "attr", None))
                    if not ident:
                        continue
                    low = ident.lower()
                    if any(hint in low for hint in _EXEMPTION_HINTS) and isinstance(
                            node.value,
                            (ast.Dict, ast.Set, ast.List, ast.Tuple, ast.Call)):
                        self.exemptions.append((ident, node.value))

    @property
    def has_positive_control(self) -> bool:
        return any(marker in self.source for marker in _CONTROL_MARKERS)

    @property
    def is_governed(self) -> bool:
        """A scan that also carries an exemption — the shape that went blind twice."""
        return self.scans and bool(self.exemptions)


def _governed() -> list[_Analysis]:
    return [a for a in (_Analysis(p) for p in _test_files()) if a.is_governed]


# --------------------------------------------------------------------------- #
# INV-GUARD-0 — the analysis itself is not vacuous                            #
# --------------------------------------------------------------------------- #
class TestTheAnalysisIsNotVacuous:
    """First, because every assertion below is a negative one: "no governed scan
    violates X". If `_governed()` returns nothing, they all pass and prove nothing.

    This is the same floor the round-17 guards needed, applied one level up. Writing it
    first is deliberate — the failure mode being guarded against is precisely that a
    later refactor of `_Analysis` silently stops finding anything.
    """

    def test_the_test_suite_is_found(self):
        files = _test_files()
        assert len(files) > 50, f"only found {len(files)} test modules — walk is broken"

    def test_scanning_tests_are_recognised(self):
        scanners = [a for a in (_Analysis(p) for p in _test_files()) if a.scans]
        assert len(scanners) >= 8, (
            f"only recognised {len(scanners)} scanning tests; the _SCAN_CALLS matcher "
            "has stopped matching"
        )

    def test_at_least_one_governed_scan_exists(self):
        """If this ever legitimately drops to zero, the invariants below are moot and
        should be deleted rather than left passing on an empty set."""
        governed = _governed()
        assert governed, (
            "no test carries both a scan and an exemption mechanism. Either the "
            "detection broke, or the guards were all removed — both need a human."
        )

    def test_the_exemption_detector_recognises_a_synthetic_one(self):
        """Prove the detector works, on source it has never seen."""
        synthetic = (
            "import pathlib\n"
            "_ALLOWED = {'a/b.py::expr': 'because'}\n"
            "def test_x():\n"
            "    src = pathlib.Path('x').read_text()\n"
            "    assert not [k for k in _ALLOWED if k not in src]\n"
        )
        tmp = TESTS_DIR / "_r18_probe_tmp.py"
        try:
            tmp.write_text(synthetic, encoding="utf-8")
            analysis = _Analysis(tmp)
            assert analysis.scans, "read_text() was not recognised as a scan"
            assert [name for name, _ in analysis.exemptions] == ["_ALLOWED"]
        finally:
            tmp.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# INV-GUARD-1 — an exemption is keyed to an EXPRESSION, never to a file       #
# --------------------------------------------------------------------------- #
class TestExemptionsAreExpressionScoped:
    """Round 17's `_ALLOWED_BARE_BOOL` was keyed by file path. That exempted every
    future violation in those files — and a positive control proved it: a fresh
    `bool(payload.get("looks_malicious"))` injected into `feedback.py` was NOT caught,
    because the file already held one legitimate `bool(withheld)`.

    A file-scoped exemption is the test-suite equivalent of a lint-exempt directory: it
    is never revisited, so it becomes permanent. The key must name the specific thing
    excused.
    """

    # A key that looks like `path/to/file.py` and nothing more is file-scoped.
    _BARE_PATH = re.compile(r"^[\w./-]+\.(?:py|ts|tf|yaml|yml|json|md)$")

    @staticmethod
    def _string_keys(container: ast.AST) -> list[str]:
        keys: list[str] = []
        if isinstance(container, ast.Dict):
            candidates = container.keys
        elif isinstance(container, (ast.Set, ast.List, ast.Tuple)):
            candidates = container.elts
        elif isinstance(container, ast.Call):
            # e.g. frozenset({...}) — look one level in.
            candidates = []
            for arg in container.args:
                candidates.extend(TestExemptionsAreExpressionScoped._raw_elements(arg))
        else:
            return keys
        for node in candidates:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                keys.append(node.value)
            elif isinstance(node, ast.JoinedStr):
                keys.append("<f-string>")
            elif isinstance(node, ast.BinOp):
                # Implicit or explicit string concatenation across lines.
                try:
                    keys.append(ast.literal_eval(node))
                except (ValueError, TypeError):
                    keys.append("<concatenated>")
        return keys

    @staticmethod
    def _raw_elements(node: ast.AST) -> list[ast.AST]:
        if isinstance(node, ast.Dict):
            return list(node.keys)
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            return list(node.elts)
        return []

    def test_no_exemption_is_keyed_to_a_bare_file_path(self):
        offenders: list[str] = []
        for analysis in _governed():
            for name, container in analysis.exemptions:
                for key in self._string_keys(container):
                    if self._BARE_PATH.match(key):
                        offenders.append(f"{analysis.path.name}: {name}[{key!r}]")
        assert not offenders, (
            "exemption(s) keyed to a whole FILE rather than to the specific thing "
            "excused:\n  " + "\n  ".join(offenders)
            + "\n\nA file-scoped exemption never gets revisited — round 17 proved it "
              "by injecting a fresh violation into an already-exempt file and watching "
              "the guard stay silent. Key it as '<path>::<exact expression>' (or "
              "whatever identifies the single site) so new code cannot inherit the "
              "exemption."
        )

    def test_the_bare_path_detector_works(self):
        """Positive control for the pattern above."""
        assert self._BARE_PATH.match("sentinel_harness/feedback.py")
        assert self._BARE_PATH.match("tools/siem_query/handler.py")
        # ...and an expression-scoped key is NOT flagged.
        assert not self._BARE_PATH.match(
            "sentinel_harness/feedback.py::r.get('fp_alert_ids')")
        assert not self._BARE_PATH.match("Metrics")          # a statement sid
        assert not self._BARE_PATH.match("AllowThisAccountOnly")


# --------------------------------------------------------------------------- #
# INV-GUARD-2 — a governed scan has a positive control                        #
# --------------------------------------------------------------------------- #
class TestGovernedScansHaveAPositiveControl:
    """All three round-17 guards were broken on arrival, and all three were caught by a
    positive control — never by reading them. That is the empirical case for requiring
    one wherever an exemption can hide a finding.

    Note what is NOT required: the simple negative scans (one AST node type, one grepped
    word) were tested by injection and both fired, so they are out of scope. Demanding a
    control from every scanning test would be cargo-culting; demanding it where an
    allowlist exists is responding to what actually failed.
    """

    def test_every_governed_scan_declares_a_positive_control(self):
        missing = [a.path.name for a in _governed() if not a.has_positive_control]
        assert not missing, (
            f"scan(s) with an exemption mechanism and no positive control: {missing}.\n"
            "Add a test that synthesizes a violation and asserts the scan names it. "
            "Every structural guard shipped in round 17 was broken on arrival, and a "
            "control — not review — is what caught each one."
        )

    def test_the_control_detector_does_not_accept_a_mere_mention(self):
        """Guard the guard: the marker list must not be so loose that any test with the
        word 'control' in a docstring counts. Checked against a synthetic module that
        talks about controls without having one."""
        prose_only = (
            '"""This module is about access control and control planes."""\n'
            "_ALLOWED = {'a::b': 'why'}\n"
        )
        tmp = TESTS_DIR / "_r18_probe_ctl.py"
        try:
            tmp.write_text(prose_only, encoding="utf-8")
            assert not _Analysis(tmp).has_positive_control, (
                "'access control' in prose was accepted as a positive control — the "
                "marker list is too loose to mean anything"
            )
        finally:
            tmp.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# INV-GUARD-3 — a governed scan rejects stale exemptions                      #
# --------------------------------------------------------------------------- #
class TestGovernedScansRejectStaleExemptions:
    """An exemption for a violation that no longer exists is worse than useless: it
    trains readers to skim the list, and it is how an allowlist rots into a blanket
    skip. Each governed scan must assert its own list has no dead entries."""

    _STALENESS_MARKERS = ("dead", "stale", "no longer", "still exist", "unused",
                          "not needed")

    def test_every_governed_scan_checks_for_dead_entries(self):
        missing = []
        for analysis in _governed():
            if not any(marker in analysis.source.lower()
                       for marker in self._STALENESS_MARKERS):
                missing.append(analysis.path.name)
        assert not missing, (
            f"scan(s) whose exemption list has no staleness check: {missing}. Add a "
            "test asserting every entry is still needed — an exemption nobody removes "
            "is an exemption nobody reads."
        )

    def test_every_exemption_entry_carries_a_reason(self):
        """A dict-shaped exemption maps key -> reason. An entry whose reason is empty or
        a placeholder is an exemption granted without an argument."""
        thin = []
        for analysis in _governed():
            for name, container in analysis.exemptions:
                if not isinstance(container, ast.Dict):
                    continue    # a set/list has nowhere to put a reason; see below
                for key, value in zip(container.keys, container.values):
                    reason = None
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        reason = value.value
                    elif isinstance(value, ast.BinOp):
                        try:
                            reason = ast.literal_eval(value)
                        except (ValueError, TypeError):
                            reason = "<concatenated>"
                    if reason is not None and len(reason.strip()) < 15:
                        key_text = getattr(key, "value", "<expr>")
                        thin.append(f"{analysis.path.name}: {name}[{key_text!r}] "
                                    f"-> {reason!r}")
        assert not thin, (
            "exemption(s) with no usable reason:\n  " + "\n  ".join(thin)
            + "\n\nAn exemption is a claim that the flagged thing is safe. Without the "
              "argument, a reviewer cannot check the claim."
        )


# --------------------------------------------------------------------------- #
# INV-GUARD-4 — a structural question is asked of the tree                    #
# --------------------------------------------------------------------------- #
class TestStructuralQuestionsUseTheTree:
    """Substring-matching stood in for a structural judgement **six times** in this
    repo before round 18:

      INV-FP-3        `"|contains" in field_name`
      R13b            `"not " in condition` credited an OR-widening as an exclusion
      INV-GATE-1      `"pass" in text` approved on "passable"/"compassion"
      INV-GATE-6      word-boundary matching then matched the JSON KEY `"pass"`
      INV-COERCE      `"load"` matched `ctx=Load()` on every AST node
      INV-CONNECTOR-8 `'" | '` matched inside a correctly-escaped `\\" | `

    The specific trap this guards is the worst of them: substring-matching
    ``ast.dump()``. That output contains node-type names and context markers for every
    node, so any short marker matches everything — and the resulting matcher reports a
    clean tree while being unable to distinguish anything.
    """

    def test_no_test_substring_matches_an_ast_dump(self):
        offenders: list[str] = []
        for path in _test_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # Find `ast.dump(...)` results that flow into a Compare with `In`.
            dumps: set[str] = set()
            for node in ast.walk(tree):
                if (isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Call)
                        and getattr(node.value.func, "attr", None) == "dump"):
                    for target in node.targets:
                        ident = getattr(target, "id", None)
                        if ident:
                            dumps.add(ident)
                # `x.lower()` of a dump keeps the taint.
                if (isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Call)
                        and getattr(node.value.func, "attr", None) == "lower"
                        and getattr(getattr(node.value.func, "value", None),
                                    "func", None) is not None
                        and getattr(node.value.func.value.func, "attr", None) == "dump"):
                    for target in node.targets:
                        ident = getattr(target, "id", None)
                        if ident:
                            dumps.add(ident)
            if not dumps:
                continue
            for node in ast.walk(tree):
                # BOTH `in` and `not in`: they are the same defect. Checking only
                # `ast.In` missed `assert 'load' not in dumped` — caught by the
                # end-to-end control, not by reading, which is the third time in this
                # round that a control found what review did not.
                if isinstance(node, ast.Compare) and any(
                        isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                    for comparator in node.comparators:
                        ident = getattr(comparator, "id", None)
                        if ident in dumps:
                            offenders.append(f"{path.name}:{node.lineno}")
        assert not offenders, (
            "test(s) substring-match an `ast.dump()` result:\n  "
            + "\n  ".join(offenders)
            + "\n\n`ast.dump()` embeds a node-type name and a context marker for EVERY "
              "node — `ctx=Load()` alone makes the marker 'load' match any expression. "
              "A matcher built that way reports a clean tree while being unable to "
              "distinguish anything, which is exactly how the round-17 coercion sweep "
              "shipped blind. Walk the tree and test node types instead."
        )

    def test_the_ast_dump_detector_works(self):
        """POSITIVE CONTROL. Without this the assertion above is one more unverified
        scan — which would be an unusually direct way to prove its own point."""
        synthetic = (
            "import ast\n"
            "def test_x(node):\n"
            "    dumped = ast.dump(node).lower()\n"
            "    return 'load' in dumped\n"
        )
        tmp = TESTS_DIR / "_r18_probe_dump.py"
        try:
            tmp.write_text(synthetic, encoding="utf-8")
            tree = ast.parse(synthetic)
            dumps = set()
            for node in ast.walk(tree):
                if (isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Call)
                        and getattr(node.value.func, "attr", None) == "lower"
                        and getattr(node.value.func.value.func, "attr", None) == "dump"):
                    dumps.update(t.id for t in node.targets
                                 if getattr(t, "id", None))
            assert dumps == {"dumped"}, (
                f"the detector did not recognise the tainted name: {dumps}"
            )
            found = [
                n.lineno for n in ast.walk(tree)
                if isinstance(n, ast.Compare)
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops)
                and any(getattr(c, "id", None) in dumps for c in n.comparators)
            ]
            assert found, "the detector cannot see `'load' in dumped`"
        finally:
            tmp.unlink(missing_ok=True)

    @pytest.mark.parametrize("comparison,label", [
        ("assert 'load' in dumped", "positive membership"),
        ("assert 'load' not in dumped", "NEGATED membership"),
    ])
    def test_both_membership_directions_are_detected(self, comparison, label):
        """`not in` is the same defect as `in` — a substring judgement on a dump. The
        first version of the detector only matched `ast.In`, so
        `assert 'load' not in dumped` slipped past. Found by the end-to-end control."""
        synthetic = (
            "import ast\n"
            "def test_x(node):\n"
            "    dumped = ast.dump(node).lower()\n"
            f"    {comparison}\n"
        )
        tree = ast.parse(synthetic)
        dumps = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and getattr(node.value.func, "attr", None) == "lower"
            and getattr(getattr(node.value.func.value, "func", None), "attr", None)
            == "dump"
            for target in node.targets
            if getattr(target, "id", None)
        }
        hits = [
            node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Compare)
            and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
            and any(getattr(c, "id", None) in dumps for c in node.comparators)
        ]
        assert hits, f"the detector cannot see {label}: {comparison}"


# --------------------------------------------------------------------------- #
# The ratchet's own positive control                                          #
# --------------------------------------------------------------------------- #
class TestTheseInvariantsWouldFireOnAViolation:
    """Every invariant above currently has ZERO violations — the two governed scans
    already comply. A zero-violation guard is indistinguishable from a broken one
    without this, and given that all three round-17 guards were wrong on arrival, the
    prior on "my new guard works" is not high.

    Each test writes a synthetic violating module into `tests/`, runs the real predicate
    over it, and removes it. Nothing tracked is modified.
    """

    def _with_probe(self, source: str, name: str):
        path = TESTS_DIR / name
        path.write_text(source, encoding="utf-8")
        try:
            return _Analysis(path)
        finally:
            path.unlink(missing_ok=True)

    def test_a_file_scoped_exemption_is_caught(self):
        analysis = self._with_probe(
            "import pathlib\n"
            "_ALLOWED = {'sentinel_harness/feedback.py': 'presence test on a list'}\n"
            "def test_x():\n"
            "    assert not pathlib.Path('x').read_text()\n",
            "_r18_probe_filekey.py",
        )
        assert analysis.is_governed
        keys = TestExemptionsAreExpressionScoped._string_keys(
            analysis.exemptions[0][1])
        flagged = [k for k in keys
                   if TestExemptionsAreExpressionScoped._BARE_PATH.match(k)]
        assert flagged == ["sentinel_harness/feedback.py"], (
            "INV-GUARD-1 cannot see a file-scoped exemption — the very defect it "
            "exists for"
        )

    def test_a_missing_positive_control_is_caught(self):
        analysis = self._with_probe(
            "import pathlib\n"
            "_ALLOWED = {'a.py::expr': 'a sufficiently long stated reason here'}\n"
            "def test_x():\n"
            "    assert not pathlib.Path('x').read_text()\n",
            "_r18_probe_nocontrol.py",
        )
        assert analysis.is_governed
        assert not analysis.has_positive_control, (
            "INV-GUARD-2 cannot see a governed scan with no control"
        )

    def test_a_reasonless_exemption_is_caught(self):
        analysis = self._with_probe(
            "import pathlib\n"
            "_ALLOWED = {'a.py::expr': 'ok'}\n"
            "def test_x():\n"
            "    assert not pathlib.Path('x').read_text()\n",
            "_r18_probe_noreason.py",
        )
        container = analysis.exemptions[0][1]
        reasons = [v.value for v in container.values
                   if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        assert reasons == ["ok"]
        assert len(reasons[0].strip()) < 15, (
            "INV-GUARD-3's reason-length floor would not flag 'ok'"
        )

    def test_a_missing_staleness_check_is_caught(self):
        analysis = self._with_probe(
            "import pathlib\n"
            "_ALLOWED = {'a.py::expr': 'a sufficiently long stated reason here'}\n"
            "def test_x():\n"
            "    assert not pathlib.Path('x').read_text()\n",
            "_r18_probe_nostale.py",
        )
        markers = TestGovernedScansRejectStaleExemptions._STALENESS_MARKERS
        assert not any(m in analysis.source.lower() for m in markers), (
            "INV-GUARD-3's staleness detector fires on a module that has no such check"
        )

    def test_the_probes_leave_nothing_behind(self):
        """A test that writes into `tests/` must clean up, or the next collection picks
        the probe up as a real test module."""
        leftovers = sorted(p.name for p in TESTS_DIR.glob("_r18_probe*"))
        assert not leftovers, f"probe files left behind: {leftovers}"


# --------------------------------------------------------------------------- #
# The END-TO-END control — the one that found what the unit controls missed    #
# --------------------------------------------------------------------------- #
class TestTheAssembledSuiteFiresEndToEnd:
    """The in-module controls above prove each PREDICATE can see a violation. This
    proves the assembled SUITE does — that each predicate is wired to an assertion that
    actually runs over the real test directory.

    That distinction earned its keep immediately, twice:

    1. My first e2e probes were named ``_r18_e2e_*.py``. ``_test_files()`` globs
       ``test_*.py`` (correctly — pytest collects the same set), so the probes were
       invisible and all three reported MISSED. **A "the guard is blind" conclusion can
       come from a broken probe**, so a control needs its own sanity check; that is what
       `test_a_clean_probe_does_not_trip_anything` below is for.
    2. With the naming fixed, INV-GUARD-4 still missed its probe: the detector matched
       only ``ast.In`` and the probe used ``assert 'load' not in dumped``. ``not in`` is
       the same defect. **The unit control had the same blind spot as the code**, because
       I wrote both from the same wrong mental model — which is exactly why an
       independent, end-to-end path matters.

    Round 16 shipped a ``_NoRedirect`` class that existed but was never installed. Same
    gap, different shape.
    """

    _PROBES = {
        # INV-GUARD-1: keyed to a whole file. Carries a control marker and a staleness
        # marker so ONLY the file-scope invariant fires.
        "test_r18_probe_filekey.py": (
            "import pathlib\n"
            "_ALLOWED_THINGS = {'sentinel_harness/feedback.py': "
            "'a sufficiently long stated reason for this exemption'}\n"
            "def test_scan():\n"
            "    src = pathlib.Path('x').read_text()\n"
            "    assert not [k for k in _ALLOWED_THINGS if k in src]\n"
            "# no longer needed entries are pruned\n"
            "# POSITIVE CONTROL lives elsewhere\n"
        ),
        # INV-GUARD-2: an exemption with no positive control.
        "test_r18_probe_nocontrol.py": (
            "import pathlib\n"
            "_ALLOWED_THINGS = {'a.py::some.expr()': "
            "'a sufficiently long stated reason for this exemption'}\n"
            "def test_scan():\n"
            "    src = pathlib.Path('x').read_text()\n"
            "    assert not [k for k in _ALLOWED_THINGS if k in src]\n"
            "# no longer needed entries are pruned\n"
        ),
        # INV-GUARD-4: substring-matching an ast.dump(), in the NEGATED form.
        "test_r18_probe_astdump.py": (
            "import ast\n"
            "def test_scan(node):\n"
            "    dumped = ast.dump(node).lower()\n"
            "    assert 'load' not in dumped\n"
        ),
    }

    @staticmethod
    def _run_suite() -> tuple[int, str]:
        """Run the rest of THIS module in a child pytest.

        `sys.executable` rather than a bare `python`: the suite runs under `uv`, whose
        interpreter is the only one with pytest importable. A bare `python` produced an
        empty output and an exit code that read as "the guard fired" — a false positive
        in the control itself, which is the third such miscue in this round and the
        reason `test_a_clean_probe_does_not_trip_anything` exists.
        """
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pytest", f"tests/{THIS_FILE}", "-q", "--no-header",
             "-p", "no:randomly", "-p", "no:cacheprovider",
             # Skip THIS class, or the child recurses into another child.
             "--deselect",
             f"tests/{THIS_FILE}::TestTheAssembledSuiteFiresEndToEnd"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
        )
        return result.returncode, result.stdout + result.stderr

    def test_a_clean_probe_does_not_trip_anything(self):
        """Sanity-check the CONTROL: a compliant module must leave the suite green.
        Without this, a probe that is simply invisible would read as "the guard works"
        in the tests below — and an invisible probe is exactly what happened first."""
        path = TESTS_DIR / "test_r18_probe_clean.py"
        path.write_text(
            "import pathlib\n"
            "_ALLOWED_THINGS = {'a.py::some.expr()': "
            "'a sufficiently long stated reason for this exemption'}\n"
            "def test_scan():\n"
            "    src = pathlib.Path('x').read_text()\n"
            "    assert not [k for k in _ALLOWED_THINGS if k in src]\n"
            "# no longer needed entries are pruned\n"
            "# POSITIVE CONTROL: this module has one\n",
            encoding="utf-8",
        )
        try:
            code, output = self._run_suite()
            assert code == 0, (
                "a COMPLIANT probe made the suite fail, so the failures below prove "
                f"nothing about detection:\n{output[-600:]}"
            )
        finally:
            path.unlink(missing_ok=True)

    @pytest.mark.parametrize("name", sorted(_PROBES))
    def test_the_suite_names_a_violating_module(self, name):
        path = TESTS_DIR / name
        path.write_text(self._PROBES[name], encoding="utf-8")
        try:
            code, output = self._run_suite()
            assert code != 0, (
                f"the assembled suite passed with {name} present — the predicate is "
                "not wired to an assertion that runs"
            )
            assert name in output, (
                f"the suite failed but never named {name}, so the failure may be "
                f"unrelated:\n{output[-600:]}"
            )
        finally:
            path.unlink(missing_ok=True)

    def test_no_probe_is_left_behind(self):
        """A test that writes into `tests/` must clean up, or the next collection picks
        the probe up as a real module and the suite fails for the wrong reason."""
        leftovers = sorted(p.name for p in TESTS_DIR.glob("test_r18_probe*"))
        assert not leftovers, f"probe files left behind: {leftovers}"
