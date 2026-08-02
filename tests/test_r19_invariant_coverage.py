"""
Round-19 — INVARIANTS.md as an executable coverage report.
==========================================================
`docs/INVARIANTS.md` holds 128 invariants across 31 families from nineteen audit rounds.
Nothing answered the one question that has consistently paid off:

    which shipped module has NO invariant naming it?

Round 16 asked it BY HAND, found four modules with tests but zero invariants, and the
worst finding of that round was in them — Play Mode's central safety claim ("no offensive
action without explicit human confirmation") turned out to be falsifiable by editing a
JSON file. Nine defects came out of those four modules.

So this module makes the question mechanical. It is a **selection mechanism**: it says
where to look next instead of leaving that to whoever remembers what has been audited.
When a new module lands with no invariant, `_UNCOVERED` goes stale and the build says so.

What it does NOT do, deliberately
---------------------------------
It does not require every module to have an invariant. Plenty legitimately do not — a
pretty-printer, a dataclass container, a re-export shim. Demanding blanket coverage would
produce ceremonial invariants, which are worse than none: they make the map lie.

Instead the uncovered set is an explicit, argued list. Adding to it is a decision a
reviewer can check ("why does the control plane need no invariant?"); leaving it stale is
a build failure. That is the INV-GUARD-1 lesson applied here — an exemption must name the
specific thing excused and be pruned when it no longer applies.

Zero network, zero AWS: this reads the doc and the source tree.
"""
from __future__ import annotations

import pathlib
import re

import pytest

import child_pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC_PATH = REPO_ROOT / "docs" / "INVARIANTS.md"

# Trees a reader would expect invariants to govern. `scenarios/` and `demo/` are excluded:
# they are executable documentation, and their behaviour is asserted by the evidence files
# they produce rather than by an invariant.
_SHIPPED_TREES = ("sentinel_harness", "tools", "intake")

# Below this, a module is a re-export shim or a constants file with no behaviour to
# govern. Chosen from the actual distribution, not a round number: the smallest module
# carrying real logic in this repo is ~40 lines.
_MIN_GOVERNABLE_LINES = 20

# Modules with NO invariant, each with the reason that is acceptable — or, for the ones
# under audit, the round that will fix it. This list is the round-19 coverage map's
# output, and it is expected to SHRINK.
#
# A module here is a claim that either (a) it holds no security-relevant decision, or
# (b) it is queued. Both are checkable by a reviewer, which is the point.
_UNCOVERED: dict[str, str] = {
    # --- QUEUED, NOT YET AUDITED --------------------------------------------------
    # Round 19 produced this list, then spent itself on `registry_live` (INV-REGISTRY,
    # a real defect: the DRAFT guarantee was asserted, not verified) and on the four
    # surviving egress copies it found while there (INV-EGRESS-3). These five were NOT
    # examined. Saying "under audit" of a module nobody looked at is the same lie this
    # whole module exists to prevent, so they are labelled as queued and the round that
    # will take them is left open rather than promised.
    "tools/harness_ops/handler.py":
        "QUEUED (round 20 candidate, highest weight at 329 lines): the harness lifecycle "
        "control plane — claims create/update/invoke/promote are deterministic and never "
        "model-authored HTTP. Not yet examined.",
    "sentinel_harness/mcp_server.py":
        "QUEUED: exposes 20 tools over stdio to any MCP client — the external trust "
        "boundary, and the only module here reachable by an untrusted peer. Not yet "
        "examined.",
    "tools/create_ticket/handler.py":
        "QUEUED: the SecOps write path, where agent output becomes a durable record. "
        "Not yet examined.",
    "tools/web_search/handler.py":
        "QUEUED for BEHAVIOUR: round 19 fixed its egress copy (INV-EGRESS-3), but that "
        "invariant governs the shared parser, not this handler's own text-only / bounded "
        "-response claims. INV-BOUNDARY covers its siblings and not this one.",
    "intake/adapter.py":
        "QUEUED: round 14 probed it and REFUTED all four findings; the confirmed negative "
        "has not been re-derived with the dimensions round 14 skipped.",

    # --- ARGUED: no security-relevant decision ------------------------------------
    "sentinel_harness/logutil.py":
        "logger construction only — it makes no decision. Round 19 did find that its "
        "`propagate = False` breaks any `caplog` assertion elsewhere in the suite "
        "(see INV-REGISTRY), which is a testing hazard, not a security decision.",
    "sentinel_harness/benchmark_models.py":
        "model metadata tables (ids, context windows, prices) — data, not logic",
    "sentinel_harness/observability.py":
        "emits spans and metrics; a defect misreports telemetry rather than changing a "
        "security decision. NOT checked for leaking secrets into span attributes, which "
        "would change this classification — queued with the others.",
    "sentinel_harness/tracing.py":
        "the OTEL exporter wiring; same reasoning, and the same unchecked leak question",
    "sentinel_harness/benchmark.py":
        "a model-comparison harness whose scores inform a human's model choice; it gates "
        "nothing automatically. That reading is from the code, not from an audit.",
}


def _doc_text() -> str:
    return DOC_PATH.read_text(encoding="utf-8")


def _invariant_rows() -> list[list[str]]:
    """Every invariant table row, split into cells on UNESCAPED pipes.

    An invariant description may contain a literal `\\|` (a Sigma `field|base64`
    modifier), which is not a column separator — the same care `test_invariants_doc`
    takes.
    """
    rows = []
    for line in _doc_text().splitlines():
        if not line.startswith("| **INV-"):
            continue
        cells = [c.strip().replace(r"\|", "|")
                 for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) >= 4:
            rows.append(cells)
    return rows


def _named_code_tokens() -> set[str]:
    """Every backticked token from the Owner and Enforced-by columns.

    Those two columns are where an invariant says WHICH CODE it governs and WHICH TEST
    proves it, so their union is the set of things claimed to be covered.
    """
    tokens: set[str] = set()
    for cells in _invariant_rows():
        for token in re.findall(r"`([^`]+)`", cells[2] + " " + cells[3]):
            tokens.add(token)
    return tokens


def _shipped_modules() -> dict[str, int]:
    """relpath -> line count, for modules carrying enough code to govern."""
    modules: dict[str, int] = {}
    for tree in _SHIPPED_TREES:
        base = REPO_ROOT / tree
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts or "build" in path.parts:
                continue
            lines = len(path.read_text(encoding="utf-8").splitlines())
            if lines < _MIN_GOVERNABLE_LINES:
                continue
            modules[str(path.relative_to(REPO_ROOT))] = lines
    return modules


def _module_key(relpath: str) -> str:
    """The name an invariant would use for this module.

    Invariants name `simulation.save_checkpoint` and `asset_lookup._normalize_service`,
    so the match is on the module stem — and for `tools/<name>/handler.py` on the TOOL
    name, since that is what the Owner column says.
    """
    path = pathlib.Path(relpath)
    return path.parent.name if path.stem == "handler" else path.stem


def _uncovered() -> dict[str, int]:
    tokens = " ".join(sorted(_named_code_tokens()))
    return {
        relpath: lines
        for relpath, lines in _shipped_modules().items()
        if _module_key(relpath) not in tokens
    }


# --------------------------------------------------------------------------- #
# INV-AUDITMAP-0 — the map is not vacuous                                     #
# --------------------------------------------------------------------------- #
class TestTheMapIsNotVacuous:
    """Every assertion below is negative ("no module is unaccounted for"), so an empty
    parse passes them all. This floor goes first — the INV-GUARD-0 pattern, which exists
    because three round-17 guards shipped blind."""

    def test_the_doc_parses_into_invariant_rows(self):
        rows = _invariant_rows()
        assert len(rows) >= 100, (
            f"only parsed {len(rows)} invariant rows from {DOC_PATH.name}; the table "
            "format changed and this whole module is now blind"
        )

    def test_the_owner_columns_name_code(self):
        tokens = _named_code_tokens()
        assert len(tokens) >= 60, (
            f"only {len(tokens)} code tokens extracted from the Owner/Enforced-by "
            "columns — the extraction is broken"
        )
        # Spot-check a few known owners, so a regex change that silently narrows the
        # extraction fails here rather than showing up as phantom "uncovered" modules.
        for expected in ("agent_loop.run_agent_loop", "loop_safety.apply_safety_veto"):
            assert any(expected in t for t in tokens), (
                f"a known owner {expected!r} is no longer extracted"
            )

    def test_the_source_tree_is_found(self):
        modules = _shipped_modules()
        assert len(modules) >= 40, (
            f"only found {len(modules)} shipped modules; the tree walk is broken"
        )

    def test_coverage_is_substantial(self):
        """A floor on the RATIO, so a regex change that stops matching anything shows up
        as a coverage collapse rather than as 50 new 'uncovered' modules."""
        modules = _shipped_modules()
        uncovered = _uncovered()
        ratio = 1 - len(uncovered) / len(modules)
        assert ratio >= 0.6, (
            f"only {ratio:.0%} of shipped modules are named by an invariant "
            f"({len(uncovered)} of {len(modules)} uncovered). Either coverage "
            "regressed badly, or the matcher broke."
        )


# --------------------------------------------------------------------------- #
# INV-AUDITMAP-1 — every uncovered module is accounted for                    #
# --------------------------------------------------------------------------- #
class TestEveryUncoveredModuleIsAccountedFor:
    """The selection mechanism. A module with no invariant is not automatically a
    problem — but it must be a DECISION, not an oversight.

    Round 16's four zero-invariant modules yielded nine defects, including the worst
    finding of that round. That is the empirical case for making this a build failure
    rather than a periodic manual sweep.
    """

    def test_no_module_is_silently_uncovered(self):
        unexplained = sorted(set(_uncovered()) - set(_UNCOVERED))
        assert not unexplained, (
            "shipped module(s) with NO invariant naming them, and no entry in "
            "_UNCOVERED explaining why:\n  "
            + "\n  ".join(f"{m}  ({_uncovered()[m]} lines)" for m in unexplained)
            + "\n\nEither add an invariant to docs/INVARIANTS.md naming this module, or "
              "add it to _UNCOVERED here with the reason it holds no security-relevant "
              "decision. Round 16 found nine defects in four such modules — an "
              "unaudited module is not the same as a safe one."
        )

    def test_no_entry_in_the_uncovered_list_is_stale(self):
        """The other direction. An entry for a module that IS now covered means the list
        has stopped tracking reality — and a stale exemption is how a list rots into a
        blanket skip (INV-GUARD-3's lesson, applied one level up)."""
        stale = sorted(set(_UNCOVERED) - set(_uncovered()))
        assert not stale, (
            f"_UNCOVERED lists module(s) that now HAVE an invariant: {stale}. Remove "
            "them — the list only means something if it tracks reality."
        )

    def test_every_uncovered_entry_carries_a_real_reason(self):
        thin = {m: r for m, r in _UNCOVERED.items() if len(r.strip()) < 30}
        assert not thin, (
            f"_UNCOVERED entries with no usable reason: {thin}. The reason is the claim "
            "a reviewer checks; without it the entry is just a silencer."
        )

    def test_no_entry_names_a_module_that_does_not_exist(self):
        missing = [m for m in _UNCOVERED if not (REPO_ROOT / m).is_file()]
        assert not missing, (
            f"_UNCOVERED names deleted/moved module(s): {missing}"
        )


# --------------------------------------------------------------------------- #
# INV-AUDITMAP-2 — the highest-risk trees are fully covered                   #
# --------------------------------------------------------------------------- #
class TestTheSecurityCriticalModulesAreCovered:
    """Not every module needs an invariant, but some do. These are the ones whose
    defects have historically been the worst: the promotion path, the sandbox, the
    provenance ledger, the safety combiner. A regression that removed their invariants
    would otherwise be invisible."""

    _MUST_BE_COVERED = (
        "sentinel_harness/agent_loop.py",       # INV-PROMOTE, INV-LOOP
        "sentinel_harness/autonomy.py",         # the promotion gate
        "sentinel_harness/loop_safety.py",      # the safety veto
        "sentinel_harness/sandbox_hooks.py",    # INV-SANDBOX
        "sentinel_harness/provenance.py",       # the audit ledger
        "sentinel_harness/simulation.py",       # INV-PLAY
        "sentinel_harness/egress.py",           # INV-EGRESS
        "sentinel_harness/connectors/siem.py",  # INV-CONNECTOR
    )

    @pytest.mark.parametrize("relpath", _MUST_BE_COVERED)
    def test_a_security_critical_module_has_an_invariant(self, relpath):
        assert (REPO_ROOT / relpath).is_file(), f"{relpath} moved or was deleted"
        assert relpath not in _uncovered(), (
            f"{relpath} has NO invariant naming it. This module is on the "
            "must-be-covered list because its defects have been the worst in this "
            "codebase's history; losing its invariants must not be silent."
        )


# --------------------------------------------------------------------------- #
# The map's own positive control                                              #
# --------------------------------------------------------------------------- #
class TestTheMapCanDetectAnUncoveredModule:
    """A coverage map that reports "all accounted for" is indistinguishable from a broken
    one. Round 18 established this the hard way: three structural guards shipped blind and
    a positive control caught each.

    These synthesize the two failure directions against the real extraction functions,
    without touching the tree.
    """

    def test_a_module_named_by_no_invariant_is_reported_uncovered(self):
        tokens = " ".join(sorted(_named_code_tokens()))
        # A name that certainly appears in no invariant.
        assert _module_key("sentinel_harness/zzz_nonexistent.py") not in tokens
        # ...and one that certainly does.
        assert _module_key("sentinel_harness/agent_loop.py") in tokens, (
            "the matcher no longer recognises a covered module, so every 'uncovered' "
            "verdict below is suspect"
        )

    def test_the_tool_handler_key_is_the_tool_name(self):
        """`tools/<name>/handler.py` must key on `<name>` — every handler shares the stem
        'handler', so keying on the stem would make all 20 tools look identical and the
        map would report them all covered the moment ONE was."""
        assert _module_key("tools/siem_query/handler.py") == "siem_query"
        assert _module_key("tools/harness_ops/handler.py") == "harness_ops"
        assert _module_key("sentinel_harness/agent_loop.py") == "agent_loop"

    def test_a_stale_entry_would_be_detected(self):
        """Simulate the other direction: an entry for a module that IS covered."""
        fake_uncovered = dict(_UNCOVERED)
        fake_uncovered["sentinel_harness/agent_loop.py"] = "a bogus stale entry here"
        stale = sorted(set(fake_uncovered) - set(_uncovered()))
        assert "sentinel_harness/agent_loop.py" in stale, (
            "the staleness check cannot see an entry for an already-covered module"
        )

    def test_a_thin_reason_would_be_detected(self):
        fake = {"tools/x/handler.py": "todo"}
        thin = {m: r for m, r in fake.items() if len(r.strip()) < 30}
        assert thin, "the reason-length floor would not flag 'todo'"

    def test_the_real_reasons_all_clear_the_floor(self):
        """CONTROL for the control: the floor must not be so high that every legitimate
        reason trips it."""
        for module, reason in _UNCOVERED.items():
            assert len(reason.strip()) >= 30, (module, reason)


# --------------------------------------------------------------------------- #
# The map's END-TO-END control                                                #
# --------------------------------------------------------------------------- #
class TestTheAssembledMapFiresEndToEnd:
    """The controls above prove the extraction functions work. This proves they are wired
    to an assertion that runs — the distinction that mattered in round 18, where a unit
    control shared its blind spot with the code and only an end-to-end path found it.

    The child launch goes through ``child_pytest.run_child_suite``, which resolves a
    launcher that works in THIS environment and raises rather than returning a non-zero
    exit when the child never ran. That indirection exists because this launcher has been
    wrong three times — bare ``python`` (no pytest), ``sys.executable`` (right only when
    the parent is pytest), ``uv run pytest`` (right only where uv is installed; CI has no
    uv) — and every one of those failures LOOKED like the guard firing.
    """

    _PROBE = REPO_ROOT / "sentinel_harness" / "zz_r19_coverage_probe.py"
    _BODY = ('"""A probe module that no invariant names."""\n'
             + "\n".join(f"CONST_{i} = {i}" for i in range(30)) + "\n")

    @staticmethod
    def _run_suite():
        this_file = pathlib.Path(__file__).name
        return child_pytest.run_child_suite(
            this_file,
            deselect=(f"tests/{this_file}::TestTheAssembledMapFiresEndToEnd",),
        )

    def test_the_child_pytest_can_actually_run(self):
        """Without this, any child-launch failure reads as "the map fired". A launcher
        that cannot start raises `ChildNeverRan` from inside `run_child_suite`, so this
        only has to check that the CLEAN tree passes."""
        result = self._run_suite()
        assert result.returncode == 0, (
            f"the child fails on the CLEAN tree:\n{result.output[-400:]}"
        )

    def test_a_new_uncovered_module_fails_the_build(self):
        """The whole point: a module lands with no invariant, and the build says so —
        naming the file, so the next round's target picks itself."""
        try:
            self._PROBE.write_text(self._BODY, encoding="utf-8")
            result = self._run_suite()
            assert result.suite_failed, (
                "a module with no invariant did NOT fail the suite — the map is not "
                "wired to an assertion that runs"
            )
            assert self._PROBE.name in result.output, (
                f"the suite failed but never named the module, so the failure may be "
                f"unrelated:\n{result.output[-500:]}"
            )
        finally:
            self._PROBE.unlink(missing_ok=True)

    def test_the_probe_leaves_nothing_behind(self):
        assert not self._PROBE.exists(), (
            f"{self._PROBE.name} was left in the tree — the next collection would fail "
            "for the wrong reason, and the module would ship"
        )
