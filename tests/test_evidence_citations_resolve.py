"""INV-EVIDENCE-2 — every `evidence/*.json` a doc cites as PROOF actually exists.

`evidence/` is the strongest claim this repository makes: 38 artifacts asserting that specific
behaviour was observed. The docs cite 31 of them by path, and a reader follows those paths to check
the work. INV-EVIDENCE-1 guards that committed evidence is byte-REPRODUCIBLE by re-running its
scenario. Nothing guarded that a cited path RESOLVES.

The gap is narrow and real. Measured three ways:

    delete a cited artifact           -> 4 tests fail  (count guards + the demo tour)
    rename one the DEMO reads         -> 1 test fails  (test_platform_demo, incidentally)
    rename one only the DOCS cite     -> 4119 passed, 20 skipped   <-- nothing

Eight artifacts are cited by a doc and named by no code at all — `closed_loop_result.json`,
`live_memory_isolation_result.json`, `live_verify_result.json` and five more. For those, the only
thing connecting the claim to the file is the sentence in the doc, so a rename leaves
`docs/ROADMAP.md` pointing at a path that 404s while the whole suite reports green. The count guards
do not help: they count artifacts, and a rename keeps the count.

Why an "all references must resolve" check would be WRONG
---------------------------------------------------------
`docs/COOKBOOK.md` is a TUTORIAL — "add a new tool", worked through with a fictional `geo_lookup`.
It cites four paths that deliberately do not exist:

    evidence/geo_lookup_result.json      evidence/geo_triage_result.json
    evidence/geo_enrichment_result.json  evidence/geo_intel_a2a_result.json

Its heading is "**Evidence to drop**" and the surrounding prose is imperative: it tells the reader to
CREATE that file. There is no `tools/geo_lookup/`, no `scenarios/scenario_geo_lookup.py`, and none is
claimed. My first scan reported all four as "docs cite a missing artifact", and acting on that would
have meant either fabricating four artifacts for a fictional tool or gutting the tutorial — a scanner
lacking context, reported as a defect. Recording it because the next person to automate this will hit
the same trap.

So the rule is about the KIND of claim, not the presence of a path: a doc that says "see
evidence/x.json" is asserting x.json exists; a tutorial that says "write your result to
evidence/x.json" is not. The tutorial is exempted BY FILE, and the exemption carries its own guard —
if COOKBOOK ever starts citing artifacts that do exist, or a non-tutorial doc starts citing
`geo_*`, the exemption has stopped matching reality and this fails.

ZERO network, ZERO AWS: reads docs and the filesystem.
"""
from __future__ import annotations

import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(REPO_ROOT, "evidence")
DOCS_DIR = os.path.join(REPO_ROOT, "docs")

# Docs whose evidence paths are INSTRUCTIONS to create a file, not claims that one exists.
#
# Only COOKBOOK.md qualifies: it is a step-by-step "add a new tool" guide built around a fictional
# `geo_lookup`, under a heading that reads "Evidence to drop". Everything else in docs/ cites
# evidence as proof of work already done.
_TUTORIAL_DOCS = {
    "COOKBOOK.md": (
        "a step-by-step 'add a new tool' tutorial; its evidence paths are targets for the reader to "
        "create, built around the fictional `geo_lookup` tool that deliberately does not exist"
    ),
}

# The fictional tool the tutorial is written around. Named so the exemption can be checked for
# still matching what COOKBOOK actually contains, rather than being a blanket pass.
_TUTORIAL_FICTION_PREFIX = "geo_"

_EVIDENCE_REF = re.compile(r"evidence/([A-Za-z0-9_\-]+\.json)")


def _docs() -> dict:
    """{filename: text} for every reader-facing markdown doc, plus the README."""
    out = {}
    for name in sorted(os.listdir(DOCS_DIR)):
        if name.endswith(".md"):
            with open(os.path.join(DOCS_DIR, name), encoding="utf-8") as fh:
                out[name] = fh.read()
    readme = os.path.join(REPO_ROOT, "README.md")
    if os.path.isfile(readme):
        with open(readme, encoding="utf-8") as fh:
            out["README.md"] = fh.read()
    return out


def _artifacts_on_disk() -> set:
    return {name for name in os.listdir(EVIDENCE_DIR) if name.endswith(".json")}


def _citations() -> dict:
    """{artifact filename: set(doc names)} for docs that CITE evidence as proof.

    Tutorial docs are excluded here rather than filtered later, so a caller cannot accidentally
    treat an instruction as a claim.
    """
    found: dict = {}
    for doc, text in _docs().items():
        if doc in _TUTORIAL_DOCS:
            continue
        for match in _EVIDENCE_REF.finditer(text):
            found.setdefault(match.group(1), set()).add(doc)
    return found


def test_the_scan_sees_docs_artifacts_and_citations():
    """Positive control. Every assertion below iterates one of these three; any coming back empty
    would make the module vacuously green — the failure mode this repo records most."""
    docs = _docs()
    assert len(docs) >= 8, f"only {len(docs)} docs found: {sorted(docs)}"
    assert len(_artifacts_on_disk()) >= 30, (
        f"only {len(_artifacts_on_disk())} evidence artifacts found; the comparison would be blind"
    )
    citations = _citations()
    assert len(citations) >= 25, (
        f"only {len(citations)} distinct artifacts cited across the docs. Either the citations were "
        "removed or this regex stopped matching — both must fail loudly."
    )


def test_every_cited_artifact_exists():
    """THE defect: a rename of a docs-only artifact left the entire suite green.

    Measured: renaming `evidence/live_memory_isolation_result.json` — cited in `docs/ROADMAP.md` and
    read by no code — produced `4119 passed, 20 skipped` while the doc pointed at a path that 404s.

    Deleting an artifact does get caught, by the count guards and the demo tour. A RENAME does not:
    the count is unchanged, and only artifacts the demo happens to read are covered. Eight cited
    artifacts are named by no code at all, so for those the doc sentence is the only link between
    the claim and the file.
    """
    on_disk = _artifacts_on_disk()
    broken = {
        artifact: sorted(docs)
        for artifact, docs in sorted(_citations().items())
        if artifact not in on_disk
    }
    assert not broken, (
        "doc(s) cite evidence artifacts that do not exist, so a reader following the citation to "
        "check the claim gets nothing:\n  "
        + "\n  ".join(f"evidence/{a} — cited in {d}" for a, d in broken.items())
        + "\n\nEither the artifact was renamed (update the citation), or it was deleted (the claim "
        "it supported must go too). Note this is about CLAIMS: a tutorial telling the reader to "
        f"create a file is exempt — see _TUTORIAL_DOCS ({sorted(_TUTORIAL_DOCS)})."
    )


def test_the_tutorial_exemption_still_describes_the_tutorial():
    """An exemption without its own check is a hole — the rule this repo applies to lint-excluded
    directories, here applied to a doc.

    Two ways the exemption could rot, both checked:

    * COOKBOOK stops being a tutorial and starts citing REAL artifacts. Then exempting it hides
      genuine breakage, and the exemption should be dropped rather than silently widened.
    * The fictional example moves out of COOKBOOK into a doc that IS making claims, in which case
      the `geo_*` paths would be read as proof of a tool that does not exist.
    """
    docs = _docs()
    on_disk = _artifacts_on_disk()

    for doc, reason in _TUTORIAL_DOCS.items():
        assert doc in docs, f"{doc} no longer exists; drop it from _TUTORIAL_DOCS"
        refs = set(_EVIDENCE_REF.findall(docs[doc]))
        assert refs, (
            f"{doc} is exempted as a tutorial but cites no evidence paths at all, so the exemption "
            f"protects nothing. Remove it. (Recorded reason: {reason})"
        )
        # Its refs must be the fictional ones — an exempted doc citing a REAL artifact means the
        # exemption is now covering a claim.
        real_refs = sorted(r for r in refs if r in on_disk)
        assert not real_refs, (
            f"{doc} is exempted as a tutorial, but it now cites artifacts that really exist: "
            f"{real_refs}. Those are claims, not instructions — the exemption is hiding them from "
            "the resolution check. Split the tutorial's fictional paths from its real citations, or "
            "drop the exemption."
        )

    # And the fiction must stay inside the tutorial.
    for doc, text in docs.items():
        if doc in _TUTORIAL_DOCS:
            continue
        fiction = sorted(
            r for r in set(_EVIDENCE_REF.findall(text))
            if r.startswith(_TUTORIAL_FICTION_PREFIX)
        )
        assert not fiction, (
            f"{doc} cites {fiction}, which belong to COOKBOOK's fictional `geo_lookup` example and "
            "do not exist. Outside a tutorial that reads as a claim about a tool this repo does "
            "not ship."
        )


def test_an_uncited_artifact_is_not_treated_as_an_error():
    """The reverse direction, deliberately NOT enforced — recorded so nobody adds it.

    Seven artifacts exist and are cited by no doc. That is fine: they are produced and consumed by
    scenarios and tests, and `evidence/` is a record of runs, not a documentation index. Demanding
    every artifact be cited would push toward writing prose about files nobody needs described, or
    deleting real evidence to satisfy a checker.

    This test states the decision and only sanity-bounds it: if the uncited set exploded, that would
    suggest the citation scan broke rather than that the repo grew.
    """
    on_disk = _artifacts_on_disk()
    uncited = on_disk - set(_citations())
    assert len(uncited) < len(on_disk), (
        "NO artifact is cited by any doc, which means the citation scan is broken rather than the "
        "repo being undocumented."
    )
