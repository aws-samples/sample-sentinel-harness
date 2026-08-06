"""Offline tests for the named cyber-skills library (AgentSkills.io SKILL.md).

ZERO AWS, ZERO network, fast, deterministic. This asserts the M5 cyber-skills
set is well-formed and honest:

  * every new ``skills/<name>/SKILL.md`` parses — YAML frontmatter with a
    non-empty ``name`` and ``description``, and the frontmatter ``name`` matches
    the directory name;
  * the procedural body is non-trivial (a real SOP, not a stub);
  * every tool the skill *references* is a tool that actually exists in the repo
    (``tools/<name>/``) — plus ``ops_query``, the sibling multi-account-ops tool
    approved alongside these skills. This is the anti-hallucination gate: a skill
    may not cite a tool the platform cannot run.

Following the sibling tool/mockworld tests, we do NOT import the package under a
shared name; there is nothing importable here (SKILL.md is data), so we read the
files directly from an absolute path derived from this test's location. No CWD
assumptions, no network, no AWS.
"""
from __future__ import annotations

import os
import re

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO_ROOT, "skills")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

SKILLS_DIR = os.path.join(REPO_ROOT, "skills")


def _skills_on_disk() -> list:
    """Every `skills/<name>/SKILL.md` in the repo.

    DERIVED, not hand-listed. This was a literal five-name list, added when those five were new —
    and by the time anyone looked, `skills/` held NINE. The four that arrived later
    (`attack-path-reasoning`, `cve-triage-rubric`, `detection-writing-sop`, `ioc-vetting`) were
    covered by nothing: not the frontmatter check, not the body-size floor, and not the
    anti-hallucination check that every tool a skill names must exist. A skill could have cited an
    invented tool and no test would have noticed.

    The original comment gave two reasons for keeping it explicit: a rename should fail loudly, and
    it should not depend on skills owned by a parallel agent. The second no longer applies. The
    first is preserved WITHOUT the cost, by deriving the list here and asserting it against the
    documented set in `test_the_skill_inventory_matches_the_documented_set` — a rename still fails,
    and a new skill is covered automatically instead of silently ignored.
    """
    return sorted(
        name for name in os.listdir(SKILLS_DIR)
        if os.path.isfile(os.path.join(SKILLS_DIR, name, "SKILL.md"))
    )


# The skills every parametrised check below runs over. Named NEW_SKILLS historically; it is now the
# full inventory.
NEW_SKILLS = _skills_on_disk()

# A body shorter than this is a stub, not a usable SOP. The existing skills are
# ~6 KB; this floor is deliberately conservative so the test asserts "genuinely
# useful" without being brittle to reasonable edits.
_MIN_BODY_CHARS = 1500

# Tool-reference detection. Real tools in this repo all end in one of these
# verb/noun suffixes (siem_query, asset_lookup, enrich_ioc, create_ticket,
# nvd_lookup, epss_kev, allowlist_optimizer, sigma_match, sigma_yara_lint,
# web_search, harness_ops, run_evaluation, ops_query). Matching on these
# suffixes lets us catch a *hallucinated* tool name (e.g. ``foo_lookup``) while
# ignoring ordinary snake_case field names (``known_vuln``, ``trust_edges``,
# ``related_hosts``, ``alert_id`` ...) that are not tools.
_TOOL_SUFFIXES = (
    "_query", "_lookup", "_ioc", "_ticket", "_kev", "_optimizer",
    "_match", "_lint", "_search", "_ops", "_evaluation",
)
# Backticked lower-case identifier: `enrich_ioc`
_BACKTICK_IDENT_RE = re.compile(r"`([a-z][a-z0-9_]+)`")
# Explicit tool citation used in the output JSON blocks: "tool:enrich_ioc"
_TOOL_CITATION_RE = re.compile(r"tool:([a-z][a-z0-9_]+)")

# ``ops_query`` is the multi-account-ops data-plane tool approved alongside this
# skill set (its code/registry entry is a listed shared change); it is a valid
# reference target even though its ``tools/`` dir may land in a sibling change.
_EXTRA_APPROVED_TOOLS = {"ops_query"}


def _repo_tool_names() -> set[str]:
    """The set of tools that actually exist in the repo (``tools/<name>/``)."""
    return {
        name
        for name in os.listdir(TOOLS_DIR)
        if os.path.isdir(os.path.join(TOOLS_DIR, name))
    }


def _allowed_tools() -> set[str]:
    return _repo_tool_names() | _EXTRA_APPROVED_TOOLS


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split an AgentSkills.io SKILL.md into (frontmatter dict, body).

    The format is a leading ``---`` fenced YAML block followed by the Markdown
    body. Raises AssertionError (test failure) if the fence is malformed.
    """
    assert text.startswith("---"), "SKILL.md must open with a '---' YAML fence"
    parts = text.split("---", 2)
    # parts == ['', '<yaml>', '<body>']
    assert len(parts) == 3, "SKILL.md frontmatter fence is malformed"
    front = yaml.safe_load(parts[1]) or {}
    body = parts[2]
    return front, body


def _read_skill(name: str) -> tuple[dict, str]:
    path = os.path.join(SKILLS_DIR, name, "SKILL.md")
    assert os.path.isfile(path), f"missing skill file: {path}"
    with open(path, "r", encoding="utf-8") as fh:
        return _split_frontmatter(fh.read())


def _referenced_tools(body: str) -> set[str]:
    """Every tool the body *refers to* (backtick idents + tool: citations)."""
    refs: set[str] = set()
    for ident in _BACKTICK_IDENT_RE.findall(body):
        if ident.endswith(_TOOL_SUFFIXES):
            refs.add(ident)
    refs.update(_TOOL_CITATION_RE.findall(body))
    return refs


@pytest.mark.parametrize("skill", NEW_SKILLS)
def test_skill_file_exists(skill: str) -> None:
    assert os.path.isfile(os.path.join(SKILLS_DIR, skill, "SKILL.md"))


@pytest.mark.parametrize("skill", NEW_SKILLS)
def test_frontmatter_has_name_and_description(skill: str) -> None:
    front, _ = _read_skill(skill)
    assert isinstance(front, dict), "frontmatter must be a YAML mapping"

    name = front.get("name")
    assert isinstance(name, str) and name.strip(), "frontmatter 'name' non-empty"
    assert name.strip() == skill, (
        f"frontmatter name {name!r} must match directory {skill!r}"
    )

    desc = front.get("description")
    assert isinstance(desc, str) and desc.strip(), (
        "frontmatter 'description' non-empty"
    )
    # A real AgentSkills.io description tells the model *when* to use the skill;
    # a one-liner does not. Keep this conservative.
    assert len(desc.strip()) >= 80, "description should be a usable trigger blurb"


@pytest.mark.parametrize("skill", NEW_SKILLS)
def test_body_is_non_trivial(skill: str) -> None:
    _, body = _read_skill(skill)
    assert len(body.strip()) >= _MIN_BODY_CHARS, (
        f"{skill} body is too short to be a usable SOP "
        f"({len(body.strip())} < {_MIN_BODY_CHARS} chars)"
    )
    # A procedural SOP has steps and a heading structure.
    assert re.search(r"(?im)^##\s", body), "body should have Markdown sections"
    assert re.search(r"(?i)step\s*\d", body), "body should be step-structured"


@pytest.mark.parametrize("skill", NEW_SKILLS)
def test_only_references_real_tools(skill: str) -> None:
    _, body = _read_skill(skill)
    allowed = _allowed_tools()
    referenced = _referenced_tools(body)
    unknown = referenced - allowed
    assert not unknown, (
        f"{skill} references tool(s) that do not exist in the repo: "
        f"{sorted(unknown)} (allowed: {sorted(allowed)})"
    )


@pytest.mark.parametrize("skill", NEW_SKILLS)
def test_references_at_least_one_real_tool(skill: str) -> None:
    # A genuinely-useful SecOps SOP names concrete platform tools to use.
    _, body = _read_skill(skill)
    assert _referenced_tools(body), f"{skill} names no platform tool at all"


def test_expected_tool_universe_present() -> None:
    # Guards the anti-hallucination allowlist: the seven tools the task calls out
    # are all either real repo tools or the approved ops_query sibling.
    expected = {
        "siem_query", "asset_lookup", "enrich_ioc", "create_ticket",
        "ops_query", "nvd_lookup", "epss_kev",
    }
    missing = expected - _allowed_tools()
    assert not missing, f"expected tool universe missing: {sorted(missing)}"

# --------------------------------------------------------------------------- #
# The inventory itself (INV-SKILL-1)                                          #
# --------------------------------------------------------------------------- #
# Every skill the repo ships, as a DOCUMENTED set. Deriving the parametrised list from disk means a
# new skill is covered automatically; this set is what makes a rename or a deletion still fail
# loudly, which is what the original hand-written list was protecting.
_DOCUMENTED_SKILLS = frozenset({
    "attack-path-reasoning",
    "cve-asset-triage",
    "cve-triage-rubric",
    "detection-writing-sop",
    "incident-ticketing",
    "ioc-vetting",
    "multi-account-ops",
    "soc-ip-lookup",
    "soc-triage",
})


def test_the_skill_inventory_matches_the_documented_set():
    """A skill added, renamed or removed must be an explicit decision.

    This replaces the guarantee the hand-written `NEW_SKILLS` list gave — a rename fails — without
    its cost, which was real: the list named five skills while `skills/` held nine, so four were
    checked by NOTHING. Not the frontmatter parse, not the body-size floor, and not the
    anti-hallucination rule that every tool a skill names must exist. A skill citing an invented
    tool would have shipped unnoticed.

    Both directions fail:
      - a skill on disk but not documented -> it was added without review
      - a documented skill missing from disk -> it was renamed or deleted
    """
    on_disk = set(_skills_on_disk())
    undocumented = sorted(on_disk - _DOCUMENTED_SKILLS)
    assert not undocumented, (
        f"skill(s) {undocumented} exist under skills/ but are not in _DOCUMENTED_SKILLS. Add them "
        "here so the addition is deliberate — every parametrised check in this module now runs "
        "over whatever is on disk, and this set is what makes a rename visible."
    )
    missing = sorted(_DOCUMENTED_SKILLS - on_disk)
    assert not missing, (
        f"documented skill(s) {missing} have no skills/<name>/SKILL.md. Either they were renamed "
        "(update this set and any doc that cites them) or deleted (remove them here)."
    )


def test_the_derived_list_is_non_trivial():
    """Positive control. Every parametrised check in this module iterates `NEW_SKILLS`; an empty or
    truncated derivation would make them all vanish rather than fail — which is precisely how four
    skills went unchecked for as long as they did."""
    assert len(NEW_SKILLS) >= 9, (
        f"only {len(NEW_SKILLS)} skills derived from {SKILLS_DIR}: {NEW_SKILLS}. The parametrised "
        "checks below cover only what this list contains, so a short list is a silent coverage gap."
    )
    assert len(NEW_SKILLS) == len(set(NEW_SKILLS)), f"duplicate entries: {NEW_SKILLS}"


def test_the_docs_state_the_current_skill_count():
    """The public docs quote a skill count; it must track the inventory.

    Same class as INV-DOC-9: a number stated to a reader. Checked here rather than in the docs guard
    because the authoritative measurement lives in this module.
    """
    count = len(_skills_on_disk())
    hits = []
    for relative in ("README.md", "docs/COMPARISON.md", "docs/ROADMAP.md"):
        path = os.path.join(REPO_ROOT, relative)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for match in re.finditer(r"\b(\d{1,3})\s+(?:named\s+)?(?:cyber-)?skills\b", text):
            hits.append((relative, int(match.group(1))))
    assert hits, (
        "no public doc states a skill count any more. If the claim was removed, delete this test; "
        "if it was reworded, update the pattern — a silent no-op here is a coverage gap."
    )
    stale = [(f, n) for f, n in hits if n != count]
    assert not stale, (
        f"doc(s) quote a stale skill count (actual {count}): {stale}"
    )
