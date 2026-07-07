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

# The five named cyber-skills this task adds. Kept explicit (not globbed) so the
# test fails loudly if one is renamed or removed, and so it never accidentally
# depends on skills owned by a parallel agent.
NEW_SKILLS = [
    "cve-asset-triage",
    "soc-ip-lookup",
    "soc-triage",
    "incident-ticketing",
    "multi-account-ops",
]

# A body shorter than this is a stub, not a usable SOP. The existing skills are
# ~6 KB; this floor is deliberately conservative so the test asserts "genuinely
# useful" without being brittle to reasonable edits.
_MIN_BODY_CHARS = 1500

# Tool-reference detection. Real tools in this repo all end in one of these
# verb/noun suffixes (siem_query, asset_lookup, enrich_ioc, create_ticket,
# nvd_lookup, epss_kev, whitelist_optimizer, sigma_match, sigma_yara_lint,
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
