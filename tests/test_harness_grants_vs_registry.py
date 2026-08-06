"""INV-GOV-10 — a harness that grants a NON-APPROVED tool says so where the operator reads it.

The registry is the platform's admission-control plane, and its gate works: `registry/tools.yaml`
ships `web_search` as `status: pending`, and

    registry.resolve("web_search")
    -> RegistryError: tool 'web_search' is registered but status='pending' (not approved)

verified against the shipped registry with all 20 factories wired.

Meanwhile `harnesses/research-supervisor/harness.yaml` GRANTS `@gateway/web_search`, and nothing
compared the two. That matters because of the property INV-HARNESS-1 already records: `allowedTools`
is a **GRANT, not a lookup**. An unresolvable name does not raise — the agent simply comes up with a
smaller tool surface than its config declares. So an operator reads the harness file, sees
`@gateway/web_search  # egress-controlled web search`, and concludes the supervisor can search the
web. At runtime that grant yields nothing at all.

This is a DIFFERENT gate from the one INV-HARNESS-1 checks. That guard asks "does this name resolve
to a stub under `tools/`?" — and `web_search` DOES have one, so it passes there. This asks "has
governance approved it?", which is the registry's job and was compared by nobody.

What this module does NOT do
---------------------------
It does not demand the grant be removed, nor that `web_search` be flipped to `approved`. Both would
be wrong:

* `pending` is an ON-PURPOSE demonstration. `docs/GOVERNANCE.md` says so explicitly — "`web_search`
  ships as `pending` on purpose: it demonstrates a capability held back pending SecOps approval of
  its egress allowlist" — and `tests/test_registry.py` exercises the refusal. Approving it to make a
  checker green would delete the repo's only worked example of admission control actually denying
  something.
* Deleting the grant would lose the record of what this supervisor is *intended* to do once the
  egress allowlist is signed off.

So the requirement is DISCLOSURE: the harness file must state, next to the grant, that it is not
currently resolvable. That keeps the demo intact and stops the config from misleading a reader. When
the registry entry flips to `approved`, this guard stops requiring the note — and
`test_the_disclosure_is_removed_once_approved` fails if a stale note is left behind, so the comment
cannot outlive its reason.

ZERO network, ZERO AWS: reads YAML and the registry as data.
"""
from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML parses the registry and harness configs")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESSES_DIR = os.path.join(REPO_ROOT, "harnesses")
SKILLS_DIR = os.path.join(REPO_ROOT, "skills")
REGISTRY_PATH = os.path.join(REPO_ROOT, "registry", "tools.yaml")

# Skill SOPs that MANDATE a tool rather than merely mentioning one. Written as (skill, tool) pairs
# because the requirement is per-claim: a skill may name several tools and only some be mandatory.
#
# These were found by reading the prose, and they are worse than the harness case. `cve-triage-rubric`
# rule 3 is "**Egress via `web_search`, not raw download**" and `ioc-vetting` rule 4 is "**Egress via
# reputation tools + `web_search`** … Never download the sample" — each makes `web_search` the ONLY
# compliant way out, while `resolve("web_search")` raises. An SOP whose sole permitted path is
# unavailable is a dead end in a SAFETY procedure: the agent either abandons external context
# (degraded but safe) or finds another route (violating the SOP). The disclosure has to say which.
_SKILLS_MANDATING_TOOLS = {
    ("cve-triage-rubric", "web_search"),
    ("ioc-vetting", "web_search"),
    ("detection-writing-sop", "web_search"),
}

# Phrases that count as disclosing "this grant does not resolve today". Any ONE suffices; the point
# is that a reader scanning the allowlist is warned, not that a fixed sentence is present.
_DISCLOSURE_RE = re.compile(
    r"NOT YET RESOLVABLE|not yet resolvable|status\s*=\s*'?pending'?|pending approval|not approved",
    re.I,
)

# A `@gateway/<name>` reference in an allowedTools list.
_GRANT_RE = re.compile(r'"@gateway/([A-Za-z0-9_]+)"')


def _registry_status() -> dict:
    """{tool name: status} from the shipped registry."""
    with open(REGISTRY_PATH, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    entries = doc.get("tools") or []
    return {
        entry["name"]: entry.get("status")
        for entry in entries
        if isinstance(entry, dict) and "name" in entry
    }


def _harness_files() -> list:
    return sorted(
        os.path.join(HARNESSES_DIR, name, "harness.yaml")
        for name in os.listdir(HARNESSES_DIR)
        if os.path.isfile(os.path.join(HARNESSES_DIR, name, "harness.yaml"))
    )


def _grants(path: str) -> dict:
    """{tool name: the line it was granted on} for every `@gateway/<name>` in the file.

    Read from the RAW TEXT rather than the parsed YAML because the disclosure lives in a comment, and
    `yaml.safe_load` discards comments. Reading the text is what makes "is it documented next to the
    grant" answerable at all.
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out = {}
    for index, line in enumerate(lines):
        for name in _GRANT_RE.findall(line):
            out[name] = index
    return out


def _comment_block_above(path: str, line_index: int) -> str:
    """The contiguous run of comment lines immediately above `line_index`."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    collected = []
    cursor = line_index - 1
    while cursor >= 0 and lines[cursor].strip().startswith("#"):
        collected.append(lines[cursor])
        cursor -= 1
    # The grant's own trailing comment counts too.
    if 0 <= line_index < len(lines) and "#" in lines[line_index]:
        collected.append(lines[line_index])
    return "\n".join(reversed(collected))


def test_the_scan_sees_the_registry_and_the_harness_grants():
    """Positive control. Both sides of the comparison are derived; either coming back empty would
    make every assertion below pass while checking nothing."""
    status = _registry_status()
    assert len(status) >= 20, f"only {len(status)} registry entries parsed: {sorted(status)}"
    assert any(v != "approved" for v in status.values()), (
        "every registry entry is `approved`, so this module's subject — a harness granting a "
        "non-approved tool — cannot occur. If governance really approved everything, that is worth "
        "knowing: docs/GOVERNANCE.md relies on `web_search` staying `pending` as its worked example "
        "of admission control denying something."
    )

    harnesses = _harness_files()
    assert len(harnesses) >= 6, f"only {len(harnesses)} harness configs found"
    total_grants = sum(len(_grants(path)) for path in harnesses)
    assert total_grants >= 15, (
        f"only {total_grants} gateway grants found across {len(harnesses)} harnesses — either the "
        "allowlists were emptied or this parse is broken."
    )


def test_a_grant_of_a_non_approved_tool_is_disclosed():
    """THE defect: `research-supervisor` granted `web_search` with no hint it cannot resolve.

    `allowedTools` is a grant, not a lookup (INV-HARNESS-1), so the failure is silent: the agent
    comes up with a smaller tool surface than the file declares, and the only signal is an operator
    noticing the capability is missing.

    The fix required is DISCLOSURE, not removal — see this module's docstring for why flipping the
    registry entry or deleting the grant would each destroy something real.
    """
    status = _registry_status()
    undisclosed = []
    for path in _harness_files():
        harness = os.path.basename(os.path.dirname(path))
        for tool, line_index in sorted(_grants(path).items()):
            tool_status = status.get(tool)
            if tool_status is None or tool_status == "approved":
                continue
            context = _comment_block_above(path, line_index)
            if not _DISCLOSURE_RE.search(context):
                undisclosed.append(f"{harness} grants {tool!r} (status={tool_status!r})")

    assert not undisclosed, (
        "harness(es) grant a tool the registry has NOT approved, with nothing in the file saying "
        "so:\n  " + "\n  ".join(undisclosed)
        + "\n\n`registry.resolve()` raises RegistryError for a non-approved tool, and "
        "`allowedTools` is a GRANT rather than a lookup — an unresolvable name does not raise, the "
        "agent just gets fewer tools than the config implies (INV-HARNESS-1). An operator reading "
        "the allowlist would believe the capability is available.\n\n"
        "Add a comment beside the grant stating it is not yet resolvable and why (or remove the "
        "grant). Do NOT flip the registry entry to `approved` to silence this: `pending` is "
        "docs/GOVERNANCE.md's worked example of admission control actually denying something."
    )


def test_the_disclosure_is_removed_once_approved():
    """The reverse direction, so the note cannot outlive its reason.

    A "not yet resolvable" comment left beside a tool that IS approved is worse than no comment: it
    tells an operator a working capability is unavailable, and it is the "lint-exempt directory =
    never cleaned" shape applied to a caveat. When governance approves the tool, the note must go.
    """
    status = _registry_status()
    stale = []
    for path in _harness_files():
        harness = os.path.basename(os.path.dirname(path))
        for tool, line_index in sorted(_grants(path).items()):
            if status.get(tool) != "approved":
                continue
            context = _comment_block_above(path, line_index)
            # Only flag a disclosure that names THIS tool — a shared header mentioning `pending`
            # generally must not implicate every approved grant beneath it.
            if _DISCLOSURE_RE.search(context) and tool in context:
                stale.append(f"{harness}: {tool!r} is approved but still carries a not-resolvable note")

    assert not stale, (
        "harness(es) still warn that a tool is unresolvable after the registry approved it:\n  "
        + "\n  ".join(stale)
        + "\n\nRemove the note — it now tells an operator that a working capability is unavailable."
    )


def test_a_skill_that_mandates_a_non_approved_tool_discloses_it():
    """The same coupling on a second, more dangerous surface: skill SOPs.

    `cve-triage-rubric` rule 3 reads "**Egress via `web_search`, not raw download**" and
    `ioc-vetting` rule 4 "**Egress via reputation tools + `web_search`** … Never download the
    sample". Each makes `web_search` the ONLY compliant way to reach external context — while
    `registry.resolve("web_search")` raises `RegistryError`.

    That is worse than the harness case. There the consequence is a missing capability; here the SOP
    prescribes a path that does not exist, so an agent following it either abandons enrichment
    (degraded but safe) or improvises (violating the very rule that forbids raw downloads). A safety
    procedure must not contain a dead end silently, and the disclosure has to state WHICH branch is
    correct — recording `UNKNOWN` rather than substituting a download.
    """
    status = _registry_status()
    undisclosed = []
    for skill, tool in sorted(_SKILLS_MANDATING_TOOLS):
        if status.get(tool) in (None, "approved"):
            continue
        path = os.path.join(SKILLS_DIR, skill, "SKILL.md")
        assert os.path.isfile(path), (
            f"skills/{skill}/SKILL.md is missing, but this module records it as mandating "
            f"{tool!r}. Update _SKILLS_MANDATING_TOOLS — a guard whose subject moved verifies "
            "nothing."
        )
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if tool not in text:
            continue  # the mandate was removed; nothing to disclose
        if not _DISCLOSURE_RE.search(text):
            undisclosed.append(f"{skill} mandates {tool!r} (status={status[tool]!r})")

    assert not undisclosed, (
        "skill SOP(s) MANDATE a tool the registry has not approved, with nothing saying so:\n  "
        + "\n  ".join(undisclosed)
        + "\n\nThese are not optional mentions — the prose makes the tool the only compliant egress "
        "path, while `registry.resolve()` refuses it. An agent following the SOP hits a dead end and "
        "must either degrade or improvise; the file has to say which is correct (record UNKNOWN, "
        "never substitute a raw download). Add that note beside the rule."
    )


def test_the_skill_mandate_disclosures_say_what_to_do_instead():
    """A disclosure that only says "unavailable" is half a fix.

    The rules these notes sit beside are PROHIBITIONS ("never download the sample", "no raw
    download"). Telling an agent the approved path is gone, without saying the prohibition still
    holds, invites exactly the substitution the rule exists to prevent — the degradation rule this
    repo applies elsewhere: a failure must be distinguishable from a pass, and the safe branch must
    be named.
    """
    status = _registry_status()
    thin = []
    for skill, tool in sorted(_SKILLS_MANDATING_TOOLS):
        if status.get(tool) in (None, "approved"):
            continue
        path = os.path.join(SKILLS_DIR, skill, "SKILL.md")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if not _DISCLOSURE_RE.search(text):
            continue  # the other test reports this

        # Scoped to the BLOCKQUOTE LINES — the disclosure itself — and nothing else.
        #
        # Two narrowings were needed, both found by mutation rather than reasoning:
        #
        #  1. A file-wide search for UNKNOWN/never SURVIVED "strip the safe branch from the note":
        #     these SOPs say "never" and "UNKNOWN" throughout, so the evidence came from unrelated
        #     prose.
        #  2. Splitting into paragraph-ish blocks ALSO survived, because the block containing the
        #     note also contains the rule it annotates — and that rule opens with "Never download
        #     binaries". The guard was reading the prohibition it exists to protect as proof that
        #     the note restates it.
        #
        # The disclosure is written as a markdown blockquote, so `>`-prefixed lines isolate it from
        # the rule above it. A guard whose evidence can come from the very text it is checking
        # against is not checking anything.
        disclosure = "\n".join(
            line for line in text.splitlines() if line.lstrip().startswith(">")
        )
        if not _DISCLOSURE_RE.search(disclosure):
            thin.append(f"{skill}: the {tool!r} disclosure is not in a blockquote, so it cannot be "
                        "distinguished from the rule it annotates")
            continue
        if not re.search(r"UNKNOWN|never|not ready|unconditional|stands regardless",
                         disclosure, re.I):
            thin.append(f"{skill}: discloses {tool!r} is unavailable but names no safe branch")

    assert not thin, (
        "disclosure(s) state a mandated tool is unavailable without saying what to do instead:\n  "
        + "\n  ".join(thin)
        + "\n\nThe adjacent rule is a PROHIBITION. A note that only reports the gap invites the "
        "substitution the rule forbids. State the safe branch — record UNKNOWN, or declare the rule "
        "not ready — and that the prohibition still holds."
    )


def test_the_registry_gate_actually_refuses_a_non_approved_tool():
    """The premise of everything above, executed rather than assumed.

    If `resolve()` stopped enforcing status, a grant of a `pending` tool would be harmless and this
    module would be demanding a comment about nothing. Asserted against the SHIPPED registry, so it
    also covers the enforcement path — not a fixture that agrees by construction.
    """
    from sentinel_harness.registry import DEFAULT_REGISTRY_PATH, RegistryError, load_registry

    status = _registry_status()
    non_approved = sorted(name for name, value in status.items() if value != "approved")
    approved = sorted(name for name, value in status.items() if value == "approved")
    assert non_approved and approved, (
        f"need at least one of each to test the gate: non_approved={non_approved}"
    )

    factory_map = {name: (lambda name=name: {"name": name}) for name in status}
    registry = load_registry(factory_map, DEFAULT_REGISTRY_PATH)

    # The gate refuses the non-approved one...
    with pytest.raises(RegistryError) as excinfo:
        registry.resolve(non_approved[0])
    message = str(excinfo.value)
    assert "not approved" in message or "pending" in message, (
        f"resolve({non_approved[0]!r}) raised RegistryError but the message does not say why: "
        f"{message!r}. A refusal an operator cannot act on is barely better than a silent one."
    )

    # ...and admits an approved one, so the refusal above is discriminating rather than blanket.
    resolved = registry.resolve(approved[0])
    assert resolved is not None, (
        f"resolve({approved[0]!r}) returned nothing for an APPROVED tool — the gate refuses "
        "everything, so the test above proves nothing about status enforcement."
    )
