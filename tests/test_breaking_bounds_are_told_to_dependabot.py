"""INV-SUPPLY-2 — a version bound that exists for a BREAKAGE is declared where Dependabot reads it.

`pyproject.toml` pins `mcp>=1.0,<2` and carries a long comment explaining why; `docs/INVARIANTS.md`
records it as INV-MCP-5; `tests/test_mcp_version_bound.py` fails if the bound is lifted while the
code still needs the 1.x API. Three places state the constraint.

**Dependabot reads none of them.** So it proposed lifting the bound anyway — twice, in the same
week, and the second one was worse than the first:

    PR #59  pyproject.toml   mcp>=1.0,<2  ->  mcp>=1.0,<3      (widens the range)
    PR #60  specialists/*    mcp==1.28.1  ->  mcp==2.0.0       (pins deployed containers to it)

Both were re-verified against the real mcp 2.0.0 release rather than trusted from the record,
because a bound whose evidence has expired is worse than no bound. The measurements:

    from mcp.server import Server                                -> OK       <-- proves nothing
    Server("probe").list_tools                                   -> GONE
    Server("probe").call_tool                                    -> GONE
    sentinel_harness.mcp_server.create_server()
        -> AttributeError: 'Server' object has no attribute 'list_tools'

    from mcp import ClientSession                                -> OK
    from mcp.client.streamable_http import streamablehttp_client -> ImportError

That last pair is the part that could have been missed. The root bound is about the **server**
surface, and the specialists never touch it — they use the **client** surface, so "the same bound
applies" was an assumption that needed its own measurement. It turned out to hold for an
independent reason: all four `specialists/*/agent_a2a.py` import `streamablehttp_client`, which 2.0
also removed. Two separate breakages behind one version number, and PR #60 would have shipped both
into the deployed containers.

So the rule this module enforces: **if the code depends on a major's API, the `ignore` must live in
`.github/dependabot.yml`** — the one file Dependabot actually reads. Otherwise the PR arrives every
week, the reason has to be re-derived from scratch each time, and eventually someone merges it
because the diff is one character and CI is green (it would be: no test installs mcp 2.x).

`ignore` is per-update-block, not global
----------------------------------------
This is the detail that makes the guard non-trivial. An `ignore` under the root `pip` entry does
NOT cover the container `pip` entry, so the same bound has to be repeated per block that could
propose it — and PR #60 came from the container block, which had no ignore at the time. A guard
that only checked "mcp is ignored somewhere" would have passed while the dangerous PR was open.
So this checks EVERY block whose ecosystem could bump the pin.

The precedent this generalises
------------------------------
`iac-cdk`'s TypeScript bound already did it right: `ignore: typescript >=7.0.0` in dependabot.yml
with the ts-node/`ts.sys` evidence written beside it (INV-IAC). That was one dependency solved
correctly; this makes it the rule, which is the "a fix applied to one call site is not an
invariant" lesson applied to a supply-chain declaration.

ZERO network, ZERO AWS — reads config files as data. The 2.x incompatibility itself is proven by
`tests/test_mcp_version_bound.py`, which probes the installed API surface; this module's subject is
whether the constraint is stated where it takes effect.
"""
from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML parses the dependabot config")

from repo_infra import require_workflow  # noqa: E402

DEPENDABOT = require_workflow("dependabot.yml")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")

# Dependencies whose upper bound exists because a MAJOR version breaks this code, and where the
# bound is declared. Each entry must have a matching `ignore` in every dependabot block that could
# propose crossing it.
#
# The value is the reason, kept here so a failure message can explain itself and so an entry cannot
# quietly become a bound nobody remembers the purpose of.
_BREAKING_BOUNDS = {
    "mcp": (
        "mcp 2.0.0 removed BOTH surfaces this repo uses. Server side: `Server.list_tools` / "
        "`.call_tool` are gone, so `sentinel_harness.mcp_server.create_server()` raises "
        "AttributeError and `sentinel mcp serve` cannot start (INV-MCP-5). Client side: "
        "`mcp.client.streamable_http.streamablehttp_client` is gone, which all four "
        "specialists/*/agent_a2a.py import to reach the Gateway."
    ),
    "typescript": (
        "TypeScript 7 is the native rewrite and no longer exposes the `ts.sys` JS surface that "
        "`ts-node` reads its tsconfig through, so all 8 iac-cdk stack tests die at startup "
        "(INV-IAC). ci.yml runs them via `npx ts-node` per file, with no jest."
    ),
}

# Which ecosystem could bump each bounded dependency. A `pip` ignore does nothing about an `npm`
# proposal and vice versa, so the check is scoped per ecosystem rather than repo-wide.
_ECOSYSTEM_OF = {"mcp": "pip", "typescript": "npm"}


def _config() -> dict:
    with open(DEPENDABOT, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _blocks(ecosystem: str) -> list:
    return [u for u in _config().get("updates", [])
            if u.get("package-ecosystem") == ecosystem]


def _ignored_names(block: dict) -> set:
    return {i.get("dependency-name") for i in (block.get("ignore") or [])}


def _block_label(block: dict) -> str:
    directory = block.get("directory")
    if directory:
        return directory
    dirs = block.get("directories") or []
    return f"{len(dirs)} directories ({', '.join(dirs[:2])}{', …' if len(dirs) > 2 else ''})"


def test_the_config_parses_and_has_the_blocks_this_module_checks():
    """Positive control. Every assertion below iterates update blocks; an empty parse would make
    them vacuously green — a scan finding nothing looks exactly like a repo with nothing to find."""
    updates = _config().get("updates", [])
    assert len(updates) >= 5, f"only {len(updates)} update blocks parsed"
    for dependency, ecosystem in _ECOSYSTEM_OF.items():
        assert _blocks(ecosystem), (
            f"no `{ecosystem}` update block found, so the check for {dependency}'s bound would "
            "iterate nothing and pass while verifying nothing."
        )


@pytest.mark.parametrize("dependency", sorted(_BREAKING_BOUNDS))
def test_every_breaking_bound_is_declared_to_dependabot(dependency):
    """The core assertion, and the defect: `mcp`'s bound was stated in three places Dependabot
    cannot read, so it proposed lifting it twice in one week.

    Checked in EVERY block of the relevant ecosystem, because `ignore` is per-block: the root
    `pip` entry's ignore does not cover the container `pip` entry, and PR #60 came from the
    container entry precisely because that one had none.
    """
    ecosystem = _ECOSYSTEM_OF[dependency]
    blocks = _blocks(ecosystem)
    missing = [
        _block_label(block) for block in blocks
        if dependency not in _ignored_names(block)
    ]
    assert not missing, (
        f"the `{dependency}` bound is not declared to Dependabot in {ecosystem} block(s) "
        f"{missing}, so it will keep proposing a version that breaks this code.\n\n"
        f"Why the bound exists: {_BREAKING_BOUNDS[dependency]}\n\n"
        f"`ignore` is PER-BLOCK, not global — add it to each {ecosystem} block that could bump "
        f"{dependency}. This is not bureaucracy: PR #59 widened the constraint and PR #60 pinned "
        "the DEPLOYED containers to the breaking version, both because the reason lived only in "
        "pyproject.toml comments and docs/INVARIANTS.md."
    )


@pytest.mark.parametrize("dependency", sorted(_BREAKING_BOUNDS))
def test_each_ignore_names_the_major_it_blocks(dependency):
    """An `ignore` with no version range ignores the dependency ENTIRELY — including the security
    patches inside the major that works.

    That failure mode is quiet and bad: `ignore: mcp` with no `versions` would stop the 2.x PRs and
    also stop a 1.x CVE fix, turning a compatibility bound into an unmaintained dependency. So the
    range must be present and must name the blocked major.
    """
    ecosystem = _ECOSYSTEM_OF[dependency]
    for block in _blocks(ecosystem):
        for entry in block.get("ignore") or []:
            if entry.get("dependency-name") != dependency:
                continue
            versions = entry.get("versions")
            assert versions, (
                f"the `{dependency}` ignore in the {ecosystem} block "
                f"{_block_label(block)!r} has no `versions`, so Dependabot ignores the dependency "
                "COMPLETELY — including patch releases within the major that works. A "
                "compatibility bound must not silently become an unmaintained dependency."
            )
            joined = " ".join(versions)
            assert re.search(r"\d", joined), (
                f"the `{dependency}` ignore range {versions!r} names no version number"
            )


def test_the_bound_and_the_ignore_agree_for_mcp():
    """The two declarations must describe the SAME boundary.

    `pyproject.toml` says `<2`; dependabot.yml says ignore `>=2.0.0`. If someone bumped the
    pyproject bound to `<3` (which is exactly what PR #59 proposed) while leaving the ignore at
    `>=2.0.0`, the repo would permit 2.x installs while Dependabot stayed quiet about them — the
    worst combination, since the guard that would have complained is the one now disabled.
    """
    with open(PYPROJECT, encoding="utf-8") as fh:
        pyproject = fh.read()

    declared = set(re.findall(r"mcp>=[0-9.]+,<(\d+)", pyproject))
    assert declared, (
        "pyproject.toml no longer declares an `mcp>=X,<Y` bound. If the code was ported to mcp "
        "2.x, remove the dependabot ignore in the same change and update _BREAKING_BOUNDS — a "
        "stale ignore blocks upgrades nobody is blocked by any more."
    )
    assert declared == {"2"}, (
        f"pyproject.toml bounds mcp below major {sorted(declared)}, but the dependabot ignore "
        "blocks >=2.0.0. Those must describe the same boundary, or the repo permits a version "
        "Dependabot has stopped warning about."
    )

    for block in _blocks("pip"):
        for entry in block.get("ignore") or []:
            if entry.get("dependency-name") == "mcp":
                joined = " ".join(entry.get("versions") or [])
                assert "2" in joined, (
                    f"the mcp ignore range {joined!r} does not block major 2, which is the major "
                    "pyproject.toml excludes."
                )


def test_the_reason_is_written_where_dependabot_users_will_read_it():
    """A pin with no recorded reason gets lifted by the next person who sees a stale dependency.

    The `ignore` alone only says "no"; the file has to say why, or the constraint is
    indistinguishable from caution and someone deletes it. INV-IAC established this for TypeScript
    (`ts.sys` / `ts-node` named in dependabot.yml); this asserts it for every bounded dependency.
    """
    with open(DEPENDABOT, encoding="utf-8") as fh:
        text = fh.read()

    # A marker phrase per dependency that only a real explanation would contain.
    required_evidence = {
        "mcp": ("list_tools", "streamablehttp_client"),
        "typescript": ("ts.sys", "ts-node"),
    }
    for dependency, markers in required_evidence.items():
        assert dependency in text, f"dependabot.yml does not mention {dependency} at all"
        absent = [m for m in markers if m not in text]
        assert not absent, (
            f"dependabot.yml holds `{dependency}` back but does not name the evidence {absent} "
            "that justifies it. A bound without its evidence reads as caution, and the next "
            "person removes it.\n\n"
            f"The reason on record: {_BREAKING_BOUNDS[dependency]}"
        )

    # And the lift procedure must be there too, so the bound can be removed deliberately rather
    # than becoming permanent by default.
    assert "uv run --with 'mcp>=2.0'" in text, (
        "dependabot.yml does not record HOW to re-verify the mcp bound, so it can only be lifted "
        "by guesswork. State the command that would prove the port is done."
    )
