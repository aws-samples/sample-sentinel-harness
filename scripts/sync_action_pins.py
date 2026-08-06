#!/usr/bin/env python3
"""Regenerate the INV-CI-3 authoritative pin table from GitHub, and fix stale version comments.

Why this exists
---------------
INV-CI-3 guards that every SHA-pinned Action's version comment names the version the SHA REALLY is,
by comparing each pin against an `_AUTHORITATIVE` table in `tests/test_action_pin_comments.py`.
That guard works — it blocked Dependabot PR #61, which bumped the three `codeql-action` sub-actions
to an unrecorded SHA.

But it was **not actionable**. Its failure message said to "resolve each against GitHub
(SENTINEL_VERIFY_ACTION_PINS=1 does this)", and that was false: the online test only *validates*
entries already in the table, so on a new SHA it iterates nothing and PASSES while the offline layer
fails. Measured, reproducing PR #61 locally:

    offline layer                         2 failed   (SHA not in the table)
    online layer (VERIFY_ACTION_PINS=1)   PASSED     (it never sees the new SHA)

So the only route was for a human to hand-copy a 40-hex SHA and hand-resolve it against the GitHub
API — exactly the manual work the guard exists to eliminate. A guard that turns the labour it
prevents into a mandatory ritual has traded one defect for another, and Dependabot bumps Actions
weekly, so this was a recurring red CI with no supported fix.

This script is that fix: one command that re-derives the mapping from the authoritative source.

Usage
-----
    uv run python scripts/sync_action_pins.py            # show what would change (default)
    uv run python scripts/sync_action_pins.py --write    # apply it
    make sync-action-pins                                # same, via the Makefile

Needs `gh` authenticated (it uses `gh api`, so no token handling lives here — the same reason the
online test layer shells out rather than reading a secret).

What it does, and what it refuses to do
---------------------------------------
For every `uses: <action>@<40-hex>` in `.github/workflows/`:

1. Resolve the SHA to the tag(s) pointing at it — the AUTHORITATIVE direction. Deriving the version
   from the neighbouring comment instead would launder a wrong label into the table, and stale
   labels are the entire defect INV-CI-3 records (`setup-python` claimed v6.3.0 while pinned to
   v7.0.0; `codeql-action` claimed v3.37.0 while pinned to v4.37.4).
2. Rewrite `_AUTHORITATIVE` in `tests/test_action_pin_comments.py` to exactly the pinned SHAs.
3. Rewrite each workflow's version comment to the resolved version.

It REFUSES to write anything if any SHA cannot be resolved to a tag. A partial table is worse than
a stale one: the guard would pass on the entries that resolved while the unresolvable pin — the
suspicious one — sat unrecorded. "A check that no-ops must not look like a check that passed"
(INV-CI-1 / INV-DOC-5), applied to a code generator.

A pin on a BRANCH rather than a tag (pypa/gh-action-pypi-publish tracks `release/v1`) has no tag to
resolve, so its recorded label is preserved rather than invented. Those are listed explicitly, so a
new unresolvable pin is an error instead of joining a silent exemption.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
GUARD_MODULE = REPO_ROOT / "tests" / "test_action_pin_comments.py"

# Pins that deliberately track a BRANCH, not a tag: there is no tag to resolve, so the existing
# label is authoritative and must be preserved verbatim. Listed rather than inferred so a NEW
# unresolvable pin is an error instead of quietly joining an exemption.
_BRANCH_TRACKING = {
    "pypa/gh-action-pypi-publish": "release/v1",
}

_PIN_RE = re.compile(r"uses:\s+(?P<action>[A-Za-z0-9][A-Za-z0-9/._-]+)@(?P<sha>[0-9a-f]{40})")
_VERSION_RE = re.compile(r"(?:release/v\d+|v\d+(?:\.\d+)*)")


def gh_api(path: str) -> object | None:
    """`gh api <path>` decoded, or None on any failure.

    Returning None rather than raising lets the caller distinguish "could not resolve" from a
    resolved-but-different answer, and the caller refuses to write on any None.
    """
    proc = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def resolve_sha_to_version(repo: str, sha: str) -> str | None:
    """The tag pointing at `sha`, preferring the most specific one.

    `/tags` lists lightweight and annotated tags with their COMMIT sha already dereferenced, which
    avoids the annotated-tag trap: an annotated tag's ref object is a tag object, not a commit, and
    treating its sha as the commit sha reports every pin as mismatched. (That mistake was made and
    caught during the round that established INV-CI-3.)

    Where several tags point at one commit the choice matters, and picking by "most dot-separated
    components" is WRONG. `actions/deploy-pages` has three tags on one commit:

        v5.0.0            <-- the release
        v5                <-- a moving major alias
        v3.0.2-node.24    <-- a historical re-tag of the same commit under the old major

    A component count picks `v3.0.2-node.24` (three dots beats two), which is how the first version
    of this script proposed rewriting a CORRECT `v5.0.0` comment into a misleading one — the guard's
    own defect class, reintroduced by its remediation tool.

    So the rule is semantic, not lexical:
      * prefer a plain `vMAJOR.MINOR.PATCH` over anything carrying a pre-release/build suffix
      * among those, prefer the HIGHEST version (a re-tag under an older major is not the identity
        of the commit today)
      * prefer a fully-qualified version over a bare major alias like `v5`, which moves
    """
    tags = gh_api(f"/repos/{repo}/tags?per_page=100")
    if not isinstance(tags, list):
        return None
    matching = [t["name"] for t in tags
                if isinstance(t, dict) and t.get("commit", {}).get("sha") == sha]
    if not matching:
        return None

    def rank(name: str) -> tuple:
        core = name.lstrip("v")
        # A suffix like `-node.24` or `-rc1` makes this not a plain release tag.
        plain = re.fullmatch(r"\d+(?:\.\d+)*", core) is not None
        parts = tuple(int(p) for p in re.findall(r"\d+", core))
        # Sort key: plain releases first, then most-qualified, then highest version.
        return (plain, len(parts), parts)

    return max(matching, key=rank)


def collect_pins() -> dict:
    """{sha: {"repo": str, "actions": set, "sites": [(path, lineno, action)]}} for every pin."""
    pins: dict = {}
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml")):
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            match = _PIN_RE.search(line)
            if not match:
                continue
            action, sha = match.group("action"), match.group("sha")
            repo = "/".join(action.split("/")[:2])
            entry = pins.setdefault(sha, {"repo": repo, "actions": set(), "sites": []})
            entry["actions"].add(action)
            entry["sites"].append((path, index + 1, action))
    return pins


def existing_table() -> dict:
    """The `_AUTHORITATIVE` mapping as currently written, parsed from the guard module.

    Read with a literal-scoped regex rather than by importing the module: importing would execute
    `require_workflow`, which is repository-scoped and would make this script unusable in the very
    situation it exists for.
    """
    text = GUARD_MODULE.read_text(encoding="utf-8")
    block = re.search(r"_AUTHORITATIVE = \{(.*?)\n\}", text, re.S)
    if not block:
        return {}
    return dict(re.findall(r'"([0-9a-f]{40})":\s*"([^"]+)"', block.group(1)))


def render_table(resolved: dict, pins: dict) -> str:
    """The `_AUTHORITATIVE` literal, sorted by SHA so a diff is minimal and reviewable."""
    lines = ["_AUTHORITATIVE = {"]
    for sha in sorted(resolved):
        version = resolved[sha]
        actions = sorted(pins[sha]["actions"])
        if len(actions) == 1:
            comment = actions[0]
        else:
            # github/codeql-action/{analyze,init,upload-sarif} — one SHA, several sub-actions.
            base = actions[0].rsplit("/", 1)[0]
            leaves = ",".join(sorted(a.rsplit("/", 1)[1] for a in actions))
            comment = f"{base}/{{{leaves}}}"
        if pins[sha]["repo"] in _BRANCH_TRACKING:
            comment += " (branch)"
        lines.append(f'    "{sha}": "{version}",'.ljust(70) + f"# {comment}")
    lines.append("}")
    return "\n".join(lines)


def rewrite_comments(pins: dict, resolved: dict, write: bool) -> list:
    """Update each pin's neighbouring version comment. Returns a list of human-readable changes."""
    changes = []
    for path in sorted({site[0] for entry in pins.values() for site in entry["sites"]}):
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for index, line in enumerate(lines):
            match = _PIN_RE.search(line)
            if not match:
                continue
            action, sha = match.group("action"), match.group("sha")
            want = resolved.get(sha)
            if not want:
                continue

            # Inline form: `uses: x@sha # v1`
            if "#" in line:
                head, _, tail = line.partition("#")
                found = _VERSION_RE.search(tail)
                if found and found.group(0) != want:
                    changes.append(f"{path.name}:{index+1} inline {found.group(0)} -> {want}")
                    if write:
                        lines[index] = head + "#" + tail.replace(found.group(0), want, 1)
                continue

            # Line-above form: `# actions/checkout v7.0.1`
            if index == 0:
                continue
            previous = lines[index - 1]
            if not (previous.lstrip().startswith("#") and action in previous):
                continue
            after = previous.split(action, 1)[1]
            found = _VERSION_RE.search(after)
            if found and found.group(0) != want:
                changes.append(f"{path.name}:{index} comment {found.group(0)} -> {want}")
                if write:
                    lines[index - 1] = previous.replace(found.group(0), want, 1)
        if write:
            path.write_text("".join(lines), encoding="utf-8")
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", action="store_true",
                        help="apply the changes (default is a dry run)")
    args = parser.parse_args()

    pins = collect_pins()
    if not pins:
        print("ERROR: no SHA-pinned actions found under .github/workflows/ — refusing to write an "
              "empty table, which would make the guard pass while checking nothing.",
              file=sys.stderr)
        return 2
    print(f"found {len(pins)} unique pinned SHAs across {len(list(WORKFLOWS_DIR.glob('*.yml')))} "
          f"workflows\n")

    resolved: dict = {}
    unresolved: list = []
    for sha, entry in sorted(pins.items(), key=lambda kv: sorted(kv[1]["actions"])[0]):
        repo = entry["repo"]
        label = sorted(entry["actions"])[0]
        if repo in _BRANCH_TRACKING:
            resolved[sha] = _BRANCH_TRACKING[repo]
            print(f"  BRANCH {label:44s} {sha[:12]} -> {resolved[sha]} (tracks a branch)")
            continue
        version = resolve_sha_to_version(repo, sha)
        if version is None:
            unresolved.append((label, sha))
            print(f"  UNRESOLVED {label:40s} {sha[:12]} -> no tag points at this commit")
            continue
        resolved[sha] = version
        print(f"  OK     {label:44s} {sha[:12]} -> {version}")

    if unresolved:
        print(
            f"\nERROR: {len(unresolved)} pin(s) could not be resolved to a tag. Refusing to write "
            "anything.\n\n"
            "A partial table is worse than a stale one: the guard would pass on the entries that "
            "resolved while the UNRESOLVABLE pin — the suspicious one — stayed unrecorded.\n\n"
            "Either the SHA is not on any released tag (check whether the pin is intentional), the "
            "tag list exceeds one page, or `gh` is not authenticated (`gh auth status`). If the pin "
            "deliberately tracks a branch, add its repo to _BRANCH_TRACKING with the branch name.",
            file=sys.stderr,
        )
        return 1

    comment_changes = rewrite_comments(pins, resolved, args.write)

    old_table = existing_table()
    new_literal = render_table(resolved, pins)
    table_changed = old_table != resolved
    if table_changed:
        added = sorted(set(resolved) - set(old_table))
        removed = sorted(set(old_table) - set(resolved))
        altered = sorted(s for s in set(old_table) & set(resolved) if old_table[s] != resolved[s])
        print("\n_AUTHORITATIVE changes:")
        for sha in added:
            print(f"  + {sha[:12]} = {resolved[sha]}")
        for sha in removed:
            print(f"  - {sha[:12]} (was {old_table[sha]}, no longer pinned)")
        for sha in altered:
            print(f"  ~ {sha[:12]} {old_table[sha]} -> {resolved[sha]}")
        if args.write:
            text = GUARD_MODULE.read_text(encoding="utf-8")
            updated = re.sub(r"_AUTHORITATIVE = \{.*?\n\}", new_literal, text, count=1, flags=re.S)
            if updated == text:
                print("ERROR: could not locate the _AUTHORITATIVE literal to replace.",
                      file=sys.stderr)
                return 2
            GUARD_MODULE.write_text(updated, encoding="utf-8")

    if comment_changes:
        print("\nversion comment changes:")
        for change in comment_changes:
            print(f"  {change}")

    if not table_changed and not comment_changes:
        print("\nnothing to do — the table and every comment already match GitHub.")
        return 0

    if args.write:
        print(f"\nWROTE: {len(comment_changes)} comment(s), table "
              f"{'updated' if table_changed else 'unchanged'}.")
        print("Now run: uv run pytest tests/test_action_pin_comments.py -q")
    else:
        print("\nDRY RUN — nothing written. Re-run with --write (or `make sync-action-pins`).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
