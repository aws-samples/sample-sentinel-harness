"""INV-CI-3 — every SHA-pinned Action's version comment names the version the SHA REALLY is.

Every `uses:` in `.github/workflows/` is pinned to a 40-hex commit SHA (the supply-chain control:
a tag is mutable, a SHA is not). Beside each pin is a human-readable version comment —

    # actions/checkout v7.0.1
    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1

— so a reader, and Dependabot, can see *what* is pinned without resolving the hash. Nothing checked
that the comment tells the truth, and it had drifted badly:

    comment said      SHA actually is     gap
    ----------------  ------------------  --------------------
    checkout v7.0.0   v7.0.1              a patch
    setup-python      v7.0.0              a WHOLE MAJOR (said v6.3.0)
    codeql-action     v4.37.4            a WHOLE MAJOR (said v3.37.0)  x3 sub-actions
    scorecard v2.4.3  v2.4.4              a patch
    gh-release v3.0.1 v3.0.2              a patch
    upload-artifact   v7.0.1              said v4.6.2 in two files, v7.0.1 in a third
                                          — the SAME SHA carrying two different labels

Resolved authoritatively against the GitHub API: every one of those SHAs points at a real published
tag, so the *pins* are sound — the labels were stale. Dependabot bumps the SHA and rewrites the
comment in the same PR, but a hand-merge, a rebase, or a partial edit leaves the two out of step,
and after that the comment is worse than absent: it is pseudo-assurance in a supply-chain control.
A maintainer reads `# codeql-action v3.37.0` and believes CI runs CodeQL v3; it runs v4.

This is the "hand-written list drifting from what it mirrors" shape this repo keeps finding, applied
to the one place the drift is a security-relevant lie about what code executes in CI.

Two layers, because the ground truth lives on a server this suite must not call
------------------------------------------------------------------------------
A comment and a SHA are both just strings in a file; offline, nothing links a SHA to the real tag.
So the truth is recorded ONCE, in `_AUTHORITATIVE` below (each entry produced by resolving the SHA
against the GitHub API), and the two layers police different drift:

* **Offline (always runs, ZERO network).** Every pin's comment must equal `_AUTHORITATIVE[sha]`,
  the same SHA may not carry two labels, and the table must cover exactly the pinned SHAs — no
  more, no less. Bumping a SHA without updating the table fails loudly (the new SHA is unknown),
  which is the point: it forces the bumper back to the authoritative source instead of guessing.

* **Online (opt-in via `SENTINEL_VERIFY_ACTION_PINS=1`, needs `gh`).** Re-resolves every SHA
  against GitHub and asserts `_AUTHORITATIVE` still tells the truth — the check that keeps the
  offline table from becoming its own stale hand-written list. It SKIPS by default, and a skip is
  not a pass: the offline layer still fully enforces comment/table agreement without it. This is
  the INV-CI-1/INV-DOC-5 rule — a check that no-ops must not look like a check that passed — which
  is why the skip reason says explicitly what was and was not verified.
"""
from __future__ import annotations

import json
import os
import re
import subprocess

import pytest

from repo_infra import require_workflow

# Module-level: in a checkout a missing ci.yml FAILS; in an sdist (no .github/) the whole module
# skips with a reason. WORKFLOWS_DIR is then the directory we glob.
CI_YML = require_workflow("workflows", "ci.yml")
WORKFLOWS_DIR = os.path.dirname(CI_YML)

# The authoritative SHA -> version-label map. Each label was produced by resolving the SHA against
# the GitHub API (SHA -> the tag that points at it), NOT copied from the comment it checks — the
# whole defect was comments that lied, so trusting them to seed this table would encode the lie.
#
# `release/v1` for pypa is a BRANCH ref, not a tag: pypa/gh-action-pypi-publish documents pinning
# to a commit on the release/v1 line, so its comment tracks the branch rather than a version. (That
# SHA is also tag v1.14.2; the online layer verifies the branch containment, not a tag equality.)
_AUTHORITATIVE = {
    "0f67c3f4856b2e3261c31976d6725780e5e4c373": "v4.1.1",     # actions/attest-build-provenance
    "3d3c42e5aac5ba805825da76410c181273ba90b1": "v7.0.1",     # actions/checkout
    "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128": "v5.0.0",     # actions/deploy-pages
    "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c": "v8.0.1",     # actions/download-artifact
    "820762786026740c76f36085b0efc47a31fe5020": "v7.0.0",     # actions/setup-node
    "5fda3b95a4ea91299a34e894583c3862153e4b97": "v7.0.0",     # actions/setup-python
    "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": "v7.0.1",     # actions/upload-artifact
    "fc324d3547104276b827a68afc52ff2a11cc49c9": "v5.0.0",     # actions/upload-pages-artifact
    "f205ea1c3313d32999d8d6a48b4f6530d4437b38": "v4.37.4",    # github/codeql-action/{init,analyze,upload-sarif}
    "2d1146689b8cda280b9bc96326124645441f03bc": "v2.4.4",     # ossf/scorecard-action
    "dc37677b2e1c63e2034f94d8a5b11f265b73ba33": "release/v1",  # pypa/gh-action-pypi-publish (branch)
    "3d0d9888cb7fd7b750713d6e236d1fcb99157228": "v3.0.2",     # softprops/action-gh-release
}

# A version token: `v1`, `v7.0.1`, or a `release/vN` branch ref. Deliberately anchored so a bare
# word in a comment ("Node 24") is not mistaken for a version.
_VERSION = re.compile(r"(?:release/v\d+|v\d+(?:\.\d+)*)")
_PIN = re.compile(r"uses:\s+(?P<action>[A-Za-z0-9][A-Za-z0-9/._-]+)@(?P<sha>[0-9a-f]{40})")


class Pin:
    """One `uses: action@sha` occurrence and the version label attached to it."""

    __slots__ = ("file", "lineno", "action", "repo", "sha", "label")

    def __init__(self, file, lineno, action, sha, label):
        self.file = file
        self.lineno = lineno
        self.action = action
        # github/codeql-action/init -> repo github/codeql-action
        self.repo = "/".join(action.split("/")[:2])
        self.sha = sha
        self.label = label  # the version token, or None if the pin has no comment

    def __repr__(self):
        return f"{self.file}:{self.lineno} {self.action}@{self.sha[:12]} label={self.label!r}"


def _label_for(action: str, line: str, prev_line: str) -> str | None:
    """The version label for a pin, from the inline comment or the line above.

    Two comment placements are in use in this repo, both must be read:
        inline:      uses: pypa/...@<sha> # release/v1
        line-above:  # actions/checkout v7.0.1
                     uses: actions/checkout@<sha>
    In the line-above form the version must follow the action path, so a stray version-looking
    token elsewhere on the line cannot be picked up.
    """
    inline = line.split("#", 1)
    if len(inline) == 2:
        m = _VERSION.search(inline[1])
        if m:
            return m.group(0)
    stripped = prev_line.strip()
    if stripped.startswith("#") and action in stripped:
        after = stripped.split(action, 1)[1]
        m = _VERSION.search(after)
        if m:
            return m.group(0)
    return None


def _all_pins() -> list:
    pins = []
    for name in sorted(os.listdir(WORKFLOWS_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(WORKFLOWS_DIR, name)
        lines = open(path, encoding="utf-8").read().splitlines()
        for i, line in enumerate(lines):
            m = _PIN.search(line)
            if not m:
                continue
            prev = lines[i - 1] if i > 0 else ""
            label = _label_for(m.group("action"), line, prev)
            pins.append(Pin(name, i + 1, m.group("action"), m.group("sha"), label))
    return pins


_PINS = _all_pins()


def test_the_scan_finds_the_pins_at_all():
    """Positive control. Every assertion below iterates `_PINS`; an empty scan — a moved
    workflows dir, a regex that stopped matching — would make them all vacuously green, the
    failure mode this repo records most. 14 unique SHAs across ~25 occurrences today."""
    assert len(_PINS) >= 20, (
        f"only {len(_PINS)} pinned actions found across {WORKFLOWS_DIR}. Either the workflows "
        "moved or the pin regex broke — both must fail loudly, not shrink the check."
    )
    assert len({p.sha for p in _PINS}) >= 12, (
        f"only {len({p.sha for p in _PINS})} distinct SHAs; the authoritative table expects 12"
    )


def test_every_pin_carries_a_version_comment():
    """A bare SHA with no comment is not a defect on its own, but it is undocumented supply chain:
    a reader cannot tell v3 from v4 without resolving the hash. The whole repo pins WITH a comment,
    so a missing one is a regression in the convention."""
    bare = [p for p in _PINS if p.label is None]
    assert not bare, (
        "these pins have no version comment, so nothing states what is pinned:\n  "
        + "\n  ".join(map(repr, bare))
        + "\n\nAdd a `# <action> <version>` line above (or an inline `# <version>`)."
    )


def test_no_sha_carries_two_different_labels():
    """The upload-artifact defect: the SAME SHA was commented v4.6.2 in two files and v7.0.1 in a
    third. Whichever is wrong, they cannot both be right, and a per-file grep sees only one at a
    time. One SHA is one commit is one version — across the whole repo."""
    by_sha: dict = {}
    for p in _PINS:
        if p.label is not None:
            by_sha.setdefault(p.sha, {}).setdefault(p.label, []).append(p)
    conflicts = {sha: labels for sha, labels in by_sha.items() if len(labels) > 1}
    assert not conflicts, (
        "the same SHA carries conflicting version labels — a self-contradiction a single-file "
        "read cannot catch:\n"
        + "\n".join(
            f"  {sha[:12]}: " + ", ".join(f"{lbl} ({[p.file for p in ps]})"
                                          for lbl, ps in labels.items())
            for sha, labels in conflicts.items()
        )
    )


def test_every_pin_matches_the_authoritative_version():
    """The core assertion: each comment must name the version the SHA REALLY is.

    `_AUTHORITATIVE` was built by resolving SHAs against GitHub, so this catches a comment that
    drifted away from its pin. A SHA absent from the table fails too — that is a pin bumped without
    the table being updated, and the fix is to re-resolve it authoritatively (run this module with
    SENTINEL_VERIFY_ACTION_PINS=1), never to copy the comment into the table.
    """
    wrong = []
    unknown = []
    for p in _PINS:
        if p.sha not in _AUTHORITATIVE:
            unknown.append(p)
            continue
        expected = _AUTHORITATIVE[p.sha]
        if p.label is not None and p.label != expected:
            wrong.append((p, expected))
    assert not unknown, (
        "pinned SHA(s) are not in the authoritative table — a pin was changed without recording "
        "what it now is:\n  " + "\n  ".join(map(repr, unknown))
        + "\n\nResolve each against GitHub (SENTINEL_VERIFY_ACTION_PINS=1 does this) and add the "
        "real version to _AUTHORITATIVE. Do NOT copy the comment — the comment is what may be wrong."
    )
    assert not wrong, (
        "version comment(s) disagree with what the SHA authoritatively is:\n  "
        + "\n  ".join(f"{p!r} — comment says {p.label}, SHA is actually {exp}"
                      for p, exp in wrong)
    )


def test_the_table_has_no_stale_entries():
    """The table's other direction: an entry for a SHA no longer pinned anywhere is dead weight
    that will silently rot. The 'lint-exempt directory = never cleaned' rule, applied to a lookup
    table — it must mirror exactly the SHAs in use."""
    pinned = {p.sha for p in _PINS}
    stale = sorted(sha for sha in _AUTHORITATIVE if sha not in pinned)
    assert not stale, (
        f"_AUTHORITATIVE has entries for SHA(s) no longer pinned in any workflow: {stale}. "
        "Remove them so the table mirrors the workflows exactly."
    )


# --------------------------------------------------------------------------- #
# Online layer — opt-in, and a skip is NOT a pass                             #
# --------------------------------------------------------------------------- #
def _gh(path: str):
    proc = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=40)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _resolve_tag_sha(repo: str, tag: str) -> str | None:
    """The commit SHA a tag points at, dereferencing an annotated tag to its commit.

    A lightweight tag's ref object IS the commit; an annotated tag's ref object is a tag object
    that must be dereferenced one more hop. Getting this wrong is how an earlier probe reported
    every pin as mismatched — the annotated-tag object SHA is not the commit SHA.
    """
    ref = _gh(f"/repos/{repo}/git/refs/tags/{tag}")
    if not ref or "object" not in ref:
        return None
    obj = ref["object"]
    if obj["type"] == "tag":
        deref = _gh(f"/repos/{repo}/git/tags/{obj['sha']}")
        return deref["object"]["sha"] if deref else None
    return obj["sha"]


@pytest.mark.skipif(
    os.environ.get("SENTINEL_VERIFY_ACTION_PINS") != "1",
    reason=(
        "online GitHub verification is opt-in (set SENTINEL_VERIFY_ACTION_PINS=1 with `gh` "
        "authenticated). SKIPPED != PASSED: the offline layer still fully enforces that every "
        "comment matches _AUTHORITATIVE and that no SHA carries two labels. What this skip leaves "
        "unverified is whether _AUTHORITATIVE itself still matches GitHub — run it before a release "
        "or after bumping a pin."
    ),
)
def test_the_authoritative_table_matches_github():
    """Keep `_AUTHORITATIVE` from becoming its own stale hand-written list.

    For a tag label: the tag must resolve to exactly the pinned SHA.
    For the `release/v1` branch label: the pinned SHA must be contained in that branch (the branch
    is at or ahead of it), since it tracks a branch line rather than a fixed tag.
    """
    if _gh("/rate_limit") is None:
        pytest.fail(
            "SENTINEL_VERIFY_ACTION_PINS=1 but `gh api` is not working (auth? network?). Refusing "
            "to pass silently — a broken probe must not look like a verified table."
        )

    by_sha: dict = {}
    for p in _PINS:
        by_sha.setdefault(p.sha, p.repo)

    failures = []
    for sha, expected in _AUTHORITATIVE.items():
        repo = by_sha.get(sha)
        if repo is None:
            continue  # covered by test_the_table_has_no_stale_entries
        if expected.startswith("release/"):
            cmp = _gh(f"/repos/{repo}/compare/{sha}...{expected}")
            status = (cmp or {}).get("status")
            if status not in {"identical", "ahead"}:
                failures.append(
                    f"{repo}@{sha[:12]} is not contained in branch {expected} "
                    f"(compare status={status!r}); the pin may be off that branch line"
                )
            continue
        real = _resolve_tag_sha(repo, expected)
        if real is None:
            failures.append(f"{repo} tag {expected} does not resolve — table names a dead tag")
        elif real != sha:
            failures.append(
                f"{repo}: table says {sha[:12]} is {expected}, but {expected} resolves to "
                f"{real[:12]} — the authoritative table has drifted from GitHub"
            )
    assert not failures, "authoritative table no longer matches GitHub:\n  " + "\n  ".join(failures)
