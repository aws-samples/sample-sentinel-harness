"""
Repo-identity guard — every self-reference points at the CANONICAL repository.
=============================================================================
This project was developed in a personal repository and transferred to
``aws-samples/sample-sentinel-harness``. The transfer moved the code; it did NOT
move the 26 URLs embedded in the docs, the landing page and the issue templates,
all of which kept pointing at the pre-transfer location.

Why that is a defect and not a cosmetic nit
-------------------------------------------
The pre-transfer repository is still PUBLIC and still answers HTTP 200. A stale
link therefore does not 404 — it silently serves a frozen copy that *looks*
authoritative. Three concrete harms, in descending severity:

1. **Misrouted vulnerability reports.** ``.github/ISSUE_TEMPLATE/config.yml``
   pointed its "Security report (private)" contact link at the OLD repo's
   ``/security/advisories/new``. A researcher following it files a PRIVATE
   advisory that the aws-samples maintainers can never see — and because the
   report is private by design, nobody ever notices it was misdelivered. This is
   the one entry in the set that is a security defect outright.
2. **Un-updatable documentation.** Readers land on a copy that will never receive
   the fixes shipped here, including the 45 security defects closed in #11.
3. **Broken copy-paste.** ``git clone <url> && cd sentinel-harness`` cannot work
   against the new URL: the directory that clone creates is now
   ``sample-sentinel-harness``.

What is deliberately NOT flagged
--------------------------------
- The **author attribution** link (``github.com/<author>`` with no repo path) in
  ``site/index.html``'s footer. That is a byline, not a project location.
- ``sentinel-harness-deck.pages.dev`` — an independent, live (HTTP 200)
  Cloudflare Pages site whose hostname is unrelated to the GitHub org.
- ``pypi.org/project/sentinel-harness`` and ``pip install sentinel-harness`` —
  the published distribution name, verified live on PyPI. The PyPI name did not
  change with the transfer.
- ``sentinel-harness-exec`` in ``iac-terraform/`` — an IAM role name in a
  placeholder-account example.
- Build artifacts (``*.egg-info/``, ``.venv/``) — git-ignored, and regenerated
  from the corrected README on the next build.

This module scans the working tree the way a reader would: the FILES, not the
rendered site. Zero network, zero AWS.

Self-exemption: the forbidden owner/repo strings are assembled from fragments
below so that this guard file does not match its own patterns — the same
convention ``.github/workflows/ci.yml``'s secret scan uses on itself.
"""
from __future__ import annotations

import os
import re
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- canonical identity ---------------------------------------------------- #
CANONICAL_OWNER = "aws-samples"
CANONICAL_REPO = "sample-sentinel-harness"
CANONICAL_PAGES_HOST = f"{CANONICAL_OWNER}.github.io"

# --- the pre-transfer identity, assembled so this file is not a self-hit ---- #
# Split at a character boundary: the literal never appears contiguously here.
_OLD_OWNER = "neosun" + "100"
_OLD_REPO = "sentinel-harness"
_OLD_REPO_PATH = f"{_OLD_OWNER}/{_OLD_REPO}"
_OLD_PAGES = f"{_OLD_OWNER}.github.io/{_OLD_REPO}"

# A bare owner reference with NO repository path after it is an attribution
# byline, which is legitimate. Only owner-plus-repo is a project location.
_STALE_PROJECT_URL_RE = re.compile(
    re.escape(_OLD_REPO_PATH) + r"|" + re.escape(_OLD_PAGES)
)

# Text files a reader or a tool actually consumes. Binary assets and vendored or
# generated trees are out of scope.
_SCANNED_SUFFIXES = (".md", ".html", ".yml", ".yaml", ".toml", ".py", ".ts",
                     ".json", ".cfg", ".txt", ".sh")
_SKIP_DIR_PARTS = (
    os.sep + ".git" + os.sep,
    os.sep + "node_modules" + os.sep,
    os.sep + ".venv" + os.sep,
    os.sep + ".egg-info" + os.sep,
    ".egg-info" + os.sep,
    os.sep + "cdk.out" + os.sep,
    os.sep + "htmlcov" + os.sep,
    os.sep + ".hypothesis" + os.sep,
    os.sep + ".pytest_cache" + os.sep,
    os.sep + ".ruff_cache" + os.sep,
)

_THIS_FILE = os.path.abspath(__file__)


def _tracked_text_files() -> list[str]:
    """Every git-TRACKED text file, as repo-relative paths.

    Uses ``git ls-files`` rather than a walk so that git-ignored build output
    (``*.egg-info/``, ``.venv/``) is excluded by construction instead of by an
    ever-growing skip list — those files are regenerated from the corrected
    sources on the next build and are not what a reader sees.
    """
    try:
        out = subprocess.run(
            ["git", "-C", REPO_ROOT, "ls-files", "-z"],
            capture_output=True, text=True, check=True, timeout=60,
        ).stdout
    except (subprocess.SubprocessError, OSError, FileNotFoundError):  # pragma: no cover
        # Degradation must leave a trace: an empty list would make every test
        # below vacuously pass, which is exactly the silent fail-open this repo
        # forbids. Raise instead.
        raise RuntimeError(
            "cannot enumerate tracked files via `git ls-files` — refusing to "
            "report a vacuous pass"
        )
    rels = [p for p in out.split("\0") if p]
    keep = []
    for rel in rels:
        if not rel.endswith(_SCANNED_SUFFIXES):
            continue
        abspath = os.path.join(REPO_ROOT, rel)
        if abspath == _THIS_FILE:
            continue  # documents the old identity on purpose
        if any(part in os.sep + rel for part in _SKIP_DIR_PARTS):
            continue
        if os.path.isfile(abspath):
            keep.append(rel)
    return keep


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _hits(pattern: re.Pattern) -> dict[str, list[str]]:
    """Map repo-relative path -> the offending lines, for every tracked text file."""
    found: dict[str, list[str]] = {}
    for rel in _tracked_text_files():
        bad = [f"{n}: {line.strip()[:120]}"
               for n, line in enumerate(_read(rel).splitlines(), 1)
               if pattern.search(line)]
        if bad:
            found[rel] = bad
    return found


# --------------------------------------------------------------------------- #
# INV-IDENTITY-1 — no self-reference points at the pre-transfer repository     #
# --------------------------------------------------------------------------- #
def test_no_stale_project_url_anywhere():
    """No tracked text file may reference the pre-transfer owner/repo pair.

    This is the guard that would have caught all 26 stale links at once. It
    deliberately matches ``<old-owner>/<old-repo>`` and the old Pages host, NOT a
    bare owner reference — an attribution byline is legitimate.
    """
    stale = _hits(_STALE_PROJECT_URL_RE)
    assert not stale, (
        "these files still point at the pre-transfer repository. The old repo is "
        "still public and answers HTTP 200, so these do not 404 — they silently "
        "serve a frozen copy that looks authoritative:\n"
        + "\n".join(f"  {rel}\n    " + "\n    ".join(lines)
                    for rel, lines in sorted(stale.items()))
    )


def test_the_sanity_of_this_guard():
    """Meta-test: the scan must actually be looking at a non-trivial file set.

    Without this, a bug in ``_tracked_text_files`` (a wrong suffix list, an
    over-broad skip rule) would make every assertion above vacuously true —
    the silent fail-open this repo's own rules forbid.
    """
    files = _tracked_text_files()
    assert len(files) > 100, f"scan collected only {len(files)} files — too few to trust"
    assert any(f == "README.md" for f in files), "README.md not scanned"
    assert any(f == "site/index.html" for f in files), "site/index.html not scanned"
    assert any(f == ".github/ISSUE_TEMPLATE/config.yml" for f in files), \
        "the issue-template config (the misrouted-advisory file) is not scanned"
    # And the pattern must be capable of matching: prove it on a synthetic line.
    assert _STALE_PROJECT_URL_RE.search(f"https://github.com/{_OLD_REPO_PATH}")
    assert _STALE_PROJECT_URL_RE.search(f"https://{_OLD_PAGES}/")
    # ...while a bare attribution byline is NOT a hit.
    assert not _STALE_PROJECT_URL_RE.search(f"https://github.com/{_OLD_OWNER}")


# --------------------------------------------------------------------------- #
# INV-IDENTITY-2 — the security-report contact link resolves to THIS repo      #
# --------------------------------------------------------------------------- #
def test_security_contact_link_points_at_this_repository():
    """A private-advisory link on the wrong repo misdelivers vulnerability reports.

    Because the report is private by design, a misdelivery is undetectable from
    the outside: the reporter believes they disclosed responsibly and the
    maintainers never learn of the issue. Pinned explicitly rather than left to
    the generic scan above, so the intent survives a refactor of that scan.
    """
    rel = ".github/ISSUE_TEMPLATE/config.yml"
    text = _read(rel)
    assert "security/advisories/new" in text, (
        f"{rel} no longer offers a private security-report channel"
    )
    for line in text.splitlines():
        if "security/advisories/new" not in line:
            continue
        assert f"{CANONICAL_OWNER}/{CANONICAL_REPO}/security/advisories/new" in line, (
            f"{rel} routes private security reports to the wrong repository: "
            f"{line.strip()}"
        )


# --------------------------------------------------------------------------- #
# INV-IDENTITY-3 — a documented clone command actually works                   #
# --------------------------------------------------------------------------- #
_CLONE_RE = re.compile(
    r"git clone\s+(?:--\S+\s+)*https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?"
    r"(?:\s+&&\s+cd\s+(\S+))?\s*$"
)


def test_documented_clone_commands_are_copy_pasteable():
    """``git clone <url> && cd <dir>``: the dir must be the one clone creates.

    Renaming the repository to ``sample-sentinel-harness`` broke every documented
    clone-then-cd pair, because ``cd`` still named the old directory. A reader
    copy-pasting the quickstart lands in ``No such file or directory`` on line 1.
    """
    broken = []
    for rel in _tracked_text_files():
        for n, line in enumerate(_read(rel).splitlines(), 1):
            m = _CLONE_RE.search(line.strip())
            if not m:
                continue
            owner, repo, cd_target = m.group(1), m.group(2), m.group(3)
            if (owner, repo) != (CANONICAL_OWNER, CANONICAL_REPO):
                broken.append(f"{rel}:{n}: clones {owner}/{repo}, not the canonical repo")
            if cd_target is not None and cd_target != repo:
                broken.append(
                    f"{rel}:{n}: clones '{repo}' but cds into '{cd_target}' "
                    f"(clone creates a directory named '{repo}')"
                )
    assert not broken, "documented clone commands do not work as written:\n  " + \
        "\n  ".join(broken)


def test_at_least_one_clone_command_is_documented():
    """Guard the guard: if the phrasing changes, the test above goes vacuous."""
    found = any(_CLONE_RE.search(line.strip())
                for rel in _tracked_text_files()
                for line in _read(rel).splitlines())
    assert found, (
        "no `git clone https://github.com/...` line found in the docs — either the "
        "quickstart lost it or the phrasing changed (update _CLONE_RE)"
    )


# --------------------------------------------------------------------------- #
# INV-IDENTITY-4 — the API-docs links point at the live Pages site             #
# --------------------------------------------------------------------------- #
def test_pages_links_use_the_canonical_host():
    """Every GitHub-Pages link to THIS PROJECT must use the canonical host + path.

    The API reference is published by ``.github/workflows/docs.yml`` to
    ``<canonical-owner>.github.io/<canonical-repo>/``.

    Scoped by SUBJECT, not by shape. The repo legitimately links third-party
    ``*.github.io`` docs (MITRE's ATT&CK Navigator, LangGraph); flagging those
    would be judging a link by its form instead of by what it refers to — the same
    breadth-vs-selectivity error round 13 found in the FP heuristic. A link is
    this project's own iff its path segment names a repo in the project's own
    naming lineage (the canonical name or the pre-transfer one).
    """
    pages_re = re.compile(r"([\w.-]+)\.github\.io/([\w.-]+)")
    # The names this project has ever been published under. Anything else on a
    # *.github.io host belongs to somebody else.
    own_repo_names = {CANONICAL_REPO, _OLD_REPO}
    wrong = []
    for rel in _tracked_text_files():
        for n, line in enumerate(_read(rel).splitlines(), 1):
            for m in pages_re.finditer(line):
                host_owner, path_repo = m.group(1), m.group(2)
                if path_repo not in own_repo_names:
                    continue  # a third party's docs site — not ours to police
                if (host_owner, path_repo) != (CANONICAL_OWNER, CANONICAL_REPO):
                    wrong.append(f"{rel}:{n}: {m.group(0)}")
    assert not wrong, (
        f"GitHub-Pages links to THIS project that are not "
        f"{CANONICAL_PAGES_HOST}/{CANONICAL_REPO}: " + ", ".join(wrong)
    )


def test_third_party_pages_links_are_not_flagged():
    """Regression for the fix above: a third-party github.io link must pass.

    The first version of this guard keyed on the URL SHAPE and flagged MITRE's
    ATT&CK Navigator and the LangGraph docs as stale self-references.
    """
    pages_re = re.compile(r"([\w.-]+)\.github\.io/([\w.-]+)")
    own_repo_names = {CANONICAL_REPO, _OLD_REPO}
    for third_party in ("https://mitre-attack.github.io/attack-navigator/",
                        "https://langchain-ai.github.io/langgraph/"):
        m = pages_re.search(third_party)
        assert m is not None
        assert m.group(2) not in own_repo_names, (
            f"{third_party} would be mis-flagged as this project's own link"
        )
    # ...and the stale self-link IS still caught.
    m = pages_re.search(f"https://{_OLD_PAGES}/")
    assert m is not None and m.group(2) in own_repo_names
    assert (m.group(1), m.group(2)) != (CANONICAL_OWNER, CANONICAL_REPO)


def test_pages_link_is_actually_present():
    """The README must still advertise the API reference (it is a headline claim)."""
    readme = _read("README.md")
    assert f"{CANONICAL_PAGES_HOST}/{CANONICAL_REPO}" in readme, (
        "README no longer links the published API reference"
    )
