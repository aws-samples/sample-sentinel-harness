"""INV-SUPPLY-1 — every dependency manifest in the repo is covered by a Dependabot ecosystem.

`.github/dependabot.yml` is the only thing that patches this repo's dependencies. It covered three
ecosystems — pip at the root, npm under `iac-cdk/`, github-actions — and stopped there. Meanwhile
the repo also ships:

    specialists/{adversarial-reviewer,attack-mapper,cve-intel,threat-hunt}/requirements.txt
    longrunning/bas-runner/requirements.txt
    ...and a Dockerfile beside each of those five

Those are the deps that actually run in the **deployed** Runtime containers, and nothing watched
them. Two independent facts confirmed the gap rather than inferring it:

* Dependabot's entire commit history in this repo touches ONLY `.github/workflows/`. Every commit
  that ever changed a container `requirements.txt` is a human one — including `3e1dacf`, a manual
  "bump bedrock-agentcore to 1.18.1 across all 4 specialists".
* `pip-audit` in `supply-chain.yml` does not close the gap: it builds its audit set from
  `pyproject.toml`'s `project.dependencies` alone.

So the container deps were patched by nobody and audited by nothing. Measured consequence, with
`pip-audit -r` on each file:

    specialists/adversarial-reviewer   19 known vulnerabilities in 2 packages
    specialists/attack-mapper          19 known vulnerabilities in 2 packages
    specialists/cve-intel              19 known vulnerabilities in 2 packages
    specialists/threat-hunt            19 known vulnerabilities in 2 packages
    longrunning/bas-runner             No known vulnerabilities found   <-- negative control

`litellm` (12 advisories) and `starlette` (7) — both TRANSITIVE, pulled by
`strands-agents[a2a,litellm]==1.9.1` and `fastapi==0.139.0`, so neither was visible as a line in
any requirements.txt. The clean `bas-runner` result is the control that matters: it proves the
audit discriminated rather than reporting red for everything, which is the difference between a
finding and a broken tool.

What this module asserts
------------------------
* every dependency manifest on disk falls under some declared ecosystem+directory — so a NEW
  container cannot be added without its deps being watched
* every declared directory really contains the manifest its ecosystem implies (the reverse
  direction: a typo'd path silently covers nothing, and Dependabot does not complain loudly)
* `directories:` entries stay in step with the specialists actually on disk
* the `real-stack` CI job installs the specialist stack FROM a requirements.txt rather than from a
  re-typed version string — the hand-copied `==1.9.1` was already stale

Deliberately NOT asserted: that the pinned versions are vulnerability-free. That needs the network
and a live advisory database, which would make this suite non-hermetic and time-dependent (today's
clean pin is tomorrow's advisory). Auditing is CI's job, in `supply-chain.yml`; this module's job
is that nothing is left OUT of the audit's reach. `test_container_deps_are_audited_in_ci` below
asserts that coupling instead.

ZERO network, ZERO AWS — reads config files as data.
"""
from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML parses the dependabot config")

from repo_infra import require_workflow  # noqa: E402

DEPENDABOT = require_workflow("dependabot.yml")
CI_YML = require_workflow("workflows", "ci.yml")
SUPPLY_CHAIN_YML = require_workflow("workflows", "supply-chain.yml")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that hold vendor/build output rather than first-party manifests.
_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache",
    "build", "dist", "cdk.out", ".terraform", "htmlcov", ".hypothesis", "site",
}

# Which manifest filenames belong to which Dependabot ecosystem.
_MANIFESTS = {
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "package.json": "npm",
    "Dockerfile": "docker",
}


def _config() -> dict:
    with open(DEPENDABOT, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _declared() -> dict:
    """{ecosystem: set(normalised directory)} as declared in dependabot.yml.

    Reads BOTH `directory` (single) and `directories` (list). Dependabot supports both, and a
    guard that knew only the singular form would report the new multi-directory entries as
    covering nothing — silently inverting its own verdict.
    """
    declared: dict = {}
    for update in _config().get("updates", []):
        eco = update.get("package-ecosystem")
        dirs = update.get("directories") or [update.get("directory")]
        for raw in dirs:
            if raw is None:
                continue
            declared.setdefault(eco, set()).add(raw.strip("/") or ".")
    return declared


def _manifests_on_disk() -> dict:
    """{ecosystem: set(directory relative to repo root)} for every manifest present."""
    found: dict = {}
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            eco = _MANIFESTS.get(name)
            if eco is None:
                continue
            rel = os.path.relpath(root, REPO_ROOT)
            found.setdefault(eco, set()).add("." if rel == "." else rel)
    return found


def test_the_scan_finds_manifests_and_declarations():
    """Positive control. Both sides of every comparison below are computed; if either came back
    empty the assertions would pass vacuously — a scan finding nothing looks exactly like a repo
    with nothing to find, which is this repo's most-recorded failure mode."""
    declared, on_disk = _declared(), _manifests_on_disk()
    assert len(declared) >= 3, f"only {len(declared)} ecosystems declared: {sorted(declared)}"
    assert len(on_disk) >= 3, f"only {len(on_disk)} ecosystems found on disk: {sorted(on_disk)}"
    # The five container requirements.txt files are the whole point of this module.
    pip_dirs = on_disk.get("pip", set())
    containers = {d for d in pip_dirs if d.startswith(("specialists", "longrunning"))}
    assert len(containers) >= 5, (
        f"expected at least 5 container manifest dirs, found {sorted(containers)}. If the "
        "specialists moved, this module's premise needs updating rather than quietly shrinking."
    )


def test_every_manifest_on_disk_is_covered_by_an_ecosystem():
    """The core assertion, and the defect: five deployed-container manifests were covered by
    nothing, and their deps carried 19 known advisories.

    A manifest under a directory nobody declared is a dependency set that is never patched and
    never audited. Adding a new specialist without a Dependabot entry must fail HERE rather than
    surface months later as a stale transitive CVE in a shipped image.
    """
    declared, on_disk = _declared(), _manifests_on_disk()
    uncovered = []
    for eco, dirs in sorted(on_disk.items()):
        covered = declared.get(eco, set())
        for directory in sorted(dirs):
            if directory not in covered:
                uncovered.append(f"{eco}: {directory}")
    assert not uncovered, (
        "dependency manifest(s) are not covered by any Dependabot ecosystem, so they are never "
        "patched:\n  " + "\n  ".join(uncovered)
        + "\n\nAdd the directory to the matching `package-ecosystem` block in "
        ".github/dependabot.yml. Note what the gap already cost: the five container "
        "requirements.txt files went uncovered and carried 19 known advisories in transitive "
        "litellm/starlette."
    )


def test_every_declared_directory_really_has_its_manifest():
    """The reverse direction — a declared path that contains no manifest covers nothing.

    Dependabot does not fail loudly on this: a typo'd or moved directory just silently stops
    producing PRs, which reads identically to "no updates available". The
    "lint-exempt directory = never cleaned" rule, applied to a supply-chain declaration.
    """
    problems = []
    for eco, dirs in sorted(_declared().items()):
        if eco == "github-actions":
            # Special-cased: its manifests are the workflow files, not a file in `directory`.
            workflows = os.path.join(REPO_ROOT, ".github", "workflows")
            if not os.path.isdir(workflows):
                problems.append("github-actions: .github/workflows does not exist")
            continue
        wanted = sorted(n for n, e in _MANIFESTS.items() if e == eco)
        for directory in sorted(dirs):
            base = REPO_ROOT if directory == "." else os.path.join(REPO_ROOT, directory)
            if not any(os.path.isfile(os.path.join(base, n)) for n in wanted):
                problems.append(f"{eco}: {directory} contains none of {wanted}")
    assert not problems, (
        "dependabot.yml declares director(ies) with no matching manifest, so those entries cover "
        "nothing and produce no PRs — indistinguishable from 'no updates':\n  "
        + "\n  ".join(problems)
    )


def test_the_declared_container_dirs_match_the_specialists_on_disk():
    """Guard the hand-written directory list against the tree it mirrors.

    `directories:` is a literal list, and every hand-maintained list in this repo has eventually
    drifted from what it mirrors (the reason INV-DOC-7/9, INV-MAKE-1 and INV-SKILL-1 exist). A new
    specialist that nobody adds here is covered by nothing; a removed one leaves a dead entry.
    """
    specialists_dir = os.path.join(REPO_ROOT, "specialists")
    on_disk = {
        f"specialists/{name}"
        for name in os.listdir(specialists_dir)
        if os.path.isfile(os.path.join(specialists_dir, name, "requirements.txt"))
    }
    assert len(on_disk) >= 4, f"only {len(on_disk)} specialists with requirements.txt: {on_disk}"

    for eco in ("pip", "docker"):
        declared = {d for d in _declared().get(eco, set()) if d.startswith("specialists/")}
        missing = sorted(on_disk - declared)
        stale = sorted(declared - on_disk)
        assert not missing, (
            f"specialist(s) {missing} have a manifest but no `{eco}` Dependabot entry — their "
            "deps are never patched."
        )
        assert not stale, (
            f"dependabot.yml declares `{eco}` for {stale}, which have no manifest on disk. A "
            "declaration whose target is gone covers nothing while looking like coverage."
        )


def test_the_real_stack_job_installs_from_a_requirements_file():
    """The sixth copy of one fact, removed.

    `ci.yml`'s `real-stack` job existed to test "the stack that actually ships" and did it by
    re-typing the version: `pip install "strands-agents[a2a,litellm]==1.9.1"`, with a comment
    claiming it was "the SAME version the specialist containers pin". It was a claim, not a fact,
    and it went stale — the containers moved and the job kept installing 1.9.1, so the job
    verifying the shipped stack was verifying a version nothing shipped.

    Installing FROM the file makes it a fact, the same way `-e ".[test]"` replaced a hand-copied
    dep list in this workflow (INV-CI-1).
    """
    with open(CI_YML, encoding="utf-8") as fh:
        text = fh.read()

    assert "pip install -r specialists/" in text, (
        "the real-stack job no longer installs the specialist stack from a requirements.txt. If "
        "it went back to a literal `pip install strands-agents==X`, that version is a copy that "
        "will drift from the containers — which is exactly what it did at ==1.9.1 while the "
        "containers had moved on."
    )
    # And no re-typed pin may come back alongside it.
    retyped = re.findall(r'pip install\s+"?strands-agents\[[^"]*\]==([0-9.]+)"?', text)
    assert not retyped, (
        f"ci.yml pins strands-agents to a literal {retyped} again. Install from the specialist's "
        "requirements.txt instead so the CI job and the shipped container cannot disagree."
    )
    # The file it installs from must exist, or the job fails at runtime instead of here.
    for match in re.finditer(r"pip install -r (\S+/requirements\.txt)", text):
        path = os.path.join(REPO_ROOT, match.group(1))
        assert os.path.isfile(path), (
            f"ci.yml installs from {match.group(1)}, which does not exist — the real-stack job "
            "would fail at runtime with a path error rather than here."
        )


def test_container_deps_are_audited_in_ci():
    """The coupling this module deliberately does NOT test offline: that something audits them.

    Vulnerability status needs the network and a live advisory DB, so asserting "these pins are
    clean" here would make the suite non-hermetic and time-dependent — today's clean pin is
    tomorrow's advisory. What IS checkable offline is that CI's audit step reaches the container
    manifests at all. Before this round it did not: `pip-audit` resolved its set from
    `pyproject.toml` alone, so 19 advisories in the deployed containers were invisible to it.
    """
    with open(SUPPLY_CHAIN_YML, encoding="utf-8") as fh:
        text = fh.read()

    assert "pip-audit" in text, "supply-chain.yml no longer runs pip-audit at all"

    # Parsed as YAML and matched against the audit step's real command, NOT by substring.
    #
    # My first version asked `"requirements.txt" in text`, which passed while the container audit
    # did not exist at all: pip-audit's own step writes a TEMP file called
    # `audit-requirements.txt`, and that string satisfied the check. A substring standing in for a
    # structural question is the defect this repo records more than any other, and it made a guard
    # green on the exact gap it was written to catch. So: find the steps whose `run` invokes
    # pip-audit, and require one of them to name a real container manifest path.
    config = yaml.safe_load(text)
    audit_commands = []
    for job in (config.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if "pip-audit" in run:
                audit_commands.append(run)
    assert audit_commands, (
        "no step in supply-chain.yml actually RUNS pip-audit (the name appears only in prose)"
    )

    # A container manifest path, as an argument rather than anywhere in the file.
    container_audit = [
        run for run in audit_commands
        if re.search(r"(specialists|longrunning)/[^\s]*requirements\.txt", run)
    ]
    assert container_audit, (
        "supply-chain.yml runs pip-audit, but no invocation names a container requirements.txt, so "
        "the deps that actually run in the deployed Runtime images are audited by nothing. That "
        "gap already let 19 known advisories (transitive litellm + starlette) ship. Add a step "
        "auditing `specialists/*/requirements.txt` and `longrunning/*/requirements.txt`.\n\n"
        f"pip-audit invocations found:\n{chr(10).join(audit_commands)}"
    )

    # The audit must FAIL the job on a finding. A loop that swallows the per-file exit code would
    # print advisories and still report green — the "a check that no-ops must not look like a check
    # that passed" rule (INV-CI-1 / INV-DOC-5) applied to a blocking gate.
    loop = container_audit[0]
    assert re.search(r"exit \$status|exit \$\{status\}|set -e", loop), (
        "the container audit loop does not propagate a failure (no `exit $status` / `set -e`), so "
        f"an advisory would be printed and the job would still pass:\n{loop}"
    )
