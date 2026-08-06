"""INV-CI-4 — every CI job bounds its runtime, and concurrency is decided per workflow semantics.

Two runtime protections were missing across all six workflows.

**1. No job declared `timeout-minutes`.** All 14 inherited GitHub's default of **360 minutes**.
A hung job — a network read with no timeout, a test waiting on a lock, a `npm install` against a
degraded registry — would occupy a runner for six hours before being killed. On a public repo that
is the whole concurrency budget, so one wedged job blocks every other PR's CI. Nothing capped it.

The values here are calibrated to MEASURED durations, not guessed. From five real runs:

    test (py3.10-3.13)   321-345s   -> 15   (~3x headroom)
    codeql analyze        65-94s    -> 20   (first-run compilation is slower)
    iac                   74-88s    -> 10
    real-stack            57-63s    -> 10
    pip-audit             25-90s    -> 15   (grew when the container audit landed, INV-SUPPLY-1)
    mypy                  20s       -> 10
    bandit                12-13s    ->  5
    secret-and-name scan  4-5s      ->  3

A timeout far above the real duration is not a bound, it is decoration; one just above it turns
normal variance into flakes. ~3x measured is the compromise, and it is asserted below to stay
within a band so neither failure mode creeps back.

That band earned its keep immediately: my first pass set `bandit` to 10min (46x its 13s) and
`secret-and-name scan` to 5min (60x its 5s), and the guard failed on both. The fix was to tighten
the timeouts, not to widen the band — a bound chosen to make the check pass is not a bound.

**2. Five of six workflows had no `concurrency` block.** Superseded runs kept going: pushing twice
to a PR ran the full matrix twice, and only the last verdict was ever read.

The interesting part is that this is NOT a uniform fix, and treating it as one would be a defect:

    ci / codeql / supply-chain / scorecard   cancel-in-progress: TRUE
    release                                  cancel-in-progress: FALSE

`release.yml` publishes. Cancelling it midway can leave a state no retry cleanly repairs — a
GitHub Release created and tagged while PyPI never received the upload, or a signed attestation for
artifacts that were never published. Two tags pushed in quick succession is exactly the scenario
`cancel-in-progress: true` would fire on, i.e. precisely when it does the most damage. So release
groups by tag (serialising a re-run of the same tag) but never cancels. This module asserts that
asymmetry directly, because "add concurrency everywhere" is the obvious cleanup that would break it.

A negative result, recorded so it is not "tidied up"
----------------------------------------------------
`docs.yml` keys its group on the literal string `pages`, with NO `github.ref` — so every docs run
shares one group repo-wide, and in principle a PR's docs build can cancel `main`'s in-flight Pages
deployment. Adding `${{ github.ref }}` looks like the obvious fix. It is wrong twice over:

* **Measured**: across 40 historical docs runs (19 push/main + 21 pull_request), the conclusion was
  `success` every single time — **zero cancellations**. The race has never occurred, because a PR's
  docs build and main's deploy do not overlap in this repo's merge-then-push flow.
* **A global group is the POINT.** GitHub Pages deployment is a singleton; two concurrent
  `deploy-pages` runs conflict with each other. Keying on ref would *permit* that concurrency.

So `docs.yml` is deliberately exempt, and the exemption is asserted (its group must stay
ref-independent) rather than left as a silent inconsistency for someone to "fix". An exemption
without its own check is a hole — the rule this repo applies to lint-excluded directories, here
applied to a config exception.

Also verified and left alone: **permissions are already correct.** Every workflow declares a
top-level `contents: read` (or `read-all`), and the four jobs needing more narrow it themselves
(`security-events: write`, `pages: write`, `id-token: write`, `attestations: write`). That is
least-privilege done properly, so this round changed nothing there — but the property is now
asserted, since a future job could quietly inherit write access.

ZERO network, ZERO AWS — reads workflow files as data.
"""
from __future__ import annotations

import os

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML parses the workflow files")

from repo_infra import require_workflow  # noqa: E402

WORKFLOWS_DIR = os.path.dirname(require_workflow("workflows", "ci.yml"))

# Measured duration -> declared timeout. Kept here so a future edit that doubles a timeout has to
# argue with a number rather than silently widening the bound.
#
# The band is 2x-40x the measured seconds. The lower bound stops a timeout being set so close to
# the real duration that ordinary variance becomes a flake; the upper stops it being decorative.
# `secret-and-name scan` (5s -> 3min = 36x) and `mypy` (20s -> 10min = 30x) sit at the loose end,
# deliberately: a 1-minute timeout on a 5-second job would fire on a slow runner boot, and there is
# no value in tightening a job that cannot plausibly hang for minutes.
_MEASURED_SECONDS = {
    ("ci.yml", "test"): 345,
    ("ci.yml", "iac"): 88,
    ("ci.yml", "real-stack"): 63,
    ("ci.yml", "mypy"): 20,
    ("ci.yml", "secret-and-name-scan"): 5,
    ("codeql.yml", "analyze"): 94,
    ("supply-chain.yml", "pip-audit"): 90,
    ("supply-chain.yml", "bandit"): 13,
}

# The upper bound on any timeout. GitHub's default is 360; anything near it is not a bound.
_MAX_TIMEOUT_MINUTES = 30

# Workflows whose concurrency group is deliberately ref-INDEPENDENT, with why.
_GLOBAL_GROUP_EXEMPT = {
    "docs.yml": (
        "GitHub Pages deployment is a singleton — two concurrent deploy-pages runs conflict — so "
        "one repo-wide group is the intended behaviour, not an oversight. Measured: 40 historical "
        "docs runs, zero cancellations."
    ),
}

# Workflows that must NEVER cancel a run in progress, with why.
_MUST_NOT_CANCEL = {
    "release.yml": (
        "it publishes. Cancelling midway can leave a GitHub Release created while PyPI never got "
        "the upload, or an attestation signed for unpublished artifacts — a state no retry "
        "cleanly repairs."
    ),
}


def _workflows() -> dict:
    """{filename: parsed yaml} for every workflow."""
    out = {}
    for name in sorted(os.listdir(WORKFLOWS_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(WORKFLOWS_DIR, name), encoding="utf-8") as fh:
            out[name] = yaml.safe_load(fh)
    return out


def _jobs(doc: dict) -> dict:
    return doc.get("jobs") or {}


def test_the_scan_finds_the_workflows_and_jobs():
    """Positive control. Every assertion below iterates workflows and their jobs; an empty parse
    would make them all vacuously green — the failure mode this repo records most."""
    workflows = _workflows()
    assert len(workflows) >= 6, f"only {len(workflows)} workflows found: {sorted(workflows)}"
    total_jobs = sum(len(_jobs(doc)) for doc in workflows.values())
    assert total_jobs >= 13, (
        f"only {total_jobs} jobs found across {len(workflows)} workflows. Either the workflows "
        "were gutted or this parse is broken; both must fail loudly."
    )


def test_every_job_bounds_its_runtime():
    """All 14 jobs inherited GitHub's 360-minute default, so a hung job held a runner for six
    hours. On a public repo that is the entire concurrency budget — one wedged job blocks every
    other PR's CI."""
    missing = []
    for name, doc in _workflows().items():
        for job_name, job in _jobs(doc).items():
            if "timeout-minutes" not in (job or {}):
                missing.append(f"{name}:{job_name}")
    assert not missing, (
        "job(s) declare no `timeout-minutes`, so they inherit GitHub's 360-minute default and a "
        "hung job occupies a runner for six hours:\n  " + "\n  ".join(missing)
        + "\n\nSet one calibrated to the job's measured duration (roughly 3x), not a round number."
    )


def test_no_timeout_is_so_large_it_is_decorative():
    """A bound must actually bound. 360 minutes is the default this exists to replace; a timeout
    of 120 is barely different in practice."""
    excessive = []
    for name, doc in _workflows().items():
        for job_name, job in _jobs(doc).items():
            value = (job or {}).get("timeout-minutes")
            if isinstance(value, int) and value > _MAX_TIMEOUT_MINUTES:
                excessive.append(f"{name}:{job_name} = {value}min")
    assert not excessive, (
        f"timeout(s) exceed {_MAX_TIMEOUT_MINUTES} minutes, which is close enough to the "
        f"360-minute default to be decoration rather than a bound:\n  " + "\n  ".join(excessive)
        + "\n\nIf a job genuinely needs longer, record the measurement that justifies it here."
    )


@pytest.mark.parametrize(("key", "seconds"), sorted(_MEASURED_SECONDS.items()))
def test_each_timeout_is_calibrated_to_its_measured_duration(key, seconds):
    """A tolerance is calibrated to a magnitude.

    This repo already recorded the cost of borrowing one across magnitudes (INV-DOC-9: a +-60
    tolerance meant for ~3800 tests was reused for a 157-file count, accepting almost any number
    while reporting green). Same trap here: a single "30 minutes for everything" would bound the
    5-second secret scan not at all.

    So each timeout is checked against the job's real measured duration. Too tight turns variance
    into flakes; too loose is decoration.
    """
    filename, job_name = key
    doc = _workflows()[filename]
    job = _jobs(doc).get(job_name)
    assert job is not None, (
        f"job {job_name!r} no longer exists in {filename}. If it was renamed, update "
        "_MEASURED_SECONDS with a fresh measurement rather than deleting the entry — a guard "
        "whose premise expired is worse than none."
    )
    declared = job.get("timeout-minutes")
    assert isinstance(declared, int), f"{filename}:{job_name} has no integer timeout: {declared!r}"

    ratio = (declared * 60) / seconds
    assert ratio >= 2.0, (
        f"{filename}:{job_name} times out at {declared}min but really takes ~{seconds}s "
        f"({ratio:.1f}x). That is tight enough that ordinary runner variance becomes a flake — "
        "raise it, or re-measure if the job genuinely got faster."
    )
    assert ratio <= 40.0, (
        f"{filename}:{job_name} times out at {declared}min for a job that takes ~{seconds}s "
        f"({ratio:.0f}x). A bound that loose does not bound anything; tighten it or record why "
        "this job can legitimately run far longer than measured."
    )


def test_every_workflow_declares_concurrency():
    """Five of six had none, so superseded runs kept going — pushing twice to a PR ran the full
    matrix twice and only the last verdict was read."""
    missing = [name for name, doc in _workflows().items() if "concurrency" not in doc]
    assert not missing, (
        f"workflow(s) declare no `concurrency` block, so a superseded run keeps burning a runner: "
        f"{missing}. Add one — but decide `cancel-in-progress` per workflow SEMANTICS: see "
        "test_a_publishing_workflow_never_cancels_itself."
    )


def test_a_publishing_workflow_never_cancels_itself():
    """The asymmetry, asserted because "add concurrency everywhere" is the obvious cleanup that
    would break it.

    `release.yml` is the one workflow where cancelling is worse than wasting a runner: a partial
    release can leave a tagged GitHub Release with nothing on PyPI, or an attestation signed for
    artifacts that were never published. Two tags pushed in quick succession is exactly when
    `cancel-in-progress: true` fires — precisely the moment it does the most harm.
    """
    workflows = _workflows()
    for name, reason in _MUST_NOT_CANCEL.items():
        assert name in workflows, f"{name} no longer exists; update _MUST_NOT_CANCEL"
        concurrency = workflows[name].get("concurrency")
        assert isinstance(concurrency, dict), (
            f"{name} has no concurrency mapping to check: {concurrency!r}"
        )
        assert concurrency.get("cancel-in-progress") is False, (
            f"{name} sets cancel-in-progress={concurrency.get('cancel-in-progress')!r}, but it "
            f"MUST be false because {reason}"
        )
        # And its group must be keyed on the tag, or a re-run of the same tag could race itself.
        assert "github.ref" in str(concurrency.get("group", "")), (
            f"{name}'s concurrency group {concurrency.get('group')!r} does not include "
            "github.ref, so unrelated tags would serialise behind each other (or, worse, a "
            "re-run of one tag would not)."
        )


def test_verification_workflows_do_cancel_superseded_runs():
    """The other half: a workflow whose verdict is obsolete the moment a new commit lands SHOULD
    cancel. Asserted so the saving is not silently dropped by a future edit."""
    for name, doc in _workflows().items():
        if name in _MUST_NOT_CANCEL or name in _GLOBAL_GROUP_EXEMPT:
            continue
        concurrency = doc.get("concurrency") or {}
        assert concurrency.get("cancel-in-progress") is True, (
            f"{name} is a verification workflow but does not cancel superseded runs "
            f"(cancel-in-progress={concurrency.get('cancel-in-progress')!r}). Its verdict on an "
            "old commit is read by nobody, so the run is pure waste."
        )
        assert "github.ref" in str(concurrency.get("group", "")), (
            f"{name}'s concurrency group {concurrency.get('group')!r} omits github.ref, so runs "
            "for DIFFERENT branches/PRs would cancel each other — one PR's push would kill "
            "another's CI."
        )


def test_the_global_group_exemption_is_still_accurate():
    """Guard the exemption rather than leaving it as a silent inconsistency.

    `docs.yml` keys its group on the literal `pages`. That looks like a bug next to every other
    workflow's ref-keyed group, and "fixing" it would be a real regression: Pages deployment is a
    singleton, so a repo-wide group is the intended serialisation and adding a ref would PERMIT
    concurrent deploys. Measured before deciding: 40 historical docs runs, zero cancellations.

    So the exemption is asserted in the direction that matters — the group must stay
    ref-independent — and this test names why, so the next reader does not have to re-derive it.
    """
    workflows = _workflows()
    for name, reason in _GLOBAL_GROUP_EXEMPT.items():
        assert name in workflows, f"{name} no longer exists; update _GLOBAL_GROUP_EXEMPT"
        group = str((workflows[name].get("concurrency") or {}).get("group", ""))
        assert group, f"{name} lost its concurrency block entirely"
        assert "github.ref" not in group, (
            f"{name}'s concurrency group is now {group!r}, keyed on github.ref. That was a "
            f"deliberate exemption: {reason} Keying on ref lets two Pages deployments run at "
            "once, which is the conflict the single group prevents."
        )


def test_no_workflow_grants_write_permission_at_the_top_level():
    """Least privilege, which was ALREADY correct — asserted so it stays that way.

    Every workflow declares a top-level `contents: read` / `read-all`, and only the four jobs that
    need more (`security-events: write`, `pages: write`, `id-token: write`,
    `attestations: write`) widen it themselves. This round changed nothing here; without a check,
    a future job could quietly inherit write access from a relaxed top-level block.
    """
    offenders = []
    for name, doc in _workflows().items():
        perms = doc.get("permissions")
        assert perms is not None, (
            f"{name} declares no top-level `permissions`, so it inherits the repository default "
            "— which may be read/write. Declare `contents: read` and let jobs widen as needed."
        )
        if isinstance(perms, str):
            if perms not in {"read-all"}:
                offenders.append(f"{name}: permissions: {perms}")
            continue
        for scope, level in perms.items():
            if level == "write":
                offenders.append(f"{name}: top-level {scope}: write")
    assert not offenders, (
        "workflow(s) grant write permission at the TOP level, so every job in them inherits it "
        "whether it needs it or not:\n  " + "\n  ".join(offenders)
        + "\n\nKeep the top level read-only and let the individual job that needs write declare it."
    )


def test_jobs_that_widen_permissions_are_the_expected_ones():
    """The complement: writes are permitted, but only where they are understood.

    Recorded so a new write-scoped job is a deliberate decision rather than a diff nobody read.
    """
    expected = {
        ("codeql.yml", "analyze"): {"security-events"},
        ("docs.yml", "deploy"): {"pages", "id-token"},
        ("release.yml", "build"): {"contents", "id-token", "attestations"},
        ("release.yml", "pypi-publish"): {"id-token"},
        ("scorecard.yml", "analysis"): {"security-events", "id-token"},
    }
    actual = {}
    for name, doc in _workflows().items():
        for job_name, job in _jobs(doc).items():
            perms = (job or {}).get("permissions")
            if not isinstance(perms, dict):
                continue
            writes = {scope for scope, level in perms.items() if level == "write"}
            if writes:
                actual[(name, job_name)] = writes

    unexpected = {k: v for k, v in actual.items() if k not in expected}
    assert not unexpected, (
        f"job(s) request write permissions and are not in this module's recorded set: "
        f"{ {f'{a}:{b}': sorted(v) for (a, b), v in unexpected.items()} }. If the new scope is "
        "correct, add it here with the reason; a write scope nobody reviewed is how a workflow "
        "gains more authority than its purpose needs."
    )
    for key, wanted in expected.items():
        assert key in actual, (
            f"{key[0]}:{key[1]} no longer requests write scopes {sorted(wanted)}. If the job was "
            "renamed or the scope genuinely became unnecessary, update this map — a stale "
            "expectation silently stops checking the real job."
        )
        assert actual[key] == wanted, (
            f"{key[0]}:{key[1]} write scopes changed from {sorted(wanted)} to "
            f"{sorted(actual[key])}. Confirm the new scope is required and update this map."
        )
