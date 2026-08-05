"""INV-EVIDENCE-1 — committed evidence is byte-reproducible by re-running its scenario.

`evidence/*.json` is the strongest claim this repository makes: 38 artifacts asserting that
specific behaviour was observed. A reader is invited to trust them, and README/FIDELITY-REPORT
count them as proof of scale.

That trust rests on a property nothing checked: **that re-running the scenario reproduces the
committed file.** Measured, all 11 offline-runnable scenarios: corrupt the artifact, re-run,
and `git diff` is empty — byte-identical, not merely semantically equal. No timestamps, no random
ids, no dict-order churn.

Which is excellent, and entirely undefended. Any change that introduces non-determinism — a
`datetime.now()` in an output field, an unsorted `set` rendered into a list, a uuid — would
silently break "the evidence is reproducible" and only surface when a human happened to re-run a
scenario and see a dirty tree. Meanwhile the artifacts would keep asserting behaviour that could
no longer be confirmed.

Worse, the reverse: if a scenario's behaviour CHANGES and the artifact is not regenerated, the
committed evidence asserts something the code no longer does. That is a false claim in the one
place the project asks to be believed. This guard fails in both directions, because it compares
what the code produces now against what is committed.

Why "corrupt, re-run, compare" rather than "run twice"
-----------------------------------------------------
Running a scenario twice and diffing proves only self-consistency: a scenario that always writes
`{"timestamp": now()}` fails that test, but so would a scenario that writes nothing at all — in
which case the two runs agree trivially. Corrupting the file first makes "did not write" fail
loudly, so a passing result means both *wrote* and *reproduced*. That distinction is the same one
INV-CI-1/INV-DOC-5 record: a check that no-ops must not look like a check that passed.

ZERO network, ZERO AWS: the scenarios in `_REPRODUCIBLE` are the offline-runnable set already
established by `tests/test_scenarios_execute.py`.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS_DIR = os.path.join(REPO_ROOT, "scenarios")
EVIDENCE_DIR = os.path.join(REPO_ROOT, "evidence")

# The offline-runnable scenarios that write an evidence artifact. Kept in step with
# `tests/test_scenarios_execute.py::_OFFLINE_RUNNABLE` by
# `test_the_reproducible_set_matches_the_offline_runnable_set` below — two hand-maintained lists
# that agree today and would drift silently is the coupling this repo keeps finding defects in.
_REPRODUCIBLE = (
    "scenario_agent_authored_loop",
    "scenario_alert_triage_poc",
    "scenario_autonomous_loop",
    "scenario_bas_replay",
    "scenario_benchmark",
    "scenario_cve_asset_triage",
    "scenario_detonation",
    # Added after the list-parity guard below caught its absence — I had assembled
    # `_REPRODUCIBLE` by hand from the scenarios I happened to run, and missed this one.
    "scenario_e2e_pipeline",
    "scenario_eval_all_domains",
    "scenario_feedback_loop",
    "scenario_registry_governance",
    "scenario_tracing",
)

_ENV = {
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/test",
    "SENTINEL_REGION": "us-east-1",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "SENTINEL_GATEWAY_ARN": "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test",
    "SENTINEL_GATEWAY_URL": "https://gw.example.internal/mcp",
    "SENTINEL_MEMORY_ID": "mem-test-000",
}


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True, timeout=180)


def _in_git_checkout() -> bool:
    dot_git = os.path.join(REPO_ROOT, ".git")
    return os.path.isdir(dot_git) or os.path.isfile(dot_git)


def _evidence_path_for(scenario: str) -> str | None:
    """The evidence file a scenario writes, read out of its source."""
    path = os.path.join(SCENARIOS_DIR, f"{scenario}.py")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        source = fh.read()

    # Resolved from the AST, not by regex.
    #
    # Two regex attempts failed here, both instructively. The first took the first `"*.json"`
    # literal present on disk and mis-resolved `scenario_live_a2a_runtime`: that scenario writes
    # `live_a2a_runtime_mock_result.json` offline and deliberately uses a DIFFERENT name so the
    # genuine one-off on-account capture in `live_a2a_runtime_result.json` is never clobbered (its
    # own source says so). The loose parser picked the live capture, "proved" it non-deterministic,
    # and — but for a backup — would have destroyed verified evidence to make that point: exactly
    # the failure this module exists to prevent, committed by the module itself.
    #
    # The second tightened it to `os.path.join(...["evidence"], "<name>.json")` and then missed
    # `scenario_bas_replay` / `scenario_detonation`, which write
    # `os.path.join(os.path.dirname(__file__), "..", "evidence", "x.json")` — the NESTED call's
    # closing paren defeats a `[^)]*?` character class.
    #
    # Parsing code structure with regexes is the trap this repo records most, so: walk the tree,
    # find `os.path.join` calls, and take the string arguments that follow an "evidence" segment.
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - the suite would not import either
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "join"):
            continue
        parts = [a.value for a in node.args
                 if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if "evidence" not in parts:
            continue
        for part in parts[parts.index("evidence") + 1:]:
            if part.endswith(".json"):
                candidate = os.path.join(EVIDENCE_DIR, part)
                if os.path.isfile(candidate):
                    return candidate
    return None


def _run_scenario(scenario: str) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **_ENV}
    return subprocess.run(
        [sys.executable, os.path.join("scenarios", f"{scenario}.py")],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, env=env,
    )


def test_every_listed_scenario_has_an_evidence_artifact():
    """Positive control. Each test below resolves an evidence path; if resolution silently
    returned None the parametrised cases would skip and this module would report green while
    checking nothing."""
    missing = [s for s in _REPRODUCIBLE if _evidence_path_for(s) is None]
    assert not missing, (
        f"scenario(s) {missing} are listed as reproducible but no evidence file could be "
        "resolved from their source. Either they stopped writing one (the artifact is now "
        "stale forever) or this parser is blind — both must fail loudly."
    )
    assert len(_REPRODUCIBLE) >= 8, "the reproducible set shrank — check why before accepting it"


@pytest.mark.parametrize("scenario", _REPRODUCIBLE)
def test_rerunning_the_scenario_reproduces_the_committed_evidence(scenario, tmp_path):
    """The contract that makes `evidence/` worth trusting.

    Fails in BOTH directions, which is the point:
      - non-determinism introduced into the output -> diff appears
      - behaviour changed without regenerating the artifact -> diff appears

    The file is CORRUPTED before the re-run deliberately. Diffing two fresh runs would prove only
    self-consistency, and a scenario that writes nothing would pass that trivially. Corrupting
    first makes "did not write" fail loudly, so passing means both wrote and reproduced.
    """
    if not _in_git_checkout():
        pytest.skip("needs git to compare against the committed artifact (not an sdist)")

    evidence = _evidence_path_for(scenario)
    assert evidence, f"no evidence file resolved for {scenario}"
    relative = os.path.relpath(evidence, REPO_ROOT)

    # Refuse to run against a dirty artifact: the comparison would be against uncommitted work
    # and its verdict would be meaningless in either direction.
    dirty = _git("status", "--porcelain", "--", relative).stdout.strip()
    if dirty:
        pytest.skip(
            f"{relative} has uncommitted changes ({dirty!r}); this guard compares against the "
            "COMMITTED artifact, so its verdict would be meaningless. Commit or restore first."
        )

    backup = tmp_path / os.path.basename(evidence)
    shutil.copy2(evidence, backup)
    try:
        with open(evidence, "w", encoding="utf-8") as fh:
            fh.write('{"deliberately": "corrupted by test_evidence_is_reproducible"}\n')

        proc = _run_scenario(scenario)
        assert proc.returncode == 0, (
            f"{scenario} failed to run:\n{(proc.stdout + proc.stderr)[-1500:]}"
        )

        diff = _git("diff", "--", relative)
        assert diff.stdout.strip() == "", (
            f"re-running {scenario} did NOT reproduce the committed {relative}.\n\n"
            "Either the scenario became non-deterministic (a timestamp, a uuid, an unsorted set "
            "rendered to a list), or its behaviour changed and the artifact was not regenerated "
            "— in which case the committed evidence asserts something the code no longer does.\n"
            "Regenerate with:\n"
            f"    uv run python scenarios/{scenario}.py\n\n"
            f"diff (first 2500 chars):\n{diff.stdout[:2500]}"
        )
    finally:
        shutil.copy2(backup, evidence)


def test_the_reproducible_set_matches_the_offline_runnable_set():
    """Guard the coupling between two hand-maintained lists.

    `test_scenarios_execute.py` already classifies every scenario as offline-runnable or
    live-only. If a scenario is added there as offline but not here, its evidence silently stops
    being reproducibility-checked — and nothing would say so. Two lists that agree today and
    drift tomorrow is the shape this repo keeps finding defects in.
    """
    sibling = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "test_scenarios_execute.py")
    with open(sibling, encoding="utf-8") as fh:
        source = fh.read()
    block = re.search(r"_OFFLINE_RUNNABLE\s*=\s*\((.*?)\n\)", source, re.S)
    assert block, "could not locate _OFFLINE_RUNNABLE in test_scenarios_execute.py"
    offline = set(re.findall(r'"(scenario_[a-z0-9_]+)"', block.group(1)))
    assert len(offline) >= 8, f"parsed only {len(offline)} offline scenarios: {sorted(offline)}"

    # A scenario may be offline-runnable and write NO evidence — that is fine and not drift.
    writes_evidence = {s for s in offline if _evidence_path_for(s) is not None}
    unchecked = sorted(writes_evidence - set(_REPRODUCIBLE))
    assert not unchecked, (
        f"scenario(s) {unchecked} run offline and write evidence, but are not in _REPRODUCIBLE, "
        "so their artifacts are never checked for reproducibility. Add them here."
    )
    stale = sorted(set(_REPRODUCIBLE) - offline)
    assert not stale, (
        f"scenario(s) {stale} are listed here but no longer offline-runnable per "
        "test_scenarios_execute.py. A guard whose premise expired is worse than none."
    )


def test_no_committed_evidence_carries_a_real_account_id():
    """Adjacent property, cheap to check while we are reading every artifact.

    Every account id in this public repo must be the `000000000000` placeholder. The shared
    secret scan covers source; this walks the JSON structurally, so an id nested in a
    deeply-embedded ARN cannot hide behind a line-oriented grep.
    """
    account_re = re.compile(r"arn:aws[a-z-]*:[^:]*:[^:]*:(\d{12}):")
    offenders = []
    for name in sorted(os.listdir(EVIDENCE_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(EVIDENCE_DIR, name), encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:  # a corrupt artifact is its own defect
                pytest.fail(f"evidence/{name} is not valid JSON: {exc}")

        def walk(node, path=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    walk(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}[{index}]")
            elif isinstance(node, str):
                for account in account_re.findall(node):
                    if account != "000000000000":
                        offenders.append(f"{name}{path}: {account}")

        walk(data)
    assert not offenders, (
        f"evidence file(s) carry a non-placeholder AWS account id: {offenders}. This repo is "
        "public; every account id must be 000000000000."
    )
