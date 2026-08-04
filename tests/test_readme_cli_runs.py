"""
The documented CLI commands must run on a fresh clone.
=====================================================
The README advertises the detection suite with four copy-pasteable commands over a
directory of Sigma rules::

    sentinel detection audit rules/ --techniques T1059,T1190
    sentinel detection audit rules/ --navigator layer.json
    sentinel detection baseline rules/ --snapshot baseline.json
    sentinel detection ci rules/ --min-score 90 --against baseline.json --navigator-out ...

A third test sweep ran them and found `rules/` **did not exist anywhere in the
repository**. Every one of the four failed on line 1 for a new reader, and the flagship
offline feature had no runnable input. Not a code defect — the CLI is correct — but the
same class as INV-IDENTITY-3, where documented `git clone && cd` commands named a
directory clone does not create: a documented command that cannot run is a false claim.

It also meant these three commands had never been executed end to end. The suite was
green at 3693 and `make ci` passed, because nothing could feed them a rule library.

`tests/test_docs_drift.py` checks quoted COUNTS and docstrings; it does not check whether
a documented command runs. This file does, for the commands whose inputs are in-repo.

The `rules/` library is deliberately imperfect (a near-duplicate pair, one untagged rule)
so the health score, the findings list and the `--min-score` gate all have something real
to report — a library scoring 100 would make all three look like decoration.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

import child_pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
README = REPO_ROOT / "README.md"


def _run_cli(*args: str, timeout: float = 300):
    """Run `sentinel <args>` through the shared child launcher.

    Uses `-m sentinel_harness.cli` rather than the `sentinel` console script: the script
    only exists once the package is installed, and hardcoding a launcher is the mistake
    this repo has now made five times (see tests/child_pytest.py).
    """
    import os
    import subprocess

    launcher = child_pytest.resolve_python_launcher()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["SENTINEL_REGION"] = "us-east-1"
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    return subprocess.run(
        [*launcher, "-m", "sentinel_harness.cli", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout, env=env,
    )


# --------------------------------------------------------------------------- #
# The sample library the README's commands point at                            #
# --------------------------------------------------------------------------- #
def test_the_documented_rules_directory_exists():
    """The README names `rules/` in four commands. It must be there."""
    assert RULES_DIR.is_dir(), (
        "rules/ is missing, so every documented `sentinel detection ...` command fails "
        "on line 1 for a new reader"
    )
    rules = sorted(RULES_DIR.glob("*.yml")) + sorted(RULES_DIR.glob("*.yaml"))
    assert len(rules) >= 3, f"rules/ has only {len(rules)} rule(s); too few to audit"


def test_the_sample_library_is_deliberately_imperfect():
    """A library that scored 100 would make the health score, the findings list and the
    --min-score gate all look decorative. The audit must have something to report."""
    result = _run_cli("detection", "audit", "rules/", "--json")
    assert result.returncode == 0, (result.stdout + result.stderr)[-800:]
    report = json.loads(result.stdout)
    score = report.get("health_score", report.get("score"))
    assert isinstance(score, int) and 0 < score < 100, (
        f"health score is {score!r}; the sample library must be imperfect enough to "
        "exercise the findings path, and good enough to look like real content"
    )
    findings = report.get("findings") or []
    assert findings, "the audit produced no findings — nothing to demonstrate"


# --------------------------------------------------------------------------- #
# The four README commands, verbatim                                          #
# --------------------------------------------------------------------------- #
class TestTheReadmeCommandsRun:
    """Each is the README line with only the output path redirected to tmp."""

    def test_audit_with_techniques(self):
        result = _run_cli("detection", "audit", "rules/",
                          "--techniques", "T1059,T1190")
        assert result.returncode == 0, (result.stdout + result.stderr)[-800:]
        assert "Rule-library health" in result.stdout, result.stdout[-400:]

    def test_audit_exports_a_navigator_layer(self, tmp_path):
        out = tmp_path / "layer.json"
        result = _run_cli("detection", "audit", "rules/", "--navigator", str(out))
        assert result.returncode == 0, (result.stdout + result.stderr)[-800:]
        assert out.is_file() and out.stat().st_size > 0, "no Navigator layer written"
        layer = json.loads(out.read_text(encoding="utf-8"))
        assert layer.get("techniques") is not None, f"not a Navigator layer: {sorted(layer)}"

    def test_baseline_writes_a_snapshot(self, tmp_path):
        out = tmp_path / "baseline.json"
        result = _run_cli("detection", "baseline", "rules/", "--snapshot", str(out))
        assert result.returncode == 0, (result.stdout + result.stderr)[-800:]
        assert out.is_file() and out.stat().st_size > 0, "no baseline written"

    def test_ci_gate_passes_on_the_shipped_library(self, tmp_path):
        base = tmp_path / "baseline.json"
        assert _run_cli("detection", "baseline", "rules/",
                        "--snapshot", str(base)).returncode == 0
        result = _run_cli("detection", "ci", "rules/", "--min-score", "60",
                          "--against", str(base),
                          "--navigator-out", str(tmp_path / "layer.json"))
        assert result.returncode == 0, (
            "the CI gate fails on the library this repo ships — a reader following the "
            f"README gets a red build:\n{(result.stdout + result.stderr)[-800:]}"
        )
        assert "CI GATE: PASS" in result.stdout


# --------------------------------------------------------------------------- #
# The gate must FAIL when it should — else it is decoration                    #
# --------------------------------------------------------------------------- #
class TestTheCiGateActuallyBites:
    """A gate verified only on its passing branch is half-verified — the lesson from
    rounds 18-21. Each of these is a positive control that ran red before being asserted.
    """

    def test_a_score_below_the_floor_fails(self):
        result = _run_cli("detection", "ci", "rules/", "--min-score", "99")
        assert result.returncode != 0, "an unreachable --min-score exited 0"
        assert "CI GATE: FAIL" in result.stdout, result.stdout[-400:]

    def test_the_gate_still_fires_with_an_export_requested(self, tmp_path):
        """INV-CLI-1 as an END-TO-END check. The `--navigator` branch used to return 0
        before reaching the gate, so asking for an export silently lost the check. The
        invariant has a unit test; this proves it through the real CLI."""
        result = _run_cli("detection", "ci", "rules/", "--min-score", "99",
                          "--navigator-out", str(tmp_path / "layer.json"))
        assert result.returncode != 0, (
            "the gate passed when an export was requested — INV-CLI-1 has regressed, "
            "and a pipeline author who adds an export loses the check with no warning"
        )

    def test_a_shrinking_library_fails_against_a_baseline(self, tmp_path):
        """The regression half of the gate: capture a baseline, remove a rule, compare.

        Moves the file aside and restores it in `finally`, so a failure cannot leave the
        shipped library short a rule.
        """
        base = tmp_path / "baseline.json"
        assert _run_cli("detection", "baseline", "rules/",
                        "--snapshot", str(base)).returncode == 0
        victim = sorted(RULES_DIR.glob("*.yml"))[0]
        stashed = tmp_path / victim.name
        stashed.write_text(victim.read_text(encoding="utf-8"), encoding="utf-8")
        try:
            victim.unlink()
            result = _run_cli("detection", "ci", "rules/", "--min-score", "1",
                             "--against", str(base))
            assert result.returncode != 0, (
                "the library lost a rule and the gate passed — the regression half of "
                "the gate is not wired"
            )
            assert "regressed vs baseline" in result.stdout, result.stdout[-400:]
        finally:
            victim.write_text(stashed.read_text(encoding="utf-8"), encoding="utf-8")
        assert victim.is_file(), "the restore failed; rules/ is now short a rule"


# --------------------------------------------------------------------------- #
# The README and the repo must not drift apart again                          #
# --------------------------------------------------------------------------- #
def test_every_rules_path_the_readme_names_exists():
    """Guard the guard, and the general case: any local path a documented command takes
    must exist, or the command is a false claim.

    Deliberately narrow — only `sentinel detection <cmd> <path>` invocations, whose
    input is a repo directory. Output paths (`layer.json`, `baseline.json`) are created
    BY the commands and must not be required to pre-exist.
    """
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(r"sentinel detection (?:audit|baseline|ci) ([\w./-]+)")
    paths = sorted(set(pattern.findall(text)))
    assert paths, (
        "no documented `sentinel detection <cmd> <path>` invocations found — the regex "
        "stopped matching and this check is vacuous"
    )
    missing = [p for p in paths if not (REPO_ROOT / p.rstrip("/")).exists()]
    assert not missing, (
        f"the README documents these rule paths, which do not exist: {missing}. A "
        "copy-pasteable command that fails on line 1 is a false claim (the "
        "INV-IDENTITY-3 lesson)."
    )


@pytest.mark.parametrize("subcommand", ["audit", "baseline", "ci"])
def test_the_documented_subcommand_exists(subcommand):
    """A README-named subcommand that argparse does not define would fail with a usage
    error, which is the same false claim in a different shape."""
    result = _run_cli("detection", subcommand, "--help")
    assert result.returncode == 0, (result.stdout + result.stderr)[-400:]
    assert f"detection {subcommand}" in result.stdout, result.stdout[:200]
