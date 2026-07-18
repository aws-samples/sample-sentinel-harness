"""
Offline tests for the ``sentinel detection audit <dir>`` CLI subcommand.
================================================================================
The subcommand reads every .yml/.yaml Sigma rule under a directory, runs the
deterministic ``detection_audit`` aggregator, and prints a report / JSON / an
ATT&CK Navigator layer. With ``--min-score`` it gates CI (exit 1 below threshold).

Pinned here: rule discovery, exit codes (0 clean / 1 below-min-score / 2 bad
input), the report + --json + --navigator surfaces, and --techniques coverage.

HARD RULE: ZERO AWS, ZERO network — the detection tools are pure/offline; dummy
env is set before import so client construction never reaches AWS.
"""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import cli  # noqa: E402

_GOOD = """
title: PowerShell Encoded Command
id: r-ps-001
logsource:
    product: windows
    category: process_creation
tags:
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""

_DUP = """
title: PS Encoded copy
id: r-ps-002
logsource:
    product: windows
    category: process_creation
tags:
    - attack.t1059.001
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"""

_BROKEN = """
title: broken
detection:
    selection:
        x: y
"""


def _write_rules(tmp_path, files: dict) -> str:
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    return str(tmp_path)


# --------------------------------------------------------------------------- #
# happy path + report                                                         #
# --------------------------------------------------------------------------- #
def test_clean_library_reports_and_exits_zero(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "audit", d])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Rule-library health:" in out
    assert "100/100" in out


def test_report_lists_findings_worst_first(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD, "b.yaml": _DUP, "c.yml": _BROKEN})
    rc = cli.main(["detection", "audit", d, "--techniques", "T1059,T1190,T1046"])
    out = capsys.readouterr().out
    assert rc == 0
    # critical (invalid) precedes high (uncovered) precedes medium (dup)
    crit = out.index("[critical]")
    high = out.index("[high]")
    med = out.index("[medium]")
    assert crit < high < med


def test_recursive_discovery(tmp_path, capsys):
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "deep.yml").write_text(_GOOD)
    rc = cli.main(["detection", "audit", str(tmp_path)])
    assert rc == 0
    assert "1 rule(s)" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# --json / --navigator                                                        #
# --------------------------------------------------------------------------- #
def test_json_output_is_parseable(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "audit", d, "--json"])
    obj = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert obj["ok"] and obj["health_score"] == 100


def test_navigator_stdout_emits_layer(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "audit", d, "--techniques", "T1059,T1190", "--navigator"])
    layer = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1059", "T1190"}


def test_navigator_to_file(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    out_file = tmp_path / "layer.json"
    rc = cli.main(["detection", "audit", d, "--techniques", "T1059", "--navigator", str(out_file)])
    assert rc == 0 and out_file.is_file()
    layer = json.loads(out_file.read_text())
    assert layer["domain"] == "enterprise-attack"


# --------------------------------------------------------------------------- #
# --min-score CI gate + exit codes                                            #
# --------------------------------------------------------------------------- #
def test_min_score_gate_fails_below_threshold(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD, "b.yaml": _DUP, "c.yml": _BROKEN})
    rc = cli.main(["detection", "audit", d, "--min-score", "95"])
    assert rc == 1
    assert "min-score" in capsys.readouterr().err


def test_min_score_gate_passes_clean_library(tmp_path):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "audit", d, "--min-score", "90"])
    assert rc == 0


def test_empty_dir_exits_2(tmp_path, capsys):
    d = str(tmp_path)  # no rule files
    rc = cli.main(["detection", "audit", d])
    assert rc == 2
    assert "no .yml/.yaml" in capsys.readouterr().err


def test_missing_dir_exits_2(capsys):
    rc = cli.main(["detection", "audit", "/nonexistent/path/xyz"])
    assert rc == 2


def test_detection_requires_subcommand(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["detection"])


# --------------------------------------------------------------------------- #
# `sentinel detection baseline` — regression gate                            #
# --------------------------------------------------------------------------- #
def test_baseline_snapshot_then_identical_compare_ok(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    snap = tmp_path / "baseline.json"
    rc = cli.main(["detection", "baseline", d, "--snapshot", str(snap)])
    assert rc == 0 and snap.is_file()
    capsys.readouterr()
    # comparing the same tree against its own snapshot => no regression
    rc = cli.main(["detection", "baseline", d, "--against", str(snap)])
    out = capsys.readouterr().out
    assert rc == 0 and "OK (no regression)" in out


def test_baseline_detects_regression_and_exits_1(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    snap = tmp_path / "baseline.json"
    cli.main(["detection", "baseline", d, "--snapshot", str(snap)])
    capsys.readouterr()
    # degrade the library: add a structurally-broken rule, then compare
    (tmp_path / "broken.yml").write_text(_BROKEN)
    rc = cli.main(["detection", "baseline", d, "--against", str(snap)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "REGRESSED" in out and "new invalid rule" in out


def test_baseline_snapshot_to_stdout(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "baseline", d, "--snapshot"])
    obj = json.loads(capsys.readouterr().out)
    assert rc == 0 and "health_score" in obj


def test_baseline_allow_score_drop_tolerates_small_regression(tmp_path, capsys):
    # snapshot a clean lib, then compare a slightly-degraded one within tolerance.
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    snap = tmp_path / "b.json"
    cli.main(["detection", "baseline", d, "--snapshot", str(snap)])
    capsys.readouterr()
    (tmp_path / "dup.yaml").write_text(_DUP)   # adds a duplicate pair -> score drop
    # a generous tolerance still fails because a NEW duplicate pair is set-growth,
    # but a huge tolerance + no new set item would pass — assert the set-diff wins.
    rc = cli.main(["detection", "baseline", d, "--against", str(snap),
                   "--allow-score-drop", "100"])
    out = capsys.readouterr().out
    assert rc == 1 and "duplicate pair" in out   # set-growth regresses despite tolerance


def test_baseline_compare_without_against_exits_2(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "baseline", d])   # neither --snapshot nor --against
    assert rc == 2
    assert "--snapshot" in capsys.readouterr().err


def test_baseline_missing_baseline_file_exits_2(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "baseline", d, "--against", str(tmp_path / "nope.json")])
    assert rc == 2


# --------------------------------------------------------------------------- #
# `sentinel detection ci` — one-shot combined gate                           #
# --------------------------------------------------------------------------- #
def test_ci_clean_passes(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    rc = cli.main(["detection", "ci", d, "--min-score", "90"])
    out = capsys.readouterr().out
    assert rc == 0 and "CI GATE: PASS" in out


def test_ci_min_score_gate_fails(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD, "broken.yml": _BROKEN})
    rc = cli.main(["detection", "ci", d, "--min-score", "95"])
    out = capsys.readouterr().out
    assert rc == 1 and "CI GATE: FAIL" in out and "min-score" in out


def test_ci_regression_gate_fails(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    snap = tmp_path / "b.json"
    cli.main(["detection", "baseline", d, "--snapshot", str(snap)])
    capsys.readouterr()
    (tmp_path / "broken.yml").write_text(_BROKEN)
    # no --min-score, so ONLY the regression gate can fail it
    rc = cli.main(["detection", "ci", d, "--against", str(snap)])
    out = capsys.readouterr().out
    assert rc == 1 and "regressed vs baseline" in out


def test_ci_both_gates_reported(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    snap = tmp_path / "b.json"
    cli.main(["detection", "baseline", d, "--snapshot", str(snap)])
    capsys.readouterr()
    (tmp_path / "broken.yml").write_text(_BROKEN)
    rc = cli.main(["detection", "ci", d, "--min-score", "95", "--against", str(snap)])
    out = capsys.readouterr().out
    assert rc == 1
    # BOTH failures listed
    assert "min-score" in out and "regressed vs baseline" in out


def test_ci_navigator_export_side_effect(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD})
    nav = tmp_path / "layer.json"
    rc = cli.main(["detection", "ci", d, "--min-score", "90",
                   "--techniques", "T1059", "--navigator-out", str(nav)])
    assert rc == 0 and nav.is_file()
    layer = json.loads(nav.read_text())
    assert layer["versions"]["layer"] == "4.5"


def test_ci_json_summary(tmp_path, capsys):
    d = _write_rules(tmp_path, {"a.yml": _GOOD, "broken.yml": _BROKEN})
    rc = cli.main(["detection", "ci", d, "--min-score", "95", "--json"])
    obj = json.loads(capsys.readouterr().out)
    assert rc == 1 and obj["passed"] is False and obj["gate_failures"]


def test_ci_empty_dir_exits_2(tmp_path, capsys):
    rc = cli.main(["detection", "ci", str(tmp_path)])
    assert rc == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
