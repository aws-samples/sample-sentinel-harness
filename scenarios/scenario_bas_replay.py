"""
Scenario — BAS replay: attack cases -> detection replay -> blind-spot report
============================================================================
Layer 2 (Attack Validation & Simulation) · the M3 proof point.

Mirrors the customer flow "generate a set of Breach-and-Attack-Simulation (BAS)
cases from a chosen ATT&CK technique set -> replay each case against the SIEM's
current Sigma detection rules -> report which techniques went UNDETECTED (the
'detection blind spots')". That undetected list is the deliverable a detection
engineer acts on.

What is REAL vs SIMULATED (be scrupulous — this is L2 attack simulation)
------------------------------------------------------------------------
- REAL, deterministic, offline Python (the provable core): BAS case generation
  + the Sigma matcher + the replay/blind-spot report. All delegated to the
  existing ``longrunning/bas-runner/bas_cases.py`` (which itself reuses the real
  ``tools/sigma_match`` matcher — a hand-written parser + evaluator, no eval, no
  LLM, no network, no AWS). Same input -> same output.
- SIMULATED: the "attack" itself. A BAS case carries synthetic *telemetry
  events* (dicts of Sysmon-style log fields) describing what the technique WOULD
  emit — never a real exploit, real malware, or a live network action. Nothing
  is executed. Sample "entry" is modeled as a controlled S3-dropbox path/uri
  abstraction elsewhere, never a live fetch.
- The optional live path (behind :func:`build` / ``__main__``) is where an
  authoring harness could DRAFT new Sigma rules for the blind spots; even there
  every offensive/authoring step stays HITL-gated via the existing Play Mode and
  detonation is a simulated no-op. The DEFAULT run is PURE and needs no AWS / no
  invoke quota.

Structured verdict
-------------------
This scenario's deliverable is a verdict::

    {"techniques_tested": [...], "techniques_detected": [...],
     "blind_spots": [...], "coverage_ratio": <float in [0,1]>, "note": "..."}

built on top of ``bas_cases.replay``. The built-in Sigma rule set below covers
SOME but NOT all of the default techniques, so the blind-spot finding is real.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from types import ModuleType
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

RESULT: Dict[str, Any] = {"scenario": "bas_replay_blind_spots", "steps": []}

# Account-id scrubber — identical pattern to the other scenarios. This run is
# PURE (no ARNs are produced), but we keep the scrubber for consistency so any
# ARN that ever flows through evidence is masked to <ACCOUNT_ID>.
_ACCT_RE = re.compile(r"(arn:aws[^:]*:[^:]*:[^:]*:)\d{12}(:)")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ACCT_RE.sub(r"\1<ACCOUNT_ID>\2", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def rec(step: str, data: Any) -> None:
    data = _scrub(data)
    RESULT["steps"].append({"step": step, "data": data})
    print(f"[{step}] {json.dumps(data, ensure_ascii=False)[:220]}", flush=True)


# --------------------------------------------------------------------------
# Load the deterministic BAS core (generate_cases + replay) by absolute path.
#
# bas_cases.py lives at longrunning/bas-runner/bas_cases.py — a hyphenated
# directory that is NOT an importable package, so we load it by path via
# importlib exactly as its own callers do. We never swallow a *broken* module:
# a present-but-unloadable bas_cases.py surfaces its ImportError.
# --------------------------------------------------------------------------
def _bas_cases_path() -> str:
    return os.path.join(
        os.path.dirname(__file__), "..", "longrunning", "bas-runner", "bas_cases.py"
    )


def _load_bas_cases() -> ModuleType:
    """Import the bas_cases module by absolute path.

    Raises ImportError if the module is missing or cannot be loaded — the BAS
    replay is meaningless without the real case generator + matcher, so we refuse
    to silently degrade rather than fabricate a fake report.
    """
    path = _bas_cases_path()
    if not os.path.exists(path):
        raise ImportError(
            f"bas_cases module not found at {path!r}; the M3 BAS replay requires "
            "longrunning/bas-runner/bas_cases.py (generate_cases + replay)"
        )
    spec = importlib.util.spec_from_file_location("bas_cases", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not build import spec for {path!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for attr in ("generate_cases", "replay"):
        if not hasattr(module, attr):
            raise ImportError(f"{path!r} does not expose a '{attr}' callable")
    return module


# --------------------------------------------------------------------------
# Default technique set + built-in Sigma rules.
#
# The technique set is drawn from the built-in BAS case library. The rule set
# below covers T1059.001 (PowerShell) and T1046 (nmap) but NOT T1003.001 (LSASS
# dump) or T1547.001 (Run-key persistence) — so replaying all four yields a real,
# non-empty blind-spot list. Field names follow the Sysmon-style Sigma
# convention the BAS cases emit (Image / CommandLine / ...), so rules replay
# unchanged through the real sigma_match matcher.
# --------------------------------------------------------------------------
DEFAULT_TECHNIQUES: List[str] = [
    "T1059.001",  # PowerShell — covered by a rule
    "T1046",      # Network service discovery (nmap) — covered
    "T1003.001",  # OS credential dumping: LSASS — NO rule (blind spot)
    "T1547.001",  # Run-key persistence — NO rule (blind spot)
]

BUILTIN_SIGMA_RULES: List[str] = [
    """
title: PowerShell Encoded Command Execution
id: 11111111-1111-1111-1111-111111111111
status: experimental
level: high
tags:
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
""",
    """
title: Network Service Discovery via nmap
id: 22222222-2222-2222-2222-222222222222
status: experimental
level: medium
tags:
    - attack.t1046
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: 'nmap.exe'
    condition: selection
""",
]


# --------------------------------------------------------------------------
# Replay -> structured verdict (the deliverable).
# --------------------------------------------------------------------------
def build_verdict(
    techniques: List[str],
    rule_texts: List[str],
    *,
    bas_module: Optional[ModuleType] = None,
) -> Dict[str, Any]:
    """Replay BAS cases for ``techniques`` vs ``rule_texts`` and shape the verdict.

    Pure, deterministic, offline. Delegates case generation + matching to the
    real ``bas_cases`` core, then reshapes its report into the scenario verdict:
    ``techniques_tested`` / ``techniques_detected`` / ``blind_spots`` (undetected)
    / ``coverage_ratio`` in [0,1] / ``note``.

    A technique counts as DETECTED iff at least one rule fired on one of its
    simulated events (the ``bas_cases`` definition of ``detected``).
    """
    bas = bas_module or _load_bas_cases()
    cases = bas.generate_cases(list(techniques))
    report = bas.replay(cases, rule_texts)

    tested = [c["technique_id"] for c in cases]
    # Preserve request order, dedupe (first-occurrence wins).
    tested_unique = [t for i, t in enumerate(tested) if t not in tested[:i]]
    detected = [r["technique_id"] for r in report["results"] if r["detected"]]
    blind_spots = list(report["blind_spots"])
    coverage_ratio = float(report["coverage"])

    return {
        "techniques_tested": tested_unique,
        "techniques_detected": detected,
        "blind_spots": blind_spots,
        "coverage_ratio": round(coverage_ratio, 4),
        "per_technique": [
            {"technique": r["technique_id"], "name": r.get("name"),
             "detected": r["detected"], "firing_rules": r["matched_rules"]}
            for r in report["results"]
        ],
        "note": (
            "REAL deterministic BAS replay (generate_cases + sigma_match matcher, "
            "offline, no LLM/network/AWS). BAS cases carry SIMULATED telemetry, "
            "never live attacks. 'blind_spots' are techniques for which no current "
            "rule fired — the detection-engineering backlog. coverage_ratio = "
            "detected / techniques_tested."
        ),
    }


def run_pure() -> Dict[str, Any]:
    """The default PURE run: replay the default techniques vs the built-in rules.

    Proves generate_cases + matcher + replay + blind-spot report end to end with
    zero AWS and zero invoke quota. Prints a clear narrative + the blind-spot list.
    """
    rec("techniques", {"set": DEFAULT_TECHNIQUES})
    rec("rules", {"count": len(BUILTIN_SIGMA_RULES),
                  "covers": ["T1059.001", "T1046"]})
    verdict = build_verdict(DEFAULT_TECHNIQUES, BUILTIN_SIGMA_RULES)
    for entry in verdict["per_technique"]:
        rec("replay_technique", entry)
    RESULT["verdict"] = verdict

    print("\n=== BAS replay narrative ===")
    print(f"Tested {len(verdict['techniques_tested'])} technique(s) against "
          f"{len(BUILTIN_SIGMA_RULES)} Sigma rule(s).")
    print(f"Detected: {verdict['techniques_detected']}")
    print(f"BLIND SPOTS (undetected, action needed): {verdict['blind_spots']}")
    print(f"coverage_ratio = {verdict['coverage_ratio']}")
    return verdict


# --------------------------------------------------------------------------
# Optional live authoring path — guarded so importing the module is offline-safe.
# --------------------------------------------------------------------------
def build() -> Any:
    """Optionally stand up an authoring harness to DRAFT new Sigma rules for the
    blind spots (the only place that would touch AWS).

    Guarded here (and under ``__main__``) so importing this module never touches
    AWS. Every authoring step stays HITL-gated via the existing Play Mode;
    detonation, if wired, is a SIMULATED no-op. The default run does NOT call this
    — the provable core is the pure replay above.
    """
    from sentinel_harness import core as sh  # imported lazily: builds a boto3 client

    author = sh.create_harness(
        "sentinel_bas_rule_author",
        "You are a detection engineer. Given an ATT&CK technique with no current "
        "coverage, draft ONE concise Sigma rule (YAML) to close the blind spot. "
        "Output only the YAML rule; a human reviews before it goes live.",
        model=sh.bedrock_model(sh.MODEL_SONNET), max_iterations=6)
    sh.wait_ready(author["harnessId"])
    rec("built_author", {"author": author["harnessId"]})
    return author["arn"]


if __name__ == "__main__":
    # Default is PURE: no AWS, no invoke quota. Proves the deterministic core.
    verdict = run_pure()
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "bas_replay_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/bas_replay_result.json")
