"""bas_cases — offline BAS case generation + detection-replay (the real M3 core).

SecOps purpose
--------------
Breach & Attack Simulation (BAS) answers a question every detection program
needs to keep answering: *of the adversary techniques we care about, which ones
would our current detection rules actually catch?* The gap — techniques whose
telemetry no rule fires on — is the set of **detection blind spots**, and it is
the single most useful output of a BAS run.

This module is the deterministic, offline heart of that loop:

  1. ``generate_cases`` yields a small built-in library of BAS cases. Each case
     is one ATT&CK technique plus the log telemetry that technique would emit
     (process / command-line / registry fields). The telemetry is **SIMULATED
     data** — hand-authored representative events, not the product of running
     any real tool, malware, or exploit. Nothing is executed; nothing touches
     a network. See "Real vs simulated" below.
  2. ``replay`` takes those cases and a set of Sigma rules, runs every simulated
     event against every rule via the sibling ``tools/sigma_match`` matcher, and
     reports per-case which rule(s) fired, a ``detected`` bool, the top-level
     ``blind_spots`` list (techniques no rule caught), and a coverage ratio.

Real vs simulated (be honest about the boundary)
------------------------------------------------
- **Real / provable:** the Sigma matching (delegated to ``sigma_match``, a pure
  hand-written parser + evaluator with no ``eval()``) and this replay/blind-spot
  arithmetic. Same inputs always produce the same report — it is deterministic,
  LLM-free, token-free, and network-free.
- **Simulated:** the ``simulated_events`` telemetry is authored reference data
  describing what a technique *would* emit. No sample is detonated here, no
  command is run, no host is touched. Actual sample detonation is a separate,
  explicitly simulated no-op skeleton (see the roadmap's M3) and stays HITL-gated
  behind Play Mode; it is deliberately NOT part of this deterministic core.

Reuse
-----
Matching is NOT reimplemented here. ``tools/sigma_match/handler.py`` is loaded by
absolute path via ``importlib`` (tools/ is a flat scripts tree, not an installed
package) exactly as the tool's own tests load it, and its ``handler`` is the sole
decider of whether an event is caught.

Egress & secrets posture
------------------------
- ZERO egress, ZERO secrets, ZERO tokens, no LLM. Import-safe fully offline.
- Execution role / region are referenced elsewhere in the harness via
  ``SENTINEL_EXECUTION_ROLE_ARN`` / ``SENTINEL_REGION`` / ``AWS_PROFILE``; this
  module needs none of them to run.

Public API
----------
- ``generate_cases(technique_ids=None) -> list[dict]``
- ``replay(cases, rules) -> dict``  (deterministic report)
- ``BAS_CASES`` : the built-in case library (list of dicts).
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, List, Optional, Sequence, Union

# A rule is either a Sigma YAML string or an already-parsed mapping — both are
# accepted by the sigma_match handler's input contract.
Rule = Union[str, Dict[str, Any]]


# --------------------------------------------------------------------------
# Load the real matcher by path.
#
# The tool handlers live under tools/<name>/handler.py — a flat scripts tree,
# not an installed package. We load sigma_match's handler by absolute path via
# importlib, the same way tools/sigma_match's own tests do, so we depend on the
# proven matcher rather than reimplementing any matching logic here.
# --------------------------------------------------------------------------
def _sigma_match_handler_path() -> str:
    """Absolute path to tools/sigma_match/handler.py, relative to this file.

    this file: ``<repo>/longrunning/bas-runner/bas_cases.py``
    matcher:   ``<repo>/tools/sigma_match/handler.py``
    """
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    return os.path.join(repo_root, "tools", "sigma_match", "handler.py")


def _load_sigma_match_module():
    """Import the sigma_match handler module by absolute path.

    tools/ is a flat scripts tree, not an installed package, so we load by path
    exactly as the matcher's own tests do. A missing matcher is a hard error
    (raised, not swallowed): blind-spot analysis is meaningless without the real
    matcher, so we refuse to silently degrade.
    """
    handler_path = _sigma_match_handler_path()
    if not os.path.exists(handler_path):
        raise ImportError(
            f"sigma_match handler not found at {handler_path!r}; "
            "BAS replay requires the real matcher (it is never reimplemented)"
        )
    spec = importlib.util.spec_from_file_location("sigma_match_handler", handler_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not build import spec for {handler_path!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "handler"):
        raise ImportError(f"{handler_path!r} does not expose a 'handler' callable")
    return module


# Loaded once at import time. Import-safe offline: sigma_match itself does no
# network / AWS / LLM work, so importing it here keeps this module offline-safe.
_SIGMA_MATCH_MODULE = _load_sigma_match_module()
_SIGMA_MATCH_HANDLER = _SIGMA_MATCH_MODULE.handler


# --------------------------------------------------------------------------
# Built-in BAS case library.
#
# Each case = {technique_id, name, simulated_events}. The events are SIMULATED
# telemetry (representative process / cmdline / registry fields) that the given
# ATT&CK technique would emit — NOT the output of any real execution. Field
# names follow the common Sysmon-style Sigma convention (Image, CommandLine,
# TargetObject, ...) so real-world Sigma rules can be replayed unchanged.
# --------------------------------------------------------------------------
BAS_CASES: List[Dict[str, Any]] = [
    {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "simulated_events": [
            {
                "Image": (
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                ),
                "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        ],
    },
    {
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "simulated_events": [
            {
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": (
                    "rundll32.exe C:\\windows\\System32\\comsvcs.dll, "
                    "MiniDump 624 C:\\temp\\lsass.dmp full"
                ),
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            },
        ],
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "simulated_events": [
            {
                "Image": "C:\\Tools\\nmap.exe",
                "CommandLine": "nmap -sS -p 1-65535 10.0.0.0/24",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        ],
    },
    {
        "technique_id": "T1547.001",
        "name": (
            "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
        ),
        "simulated_events": [
            {
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": (
                    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                    "/v Updater /t REG_SZ /d C:\\Users\\Public\\payload.exe"
                ),
                "TargetObject": (
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                ),
            },
        ],
    },
]

# Fast lookup by technique id (built once; the library is static).
_CASES_BY_TECHNIQUE: Dict[str, Dict[str, Any]] = {
    case["technique_id"]: case for case in BAS_CASES
}


# --------------------------------------------------------------------------
# Case generation
# --------------------------------------------------------------------------
def _copy_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Return a defensive deep-ish copy so callers can't mutate the library.

    Events are copied per-dict; values are scalars so a shallow per-event copy
    is sufficient and keeps the result deterministic and independent.
    """
    return {
        "technique_id": case["technique_id"],
        "name": case["name"],
        "simulated_events": [dict(ev) for ev in case["simulated_events"]],
    }


def generate_cases(
    technique_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Generate BAS cases from the built-in library.

    Parameters
    ----------
    technique_ids:
        If ``None`` (default), every case in the library is returned. Otherwise
        only the cases whose ``technique_id`` appears in the sequence are
        returned, in the order the ids were requested (deduplicated, first
        occurrence wins). Ids are matched case-insensitively and normalized to
        upper-case, mirroring ``attack_lookup``'s handling of technique ids.

    Returns
    -------
    A list of case dicts, each ``{technique_id, name, simulated_events}``. The
    returned cases are copies, so mutating them never corrupts the library.

    Raises
    ------
    ValueError
        If ``technique_ids`` contains an id not present in the library — an
        unknown id almost always signals a caller typo, and silently dropping it
        would hide a real gap in the case set. We surface it rather than swallow.
    """
    if technique_ids is None:
        return [_copy_case(c) for c in BAS_CASES]

    if isinstance(technique_ids, str):
        # A bare string is a common mistake; treat it as a single-id request
        # rather than iterating its characters.
        technique_ids = [technique_ids]

    selected: List[Dict[str, Any]] = []
    seen: set = set()
    for raw in technique_ids:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"technique id must be a non-empty string, got {raw!r}")
        tid = raw.strip().upper()
        if tid in seen:
            continue
        seen.add(tid)
        case = _CASES_BY_TECHNIQUE.get(tid)
        if case is None:
            raise ValueError(
                f"unknown technique id {tid!r}; not in the built-in BAS library "
                f"(known: {sorted(_CASES_BY_TECHNIQUE)})"
            )
        selected.append(_copy_case(case))
    return selected


# --------------------------------------------------------------------------
# Detection replay
# --------------------------------------------------------------------------
def _rule_id(rule: Rule, index: int) -> str:
    """Derive a stable label for a rule for the report.

    Prefers the rule's Sigma ``title`` (then ``id``); falls back to a positional
    label so every rule is identifiable even when it carries neither. Parsing a
    YAML string reuses the matcher's own parser so the label matches how the rule
    is actually interpreted.
    """
    doc: Any = rule
    if isinstance(rule, str):
        # Reuse the matcher's own YAML parser so a label reflects how the rule is
        # actually interpreted; a parse failure here is cosmetic (see below).
        doc = _parse_rule_for_label(rule)
    if isinstance(doc, dict):
        title = doc.get("title")
        if isinstance(title, str) and title.strip():
            return title.strip()
        rid = doc.get("id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()
    return f"rule[{index}]"


def _parse_rule_for_label(rule_text: str) -> Any:
    """Best-effort parse of a rule YAML string, only to derive a display label.

    Reuses the already-loaded matcher module's ``_parse_yaml`` so labeling uses
    the exact same parser the matcher uses. A parse failure here must NOT break
    replay (the matcher itself will surface the real error when it evaluates the
    rule), so this returns ``None`` on failure and the caller falls back to a
    positional label — the one place a parse error is intentionally tolerated,
    and only for cosmetic labeling.
    """
    try:
        return _SIGMA_MATCH_MODULE._parse_yaml(rule_text)
    except Exception:
        # Cosmetic only — never let a label parse failure abort a replay.
        return None


def replay(
    cases: Sequence[Dict[str, Any]],
    rules: Sequence[Rule],
) -> Dict[str, Any]:
    """Replay BAS cases against Sigma rules and report detection blind spots.

    For each case, every simulated event is run against every rule via the real
    ``sigma_match`` handler. A case is ``detected`` when at least one rule fires
    on at least one of its events. A technique that no rule catches is a
    **blind spot**.

    Parameters
    ----------
    cases:
        A sequence of BAS cases (as produced by :func:`generate_cases`).
    rules:
        A sequence of Sigma rules — each a YAML string or an already-parsed dict.
        An empty rule set means nothing can be detected, so every technique
        becomes a blind spot (coverage 0.0).

    Returns
    -------
    A deterministic report::

        {
            "total_cases": int,
            "detected_count": int,
            "coverage": float,          # detected_count / total_cases (0.0 if none)
            "blind_spots": [technique_id, ...],   # techniques no rule caught
            "results": [
                {
                    "technique_id": str,
                    "name": str,
                    "detected": bool,
                    "matched_rules": [rule_label, ...],  # rules that fired
                },
                ...
            ],
        }

    The report preserves the input case order; ``blind_spots`` follows that same
    order. Rule labels are derived from each rule's Sigma ``title``/``id``.

    Raises
    ------
    ValueError
        If a case is malformed (missing ``technique_id`` or ``simulated_events``)
        or if the matcher reports a validation error on a rule/event (a bad rule
        must not be silently treated as "no match" — that would mask a real gap).
    """
    rule_list = list(rules)
    rule_labels = [_rule_id(r, i) for i, r in enumerate(rule_list)]

    results: List[Dict[str, Any]] = []
    blind_spots: List[str] = []
    detected_count = 0

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(f"each case must be a dict, got {type(case).__name__}")
        technique_id = case.get("technique_id")
        name = case.get("name")
        events = case.get("simulated_events")
        if not isinstance(technique_id, str) or not technique_id.strip():
            raise ValueError("case missing a non-empty string 'technique_id'")
        if not isinstance(events, list):
            raise ValueError(
                f"case {technique_id!r} 'simulated_events' must be a list"
            )

        matched_rules: List[str] = []
        for idx, rule in enumerate(rule_list):
            fired = False
            for event in events:
                out = _SIGMA_MATCH_HANDLER({"rule": rule, "log_event": event}, None)
                if not out.get("ok"):
                    # A rule/event the matcher rejects is a real problem to
                    # surface, not a silent "no detection" — never swallow it.
                    raise ValueError(
                        f"sigma_match rejected rule {rule_labels[idx]!r} vs "
                        f"technique {technique_id!r}: "
                        f"{out.get('message', out.get('error'))}"
                    )
                if out.get("matched"):
                    fired = True
                    break  # this rule catches the technique; stop at first event
            if fired:
                matched_rules.append(rule_labels[idx])

        detected = bool(matched_rules)
        if detected:
            detected_count += 1
        else:
            blind_spots.append(technique_id)

        results.append(
            {
                "technique_id": technique_id,
                "name": name,
                "detected": detected,
                "matched_rules": matched_rules,
            }
        )

    total_cases = len(results)
    coverage = (detected_count / total_cases) if total_cases else 0.0

    return {
        "total_cases": total_cases,
        "detected_count": detected_count,
        "coverage": coverage,
        "blind_spots": blind_spots,
        "results": results,
    }


if __name__ == "__main__":
    import json

    # A single rule that only catches PowerShell encoded commands — so every
    # other technique in the library shows up as a blind spot. Illustrative only.
    demo_rule = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""
    report = replay(generate_cases(), [demo_rule])
    print(json.dumps(report, indent=2))
