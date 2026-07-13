"""
Scenario — sample detonation: acquire one-shot VM -> gated detonation -> destroy
================================================================================
Layer 2 (Simulation) · the M3 "sample detonation" proof point, driven end-to-end
by the RUN ORCHESTRATOR in ``longrunning/detonation/src/runner.py``.

Mirrors the customer flow "a controlled upstream drops a suspicious sample in a
quarantine dropbox and publishes an ``s3://`` reference -> we acquire a fresh
one-shot microVM, route a small set of controlled analysis actions through the
sandbox safety gate, require a human approval before detonating, collect a
behavioral report, then destroy the microVM after use". The deliverable is an
evidence record proving each safety invariant held.

What is REAL vs SIMULATED (be scrupulous — this is L2 simulation)
-----------------------------------------------------------------
- REAL, deterministic, offline Python (the provable core): the one-shot microVM
  LIFECYCLE + destroy-after-use, the SANDBOX GATE on every action (delegated to
  ``sentinel_harness.sandbox_hooks``), the sample-by-reference invariant, and the
  HITL approval gate. Same input -> same output.
- SIMULATED (no-op): there is NO real microVM / Firecracker / container /
  ``subprocess``, NO real malware, NO real code execution, NO network. The sample
  enters ONLY as an ``s3://`` dropbox uri (never fetched, never read). The
  analysis report's indicators are deliberately-FICTIONAL RFC-5737 documentation
  IPs and ``example.test`` names. Every result dict keeps ``simulated: true``.

The DEFAULT run is PURE OFFLINE: no AWS, no invoke quota, no network. It runs a
mix of allowed actions + one disallowed action (refused by the sandbox, not
executed) behind an approve gate, and writes the evidence record.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from types import ModuleType
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

RESULT: Dict[str, Any] = {"scenario": "detonation_run", "steps": []}

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
# Load the detonation run orchestrator by absolute path.
#
# runner.py lives at longrunning/detonation/src/runner.py — ``longrunning`` is
# not an importable package here, so we load it by path via importlib exactly as
# the other longrunning-backed scenarios do. A present-but-broken runner.py
# surfaces its ImportError rather than silently degrading.
# --------------------------------------------------------------------------
def _runner_path() -> str:
    return os.path.join(
        os.path.dirname(__file__), "..", "longrunning", "detonation", "src", "runner.py"
    )


def _load_runner() -> ModuleType:
    path = _runner_path()
    if not os.path.exists(path):
        raise ImportError(
            f"detonation runner not found at {path!r}; this scenario requires "
            "longrunning/detonation/src/runner.py (detonate_sample)"
        )
    # Put the src dir on sys.path so runner.py's ``from vm import ...`` resolves.
    src_dir = os.path.abspath(os.path.dirname(path))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    spec = importlib.util.spec_from_file_location("detonation_runner", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not build import spec for {path!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "detonate_sample"):
        raise ImportError(f"{path!r} does not expose a 'detonate_sample' callable")
    return module


# A FICTIONAL quarantine-dropbox reference. The sample enters ONLY by this
# s3:// uri — never fetched, never read.
SAMPLE_S3_URI = "s3://sentinel-quarantine-dropbox/samples/fictional-sample-0001.bin"

# A mix of ALLOWED analysis actions + ONE disallowed action. The disallowed
# ``rm -rf`` is REFUSED by the sandbox gate (recorded, never executed); the
# allowed actions are SIMULATED no-ops.
ACTIONS = [
    {"kind": "run", "command": "ls /workspace"},                 # allowed
    {"kind": "read", "path": "artifacts/behavior.log"},          # allowed
    {"kind": "run", "command": "rm -rf /"},                      # DISALLOWED -> refused
    {"kind": "run", "command": "grep -r suspicious /workspace"}, # allowed
]


def run_pure() -> Dict[str, Any]:
    """The default PURE run: detonate the fictional sample behind an approve gate.

    Proves the whole orchestration end-to-end with zero AWS / zero network:
    acquire -> stage-by-reference -> HITL approve -> gated detonation (one action
    refused by the sandbox) -> collect -> report -> destroy-after-use.
    """
    runner = _load_runner()

    rec("sample", {"s3_uri": SAMPLE_S3_URI, "by_reference": True})
    rec("actions", {"count": len(ACTIONS),
                    "includes_disallowed": True})

    # The HITL gate: an analyst approves the detonation. (A rejecting analyst
    # would HALT the run with nothing detonated — see tests.)
    def approve(context: Dict[str, Any]) -> bool:
        rec("hitl_gate", {"awaiting": context["state"],
                          "next": context["next_state"],
                          "decision": "APPROVE"})
        return True

    # Pin a sandbox root so path actions confine deterministically offline.
    result = runner.detonate_sample(
        SAMPLE_S3_URI, ACTIONS, approve=approve, sandbox_root="/workspace"
    )

    for a in result["actions"]:
        rec("action", a)
    rec("report", result["report"])

    refused = [a for a in result["actions"] if a["refused"]]
    verdict = {
        "sample_by_reference": result["sample"]["s3_uri"].startswith("s3://"),
        "sandbox_refused_bad_action": len(refused) == 1,
        "hitl_gate_required": result["hitl_approved"] is True,
        "destroyed_after_use": result["destroyed"] is True
        and result["states_visited"][-1] == "DESTROYED",
        "simulated": result["simulated"] is True,
        "closed": result["closed"] is True,
        "states_visited": result["states_visited"],
        "verdict": result["verdict"],
        "refused_reason": refused[0]["reason"] if refused else None,
        "note": (
            "REAL deterministic one-shot detonation orchestration (offline, no "
            "LLM/network/AWS): the sample entered only by s3:// reference, one "
            "disallowed action was REFUSED by sentinel_harness.sandbox_hooks and "
            "never executed, a human approval gated the DETONATING step, and the "
            "one-shot microVM was destroyed after use. SIMULATED no-op throughout: "
            "no real VM, no real execution; indicators are fictional RFC-5737 / "
            "example.test placeholders."
        ),
    }
    RESULT["verdict"] = verdict

    print("\n=== detonation narrative ===")
    print(f"Sample (by reference): {SAMPLE_S3_URI}")
    print(f"States visited: {' -> '.join(result['states_visited'])}")
    print(f"Actions refused by sandbox: {len(refused)} "
          f"({refused[0]['reason'] if refused else 'none'})")
    print(f"HITL approved: {result['hitl_approved']}  ·  verdict: {result['verdict']}")
    print(f"Destroyed after use: {verdict['destroyed_after_use']}")
    return verdict


if __name__ == "__main__":
    # Default is PURE: no AWS, no invoke quota. Proves the deterministic core.
    run_pure()
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "detonation_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/detonation_result.json  ·  verdict:", RESULT.get("verdict"))
