"""
detonation · RUN ORCHESTRATOR that drives one full analysis end-to-end (SIMULATED)
==================================================================================
``detonate_sample`` walks ONE sample through the whole (SIMULATED) detonation
lifecycle in a single, synchronous, offline call and emits an **evidence record**:

    ACQUIRING -> ACQUIRED -> STAGING -> AWAITING_APPROVAL
              -> DETONATING -> COLLECTING -> REPORTING          (approve path)
              -> HALTED                                          (reject path)
              -> DESTROYING -> DESTROYED                         (ALWAYS, finally)

It is a thin driver on top of the already-proven invariants in
:mod:`longrunning.detonation.src.vm` — it does NOT re-derive any safety rule:

* the one-shot microVM lifecycle + destroy-after-use come from
  :class:`~longrunning.detonation.src.vm.OneShotMicroVM`;
* every action is routed through :meth:`OneShotMicroVM.run_action`, which is
  gated by :mod:`sentinel_harness.sandbox_hooks` (the single source of safety
  truth) — a disallowed command / path-traversal is REFUSED before any
  simulated run and is recorded, never executed;
* the sample enters ONLY by reference as a
  :class:`~longrunning.detonation.src.vm.Sample` (``s3://`` dropbox uri) — its
  bytes are never opened, read, downloaded, or hashed;
* a **human-in-the-loop approval callback** gates the DETONATING step in the
  spirit of Play Mode's inline gate (``sentinel_harness.simulation``): a reject
  HALTS the run with NOTHING detonated. (The full multi-step, resumable,
  checkpointed Play-Mode gating lives in this package's ``bedrock_entrypoint``
  via ``PlayModeRunner``; this orchestrator is the compact single-shot form of
  the SAME invariant.)
* the microVM is **ALWAYS destroyed in a ``finally``** — destroy-after-use holds
  on the happy path, on a reject, AND when an action raises.

ABSOLUTE HONESTY — this stays a SIMULATED no-op
-----------------------------------------------
There is **no real microVM, no Firecracker, no container, no ``subprocess``, no
real malware, no real code execution, and no network**. ``run_action`` returns a
canned "would do X" result; the analysis report's ``iocs_observed`` are
deliberately-fictional RFC-5737 documentation IPs and ``example.test`` names, and
every result dict keeps ``simulated: True``. This module DEEPENS the lifecycle
model + its tests; it does NOT make detonation real.
"""
from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Callable, Dict, List, Optional

# Reuse the microVM abstraction (which itself reuses sentinel_harness.sandbox_hooks
# for the safety gate). Support both package-style and path-style import so this
# module works whether ``longrunning`` is importable as a package or ``src`` is on
# sys.path directly (the same dual-import the entrypoint uses).
try:  # pragma: no cover - import path depends on how the caller set sys.path
    from longrunning.detonation.src.vm import (
        DESTROYED,
        ActionRefused,
        OneShotMicroVM,
        Sample,
    )
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from vm import DESTROYED, ActionRefused, OneShotMicroVM, Sample  # type: ignore

# ------------------------------------------------------------------ lifecycle states
# The ordered set of (SIMULATED) states a detonation run may visit. These are the
# evidence-trail labels appended to ``states_visited``; they are NOT VM states
# (the VM only knows ACQUIRED/DESTROYED — see vm.py).
STATE_ACQUIRING = "ACQUIRING"
STATE_ACQUIRED = "ACQUIRED"
STATE_STAGING = "STAGING"                    # (simulated) place sample-by-reference in the VM
STATE_AWAITING_APPROVAL = "AWAITING_APPROVAL"  # HITL gate before any detonation
STATE_DETONATING = "DETONATING"              # (simulated) run gated actions inside the VM
STATE_COLLECTING = "COLLECTING"              # (simulated) gather behavioral artifacts
STATE_REPORTING = "REPORTING"                # assemble the deterministic analysis report
STATE_HALTED = "HALTED"                      # HITL reject: nothing detonated
STATE_DESTROYING = "DESTROYING"
STATE_DESTROYED = "DESTROYED"

# A canned, deterministic simulated verdict. Same input -> same output.
_SIMULATED_VERDICT = "malicious"


def _analysis_report() -> Dict[str, Any]:
    """Return a deterministic, clearly-FICTIONAL simulated analysis report.

    ``iocs_observed`` uses ONLY RFC-5737 documentation IP ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) and the reserved ``example.test`` domain, so
    nothing here could be mistaken for a real indicator. No sample byte was read
    to produce this — it is a fixed placeholder that models the *shape* of a
    behavioral report, not a real one.
    """
    return {
        "simulated": True,
        "verdict": _SIMULATED_VERDICT,
        "iocs_observed": [
            {"type": "ipv4", "value": "192.0.2.10",
             "note": "RFC-5737 TEST-NET-1 documentation IP — fictional placeholder"},
            {"type": "ipv4", "value": "198.51.100.23",
             "note": "RFC-5737 TEST-NET-2 documentation IP — fictional placeholder"},
            {"type": "domain", "value": "c2.malware-lab.example.test",
             "note": "reserved example.test domain — fictional placeholder"},
        ],
        "note": (
            "[SIMULATED] behavioral report — NO sample byte was read or executed. "
            "All indicators are fictional RFC-5737 / example.test placeholders."
        ),
    }


def detonate_sample(
    s3_uri: str,
    actions: Optional[List[Dict[str, Any]]] = None,
    *,
    approve: Callable[[Dict[str, Any]], Any],
    session_id: Optional[str] = None,
    sandbox_root: Optional[str] = None,
    vm: Optional[OneShotMicroVM] = None,
) -> Dict[str, Any]:
    """Drive ONE (SIMULATED) sample detonation end-to-end and return an evidence record.

    Parameters
    ----------
    s3_uri:
        The sample's dropbox reference. MUST be an ``s3://`` uri — a live-fetch
        shaped reference (``http(s)://`` / local path) is rejected by
        :class:`Sample` (sample-by-reference invariant; bytes are never read).
    actions:
        The controlled analysis actions to (SIMULATED-)run inside the microVM
        during the DETONATING step. Each is a
        :meth:`OneShotMicroVM.run_action` dict, e.g.
        ``{"kind": "run", "command": "ls /workspace"}`` or
        ``{"kind": "read", "path": "artifacts/report.txt"}``. Every action is
        routed through the sandbox gate: a disallowed command / path-traversal is
        REFUSED (recorded ``refused=True``, never executed) while the rest of the
        analysis continues.
    approve:
        REQUIRED human-in-the-loop callback, called ONCE before the DETONATING
        step with a context dict. Truthy -> detonation proceeds; falsy -> the run
        HALTS with NOTHING detonated (Play-Mode reject-halts spirit). The microVM
        is destroyed either way.
    session_id:
        Optional runtimeSessionId keying the one-shot VM. Defaults to a
        deterministic id derived from the ``s3_uri`` *string* (the reference — not
        the sample bytes) so the same reference yields the same evidence record.
    sandbox_root:
        Optional path-confinement root forwarded to a freshly-created
        :class:`OneShotMicroVM`. ``None`` -> the ``sandbox_hooks`` default roots.
    vm:
        Optional pre-built :class:`OneShotMicroVM` (dependency-injection seam for
        tests). When ``None`` a fresh one is created.

    Returns
    -------
    dict
        Structured evidence record::

            {"session_id", "states_visited", "actions", "hitl_approved",
             "destroyed": True, "simulated": True, "closed": True, ...}

        (plus ``sample`` / ``report`` / ``halted`` / ``verdict`` for the trail).

    Notes
    -----
    SIMULATED no-op throughout: no real VM, no real execution, no network. An
    unexpected error inside an action is NOT swallowed — it propagates — but the
    microVM is STILL destroyed first in the ``finally`` (destroy-after-use).
    """
    if not callable(approve):
        raise TypeError("approve must be a callable HITL approval gate")

    actions = list(actions or [])
    if session_id is None:
        # Deterministic id from the reference STRING (never the sample bytes).
        digest = hashlib.sha256(s3_uri.encode("utf-8")).hexdigest()[:16]
        session_id = f"detonation-{digest}"

    # Fail-closed on the sample-by-reference invariant before we acquire anything.
    sample = Sample(s3_uri=s3_uri)

    vm = vm or OneShotMicroVM(sandbox_root=sandbox_root)

    states_visited: List[str] = [STATE_ACQUIRING]
    action_records: List[Dict[str, Any]] = []
    report: Optional[Dict[str, Any]] = None
    hitl_approved = False
    halted = False
    handle = None

    try:
        # -- acquire the one-shot microVM for this session ----------------------
        handle = vm.acquire(session_id, sample=sample)
        states_visited.append(STATE_ACQUIRED)

        # -- stage the sample BY REFERENCE (simulated; bytes never touched) -----
        states_visited.append(STATE_STAGING)

        # -- HITL gate BEFORE any detonation (reject halts, nothing executed) ---
        states_visited.append(STATE_AWAITING_APPROVAL)
        gate_context = {
            "state": STATE_AWAITING_APPROVAL,
            "next_state": STATE_DETONATING,
            "session_id": session_id,
            "sample_s3_uri": sample.s3_uri,
            "planned_actions": len(actions),
            "note": ("HITL gate — approve to (SIMULATED-)detonate; a reject halts "
                     "the run with nothing executed."),
        }
        hitl_approved = bool(approve(gate_context))

        if not hitl_approved:
            # Reject -> HALT. No action is routed through the VM at all.
            halted = True
            states_visited.append(STATE_HALTED)
        else:
            # -- DETONATING: route each action through the sandbox gate ---------
            states_visited.append(STATE_DETONATING)
            for idx, action in enumerate(actions):
                kind = action.get("kind") if isinstance(action, dict) else None
                try:
                    result = vm.run_action(handle, action)
                    action_records.append({
                        "index": idx,
                        "kind": kind,
                        "refused": False,
                        "executed": False,   # SIMULATED — nothing really ran
                        "simulated": True,
                        "detail": {k: v for k, v in result.items()
                                   if k in ("command", "path")},
                    })
                except ActionRefused as exc:
                    # The safety gate REFUSED it — recorded, never executed. The
                    # rest of the analysis continues (a bad action does not crash
                    # the run). This is the ONLY exception we absorb here; it is a
                    # designed security outcome surfaced in the evidence record.
                    action_records.append({
                        "index": idx,
                        "kind": kind,
                        "refused": True,
                        "executed": False,
                        "simulated": True,
                        "reason": exc.reason,
                    })

            # -- COLLECTING + REPORTING (deterministic simulated report) --------
            states_visited.append(STATE_COLLECTING)
            report = _analysis_report()
            states_visited.append(STATE_REPORTING)
    finally:
        # Destroy-after-use: the one-shot microVM NEVER outlives its analysis,
        # whatever the outcome (success / reject / an action raising). Idempotent,
        # so this is safe in a finally. If an unexpected error propagates, the VM
        # is torn down here BEFORE the exception leaves this function.
        if handle is not None:
            states_visited.append(STATE_DESTROYING)
            destroy_result = vm.destroy(handle)
            assert destroy_result["state"] == DESTROYED  # invariant, provable
            states_visited.append(STATE_DESTROYED)

    return {
        "session_id": session_id,
        "states_visited": states_visited,
        "actions": action_records,
        "hitl_approved": hitl_approved,
        "destroyed": True,
        "simulated": True,
        "closed": True,
        # --- evidence trail (extra, beyond the required keys) ------------------
        "halted": halted,
        "sample": sample.as_dict(),
        "report": report,
        "verdict": report["verdict"] if report else None,
        "note": (
            "[SIMULATED] one-shot detonation orchestration — no real VM, no real "
            "execution, no network. Sample referenced only by s3:// uri; every "
            "action gated by sentinel_harness.sandbox_hooks; VM destroyed after use."
        ),
    }
