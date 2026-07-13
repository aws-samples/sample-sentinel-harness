"""
Offline tests for the detonation RUN ORCHESTRATOR (``detonate_sample``)
=======================================================================
ZERO AWS, ZERO network, ZERO real VM, ZERO real detonation. Everything is the
SIMULATED skeleton: the one-shot microVM is an in-memory abstraction, the sample
is a reference-only ``s3://`` uri, the analysis report is a deterministic
fixture, and the HITL gate is an injected callback. Deterministic and fast.

Coverage:
  * happy path -> destroyed:true + closed:true + simulated:true, a real verdict.
  * a REJECTED HITL gate HALTS with NOTHING detonated but the VM is STILL
    destroyed (finally).
  * a DISALLOWED action is REFUSED by the sandbox gate (recorded, not executed).
  * the VM is ALWAYS destroyed (finally) even when an action raises.

Modules under ``longrunning/`` are not an installed package, so we load
``runner.py`` by explicit file path via importlib under a UNIQUE module name (so
it never collides with anything else), the convention the other detonation tests
use.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# --- Make imports hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_LR = os.path.join(os.path.dirname(__file__), "..", "longrunning")
_SRC = os.path.abspath(os.path.join(_LR, "detonation", "src"))
# vm.py must be importable for runner.py's ``from vm import ...`` fallback.
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _load_runner():
    """Load longrunning/detonation/src/runner.py under a UNIQUE module name."""
    path = os.path.abspath(os.path.join(_SRC, "runner.py"))
    spec = importlib.util.spec_from_file_location("detonation_runner_undertest", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runner = _load_runner()
detonate_sample = runner.detonate_sample

# A FICTIONAL quarantine-dropbox reference (never fetched, never read).
SAMPLE = "s3://sentinel-quarantine-dropbox/samples/fictional-0001.bin"

# Allowed + one disallowed action; path actions confined to /workspace.
ALLOWED_AND_ONE_BAD = [
    {"kind": "run", "command": "ls /workspace"},
    {"kind": "read", "path": "artifacts/behavior.log"},
    {"kind": "run", "command": "rm -rf /"},  # DISALLOWED -> refused by sandbox
]


def _approve(_ctx):
    return True


def _reject(_ctx):
    return False


# --------------------------------------------------------------------------- #
# 1. Happy path: destroyed:true + closed:true, deterministic verdict           #
# --------------------------------------------------------------------------- #
def test_happy_path_yields_destroyed_and_closed():
    result = detonate_sample(
        SAMPLE, [{"kind": "run", "command": "ls /workspace"}],
        approve=_approve, sandbox_root="/workspace",
    )
    assert result["destroyed"] is True
    assert result["closed"] is True
    assert result["simulated"] is True
    assert result["hitl_approved"] is True
    assert result["halted"] is False
    # walked the full lifecycle and ended DESTROYED (destroy-after-use).
    assert result["states_visited"][0] == "ACQUIRING"
    assert result["states_visited"][-1] == "DESTROYED"
    assert "DETONATING" in result["states_visited"]
    # a deterministic simulated report with a verdict + FICTIONAL indicators.
    assert result["report"]["simulated"] is True
    assert result["verdict"] == "malicious"
    values = {i["value"] for i in result["report"]["iocs_observed"]}
    assert values == {"192.0.2.10", "198.51.100.23", "c2.malware-lab.example.test"}
    # the one allowed action ran (SIMULATED) and was NOT refused.
    assert len(result["actions"]) == 1
    assert result["actions"][0]["refused"] is False
    assert result["actions"][0]["executed"] is False  # never a real execution


def test_happy_path_is_deterministic():
    a = detonate_sample(SAMPLE, [], approve=_approve, sandbox_root="/workspace")
    b = detonate_sample(SAMPLE, [], approve=_approve, sandbox_root="/workspace")
    assert a["session_id"] == b["session_id"]          # derived from the reference
    assert a["states_visited"] == b["states_visited"]
    assert a["report"] == b["report"]


# --------------------------------------------------------------------------- #
# 2. Rejected HITL gate -> HALT with NOTHING detonated, VM STILL destroyed     #
# --------------------------------------------------------------------------- #
def test_rejected_hitl_gate_halts_with_nothing_detonated_but_still_destroyed():
    result = detonate_sample(
        SAMPLE, ALLOWED_AND_ONE_BAD, approve=_reject, sandbox_root="/workspace",
    )
    # HALTED: the reject stopped the run before any detonation.
    assert result["halted"] is True
    assert result["hitl_approved"] is False
    assert result["actions"] == []           # NOTHING was routed through the VM
    assert result["report"] is None
    assert result["verdict"] is None
    assert "DETONATING" not in result["states_visited"]
    assert "HALTED" in result["states_visited"]
    # ... but destroy-after-use STILL holds (finally).
    assert result["destroyed"] is True
    assert result["closed"] is True
    assert result["states_visited"][-1] == "DESTROYED"


# --------------------------------------------------------------------------- #
# 3. A disallowed action is REFUSED by the sandbox (recorded, not executed)    #
# --------------------------------------------------------------------------- #
def test_disallowed_action_refused_by_sandbox_not_executed():
    result = detonate_sample(
        SAMPLE, ALLOWED_AND_ONE_BAD, approve=_approve, sandbox_root="/workspace",
    )
    assert len(result["actions"]) == 3
    refused = [a for a in result["actions"] if a["refused"]]
    executed_records = [a for a in result["actions"] if not a["refused"]]
    # exactly one refusal (the rm -rf), with a sandbox reason surfaced.
    assert len(refused) == 1
    assert refused[0]["index"] == 2
    assert refused[0]["executed"] is False
    assert "rm" in refused[0]["reason"].lower()
    # the two allowed actions were the ones NOT refused.
    assert len(executed_records) == 2
    # the run still completed + destroyed after use.
    assert result["destroyed"] is True
    assert result["closed"] is True
    assert result["verdict"] == "malicious"


def test_path_traversal_action_refused_by_sandbox():
    result = detonate_sample(
        SAMPLE, [{"kind": "read", "path": "../../etc/passwd"}],
        approve=_approve, sandbox_root="/workspace",
    )
    assert result["actions"][0]["refused"] is True
    assert "traversal" in result["actions"][0]["reason"]
    assert result["destroyed"] is True


# --------------------------------------------------------------------------- #
# 4. The VM is ALWAYS destroyed (finally) even when an action raises           #
# --------------------------------------------------------------------------- #
def test_vm_always_destroyed_even_when_action_raises():
    # Import the VM classes the same path runner.py uses, so we can inject a VM
    # whose run_action raises an UNEXPECTED (non-security) error mid-plan.
    from vm import OneShotMicroVM  # noqa: E402

    class _BoomVM(OneShotMicroVM):
        def run_action(self, handle, action):
            raise RuntimeError("unexpected boom inside the (simulated) microVM")

    boom = _BoomVM(sandbox_root="/workspace")

    with pytest.raises(RuntimeError, match="boom"):
        detonate_sample(
            SAMPLE, [{"kind": "run", "command": "ls /workspace"}],
            approve=_approve, vm=boom,
        )

    # The exception propagated (NOT swallowed) — but destroy-after-use held: the
    # injected VM's live handle was torn down in the finally before it escaped.
    assert boom._live is None  # destroy() cleared the live handle


def test_invalid_sample_reference_rejected_before_acquire():
    """A live-fetch-shaped reference is rejected by the sample-by-reference
    invariant before any VM is acquired (no bytes, no fetch)."""
    for bad in ("https://evil.example/malware.bin", "/tmp/local/sample.exe", "ftp://x"):
        with pytest.raises(ValueError):
            detonate_sample(bad, [], approve=_approve)


def test_missing_approve_callable_rejected():
    with pytest.raises(TypeError):
        detonate_sample(SAMPLE, [], approve=None)  # type: ignore[arg-type]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
