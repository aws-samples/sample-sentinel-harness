"""
Offline tests for the one-shot microVM EXPLICIT state machine
=============================================================
ZERO AWS, ZERO network, ZERO real VM, ZERO real detonation — everything here is
the SIMULATED skeleton. These tests DEEPEN the lifecycle model added to
``longrunning/detonation/src/vm.py``: the explicit state machine

    QUEUED -> PROVISIONING -> ACQUIRED(ready) -> DETONATING -> ANALYZING -> DESTROYED

driven through the single :data:`ALLOWED_TRANSITIONS` table and the
:meth:`OneShotMicroVM.transition` gate that REFUSES illegal jumps.

Coverage:
  * the full legal path runs and is recorded in ``handle.state_history``;
  * EVERY transition NOT in the table raises a clear ``VMError`` (illegal jumps,
    moves out of the terminal DESTROYED state, unknown target states) and is a
    no-op (state untouched);
  * ``destroy`` works from ANY live state (QUEUED/PROVISIONING/ACQUIRED/
    DETONATING/ANALYZING) and is idempotent;
  * a destroyed handle refuses ALL further actions (run_action + transition);
  * the existing acquire/run_action/destroy invariants + sample-by-reference are
    preserved (spot-checked here; the full set lives in tests/test_detonation.py).

DETERMINISM: no assertions on exact uuid / clock values — only shape/state. The
module is loaded by an explicit importlib file-path under a UNIQUE name so it can
never collide with any other ``vm``/``bedrock_entrypoint`` module on sys.path.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# --- Hermetic env: no real region/profile/credentials resolution on import. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")


def _load_vm():
    """Load longrunning/detonation/src/vm.py under a UNIQUE module name via an
    explicit file path, so it never collides with any other ``vm`` module."""
    path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "longrunning", "detonation", "src", "vm.py")
    )
    name = "detonation_vm_lifecycle"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass introspection (which reads
    # sys.modules[cls.__module__].__dict__) resolves this module by name.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vm_mod = _load_vm()

QUEUED = vm_mod.QUEUED
PROVISIONING = vm_mod.PROVISIONING
ACQUIRED = vm_mod.ACQUIRED
DETONATING = vm_mod.DETONATING
ANALYZING = vm_mod.ANALYZING
DESTROYED = vm_mod.DESTROYED
LIVE_STATES = vm_mod.LIVE_STATES
ALLOWED_TRANSITIONS = vm_mod.ALLOWED_TRANSITIONS
OneShotMicroVM = vm_mod.OneShotMicroVM
Sample = vm_mod.Sample
VMHandle = vm_mod.VMHandle
VMError = vm_mod.VMError
VMAlreadyDestroyedError = vm_mod.VMAlreadyDestroyedError

SESSION = "detonation-lifecycle-session-000000000000000000"

# The single canonical legal path, kept in test scope so the assertions read as
# the documented lifecycle contract.
LEGAL_PATH = [QUEUED, PROVISIONING, ACQUIRED, DETONATING, ANALYZING, DESTROYED]

ALL_STATES = frozenset({QUEUED, PROVISIONING, ACQUIRED, DETONATING, ANALYZING, DESTROYED})


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #
def _fresh_handle(state):
    """A VMHandle pinned to ``state`` (history seeded to it) for testing a single
    transition edge in isolation, independent of the acquire() walk."""
    return VMHandle(session_id=SESSION, vm_id="vm-deadbeefdeadbeef", state=state)


# --------------------------------------------------------------------------- #
# 1. Table shape: the single source of truth is well-formed                   #
# --------------------------------------------------------------------------- #
def test_allowed_transitions_table_is_well_formed():
    # every state is a key; targets are always known states.
    assert set(ALLOWED_TRANSITIONS) == ALL_STATES
    for src, targets in ALLOWED_TRANSITIONS.items():
        assert targets <= ALL_STATES, f"{src} points at an unknown state"
    # DESTROYED is terminal — no outgoing edge.
    assert ALLOWED_TRANSITIONS[DESTROYED] == frozenset()
    # DESTROYED is reachable from EVERY non-terminal state (destroy-after-use).
    for src in ALL_STATES - {DESTROYED}:
        assert DESTROYED in ALLOWED_TRANSITIONS[src], f"cannot destroy from {src}"
    # LIVE_STATES is exactly the ready/working phases; ACQUIRED stays live.
    assert LIVE_STATES == frozenset({ACQUIRED, DETONATING, ANALYZING})
    assert QUEUED not in LIVE_STATES and PROVISIONING not in LIVE_STATES
    assert DESTROYED not in LIVE_STATES


# --------------------------------------------------------------------------- #
# 2. The full legal path runs and is recorded in the evidence trail          #
# --------------------------------------------------------------------------- #
def test_full_legal_lifecycle_path_and_history():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    # acquire() walked QUEUED -> PROVISIONING -> ACQUIRED via the state machine.
    assert handle.state == ACQUIRED
    assert handle.is_live
    assert handle.state_history == [QUEUED, PROVISIONING, ACQUIRED]

    # ready -> detonating -> analyzing, each a legal edge.
    vm.transition(handle, DETONATING)
    assert handle.state == DETONATING and handle.is_live
    vm.transition(handle, ANALYZING)
    assert handle.state == ANALYZING and handle.is_live

    destroyed = vm.destroy(handle)
    assert destroyed["state"] == DESTROYED
    assert handle.state == DESTROYED
    # the evidence trail proves the VM walked the whole legal path then was destroyed.
    assert handle.state_history == LEGAL_PATH
    # as_dict exposes the history for the evidence trail.
    snap = handle.as_dict()
    assert snap["state"] == DESTROYED
    assert snap["state_history"] == LEGAL_PATH


def test_transition_returns_new_state():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    assert vm.transition(handle, DETONATING) == DETONATING


# --------------------------------------------------------------------------- #
# 3. EVERY illegal transition raises VMError and is a no-op                   #
# --------------------------------------------------------------------------- #
def test_every_illegal_transition_raises_and_is_noop():
    """Exhaustively: for each ordered (src, dst) pair NOT in the allowed table,
    transition() must raise VMError and leave the handle's state untouched."""
    vm = OneShotMicroVM()
    checked = 0
    for src in ALL_STATES:
        for dst in ALL_STATES:
            if dst in ALLOWED_TRANSITIONS[src]:
                continue  # legal edge, covered elsewhere
            handle = _fresh_handle(src)
            before_state = handle.state
            before_hist = list(handle.state_history)
            with pytest.raises(VMError):
                vm.transition(handle, dst)
            # fail-closed: illegal jump changed nothing.
            assert handle.state == before_state
            assert handle.state_history == before_hist
            checked += 1
    # sanity: we actually exercised a batch of illegal edges (36 pairs - legal ones).
    assert checked > 0


def test_illegal_skip_forward_raises():
    """Representative illegal skips: QUEUED->ACQUIRED, ACQUIRED->ANALYZING."""
    vm = OneShotMicroVM()
    with pytest.raises(VMError, match="illegal microVM transition"):
        vm.transition(_fresh_handle(QUEUED), ACQUIRED)
    with pytest.raises(VMError, match="illegal microVM transition"):
        vm.transition(_fresh_handle(ACQUIRED), ANALYZING)


def test_unknown_target_state_raises():
    vm = OneShotMicroVM()
    with pytest.raises(VMError, match="unknown target state"):
        vm.transition(_fresh_handle(ACQUIRED), "exfiltrating")


def test_no_transition_out_of_destroyed():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    vm.destroy(handle)
    for dst in ALL_STATES:
        with pytest.raises(VMError):
            vm.transition(handle, dst)
    # state stayed terminal.
    assert handle.state == DESTROYED


# --------------------------------------------------------------------------- #
# 4. destroy works from ANY live state and is idempotent                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("via", [QUEUED, PROVISIONING, ACQUIRED, DETONATING, ANALYZING])
def test_destroy_from_any_live_state(via):
    """destroy() must succeed from every non-terminal state (destroy-after-use
    holds whatever phase the plan halted in)."""
    vm = OneShotMicroVM()
    handle = _fresh_handle(via)
    result = vm.destroy(handle)
    assert result["state"] == DESTROYED
    assert result["idempotent_noop"] is False
    assert handle.state == DESTROYED
    # the teardown edge is recorded in the trail (unless it was already there).
    assert handle.state_history[-1] == DESTROYED


def test_destroy_is_idempotent():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    first = vm.destroy(handle)
    hist_after_first = list(handle.state_history)
    second = vm.destroy(handle)
    assert first["idempotent_noop"] is False
    assert second["idempotent_noop"] is True
    assert second["state"] == DESTROYED
    # a double-destroy does NOT append a second DESTROYED to the trail.
    assert handle.state_history == hist_after_first
    assert handle.state_history.count(DESTROYED) == 1


# --------------------------------------------------------------------------- #
# 5. A destroyed handle refuses ALL actions                                   #
# --------------------------------------------------------------------------- #
def test_destroyed_handle_refuses_run_action():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    vm.destroy(handle)
    with pytest.raises(VMAlreadyDestroyedError):
        vm.run_action(handle, {"kind": "run", "command": "ls"})
    # nothing was (simulated-)executed.
    assert handle.action_log == []


def test_run_action_works_in_detonating_and_analyzing_states():
    """run_action stays available across the live working states, not just
    ACQUIRED — is_live now spans ACQUIRED/DETONATING/ANALYZING."""
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    vm.transition(handle, DETONATING)
    r1 = vm.run_action(handle, {"kind": "run", "command": "ls /workspace"})
    assert r1["ok"] is True and r1["simulated"] is True
    vm.transition(handle, ANALYZING)
    r2 = vm.run_action(handle, {"kind": "read", "path": "artifacts/report.txt"})
    assert r2["simulated"] is True
    assert len(handle.action_log) == 2


# --------------------------------------------------------------------------- #
# 6. Preserved invariants (spot-check): sandbox gate + sample-by-reference    #
# --------------------------------------------------------------------------- #
def test_sample_by_reference_still_enforced():
    ok = Sample(s3_uri="s3://dropbox-bucket/quarantine/abc123")
    assert ok.s3_uri.startswith("s3://") and ok.sha256 is None
    with pytest.raises(ValueError):
        Sample(s3_uri="https://evil.example/malware.bin")


def test_one_shot_second_acquire_still_refused_while_live():
    vm = OneShotMicroVM()
    h1 = vm.acquire(SESSION)
    # live across DETONATING too — a second acquire is still refused.
    vm.transition(h1, DETONATING)
    with pytest.raises(VMError):
        vm.acquire("another-session")
    vm.destroy(h1)
    h2 = vm.acquire("another-session")
    assert h2.is_live and h2.vm_id != h1.vm_id
