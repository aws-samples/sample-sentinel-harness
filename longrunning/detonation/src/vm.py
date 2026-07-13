"""
detonation · one-shot microVM ABSTRACTION (SIMULATED — never a real VM)
=======================================================================
The M3 "sample detonation" tier models this lifecycle: for each analysis a
Runtime **acquires a fresh, isolated microVM keyed by ``runtimeSessionId``**, runs
a small set of controlled actions inside it, then **destroys it after use** so no
state (and no sample) survives between analyses. A "sample" never arrives by a
live download — it enters only by REFERENCE, as an S3-dropbox uri / dropbox id
that a controlled upstream placed there.

What is REAL vs SIMULATED here
------------------------------
This module is a **pure-Python skeleton**. It is honest about being a no-op:

* REAL (provable, offline, deterministic):
    - the *lifecycle state machine* — a handle can be used only while ``LIVE``,
      and using a ``DESTROYED`` handle raises. Destroy-after-use is enforced.
    - the *safety gate* — every action is routed through
      :func:`sentinel_harness.sandbox_hooks.validate_command` /
      :func:`~sentinel_harness.sandbox_hooks.validate_path`, so a path-traversal
      or a disallowed command is REFUSED before any (simulated) execution.
    - the *sample-by-reference* invariant — a sample is only ever an
      ``s3://…`` uri / dropbox id string; nothing here opens, reads, or fetches
      the bytes.
* SIMULATED (no-op):
    - there is **no real microVM**, no hypervisor, no Firecracker, no container,
      no ``subprocess``. ``acquire`` returns an in-memory handle; ``run_action``
      returns a canned, deterministic result describing *what would happen*.
    - there is **no real detonation** — no code from any sample is executed, ever.

How this maps to production (see ``README.md`` for the full mapping)
-------------------------------------------------------------------
In production, :meth:`OneShotMicroVM.acquire` would provision a genuinely isolated
one-shot microVM (its own kernel, no shared FS, egress-denied network), keyed by
``runtimeSessionId``; :meth:`run_action` would run a controlled analysis step
inside it via the Runtime's own tool surface (still behind the sandbox hooks and
still HITL-gated by Play Mode); :meth:`destroy` would terminate the microVM and
delete its disk so nothing persists. This skeleton keeps the exact call shape so
that swap is mechanical — and keeps CI green with zero AWS / zero heavy deps.

Deliberately NO boto3 in the default (simulated) path: the abstraction is pure
Python so it imports and unit-tests with no cloud dependency.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# REUSE the single source of truth for command/path safety (allowlist +
# destructive-verb denylist + workspace-root path confinement). We do NOT
# re-derive the rules — a second copy is a second place to forget a pattern.
from sentinel_harness.sandbox_hooks import validate_command, validate_path

# ------------------------------------------------------------------ VM states
# The one-shot microVM lifecycle is an EXPLICIT state machine (still SIMULATED —
# no real VM ever exists). A handle walks a single legal path:
#
#     QUEUED -> PROVISIONING -> ACQUIRED -> DETONATING -> ANALYZING -> DESTROYED
#
# ``ACQUIRED`` ("ready") and ``DESTROYED`` keep their historical names/values so
# existing callers and tests are untouched; the intermediate states make each
# lifecycle phase observable in the evidence trail (``VMHandle.state_history``).
QUEUED = "queued"              # request accepted, nothing provisioned yet
PROVISIONING = "provisioning"  # (simulated) isolated microVM being booted
ACQUIRED = "acquired"          # microVM provisioned for a session, READY for actions
DETONATING = "detonating"      # controlled (simulated) detonation steps under way
ANALYZING = "analyzing"        # collecting (simulated) behavioral artifacts
DESTROYED = "destroyed"        # torn down after use; the handle is now unusable

# States in which the microVM exists and an action may (simulated-)run. QUEUED /
# PROVISIONING precede readiness; DESTROYED is terminal. ``is_live`` keys off this
# set — ``ACQUIRED`` stays live so the historical acquire->run_action->destroy
# path is byte-for-byte unchanged.
LIVE_STATES = frozenset({ACQUIRED, DETONATING, ANALYZING})

# The SINGLE allowed-transitions table — the one source of truth for lifecycle
# legality (do NOT re-derive it anywhere else). :meth:`OneShotMicroVM.transition`
# refuses any jump not listed here, so illegal skips (e.g. QUEUED -> ACQUIRED,
# ACQUIRED -> ANALYZING) and any move out of the terminal ``DESTROYED`` state fail
# loudly with :class:`VMError`. ``DESTROYED`` is reachable from EVERY non-terminal
# state so destroy-after-use can always tear the VM down, whatever phase it is in.
ALLOWED_TRANSITIONS: Dict[str, frozenset] = {
    QUEUED: frozenset({PROVISIONING, DESTROYED}),
    PROVISIONING: frozenset({ACQUIRED, DESTROYED}),
    ACQUIRED: frozenset({DETONATING, DESTROYED}),
    DETONATING: frozenset({ANALYZING, DESTROYED}),
    ANALYZING: frozenset({DESTROYED}),
    DESTROYED: frozenset(),  # terminal: no transition out of a destroyed VM
}

# Action kinds a detonation step may request inside the (simulated) microVM.
# ``run`` carries a command string (validated as a command); ``read`` /
# ``write`` / ``collect`` carry a path (validated as a confined path). Every
# kind is a SIMULATED no-op — nothing is actually executed or read.
_COMMAND_ACTIONS = frozenset({"run", "exec"})
_PATH_ACTIONS = frozenset({"read", "write", "collect"})
_VALID_ACTION_KINDS = _COMMAND_ACTIONS | _PATH_ACTIONS


class VMError(RuntimeError):
    """Base class for microVM-lifecycle misuse (not a security refusal)."""


class VMAlreadyDestroyedError(VMError):
    """Raised when an action is attempted on a handle that was already destroyed.

    This is what enforces *destroy-after-use*: once a one-shot microVM is torn
    down, its handle is inert and any further action is a programming error, not a
    silently-ignored no-op. Fail loudly so a caller cannot accidentally reuse a
    VM that should no longer exist."""


class ActionRefused(VMError):
    """Raised when :func:`sentinel_harness.sandbox_hooks` REFUSES an action.

    A path-traversal or a disallowed command is denied *before* any simulated
    execution. Carries the sandbox ``reason`` so the runner can surface it back to
    the model (and so a test can assert on it)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Sample:
    """A malware sample referenced ONLY by location — never by its bytes.

    A sample "enters" the detonation lifecycle as an ``s3://…`` dropbox uri (a
    controlled upstream placed it there) and/or an opaque dropbox id. This class
    holds only those references; it never opens, reads, downloads, or hashes the
    object. The ``sha256`` field, when present, is metadata supplied by the
    upstream dropbox — it is NOT computed here (computing it would require reading
    the bytes, which this skeleton must never do).
    """

    s3_uri: str
    dropbox_id: Optional[str] = None
    sha256: Optional[str] = None

    def __post_init__(self) -> None:
        # Fail-closed on the sample-by-reference invariant: only an s3:// uri is a
        # valid entry channel. Anything that looks like an http(s) URL or a local
        # path is rejected so no code path can be tempted into a live fetch.
        if not isinstance(self.s3_uri, str) or not self.s3_uri.startswith("s3://"):
            raise ValueError(
                "sample must enter via an s3:// dropbox uri (reference only, "
                f"never a live fetch); got {self.s3_uri!r}"
            )

    def as_dict(self) -> Dict[str, Any]:
        return {"s3_uri": self.s3_uri, "dropbox_id": self.dropbox_id, "sha256": self.sha256}


@dataclass
class VMHandle:
    """A handle to one (simulated) microVM as it walks the lifecycle.

    Opaque to callers except for its ``session_id`` / ``state``. It carries no
    live connection — in the simulated path there is nothing to connect to; in
    production this would wrap the microVM's id / control channel.

    ``state_history`` is the ordered list of states this handle has occupied
    (starting state first, current state last). It is the EVIDENCE TRAIL for the
    lifecycle: it proves the VM walked the legal path and was destroyed after use.
    """

    session_id: str
    vm_id: str
    state: str = ACQUIRED
    sample: Optional[Sample] = None
    action_log: List[Dict[str, Any]] = field(default_factory=list)
    state_history: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Seed the history with the state the handle is born in so the trail is
        # never empty (and so callers that build a handle directly still get a
        # coherent history). Subsequent moves go through OneShotMicroVM.transition.
        if not self.state_history:
            self.state_history = [self.state]

    @property
    def is_live(self) -> bool:
        """True while the microVM exists and can (simulated-)run an action.

        Keys off :data:`LIVE_STATES` (ACQUIRED / DETONATING / ANALYZING). QUEUED /
        PROVISIONING are pre-ready and DESTROYED is terminal, so none of them are
        live. ``ACQUIRED`` remains live, preserving the historical contract."""
        return self.state in LIVE_STATES

    def as_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "vm_id": self.vm_id,
            "state": self.state,
            "sample": self.sample.as_dict() if self.sample else None,
            "actions": len(self.action_log),
            "state_history": list(self.state_history),
        }


class OneShotMicroVM:
    """A one-shot microVM manager: acquire → run_action(s) → destroy.

    One instance manages the lifecycle of at most one live VM at a time (a fresh
    ``acquire`` after a ``destroy`` yields a new, independent VM). Every method is
    deterministic and AWS-free in the simulated path.

    Invariants enforced here (the REAL, provable part):
      * **explicit state machine**: the handle walks
        ``QUEUED -> PROVISIONING -> ACQUIRED -> DETONATING -> ANALYZING ->
        DESTROYED`` and :meth:`transition` REFUSES any illegal jump (raising
        :class:`VMError`), using the single :data:`ALLOWED_TRANSITIONS` table.
      * **one-shot**: :meth:`acquire` refuses to acquire a second VM while one is
        still live (you must :meth:`destroy` first) — models "one microVM per
        session, no reuse".
      * **destroy-after-use**: any :meth:`run_action` on a destroyed handle raises
        :class:`VMAlreadyDestroyedError`; :meth:`destroy` is reachable from any
        live state and is idempotent.
      * **sandboxed**: every :meth:`run_action` is validated by the sandbox hooks;
        a traversal / disallowed command raises :class:`ActionRefused` and is
        never (simulated-)executed.
      * **sample-by-reference**: a sample is only an ``s3://`` uri / dropbox id;
        its bytes are never touched.
    """

    def __init__(self, *, sandbox_root: Optional[str] = None) -> None:
        # ``sandbox_root`` confines path-type actions. None → the sandbox_hooks
        # default roots (12-factor: SENTINEL_SANDBOX_ROOTS). Kept injectable so a
        # test can pin a temp root without touching global env.
        self._sandbox_root = sandbox_root
        self._live: Optional[VMHandle] = None

    # -- explicit state-machine transition ----------------------------------
    def transition(self, handle: VMHandle, to_state: str) -> str:
        """Move ``handle`` to ``to_state``, REFUSING any illegal jump (SIMULATED).

        This is the one gate through which every lifecycle move must pass. It
        consults the single :data:`ALLOWED_TRANSITIONS` table: if
        ``handle.state -> to_state`` is not an allowed edge it raises
        :class:`VMError` and the handle's state is left untouched (fail-closed —
        an illegal jump is a no-op, never a silent slide). On success it appends
        ``to_state`` to ``handle.state_history`` (the evidence trail) and returns
        the new state.

        No real VM changes phase — this only flips an in-memory string and records
        it. In production each edge would drive a real microVM action (boot,
        detonate step, collect artifacts, terminate)."""
        if to_state not in ALLOWED_TRANSITIONS:
            raise VMError(
                f"unknown target state {to_state!r}; valid states are "
                f"{sorted(ALLOWED_TRANSITIONS)}"
            )
        allowed = ALLOWED_TRANSITIONS.get(handle.state, frozenset())
        if to_state not in allowed:
            raise VMError(
                f"illegal microVM transition {handle.state!r} -> {to_state!r}; "
                f"allowed from {handle.state!r}: {sorted(allowed) or '(none, terminal)'}"
            )
        handle.state = to_state
        handle.state_history.append(to_state)
        return to_state

    # -- acquire -------------------------------------------------------------
    def acquire(self, session_id: str, *, sample: Optional[Sample] = None) -> VMHandle:
        """Acquire a fresh one-shot microVM for ``session_id`` (SIMULATED).

        Walks the handle through the real provisioning path
        ``QUEUED -> PROVISIONING -> ACQUIRED`` (each step via :meth:`transition`,
        so the evidence trail records it) and returns it READY in the ``ACQUIRED``
        state. Refuses to acquire a second VM while one is still live — a caller
        must :meth:`destroy` the current VM first, which is exactly the one-shot /
        no-reuse posture.

        No real VM is provisioned: this only mints an in-memory handle. In
        production these edges would queue the request, boot a genuinely isolated
        one-shot microVM keyed by the ``runtimeSessionId``, then mark it ready.
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")
        if self._live is not None and self._live.is_live:
            raise VMError(
                f"a microVM is already live for session {self._live.session_id!r}; "
                "destroy it before acquiring another (one-shot, no reuse)"
            )
        handle = VMHandle(
            session_id=session_id,
            vm_id=f"vm-{uuid.uuid4().hex[:16]}",
            state=QUEUED,
            sample=sample,
        )
        # Walk the legal provisioning path so the evidence trail is complete and
        # ``ACQUIRED`` is reached only through the state machine (never by a jump).
        self.transition(handle, PROVISIONING)
        self.transition(handle, ACQUIRED)
        self._live = handle
        return handle

    # -- run one action ------------------------------------------------------
    def run_action(self, handle: VMHandle, action: Dict[str, Any]) -> Dict[str, Any]:
        """Run ONE controlled action inside the (simulated) microVM.

        ``action`` shape::

            {"kind": "run",  "command": "ls /workspace"}   # command-type
            {"kind": "read", "path": "artifacts/report"}   # path-type

        Order of checks (fail-closed at each step):
          1. the handle must be live (else :class:`VMAlreadyDestroyedError`) —
             this is the destroy-after-use enforcement.
          2. the action kind must be known.
          3. the action is routed through the sandbox hooks; a disallowed command
             or a path-traversal raises :class:`ActionRefused` and NOTHING runs.
          4. on success we return a **SIMULATED** result — a deterministic dict
             describing what *would* happen. No real execution, ever.

        The result is also appended to ``handle.action_log`` for the evidence
        trail.
        """
        if handle.state == DESTROYED:
            raise VMAlreadyDestroyedError(
                f"microVM for session {handle.session_id!r} was destroyed; "
                "acquire a fresh one-shot VM (destroy-after-use is enforced)"
            )
        if not handle.is_live:
            raise VMError(f"microVM handle is not live (state={handle.state!r})")

        kind = action.get("kind") if isinstance(action, dict) else None
        if kind not in _VALID_ACTION_KINDS:
            raise ValueError(
                f"unknown action kind {kind!r}; expected one of "
                f"{sorted(_VALID_ACTION_KINDS)}"
            )

        # --- the load-bearing safety gate: refuse before any (simulated) run ---
        if kind in _COMMAND_ACTIONS:
            cmd = action.get("command")
            if not isinstance(cmd, str) or not cmd.strip():
                raise ValueError(f"action kind {kind!r} requires a non-empty 'command'")
            ok, why = validate_command(cmd)
            if not ok:
                raise ActionRefused(why)
            detail = {"command": cmd}
        else:  # path-type action
            path = action.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ValueError(f"action kind {kind!r} requires a non-empty 'path'")
            ok, why = validate_path(path, self._sandbox_root)
            if not ok:
                raise ActionRefused(why)
            detail = {"path": path}

        # --- SIMULATED result (NO real execution) ------------------------------
        result = {
            "ok": True,
            "simulated": True,
            "vm_id": handle.vm_id,
            "session_id": handle.session_id,
            "kind": kind,
            **detail,
            "note": (
                f"[SIMULATED] would perform {kind!r} inside one-shot microVM "
                f"{handle.vm_id} — no action taken, no sample byte read."
            ),
        }
        handle.action_log.append(result)
        return result

    # -- destroy -------------------------------------------------------------
    def destroy(self, handle: VMHandle) -> Dict[str, Any]:
        """Destroy the microVM after use (SIMULATED, idempotent).

        Transitions the handle to ``DESTROYED`` via the state machine so any later
        :meth:`run_action` raises. ``DESTROYED`` is reachable from EVERY
        non-terminal state (see :data:`ALLOWED_TRANSITIONS`), so destroy works from
        any live phase — QUEUED, PROVISIONING, ACQUIRED, DETONATING, or ANALYZING.
        Idempotent: destroying an already-destroyed handle is a safe no-op (you
        cannot leak a VM by double-destroy, and the terminal state has no outgoing
        edge to trip :meth:`transition`). In production this terminates the microVM
        and deletes its disk so nothing — including the sample — persists.
        """
        already = handle.state == DESTROYED
        if not already:
            # Route through the state machine so the evidence trail records the
            # teardown edge; legal from any non-terminal state by the table.
            self.transition(handle, DESTROYED)
        if self._live is handle:
            self._live = None
        return {
            "ok": True,
            "simulated": True,
            "vm_id": handle.vm_id,
            "session_id": handle.session_id,
            "state": DESTROYED,
            "idempotent_noop": already,
            "note": (
                f"[SIMULATED] one-shot microVM {handle.vm_id} destroyed; "
                "no state (or sample) survives (destroy-after-use)."
            ),
        }
