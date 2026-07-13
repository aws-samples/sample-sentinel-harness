"""
bas-runner · PreToolUse / PostToolUse sandbox hooks
===================================================
The long-running BAS Runtime executes tool calls inside a per-session microVM.
Untrusted plan content (technique objectives, generated shell) must never be able
to escape the workspace or run a destructive/exfiltration command. That gate is
already implemented once, deterministically, in
:mod:`sentinel_harness.sandbox_hooks` (allowlist + destructive-verb denylist +
path confinement). We REUSE it here rather than re-deriving the rules — a second
copy of the denylist is a second place to forget a pattern.

This module is the thin adapter that shapes those validators into the hook
contract a long-running agent framework expects: a ``PreToolUse`` hook that can
BLOCK a call before it runs, and a ``PostToolUse`` hook that can flag output. The
hooks are pure/deterministic and make ZERO AWS calls, so they are unit-testable
offline and identical every time.

Why a PreToolUse *block* and not just a warning
-----------------------------------------------
In an adversary-emulation run the model may be steered by attacker-controlled
context into requesting a real destructive action. Fail-closed: if the validator
denies, the tool call is refused and the reason is surfaced back to the loop so
the model can course-correct — the offensive intent never reaches a real shell.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

# REUSE the single source of truth for command/path safety. Do not reimplement.
from sentinel_harness.sandbox_hooks import validate_command, validate_path

# Tool names whose primary argument is a shell command string. A caller wires
# its own shell-capable tool here; these are the common defaults.
_SHELL_TOOLS = frozenset({"bash", "shell", "run_command", "exec", "sh"})

# Keys under which a tool's shell command / target path commonly arrives. We probe
# these in order so the hook works with the usual tool-input shapes without the
# caller having to remap anything.
_COMMAND_KEYS = ("command", "cmd", "script", "input")
_PATH_KEYS = ("path", "file", "filename", "target_path")


@dataclass
class HookResult:
    """Outcome of a hook. ``allow=False`` means the tool call MUST be refused;
    ``reason`` is safe to surface back to the agent so it can self-correct."""

    allow: bool
    reason: str = "ok"

    def as_dict(self) -> dict[str, Any]:
        return {"allow": self.allow, "reason": self.reason}


def _first_str(tool_input: Mapping[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    """Return the first present, string-valued key from ``keys`` (or None)."""
    for k in keys:
        v = tool_input.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def pre_tool_use(tool_name: str, tool_input: Mapping[str, Any]) -> HookResult:
    """PreToolUse gate: deny a tool call BEFORE it executes if it would run a
    disallowed command or touch a path outside the sandbox.

    Fail-closed and deterministic:
      * For a shell-capable tool, the command string is run through
        :func:`~sentinel_harness.sandbox_hooks.validate_command` (allowlist +
        destructive/exfiltration denylist + per-arg path confinement).
      * Any explicit path argument (for any tool) is run through
        :func:`~sentinel_harness.sandbox_hooks.validate_path`.
      * A tool with no command/path argument is allowed (nothing to confine).

    Returns a :class:`HookResult`; the runner refuses the call when ``allow`` is
    False and feeds ``reason`` back to the model.
    """
    tool_input = tool_input or {}

    # A shell-capable tool: the whole command string must pass the validator.
    if tool_name in _SHELL_TOOLS:
        cmd = _first_str(tool_input, _COMMAND_KEYS)
        if cmd is None:
            return HookResult(False, f"{tool_name!r} called without a command string")
        ok, reason = validate_command(cmd)
        return HookResult(ok, reason)

    # Any other tool: confine an explicit path argument if it has one.
    path = _first_str(tool_input, _PATH_KEYS)
    if path is not None:
        ok, reason = validate_path(path)
        return HookResult(ok, reason)

    return HookResult(True, "ok")


def post_tool_use(tool_name: str, tool_output: Any) -> HookResult:
    """PostToolUse check: a defensive backstop after a tool ran.

    The sandbox already confines *what* can run; this stage exists so a caller can
    flag suspicious output (e.g. a tool that unexpectedly emitted a system
    credential file path) without failing the turn. Deterministic, no AWS. The
    default posture is permissive — the load-bearing gate is PreToolUse — but the
    hook point is here so a caller can tighten it (e.g. run Guardrails) without
    changing the runner loop.
    """
    text = tool_output if isinstance(tool_output, str) else str(tool_output)
    for marker in ("/etc/shadow", "/etc/sudoers"):
        if marker in text:
            return HookResult(False, f"tool output referenced sensitive path {marker!r}")
    return HookResult(True, "ok")
