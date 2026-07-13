"""
sentinel-harness · PreToolUse sandbox security hooks (Layer-3 foundation)
=========================================================================
Pure-Python, deterministic validators that gate what a shell-capable agent tool
(e.g. ``InvokeAgentRuntimeCommand`` in a caller's own wrapper) is allowed to run.
They mirror the sandbox-isolation design: an *allowlist* of safe command verbs,
a *denylist* of destructive/exfiltration patterns, and *path confinement* to a
workspace root (no ``..`` traversal, no absolute paths outside the sandbox).

These functions make ZERO AWS calls, use no LLM, and are fully deterministic —
the same command string always yields the same verdict. Wire them as a
PreToolUse check: call ``validate_command(cmd)`` before executing, and refuse the
tool call when ``allowed`` is False, surfacing ``reason`` back to the agent.

Configuration (12-factor)
-------------------------
    export SENTINEL_SANDBOX_ROOTS="/workspace:/mnt"   # optional, colon-separated
"""
from __future__ import annotations
import os
import re
import shlex

# Workspace roots an absolute path may live under. Overridable via env; a caller
# in a sandbox where the workspace mounts elsewhere sets SENTINEL_SANDBOX_ROOTS.
SANDBOX_ROOTS = tuple(
    p for p in os.environ.get("SENTINEL_SANDBOX_ROOTS", "/workspace:/mnt").split(":") if p
)

# Command verbs an agent may invoke. Read-only / build / test / VCS tooling only.
# Anything not on this list is denied by default (deny-by-default posture).
ALLOWED_COMMANDS = frozenset({
    "git", "ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "sort",
    "uniq", "diff", "echo", "pwd", "cd", "python", "python3", "pytest", "pip",
    "pip3", "uv", "ruff", "mypy", "node", "npm", "npx", "make", "sed", "awk",
    "cut", "tr", "true", "false", "test", "cp", "mv", "mkdir", "touch",
})

# Substring / regex patterns that are always denied, even for an allowed verb.
# These catch destructive filesystem ops, pipe-to-shell installers, fork bombs,
# and privilege escalation regardless of the leading command.
_DENY_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\brm\s+(-\w*\s+)*-\w*[rf]", re.I), "recursive/forced rm is blocked"),
    (re.compile(r"\brm\s+-[rf]", re.I), "recursive/forced rm is blocked"),
    (re.compile(r":\(\)\s*\{.*\};", re.S), "fork bomb pattern is blocked"),
    (re.compile(r"\bmkfs\b|\bdd\s+if=", re.I), "raw disk write is blocked"),
    (re.compile(r">\s*/dev/sd|\bshred\b", re.I), "device/secure-wipe write is blocked"),
    (re.compile(r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?)\b", re.I),
     "pipe-to-shell download execution is blocked"),
    (re.compile(r"\bsudo\b|\bsu\b\s|\bchmod\s+[0-7]*777|\bchown\b", re.I),
     "privilege/permission escalation is blocked"),
    (re.compile(r"\beval\b|\bexec\b", re.I), "eval/exec is blocked"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)", re.I), "access to system credential files is blocked"),
)

# Shell control operators that could chain a denied command onto an allowed one.
# We reject them so validation cannot be bypassed by `ls && rm -rf /`.
# Newline/CR are included: POSIX shells treat them as command separators, so
# without them a denied verb smuggled onto a second line (`echo ok\nnmap ...`)
# would slip past the leading-verb allowlist check (which only inspects tokens[0]).
_CHAIN_OPERATORS = ("&&", "||", ";", "|", "`", "$(", ">", "<", "&", "\n", "\r")


def validate_path(path: str, root: str | None = None) -> tuple[bool, str]:
    """Confine ``path`` to a workspace root.

    Rejects parent-directory traversal (``..``) and any absolute path that does
    not resolve under an allowed root. Relative paths are resolved against
    ``root`` (default: first configured sandbox root). Returns ``(allowed, reason)``.
    """
    if not path:
        return False, "empty path"
    roots = (root,) if root else (SANDBOX_ROOTS or (os.getcwd(),))
    # Reject traversal on the *lexical* form before normalization so a crafted
    # `/workspace/../etc` is caught even though it would normalize under a root.
    if ".." in path.replace("\\", "/").split("/"):
        return False, f"path {path!r} contains parent-directory traversal ('..')"
    for r in roots:
        base = os.path.normpath(r)
        candidate = path if os.path.isabs(path) else os.path.join(base, path)
        norm = os.path.normpath(candidate)
        if norm == base or norm.startswith(base + os.sep):
            return True, "ok"
    allowed = ", ".join(str(r) for r in roots)
    return False, f"path {path!r} is outside the sandbox root(s): {allowed}"


def validate_command(cmd: str) -> tuple[bool, str]:
    """Validate a shell command string against the allowlist + denylist + path
    confinement. Returns ``(allowed, reason)``; ``reason`` explains a denial and
    is safe to surface back to the agent.

    Order of checks (fail closed at each step):
      1. non-empty, parseable
      2. no destructive/exfiltration deny-pattern anywhere in the string
      3. no shell chaining operators (prevents allowlist bypass)
      4. leading verb is on the allowlist
      5. every path-like argument is confined to the sandbox root
    """
    if not cmd or not cmd.strip():
        return False, "empty command"

    for pat, why in _DENY_PATTERNS:
        if pat.search(cmd):
            return False, why

    for op in _CHAIN_OPERATORS:
        if op in cmd:
            return False, f"shell operator {op!r} is not allowed (no command chaining/redirection)"

    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        return False, f"unparseable command: {e}"
    if not tokens:
        return False, "empty command"

    verb = os.path.basename(tokens[0])
    if verb not in ALLOWED_COMMANDS:
        return False, f"command {verb!r} is not on the allowlist"

    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue  # option flag, not a path
        if os.path.isabs(tok) or ".." in tok.split("/") or "/" in tok:
            ok, why = validate_path(tok)
            if not ok:
                return False, why

    return True, "ok"
