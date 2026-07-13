"""
Property-based (Hypothesis) fuzzing of the security-critical sandbox validators.

``sentinel_harness.sandbox_hooks.validate_command`` and ``validate_path`` are the
PreToolUse gate that decides whether an agent's shell/file action is allowed. They
are load-bearing security controls, so we fuzz them against adversarial input and
assert INVARIANTS that must hold for every input — not just the ~15 hand-written
examples in test_sandbox_hooks.py:

  * validate_command never crashes; and any ALLOWED verdict never contains a shell
    chain/redirection operator (incl. newline/CR) or a denied destructive pattern —
    i.e. an attacker cannot smuggle a second command past the leading-verb allowlist.
  * validate_path never crashes; and any ALLOWED verdict never contains a `..`
    parent-directory traversal segment.

Zero network, zero AWS — pure input/output property checks.
"""
from __future__ import annotations

import importlib.util
import os
import sys

from hypothesis import given, settings
from hypothesis import strategies as st

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


sb = _load("sandbox_hooks_fuzz", "sentinel_harness/sandbox_hooks.py")

# The chain/redirection operators the validator must never let through in an
# allowed command (mirrors the module's own _CHAIN_OPERATORS, incl. newline/CR).
_CHAIN_OPS = ("&&", "||", ";", "|", "`", "$(", ">", "<", "&", "\n", "\r")

# A generator that biases toward realistic, adversarial command strings: allowed
# verbs, chain operators, denied verbs, traversal, and arbitrary text — so the
# fuzzer explores the smuggling surface, not just random noise.
_TOKENS = (
    list(sb.ALLOWED_COMMANDS)
    + ["nmap", "curl", "scp", "wget", "rm", "sudo", "bash", "sh", "eval"]
    + list(_CHAIN_OPS)
    + ["/etc/passwd", "../", "..", "/workspace/x", "-la", "foo", "  ", "\t"]
)
_cmd_strategy = st.lists(st.sampled_from(_TOKENS), min_size=0, max_size=8).map(" ".join)
_path_strategy = st.lists(
    st.sampled_from(["a", "b", "..", "/", "workspace", "etc", "passwd", "\\", "x.txt", "."]),
    min_size=0, max_size=8,
).map("/".join)


@settings(max_examples=400, deadline=None)
@given(cmd=_cmd_strategy)
def test_validate_command_never_crashes_and_allowed_is_clean(cmd):
    ok, reason = sb.validate_command(cmd)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        # An allowed command must contain NO chain/redirection operator — the whole
        # point of the gate is that a denied second statement cannot ride along.
        for op in _CHAIN_OPS:
            assert op not in cmd, f"allowed command leaked chain operator {op!r}: {cmd!r}"


@settings(max_examples=200, deadline=None)
@given(cmd=st.text(max_size=120))
def test_validate_command_survives_arbitrary_text(cmd):
    ok, reason = sb.validate_command(cmd)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        for op in _CHAIN_OPS:
            assert op not in cmd


@settings(max_examples=400, deadline=None)
@given(path=_path_strategy)
def test_validate_path_never_crashes_and_allowed_has_no_traversal(path):
    ok, reason = sb.validate_path(path)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        # An allowed path must never contain a `..` traversal segment.
        assert ".." not in path.replace("\\", "/").split("/"), f"allowed path has traversal: {path!r}"


@settings(max_examples=200, deadline=None)
@given(path=st.text(max_size=120))
def test_validate_path_survives_arbitrary_text(path):
    ok, reason = sb.validate_path(path)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        assert ".." not in path.replace("\\", "/").split("/")


def test_known_smuggling_examples_are_denied():
    """Concrete regression anchors alongside the property tests."""
    for cmd in [
        "echo ok\nnmap -sS 10.0.0.1",   # newline-smuggled denied verb
        "ls && rm -rf /",               # chain to a destructive command
        "cat foo | sh",                 # pipe to shell
        "echo $(whoami)",               # command substitution
        "grep x > /etc/passwd",         # redirection to a system file
    ]:
        ok, _ = sb.validate_command(cmd)
        assert ok is False, f"smuggling command was allowed: {cmd!r}"
