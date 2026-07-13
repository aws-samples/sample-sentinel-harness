"""
M3 surface import/callable smoke test (a coverage tripwire)
===========================================================
This is a fast, fully-OFFLINE meta-test. It does not exercise deep behavior —
the dedicated test files (``test_sigma_match.py``, ``test_asset_lookup.py``,
``test_bas_cases.py``, ``test_detonation.py``) do that. Its single job is to
GUARD that the key M3 modules stay **importable** and that their primary public
entrypoints stay **callable**:

  * ``tools/sigma_match/handler.py``            -> ``handler``
  * ``tools/asset_lookup/handler.py``           -> ``handler``
  * ``longrunning/bas-runner/bas_cases.py``     -> ``generate_cases`` / ``replay``
  * ``longrunning/detonation`` micro-VM         -> ``OneShotMicroVM``

If a refactor breaks one of these entrypoints, this test fails immediately —
instead of the measured coverage number silently dropping while the surface
rots. See ``tests/README-coverage.md`` for how coverage is measured (and why
``--include`` is required over ``--source`` for these path-loaded modules).

HARD RULE: ZERO AWS, ZERO network, no LLM, no real detonation. Every module
below is deterministic pure Python; each is loaded by a UNIQUE path-based
module name (``spec_from_file_location``) so it never collides with a bare
module name or with another test's load of the same file.
"""
from __future__ import annotations

import importlib.util
import os
import sys

# --- Hermetic env BEFORE importing anything that may build a boto3 client. --- #
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(unique_name: str, *path_parts: str):
    """Load a module by absolute file path under a UNIQUE name.

    Never use a bare module name here: the tool/specialist/long-running trees
    are flat scripts (some dirs have a dash), and two files share the basename
    ``bedrock_entrypoint.py`` — a unique name keeps every load isolated.
    """
    path = os.path.join(_REPO, *path_parts)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    assert spec and spec.loader, f"could not create spec for {path}"
    mod = importlib.util.module_from_spec(spec)
    # Register under the unique name before executing: modules that define
    # dataclasses resolve ``sys.modules[cls.__module__].__dict__`` during class
    # creation, which fails if the module is not yet registered (e.g. vm.py).
    sys.modules[unique_name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# sigma_match — the deterministic detection matcher                           #
# --------------------------------------------------------------------------- #
def test_sigma_match_imports_and_handler_is_callable():
    sm = _load("smoke_sigma_match_handler", "tools", "sigma_match", "handler.py")
    assert callable(sm.handler)
    # A malformed call must return the documented validation_error envelope —
    # proves the entrypoint is wired, not merely present.
    out = sm.handler({}, None)
    assert out["ok"] is False
    assert out["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# asset_lookup — the exposure/asset-surface tool                              #
# --------------------------------------------------------------------------- #
def test_asset_lookup_imports_and_handler_is_callable():
    al = _load("smoke_asset_lookup_handler", "tools", "asset_lookup", "handler.py")
    assert callable(al.handler)
    # Offline default: querying the whole surface returns an ok stub envelope.
    out = al.handler({"query": "*"}, None)
    assert out["ok"] is True
    assert out["source"] == "stub"


# --------------------------------------------------------------------------- #
# bas_cases — generate_cases / replay                                         #
# --------------------------------------------------------------------------- #
def test_bas_cases_imports_and_entrypoints_are_callable():
    bas = _load("smoke_bas_cases", "longrunning", "bas-runner", "bas_cases.py")
    assert callable(bas.generate_cases)
    assert callable(bas.replay)
    cases = bas.generate_cases()
    assert isinstance(cases, list) and cases, "built-in case library is non-empty"
    # replay against an empty rule set is a valid call: everything is a blind spot.
    report = bas.replay(cases, [])
    assert isinstance(report, dict)


# --------------------------------------------------------------------------- #
# detonation OneShotMicroVM — the simulated micro-VM                          #
# --------------------------------------------------------------------------- #
def test_detonation_vm_imports_and_oneshotmicrovm_is_constructible():
    # vm.py imports cleanly by path; construction is the simulated, in-memory
    # abstraction — no real VM, no AWS.
    vm = _load("smoke_detonation_vm", "longrunning", "detonation", "src", "vm.py")
    assert isinstance(vm.OneShotMicroVM, type)
    inst = vm.OneShotMicroVM()
    assert inst is not None


def test_detonation_bedrock_entrypoint_imports_and_exposes_oneshotmicrovm():
    # The entrypoint imports its ``runner_loop`` / ``vm`` siblings by bare name,
    # so those dirs must be on sys.path (mirrors tests/test_detonation.py). The
    # guarded bedrock_agentcore import means ``app`` may be None — that is fine.
    sys.path.insert(0, os.path.join(_REPO, "longrunning", "bas-runner"))
    sys.path.insert(0, os.path.join(_REPO, "longrunning", "detonation", "src"))
    ep = _load(
        "smoke_detonation_bedrock_entrypoint",
        "longrunning", "detonation", "bedrock_entrypoint.py",
    )
    # The entrypoint re-exports OneShotMicroVM and its run_detonation orchestrator.
    assert isinstance(ep.OneShotMicroVM, type)
    assert callable(ep.run_detonation)
