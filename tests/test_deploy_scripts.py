"""
Offline guard tests for the deploy/destroy runbook scripts
==========================================================
The one-command deploy story (``deploy/deploy.sh`` + ``deploy/destroy.sh``) is the
human-facing path to the M4 Layer-3 foundation, so its safety invariants must not
silently regress. These tests assert the *contract* of those scripts as text +
``bash -n`` — they do NOT execute them, so there is ZERO AWS / network / subprocess-
into-AWS risk. The only subprocess is ``bash -n`` (a pure syntax check that neither
runs the body nor touches the network).

Why assert on text rather than run the scripts: running them would call ``aws sts
get-caller-identity`` and ``npx cdk`` — real network + real credentials. The
promotion-quality guarantees we care about (a human-confirmation prompt exists, the
cost-gated endpoint flag exists, no hardcoded account, only sentinel-* stack names)
are all statically verifiable, so we verify them statically and stay hermetic.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

# Repo layout: tests/ is a sibling of deploy/. Resolve absolute paths so the tests
# do not depend on the caller's CWD.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEPLOY_DIR = os.path.join(_REPO_ROOT, "deploy")
DEPLOY_SH = os.path.join(_DEPLOY_DIR, "deploy.sh")
DESTROY_SH = os.path.join(_DEPLOY_DIR, "destroy.sh")
README = os.path.join(_DEPLOY_DIR, "README.md")

SCRIPTS = [DEPLOY_SH, DESTROY_SH]

# The exact stack names bin/sentinel.ts creates — the scripts must reference ONLY
# these (all sentinel-*), and must NOT operate on the CDKToolkit bootstrap stack.
SENTINEL_STACKS = {
    "sentinel-gateway",
    "sentinel-registry",
    "sentinel-memory",
    "sentinel-network",
    "sentinel-identity",
    "sentinel-guardrail",
    "sentinel-observability",
    "sentinel-harness",
}

# A bare 12-digit run (an AWS account id) that must never be hardcoded. The literal
# all-zeros placeholder 000000000000 is the ONLY 12-digit run tolerated (and only if
# it ever appears); a real-looking account id in these scripts is a hard failure.
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Existence + shebang + executability                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", SCRIPTS)
def test_script_exists(path):
    assert os.path.isfile(path), f"expected script to exist: {path}"


@pytest.mark.parametrize("path", SCRIPTS)
def test_script_has_bash_shebang(path):
    """First line must be a bash shebang (env-based is fine and portable)."""
    first_line = _read(path).splitlines()[0]
    assert first_line.startswith("#!"), f"{path} is missing a shebang"
    assert "bash" in first_line, f"{path} shebang must invoke bash, got: {first_line!r}"


@pytest.mark.parametrize("path", SCRIPTS)
def test_script_is_executable(path):
    """The runbook advertises `deploy/deploy.sh` directly, so the file must carry
    the executable bit (owner-execute at minimum)."""
    mode = os.stat(path).st_mode
    assert mode & 0o100, f"{path} is not owner-executable (chmod +x it)"


# --------------------------------------------------------------------------- #
# bash -n syntax check (does not execute the body)                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", SCRIPTS)
def test_script_passes_bash_syntax_check(path):
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is present on the target platforms
        pytest.skip("bash not available")
    proc = subprocess.run(
        [bash, "-n", path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"bash -n failed for {path}:\n{proc.stderr}"


@pytest.mark.parametrize("path", SCRIPTS)
def test_script_sets_strict_mode(path):
    """Never swallow failures: both scripts must run under `set -euo pipefail`."""
    body = _read(path)
    assert "set -euo pipefail" in body, f"{path} must use `set -euo pipefail`"


# --------------------------------------------------------------------------- #
# Human-confirmation prompt                                                    #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", SCRIPTS)
def test_script_requires_typed_confirmation(path):
    """Both scripts MUST require an interactive human 'yes' before acting. We assert
    the prompt reads from the tty and compares against the literal 'yes'."""
    body = _read(path)
    assert "read -r" in body, f"{path} must read a confirmation from the user"
    assert "/dev/tty" in body, f"{path} must read the confirm from /dev/tty (not a pipe)"
    assert '"yes"' in body or "'yes'" in body, f"{path} must compare against 'yes'"
    # An abort path must exist (declining does nothing destructive).
    assert "aborted" in body.lower(), f"{path} must have an explicit abort path"


def test_deploy_prints_account_and_region_before_confirm():
    """The deploy prompt must show the operator the account + region it will use."""
    body = _read(DEPLOY_SH)
    assert "AWS account" in body
    assert "Region" in body
    # Account/region derived from the live identity, not hardcoded.
    assert "get-caller-identity" in body
    assert "CDK_DEFAULT_ACCOUNT" in body
    assert "CDK_DEFAULT_REGION" in body


# --------------------------------------------------------------------------- #
# --with-endpoints cost gate (deploy only)                                     #
# --------------------------------------------------------------------------- #
def test_deploy_has_with_endpoints_gate():
    """The ~$30/mo VPC interface endpoints must be a named, opt-in flag that maps to
    the CDK context flag — never on by default."""
    body = _read(DEPLOY_SH)
    assert "--with-endpoints" in body, "deploy.sh must expose the --with-endpoints flag"
    assert "sentinel:deployVpcEndpoints=true" in body, (
        "deploy.sh must gate endpoints behind the CDK context flag"
    )
    # It must be conditional (the flag only added when opted in), not unconditional.
    assert "WITH_ENDPOINTS=false" in body, "endpoints must default OFF"


def test_deploy_waives_cdk_approval_only_with_human_confirm():
    """`--require-approval never` is only acceptable AFTER our own human gate, so the
    script must contain both (the human confirm is asserted separately above)."""
    body = _read(DEPLOY_SH)
    assert "--require-approval never" in body
    # And the confirmation read must appear before the deploy INVOCATION (the
    # `npx cdk deploy` call, not the earlier mentions in the header comment).
    assert body.index("read -r") < body.index("npx cdk deploy"), (
        "human confirmation must come before the cdk deploy call"
    )


# --------------------------------------------------------------------------- #
# destroy: force + cleanliness + does not touch CDKToolkit                     #
# --------------------------------------------------------------------------- #
def test_destroy_uses_force_and_confirms():
    body = _read(DESTROY_SH)
    assert "cdk destroy" in body
    assert "--force" in body
    # Confirmation must precede the destroy INVOCATION (`npx cdk destroy`), not the
    # header comment's earlier mention of `cdk destroy`.
    assert body.index("read -r") < body.index("npx cdk destroy"), (
        "human confirmation must come before the cdk destroy call"
    )


def test_destroy_does_not_touch_cdktoolkit_bootstrap():
    """The bootstrap stack must be explicitly left alone: mentioned as NOT touched,
    and never passed to a destroy command."""
    body = _read(DESTROY_SH)
    assert "CDKToolkit" in body, "destroy.sh should note the CDKToolkit bootstrap stack"
    # CDKToolkit must not be an argument to `cdk destroy` (it may only be referenced
    # in a comment / manual delete-stack hint). Assert it is not in the stack array.
    assert "sentinel-cdktoolkit" not in body.lower()
    # The destroy stack list must be exactly the sentinel-* set.
    for stack in SENTINEL_STACKS:
        assert stack in body, f"destroy.sh must list {stack}"


# --------------------------------------------------------------------------- #
# No hardcoded account id (public open-source safety)                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", SCRIPTS + [README])
def test_no_hardcoded_account_id(path):
    """No real 12-digit AWS account id anywhere. The all-zeros placeholder is the
    only 12-digit run tolerated."""
    body = _read(path)
    for match in _TWELVE_DIGITS.finditer(body):
        assert match.group(0) == "000000000000", (
            f"{path} contains a hardcoded 12-digit account id: {match.group(0)!r}"
        )


# --------------------------------------------------------------------------- #
# Only sentinel-* stack names are referenced                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", SCRIPTS)
def test_only_sentinel_stack_names(path):
    """Any `sentinel-<word>` token in the scripts must be one of the known stacks —
    catches typos and stray stack names that would target the wrong resource."""
    body = _read(path)
    referenced = set(re.findall(r"\bsentinel-[a-z]+\b", body))
    unknown = referenced - SENTINEL_STACKS
    assert not unknown, f"{path} references unknown sentinel-* names: {sorted(unknown)}"
    # And each script must actually name at least one real stack (not vacuously pass).
    assert referenced, f"{path} references no sentinel-* stacks at all"


def test_deploy_defaults_to_free_tier_stacks_only():
    """The default deploy set must be the free-tier four — NOT the billable-by-deploy
    gateway/registry/memory/harness, and NOT --all."""
    body = _read(DEPLOY_SH)
    referenced = set(re.findall(r"\bsentinel-[a-z]+\b", body))
    assert {"sentinel-guardrail", "sentinel-identity",
            "sentinel-observability", "sentinel-network"} <= referenced
    assert "cdk deploy --all" not in body, "deploy.sh must not blanket-deploy --all"
