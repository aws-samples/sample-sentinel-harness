"""
Offline container-contract tests for ALL A2A specialists
========================================================
100% offline, deterministic, fast. ZERO docker, ZERO network, ZERO creds.

Parametrized over every specialist under ``specialists/`` (cve-intel,
attack-mapper, threat-hunt) to prove their *packaging* is buildable-and-
runnable-shaped and at parity WITHOUT ever invoking a docker daemon:

  - Dockerfile parses, pins its base (no :latest), declares a non-root USER,
    EXPOSE 9000, and a CMD/ENTRYPOINT.
  - requirements.txt is fully PINNED (== or ~=) AND matches the cve-intel-
    verified dependency set exactly (same package -> same version), so the
    three specialists ship the identical, resolvable stack.
  - No hardcoded secret / real 12-digit account id in Dockerfile or requirements.
  - Any Bedrock model-id default baked into the module carries a full version
    suffix (-YYYYMMDD-vN:M) so a container cannot ship a silently-broken default.

An actual ``docker build`` (if a daemon exists) is NOT attempted here — this
unit test must run on a machine with no docker at all.

Each specialist module is loaded by an explicit path under a UNIQUE name to
avoid the shared ``agent_a2a`` sys.modules collision across specialists.
"""
from __future__ import annotations

import importlib.util
import os
import re

import pytest

# --------------------------------------------------------------------------- #
# Locate the specialists by absolute path (no cwd assumptions).               #
# --------------------------------------------------------------------------- #
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALISTS_DIR = os.path.join(REPO_ROOT, "specialists")

# The reference/source-of-truth specialist the other two must match.
REFERENCE = "cve-intel"
SPECIALISTS = ("cve-intel", "attack-mapper", "threat-hunt")

# A 12-digit run of digits that is NOT the all-zeros placeholder = a real account id.
_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
# Common committed-secret prefixes / long-lived AWS key ids.
_SECRET_PATTERNS = (
    "sk-",          # OpenAI-style key
    "ghp_",         # GitHub PAT
    "AKIA",         # AWS long-lived access key id
    "ASIA",         # AWS temporary access key id
    "-----BEGIN",   # PEM private key block
)
# A Bedrock/Anthropic inference-profile id must be version-pinned:
#   ...claude-haiku-4-5-20251001-v1:0  (a -YYYYMMDD-vN:M suffix).
_MODEL_ID_RE = re.compile(r"anthropic\.claude[a-z0-9.:\-]*")
_MODEL_VERSION_SUFFIX_RE = re.compile(r"-\d{8}-v\d+:\d+$")


def _dockerfile(name: str) -> str:
    return os.path.join(SPECIALISTS_DIR, name, "Dockerfile")


def _requirements(name: str) -> str:
    return os.path.join(SPECIALISTS_DIR, name, "requirements.txt")


def _agent_module_path(name: str) -> str:
    return os.path.join(SPECIALISTS_DIR, name, "agent_a2a.py")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load_specialist(name: str):
    """Load a specialist's agent_a2a under a unique module name (collision-proof)."""
    unique = f"{name.replace('-', '_')}_agent_a2a__containers_test"
    spec = importlib.util.spec_from_file_location(unique, _agent_module_path(name))
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _requirement_lines(name: str) -> list[str]:
    out = []
    for raw in _read(_requirements(name)).splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out


def _requirement_map(name: str) -> dict[str, str]:
    """Parse pinned requirements into {package[extras-normalized]: version}.

    Splits on the pin operator (== or ~=). The left side (name + optional
    ``[extras]``) is normalized to lowercase so ordering / case never matters.
    """
    out: dict[str, str] = {}
    for ln in _requirement_lines(name):
        m = re.split(r"(==|~=)", ln, maxsplit=1)
        assert len(m) == 3, f"unpinned requirement in {name}: {ln!r}"
        pkg, _op, ver = m
        out[pkg.strip().lower()] = ver.strip()
    return out


# --------------------------------------------------------------------------- #
# Files exist for every specialist                                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", SPECIALISTS)
def test_packaging_files_exist(name):
    for path in (_dockerfile(name), _requirements(name), _agent_module_path(name)):
        assert os.path.isfile(path), f"missing packaging file: {path}"


# --------------------------------------------------------------------------- #
# Dockerfile structural contract                                               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", SPECIALISTS)
def test_dockerfile_parses_and_pins_base(name):
    src = _read(_dockerfile(name))
    from_lines = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("FROM ")
    ]
    assert from_lines, f"{name}: Dockerfile has no FROM instruction"
    for ln in from_lines:
        # Extract the image reference (token after FROM, skipping --platform=...).
        toks = [t for t in ln.split() if not t.upper().startswith("--PLATFORM")]
        image_ref = toks[1]  # toks[0] == 'FROM'
        # A stage that FROMs a previous named stage (COPY --from friend) is fine
        # and needs no tag. Only external base images must be pinned.
        is_internal_stage_ref = re.fullmatch(r"\w+", image_ref) is not None
        if is_internal_stage_ref:
            continue
        assert ":" in image_ref, f"{name}: base image not tagged (unpinned): {image_ref}"
        assert not image_ref.endswith(":latest"), (
            f"{name}: base pinned to :latest: {image_ref}"
        )
    # The pinned python base at parity with cve-intel.
    assert "python:3.13-slim" in src, f"{name}: expected pinned python:3.13-slim base"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_dockerfile_declares_non_root_user(name):
    src = _read(_dockerfile(name))
    user_lines = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("USER ")
    ]
    assert user_lines, f"{name}: Dockerfile must declare a USER"
    # The effective (last) USER must not be root / uid 0.
    last_user = user_lines[-1].split()[1]
    assert last_user.lower() not in ("root", "0"), f"{name}: container runs as {last_user}"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_dockerfile_exposes_a2a_port(name):
    src = _read(_dockerfile(name))
    expose = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("EXPOSE")
    ]
    assert expose, f"{name}: Dockerfile must EXPOSE the A2A port"
    ports = {tok for ln in expose for tok in ln.split()[1:]}
    assert "9000" in ports, f"{name}: expected A2A port 9000 exposed, saw {ports}"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_dockerfile_has_cmd_or_entrypoint(name):
    src = _read(_dockerfile(name)).upper()
    padded = "\n" + src
    assert (
        "\nCMD " in padded
        or "\nCMD[" in padded
        or "\nENTRYPOINT" in padded
    ), f"{name}: Dockerfile needs a CMD or ENTRYPOINT"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_dockerfile_no_hardcoded_secret_or_account(name):
    src = _read(_dockerfile(name))
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"{name}: hardcoded account id in Dockerfile: {m}"
    for pat in _SECRET_PATTERNS:
        assert pat not in src, f"{name}: possible hardcoded secret in Dockerfile: {pat}"


# --------------------------------------------------------------------------- #
# requirements.txt: PINNED + matches the cve-intel-verified set exactly        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", SPECIALISTS)
def test_requirements_are_all_pinned(name):
    reqs = _requirement_lines(name)
    assert reqs, f"{name}: requirements.txt has no requirements"
    for ln in reqs:
        assert "==" in ln or "~=" in ln, f"{name}: unpinned requirement: {ln!r}"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_requirements_match_cve_intel_exactly(name):
    reference = _requirement_map(REFERENCE)
    got = _requirement_map(name)
    assert got == reference, (
        f"{name} requirements diverge from {REFERENCE}: "
        f"{name}={got} vs {REFERENCE}={reference}"
    )


@pytest.mark.parametrize("name", SPECIALISTS)
def test_requirements_list_the_specialist_stack(name):
    joined = "\n".join(_requirement_lines(name)).lower()
    assert "strands-agents" in joined, f"{name}: missing strands-agents"
    assert "a2a" in joined and "litellm" in joined, f"{name}: missing a2a/litellm extras"
    assert "uvicorn" in joined, f"{name}: missing uvicorn ASGI server"
    assert "fastapi" in joined, f"{name}: missing fastapi"


@pytest.mark.parametrize("name", SPECIALISTS)
def test_requirements_no_hardcoded_secret_or_account(name):
    src = _read(_requirements(name))
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"{name}: hardcoded account id in requirements: {m}"
    for pat in _SECRET_PATTERNS:
        assert pat not in src, f"{name}: possible hardcoded secret in requirements: {pat}"


# --------------------------------------------------------------------------- #
# Module contract: entrypoint/port line up + model-id default is version-pinned #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", SPECIALISTS)
def test_cmd_matches_specialist_module_and_port(name):
    """The Dockerfile CMD/EXPOSE must line up with the module's own declared
    port + entrypoint, so the image actually boots what we test."""
    src = _read(_dockerfile(name))
    mod = _load_specialist(name)
    assert "agent_a2a" in src, f"{name}: CMD must launch the agent_a2a module"
    assert mod.DEFAULT_PORT == 9000, f"{name}: module DEFAULT_PORT != 9000"
    # Each specialist keeps its own agent-card / module name.
    assert mod.SPECIALIST_NAME == name, (
        f"{name}: SPECIALIST_NAME={mod.SPECIALIST_NAME!r} does not match dir"
    )


@pytest.mark.parametrize("name", SPECIALISTS)
def test_default_model_id_is_version_pinned(name):
    """Any Bedrock model-id default the module ships (DEFAULT_MODEL_ID or a bare
    literal in source) MUST carry a full version suffix (-YYYYMMDD-vN:M). A bare
    'claude-haiku-4-5' reaches READY but raises ValidationException on the first
    live invoke (cf. core.py MODEL_HAIKU)."""
    mod = _load_specialist(name)
    default_model = getattr(mod, "DEFAULT_MODEL_ID", None)
    candidates = []
    if isinstance(default_model, str):
        candidates.append(default_model)
    # Also scan the source for any other baked anthropic.claude ids.
    candidates.extend(_MODEL_ID_RE.findall(_read(_agent_module_path(name))))
    # At least the DEFAULT_MODEL_ID should exist for a litellm specialist.
    assert candidates, f"{name}: no model id default found to validate"
    for mid in candidates:
        for found in _MODEL_ID_RE.findall(mid) or [mid]:
            assert _MODEL_VERSION_SUFFIX_RE.search(found), (
                f"{name}: default model id {found!r} is not version-pinned "
                "(needs a -YYYYMMDD-vN:M suffix, cf. core.py MODEL_HAIKU)"
            )
