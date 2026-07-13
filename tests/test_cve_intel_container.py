"""
Offline container-contract tests for the cve-intel specialist
=============================================================
100% offline, deterministic, fast. ZERO docker, ZERO network, ZERO creds.

These tests prove the *packaging* is buildable-and-runnable-shaped WITHOUT ever
invoking a docker daemon:

  - Dockerfile parses, is multi-stage, pins its base (no :latest), declares a
    non-root USER, an EXPOSE, and a CMD/ENTRYPOINT.
  - requirements.txt lists the specialist stack (strands-agents[a2a,litellm],
    litellm-capable + a2a + the A2A/HTTP server) and every requirement is PINNED
    (== or ~=), so a build is reproducible.
  - compose.yaml is valid YAML, drives the model id from an env var, exposes the
    A2A port, and carries NO hardcoded secret / real 12-digit account id.

An actual `docker build` (if a daemon exists) is attempted only in the *verify*
step, never here — the unit test must run on a machine with no docker at all.

The specialist module is loaded by an explicit path under a UNIQUE name to avoid
the shared ``agent_a2a`` / sibling ``handler`` sys.modules collisions across
specialists.
"""
from __future__ import annotations

import importlib.util
import os
import re

import yaml

# --------------------------------------------------------------------------- #
# Locate the specialist package by absolute path (no cwd assumptions).        #
# --------------------------------------------------------------------------- #
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALIST_DIR = os.path.join(REPO_ROOT, "specialists", "cve-intel")
DOCKERFILE = os.path.join(SPECIALIST_DIR, "Dockerfile")
REQUIREMENTS = os.path.join(SPECIALIST_DIR, "requirements.txt")
COMPOSE = os.path.join(SPECIALIST_DIR, "compose.yaml")
AGENT_MODULE_PATH = os.path.join(SPECIALIST_DIR, "agent_a2a.py")

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


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load_specialist():
    """Load agent_a2a under a unique module name (collision-proof)."""
    spec = importlib.util.spec_from_file_location(
        "cve_intel_agent_a2a__container_test", AGENT_MODULE_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Files exist                                                                  #
# --------------------------------------------------------------------------- #
def test_packaging_files_exist():
    for path in (DOCKERFILE, REQUIREMENTS, COMPOSE):
        assert os.path.isfile(path), f"missing packaging file: {path}"


# --------------------------------------------------------------------------- #
# Dockerfile structural contract                                               #
# --------------------------------------------------------------------------- #
def test_dockerfile_is_multi_stage_with_pinned_base():
    src = _read(DOCKERFILE)
    from_lines = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("FROM ")
    ]
    # Multi-stage: at least two FROM instructions.
    assert len(from_lines) >= 2, f"expected multi-stage build, saw: {from_lines}"
    # At least one named build stage (AS <name>).
    assert any(re.search(r"\bAS\s+\w+", ln, re.IGNORECASE) for ln in from_lines), (
        "multi-stage build must name a stage with 'AS <name>'"
    )
    for ln in from_lines:
        # Extract the image reference (token after FROM, skipping --platform=...).
        toks = [t for t in ln.split() if not t.upper().startswith("--PLATFORM")]
        image_ref = toks[1]  # toks[0] == 'FROM'
        # A stage that FROMs a previous named stage (COPY --from friend) is fine
        # and needs no tag. Only external base images must be pinned.
        is_internal_stage_ref = re.fullmatch(r"\w+", image_ref) is not None
        if is_internal_stage_ref:
            continue
        assert ":" in image_ref, f"base image not tagged (unpinned): {image_ref}"
        assert not image_ref.endswith(":latest"), f"base pinned to :latest: {image_ref}"
    # The pinned python base the task calls for.
    assert "python:3.13-slim" in src, "expected pinned python:3.13-slim base"


def test_dockerfile_declares_non_root_user():
    src = _read(DOCKERFILE)
    user_lines = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("USER ")
    ]
    assert user_lines, "Dockerfile must declare a USER"
    # The effective (last) USER must not be root / uid 0.
    last_user = user_lines[-1].split()[1]
    assert last_user.lower() not in ("root", "0"), f"container runs as {last_user}"


def test_dockerfile_exposes_a2a_port():
    src = _read(DOCKERFILE)
    expose = [
        ln.strip() for ln in src.splitlines() if ln.strip().upper().startswith("EXPOSE")
    ]
    assert expose, "Dockerfile must EXPOSE the A2A port"
    ports = {tok for ln in expose for tok in ln.split()[1:]}
    assert "9000" in ports, f"expected A2A port 9000 exposed, saw {ports}"


def test_dockerfile_has_cmd_or_entrypoint():
    src = _read(DOCKERFILE).upper()
    assert ("\nCMD " in "\n" + src or "\nCMD[" in "\n" + src or src.startswith("CMD ")
            or "\nENTRYPOINT" in "\n" + src), "Dockerfile needs a CMD or ENTRYPOINT"


def test_dockerfile_installs_requirements():
    src = _read(DOCKERFILE)
    assert "requirements.txt" in src, "Dockerfile must install requirements.txt"
    assert "pip install" in src, "Dockerfile must pip install the deps"


def test_dockerfile_no_hardcoded_secret_or_account():
    src = _read(DOCKERFILE)
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"hardcoded account id in Dockerfile: {m}"
    for pat in _SECRET_PATTERNS:
        assert pat not in src, f"possible hardcoded secret in Dockerfile: {pat}"


# --------------------------------------------------------------------------- #
# requirements.txt: present + PINNED                                           #
# --------------------------------------------------------------------------- #
def _requirement_lines() -> list[str]:
    out = []
    for raw in _read(REQUIREMENTS).splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out


def test_requirements_are_all_pinned():
    reqs = _requirement_lines()
    assert reqs, "requirements.txt has no requirements"
    for ln in reqs:
        # A pinned requirement uses == or ~= (exact or compatible-release pin).
        assert ("==" in ln or "~=" in ln), f"unpinned requirement: {ln!r}"


def test_requirements_list_the_specialist_stack():
    joined = "\n".join(_requirement_lines()).lower()
    # strands-agents with the a2a + litellm extras is the core of the specialist.
    assert "strands-agents" in joined, "missing strands-agents"
    assert "a2a" in joined and "litellm" in joined, "missing a2a/litellm extras"
    # An ASGI server is needed to actually serve the A2A + /ping surface.
    assert "uvicorn" in joined, "missing uvicorn ASGI server"
    # FastAPI hosts the /ping liveness endpoint.
    assert "fastapi" in joined, "missing fastapi"


def test_requirements_no_hardcoded_secret_or_account():
    src = _read(REQUIREMENTS)
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"hardcoded account id in requirements: {m}"


# --------------------------------------------------------------------------- #
# compose.yaml: valid YAML, env-driven model, no secrets                       #
# --------------------------------------------------------------------------- #
def _compose() -> dict:
    return yaml.safe_load(_read(COMPOSE))


def test_compose_is_valid_yaml_with_a_service():
    doc = _compose()
    assert isinstance(doc, dict), "compose.yaml must parse to a mapping"
    services = doc.get("services")
    assert isinstance(services, dict) and services, "compose.yaml needs services"
    assert "cve-intel" in services, "compose.yaml must define the cve-intel service"


def test_compose_model_id_is_env_driven():
    svc = _compose()["services"]["cve-intel"]
    env = svc.get("environment", {})
    # environment may be a dict or a list of KEY=VALUE strings; normalize to text.
    env_text = yaml.safe_dump(env)
    assert "SENTINEL_SPECIALIST_MODEL" in env_text, "model id must be configurable"
    # It must be sourced from a host env var (${...}), not a bare literal.
    assert "${SENTINEL_SPECIALIST_MODEL" in env_text, (
        "model id must be driven from the host env (${SENTINEL_SPECIALIST_MODEL...})"
    )
    # Regression guard (adversarial review 2026-07): the DEFAULT model id baked into
    # the ${VAR:-default} fallback MUST carry a full version suffix (-YYYYMMDD-vN:M).
    # A bare 'claude-haiku-4-5' is an invalid inference-profile id that reaches READY
    # but raises ValidationException on the first live invoke (see
    # sentinel_harness/core.py MODEL_HAIKU + test_agent_factory_scenario). Any Bedrock
    # model id present must be version-pinned so `docker compose up` cannot ship a
    # silently-broken default.
    import re

    for mid in re.findall(r"anthropic\.claude[a-z0-9.:\-]*", env_text):
        assert re.search(r"-\d{8}-v\d+:\d+$", mid), (
            f"specialist default model id {mid!r} is not version-pinned "
            "(needs a -YYYYMMDD-vN:M suffix, cf. core.py MODEL_HAIKU)"
        )


def test_compose_exposes_a2a_port():
    svc = _compose()["services"]["cve-intel"]
    ports = svc.get("ports", [])
    joined = " ".join(str(p) for p in ports)
    assert "9000" in joined, f"compose must publish the A2A port 9000, saw {ports}"


def test_compose_no_hardcoded_secret_or_account():
    src = _read(COMPOSE)
    for m in _ACCOUNT_ID_RE.findall(src):
        assert m == "000000000000", f"hardcoded account id in compose: {m}"
    for pat in _SECRET_PATTERNS:
        assert pat not in src, f"possible hardcoded secret in compose: {pat}"
    # Any AWS credential env keys present must be EMPTY / host-sourced, never a
    # literal value baked in.
    doc = _compose()
    env = doc["services"]["cve-intel"].get("environment", {})
    if isinstance(env, dict):
        for key in ("AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"):
            val = env.get(key)
            if val is None:
                continue
            # Allowed forms: "" or a ${VAR...} passthrough. No embedded literal.
            assert val == "" or val.startswith("${"), (
                f"{key} must be host-sourced, not a literal: {val!r}"
            )


# --------------------------------------------------------------------------- #
# Cross-check: the container CMD targets the real specialist entrypoint        #
# --------------------------------------------------------------------------- #
def test_cmd_matches_specialist_module_and_port():
    """The Dockerfile CMD/serve target and EXPOSE must line up with the module's
    own declared port + entrypoint, so the image actually boots what we test."""
    src = _read(DOCKERFILE)
    mod = _load_specialist()
    # agent_a2a is runnable as `python -m agent_a2a` (has __main__ serve()).
    assert "agent_a2a" in src, "CMD must launch the agent_a2a module"
    # The module's default port matches what the Dockerfile EXPOSEs.
    assert mod.DEFAULT_PORT == 9000
    assert mod.SPECIALIST_NAME == "cve-intel"
