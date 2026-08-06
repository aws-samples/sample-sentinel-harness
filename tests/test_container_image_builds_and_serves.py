"""INV-CONTAINER-1 — the specialist image really builds, and the built image really serves A2A.

`docs/FIDELITY-REPORT.md` claims `specialists/cve-intel/` "really `docker build`s (multi-stage,
pinned deps, non-root)". Nothing verified it. Measured:

* **CI never builds any image.** No `docker build`, no `docker/build-push-action`, no buildx in any
  of the six workflows.
* The two modules named after containers — `test_specialist_containers.py` and
  `test_cve_intel_container.py` — are pure TEXT analysis of the Dockerfile: base pinned, non-root
  declared, port exposed, CMD present. All useful, none of it executes a build. The latter's own
  docstring says an actual build "is attempted only in the *verify* step" — and there was no verify
  step anywhere in the repo.

So the strongest deployment claim the project makes rested on reading a Dockerfile, and the gap
mattered because of what the last few rounds did: INV-SUPPLY-1 upgraded `strands-agents`
1.9.1 -> 1.50.2 and `fastapi` 0.139.0 -> 0.141.1 to clear 19 advisories, and PR #64 moved
`bedrock-agentcore` -> 1.19.0, `mcp` -> 1.29.0, `uvicorn` -> 0.52.1. Every one of those was verified
by importing the packages in a scratch venv (`uv run --with`), which proves the API surface survives
and says NOTHING about whether the arm64 image still builds or boots. A break there surfaces at
deploy time.

Measured now, on a real arm64 build (Docker 29.4.0, daemon up):

    docker build --platform linux/arm64        rc=0
    versions inside the image                  bedrock-agentcore 1.19.0 · strands-agents 1.50.2
                                               mcp 1.29.0 · fastapi 0.141.1 · uvicorn 0.52.1
                                               litellm 1.91.1 · starlette 1.4.1
    import agent_a2a                           OK (agent_card/build_agent/build_app/serve present)
    docker run + 20s                           Up (healthy)
    GET /ping                                  HTTP 200 {"status":"healthy","agent":"cve-intel"}
    GET /.well-known/agent-card.json           HTTP 200, real card
    id inside the container                    uid=10001(specialist) — matches the Dockerfile

A good result, and entirely undefended. That is the finding: not that the image is broken, but that
nothing would notice when it breaks. The transitive-dependency upgrades this repo now takes weekly
(Dependabot covers the container manifests since INV-SUPPLY-1) are exactly the change class that
breaks an image build while every offline test stays green.

Why this is env-gated, and why a skip here is honest
---------------------------------------------------
A build takes minutes, needs a Docker daemon, and pulls from the network — it cannot be part of a
hermetic suite that must run on a machine with no docker at all. So it follows the pattern already
in force for expensive/live checks (`SENTINEL_SMOKE_LIVE`, `SENTINEL_TOKEN_METRIC_LIVE`,
`SENTINEL_VERIFY_ACTION_PINS`): opt in with `SENTINEL_CONTAINER_BUILD=1`.

The skip is honest rather than a hidden no-op, and the difference is asserted:

* the skip reason states exactly what is NOT verified, so "green" never reads as "the image builds"
* `test_the_static_guards_do_not_claim_to_build` keeps the sibling modules' docstrings truthful
  about being text analysis — INV-CI-1/INV-DOC-5's rule that a check which no-ops must not look
  like a check that passed, applied to documentation of coverage
* when the gate IS on, a missing daemon is a FAILURE, not a skip: opting in and silently doing
  nothing is the worst of both

Run it with:

    SENTINEL_CONTAINER_BUILD=1 uv run pytest tests/test_container_image_builds_and_serves.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from repo_infra import require_git_checkout

require_git_checkout("the container build guard (it builds specialists/ from the repository)")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALIST = "cve-intel"
SPECIALIST_DIR = os.path.join(REPO_ROOT, "specialists", SPECIALIST)
IMAGE_TAG = "sentinel-cve-intel:pytest-inv-container-1"

_GATE = "SENTINEL_CONTAINER_BUILD"
_ENABLED = os.environ.get(_GATE) == "1"

_SKIP_REASON = (
    f"container build/serve verification is opt-in: set {_GATE}=1 with a running Docker daemon. "
    "SKIPPED != PASSED — what this skip leaves unverified is that the arm64 image BUILDS, that the "
    "versions inside it match requirements.txt, and that the built image SERVES /ping and the A2A "
    "agent card. The sibling modules (test_specialist_containers.py, test_cve_intel_container.py) "
    "only analyse the Dockerfile as text and cannot cover any of that. Run before a release, and "
    "after any container dependency bump."
)

# The pins whose presence inside the IMAGE is checked. Read from requirements.txt rather than
# hard-coded: a second copy of the version list is the drift shape this repo records most
# (INV-SUPPLY-1 removed one such copy from ci.yml). Only packages pinned with `==` are comparable.
_TRANSITIVE_OF_INTEREST = ("litellm", "starlette")


def _pinned_requirements() -> dict:
    """{package: version} for every `name==version` line in the specialist's requirements.txt."""
    pins = {}
    path = os.path.join(SPECIALIST_DIR, "requirements.txt")
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if "==" not in line:
                continue
            name, _, version = line.partition("==")
            # Strip extras: `uvicorn[standard]` -> `uvicorn`, `strands-agents[a2a,litellm]` -> ...
            pins[name.split("[", 1)[0].strip().lower()] = version.strip()
    return pins


def _docker() -> str:
    """The docker binary, or fail when the gate is on.

    Deliberately a FAILURE rather than a skip: the caller asked for this verification by setting
    the env var, and quietly doing nothing in response to an explicit request is the silent no-op
    INV-CI-1 / INV-DOC-5 record.
    """
    binary = shutil.which("docker")
    if binary is None:
        pytest.fail(
            f"{_GATE}=1 was set but `docker` is not on PATH. Refusing to skip: an explicit request "
            "to verify the image must not silently verify nothing."
        )
    probe = subprocess.run([binary, "info"], capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.fail(
            f"{_GATE}=1 was set but the Docker daemon is not reachable "
            f"(`docker info` exited {probe.returncode}):\n{probe.stderr[-500:]}"
        )
    return binary


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _get(url: str, timeout: float = 10.0):
    """(status, body) for a GET, or (None, error-text)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - localhost
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        return None, str(exc)


@pytest.fixture(scope="module")
def built_image():
    """Build the arm64 image once for the module. Yields the tag."""
    docker = _docker()
    build = subprocess.run(
        [docker, "build", "--platform", "linux/arm64", "-t", IMAGE_TAG, "."],
        cwd=SPECIALIST_DIR, capture_output=True, text=True, timeout=2400,
    )
    if build.returncode != 0:
        pytest.fail(
            f"`docker build --platform linux/arm64` FAILED for specialists/{SPECIALIST} "
            f"(rc={build.returncode}).\n\n"
            "This is the claim docs/FIDELITY-REPORT.md makes and the one no offline test can "
            "check. A dependency bump that resolves in a venv can still break the image build "
            f"(pinned base, arm64 wheels, build toolchain).\n\nLast 3000 chars of the build log:\n"
            f"{(build.stdout + build.stderr)[-3000:]}"
        )
    yield IMAGE_TAG
    subprocess.run([docker, "rmi", "-f", IMAGE_TAG], capture_output=True, timeout=300)


@pytest.fixture(scope="module")
def running_container(built_image):
    """Run the built image and yield (container_id, base_url). Always torn down."""
    docker = _docker()
    port = _free_port()
    run = subprocess.run(
        [docker, "run", "-d", "--platform", "linux/arm64",
         "-p", f"127.0.0.1:{port}:9000",
         # Placeholder creds only. The A2A surface must come up without real AWS access; a
         # container that needs credentials just to serve /ping is not deployable.
         "-e", "AWS_DEFAULT_REGION=us-east-1",
         "-e", "AWS_ACCESS_KEY_ID=testing",
         "-e", "AWS_SECRET_ACCESS_KEY=testing",
         built_image],
        capture_output=True, text=True, timeout=300,
    )
    assert run.returncode == 0, f"docker run failed:\n{run.stderr[-1500:]}"
    container_id = run.stdout.strip()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 120
    last = ""
    while time.time() < deadline:
        status, body = _get(f"{base_url}/ping", timeout=5)
        if status == 200:
            break
        last = f"{status} {body[:200]}"
        time.sleep(2)
    else:
        logs = subprocess.run([docker, "logs", container_id],
                              capture_output=True, text=True, timeout=60)
        subprocess.run([docker, "rm", "-f", container_id], capture_output=True, timeout=120)
        pytest.fail(
            f"the built image never served /ping within 120s (last: {last}). The image builds but "
            f"does not come up, which no static Dockerfile check can detect.\n\n"
            f"Container logs:\n{(logs.stdout + logs.stderr)[-3000:]}"
        )

    yield container_id, base_url
    subprocess.run([docker, "rm", "-f", container_id], capture_output=True, timeout=120)


# --------------------------------------------------------------------------- #
# Gate-independent: keep the sibling modules honest about what they cover      #
# --------------------------------------------------------------------------- #
def test_the_static_guards_do_not_claim_to_build():
    """Runs ALWAYS — it is the part that needs no docker.

    `test_cve_intel_container.py`'s docstring said an actual build "is attempted only in the
    *verify* step", and no such step existed anywhere: not in CI, not in a script, not in the
    Makefile. A module describing coverage that does not exist is how a reader concludes the image
    is verified when only its Dockerfile was read.

    Now that the verify step exists, the claim must NAME it, so the sentence stays checkable.
    """
    sibling = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "test_cve_intel_container.py")
    with open(sibling, encoding="utf-8") as fh:
        text = fh.read()

    if "verify" not in text.lower():
        return  # it no longer claims anything about a verify step; nothing to keep honest

    assert _GATE in text, (
        f"test_cve_intel_container.py refers to a 'verify' step that performs the real build, but "
        f"does not name `{_GATE}` — the gate that actually runs it. When that step did not exist "
        "the reference pointed at nothing, and a reader takes 'verified elsewhere' at face value. "
        f"Point at `{_GATE}=1` (see tests/test_container_image_builds_and_serves.py)."
    )


# --------------------------------------------------------------------------- #
# Gated: the real build + the real server                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_arm64_image_builds(built_image):
    """The claim docs/FIDELITY-REPORT.md makes, executed.

    AgentCore Runtime runs arm64 microVMs, so the build is platform-explicit: an image that only
    builds for the host's x86 would be unbootable there, and the Dockerfile's own comment says so.
    """
    assert built_image == IMAGE_TAG


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_image_contains_exactly_the_pinned_versions(built_image):
    """What is INSIDE the image must match requirements.txt — and the transitive packages that were
    the point of the last upgrade must be present.

    **What this can and cannot catch, measured rather than assumed.** Mutation testing tried
    "declare `uvicorn==0.50.2` while the image has 0.52.1" and it SURVIVED. Investigating instead of
    patching the test: editing requirements.txt busts the `COPY requirements.txt` layer, so the image
    is rebuilt and installs exactly the edited pin — `declared == installed` again. The two cannot
    diverge that way, because the file is the build input.

    So the direct-pin half catches the cases where the build does NOT faithfully reflect the file:

      * pip resolved something other than the pin (a conflicting constraint, a yanked release)
      * a stale layer cache produced an image that predates the current requirements.txt
      * a package silently vanished from the environment

    The load-bearing half is the TRANSITIVE check below. INV-SUPPLY-1's 19 advisories were all in
    `litellm` (12) and `starlette` (7), and neither appears as a line in any requirements.txt —
    they arrive through `strands-agents[a2a,litellm]` and `fastapi`. Nothing else in the suite looks
    at them at all, and an extra that stops resolving (a rename, a dropped optional dependency)
    leaves every pin satisfied while the A2A or LiteLLM path is missing from the shipped artifact.
    """
    docker = _docker()
    pins = _pinned_requirements()
    assert pins, "no `==` pins parsed from requirements.txt — this check would verify nothing"

    wanted = sorted(set(pins) | set(_TRANSITIVE_OF_INTEREST))
    script = (
        "from importlib.metadata import version, PackageNotFoundError\n"
        "import json\n"
        f"names = {wanted!r}\n"
        "out = {}\n"
        "for n in names:\n"
        "    try: out[n] = version(n)\n"
        "    except PackageNotFoundError: out[n] = None\n"
        "print(json.dumps(out))\n"
    )
    probe = subprocess.run(
        [docker, "run", "--rm", "--platform", "linux/arm64", "--entrypoint", "python",
         built_image, "-c", script],
        capture_output=True, text=True, timeout=600,
    )
    assert probe.returncode == 0, f"version probe failed inside the image:\n{probe.stderr[-1500:]}"
    installed = json.loads(probe.stdout.strip().splitlines()[-1])

    mismatched = {
        name: (declared, installed.get(name))
        for name, declared in pins.items()
        if installed.get(name) != declared
    }
    assert not mismatched, (
        "the built image does not carry the versions requirements.txt pins "
        "(declared, installed):\n  "
        + "\n  ".join(f"{n}: {d} != {i}" for n, (d, i) in sorted(mismatched.items()))
        + "\n\nA pin the image does not honour means the audited dependency set is not the "
        "deployed one — pip resolved something else, or the build cached a stale layer."
    )

    # The transitive packages must be PRESENT (their absence would mean the extras stopped
    # resolving), and at or above the versions that cleared INV-SUPPLY-1's advisories.
    for name in _TRANSITIVE_OF_INTEREST:
        got = installed.get(name)
        assert got is not None, (
            f"{name} is not installed in the image. It arrives transitively via "
            "`strands-agents[a2a,litellm]` / `fastapi`; its absence means an extra stopped "
            "resolving and the A2A or LiteLLM path is broken in the shipped artifact."
        )
        major = int(got.split(".")[0])
        assert major >= 1, f"{name} {got} looks older than the 1.x that cleared the advisories"


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_specialist_module_imports_inside_the_image(built_image):
    """`CMD ["python","-m","agent_a2a"]` is only as good as that module importing in the image.

    Checked separately from the server test because the failure modes differ: an import error is a
    packaging problem (a missing dep, a wrong PATH, code not copied), while a start-up failure is a
    runtime/config problem. Conflating them makes a red result harder to act on.
    """
    docker = _docker()
    script = (
        "import agent_a2a as m, json\n"
        "print(json.dumps({f: hasattr(m, f) for f in "
        "('agent_card','build_agent','build_app','serve')}))\n"
    )
    probe = subprocess.run(
        [docker, "run", "--rm", "--platform", "linux/arm64", "--entrypoint", "python",
         built_image, "-c", script],
        capture_output=True, text=True, timeout=600,
    )
    assert probe.returncode == 0, (
        "`import agent_a2a` FAILED inside the built image, so the container's CMD cannot start:\n"
        f"{probe.stderr[-2000:]}"
    )
    surface = json.loads(probe.stdout.strip().splitlines()[-1])
    missing = sorted(name for name, present in surface.items() if not present)
    assert not missing, (
        f"agent_a2a imports in the image but is missing {missing}. `serve` is what CMD invokes; "
        "`agent_card` / `build_app` are the A2A discovery and health surface."
    )


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_running_container_reports_healthy(running_container):
    """The built image, started, answering the endpoint AgentCore polls.

    Also asserts the container reached Docker's own `healthy` state, which exercises the
    Dockerfile's HEALTHCHECK — a directive `test_specialist_containers.py` can only confirm is
    PRESENT, never that it works. (A HEALTHCHECK with a typo'd command marks a fine container
    unhealthy and AgentCore would recycle it forever.)
    """
    container_id, base_url = running_container
    docker = _docker()

    status, body = _get(f"{base_url}/ping")
    assert status == 200, f"/ping returned {status}: {body[:400]}"
    payload = json.loads(body)
    assert payload.get("status") == "healthy", f"/ping body is not healthy: {payload}"
    assert payload.get("agent") == SPECIALIST, (
        f"/ping reports agent={payload.get('agent')!r}, expected {SPECIALIST!r} — the image may "
        "have been built from the wrong specialist directory"
    )

    inspect = subprocess.run(
        [docker, "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
         container_id],
        capture_output=True, text=True, timeout=120,
    )
    health = inspect.stdout.strip()
    assert health in {"healthy", "starting"}, (
        f"Docker reports health={health!r}. The Dockerfile declares a HEALTHCHECK; if it is "
        "unhealthy while /ping answers 200, the healthcheck COMMAND is wrong — and AgentCore, "
        "which polls it, would recycle a working container indefinitely."
    )


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_running_container_serves_the_a2a_agent_card(running_container):
    """A2A discovery, from the real artifact.

    `test_specialist_a2a_contract.py` already covers the protocol IN-PROCESS, which is the right
    place for protocol semantics. This adds the one thing an in-process test structurally cannot:
    that the card is reachable over HTTP from the shipped image, through the real A2AServer wiring
    on the real port.
    """
    _, base_url = running_container
    status, body = _get(f"{base_url}/.well-known/agent-card.json")
    assert status == 200, (
        f"the A2A agent card endpoint returned {status}. A2A clients discover a specialist here; "
        f"without it the agent is unreachable regardless of /ping.\nBody: {body[:400]}"
    )
    card = json.loads(body)
    for field in ("name", "description", "capabilities"):
        assert field in card, f"the served agent card lacks {field!r}: {sorted(card)}"


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_container_runs_as_the_declared_non_root_user(running_container):
    """`test_specialist_containers.py` asserts the Dockerfile DECLARES a non-root USER. This
    asserts the running container actually is one.

    The two can differ: a later `USER root`, an entrypoint that re-escalates, or a base image
    change would leave the declaration in place and the process privileged. Defence-in-depth that
    is only declared is not defence.
    """
    container_id, _ = running_container
    docker = _docker()
    probe = subprocess.run([docker, "exec", container_id, "id", "-u"],
                           capture_output=True, text=True, timeout=120)
    assert probe.returncode == 0, f"`id -u` failed in the container:\n{probe.stderr[-500:]}"
    uid = probe.stdout.strip()
    assert uid != "0", (
        "the container is running as ROOT despite the Dockerfile declaring a non-root USER. "
        "Something re-escalated after the USER directive."
    )
    with open(os.path.join(SPECIALIST_DIR, "Dockerfile"), encoding="utf-8") as fh:
        dockerfile = fh.read()
    if "--uid 10001" in dockerfile or "--uid=10001" in dockerfile:
        assert uid == "10001", (
            f"the Dockerfile creates uid 10001 but the process runs as uid {uid} — the USER "
            "directive and the useradd call disagree."
        )
