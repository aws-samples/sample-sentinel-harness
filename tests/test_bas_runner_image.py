"""INV-CONTAINER-2 — the bas-runner image builds AND its entrypoint actually starts.

`longrunning/bas-runner/` is the fifth deployable image in this repo and the only one nothing
guarded. INV-CONTAINER-1 covered `specialists/cve-intel/`; `test_specialist_containers.py` covers
three specialists as text. bas-runner had **no test reading its Dockerfile or its requirements at
all**, and `docs/BLUEPRINT.md` names it in four places as the long-running BAS Runtime.

Four defects were found, all measured before being fixed.

**1. The container could not start.** `docker build` succeeded, and then:

    docker run … python -c "import bedrock_entrypoint"
    -> ModuleNotFoundError: No module named 'sentinel_harness'

`bedrock_entrypoint.py:46` does an UNGUARDED top-level `from sentinel_harness import core` —
unlike its `bedrock_agentcore` import three lines below, which is `try/except ImportError`-guarded.
`sentinel-harness` was **commented out** in requirements.txt under a note saying it is "listed here
so the intent is explicit", and the Dockerfile never installed it either. So `CMD ["python",
"bedrock_entrypoint.py"]` — the image's entire purpose — died immediately. Intent in a comment is
not a build step.

What hid it: the README's own "offline sanity" check is `python -c "import bedrock_entrypoint"` run
**from the repo root**, where `sentinel_harness` is importable from the working tree. The check
passed on a maintainer's laptop and could never have failed there.

**2. The build was not reproducible.** `bedrock-agentcore>=1.19.0` / `boto3>=1.43.62`, with a
comment conceding "pinned loosely; pin exact for a release" — and the project has shipped v0.5.1,
so that TODO had expired. Measured: the range resolved to **bedrock-agentcore 1.21.0**, two minors
above the `==1.19.0` every specialist pins, and the built image really contained 1.21.0. A rebuild
tomorrow could contain something else. For an adversary-emulation workload whose output is forensic
evidence, "which version produced this" has to be answerable from the repo.

**3. Nothing verified the image at all** — not the Dockerfile as text, not the build, not the start.

**4. It diverged from the specialists silently.** No guard compared the two, so bas-runner drifting
to a different `bedrock-agentcore` than the four specialists produced no signal.

Fixed by pinning `==1.21.0` / `==1.43.65` (recording what the range already resolved to and what the
image was verified against, rather than rolling anything back — the API surface this runner uses was
checked present at BOTH 1.19.0 and 1.21.0 first) and by installing `sentinel-harness==0.5.1`.
Verified after the fix:

    docker build --platform linux/arm64   rc=0
    import bedrock_entrypoint            OK · _HAS_AGENTCORE=True · app is not None
    versions in the image                bedrock-agentcore 1.21.0 · boto3 1.43.65
                                         sentinel-harness 0.5.1
    docker run + 15s                     Up
    GET /ping                            HTTP 200 {"status":"Healthy","time_of_last_update":…}

Why this is a SEPARATE module from INV-CONTAINER-1's
----------------------------------------------------
bas-runner's contract genuinely differs from a specialist's: port **8080** not 9000 (the AgentCore
Runtime HTTP contract, versus the A2A port), a different `/ping` body (`"Healthy"` with a timestamp,
versus `"healthy"` plus an agent name), **no** A2A agent card, **no** HEALTHCHECK directive, and
python 3.12 on a `public.ecr.aws` base rather than 3.13 on Docker Hub. Parametrising one module over
both would turn every assertion into an if/else — an abstraction hiding two contracts rather than
sharing one. (The four specialists ARE isomorphic — their Dockerfiles are byte-identical after
name normalisation — and that is where parametrisation belongs.)

Gated by `SENTINEL_CONTAINER_BUILD=1`, the same switch INV-CONTAINER-1 uses, so one opt-in covers
every image. The skip says what is unverified; with the gate ON a missing daemon is a FAILURE.

The text-level assertions run ALWAYS — they need no docker, and they are what makes a bas-runner
regression visible in the default suite.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from repo_infra import require_git_checkout

require_git_checkout("the bas-runner image guard (it builds longrunning/ from the repository)")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER_DIR = os.path.join(REPO_ROOT, "longrunning", "bas-runner")
SPECIALISTS_DIR = os.path.join(REPO_ROOT, "specialists")
IMAGE_TAG = "sentinel-bas-runner:pytest-inv-container-2"

# The AgentCore Runtime HTTP contract port — deliberately NOT the specialists' A2A 9000.
RUNTIME_PORT = 8080

_GATE = "SENTINEL_CONTAINER_BUILD"
_ENABLED = os.environ.get(_GATE) == "1"

_SKIP_REASON = (
    f"bas-runner image build/serve verification is opt-in: set {_GATE}=1 with a running Docker "
    "daemon. SKIPPED != PASSED — what this skip leaves unverified is that the arm64 image BUILDS, "
    "that `import bedrock_entrypoint` SUCCEEDS inside it (it did not: `sentinel-harness` was a "
    "commented-out requirement, so CMD died with ModuleNotFoundError), and that the container "
    "serves the AgentCore /ping contract on 8080. The text assertions in this module still run."
)

# The bedrock_agentcore API surface bedrock_entrypoint.py relies on. Checked present at both 1.19.0
# and 1.21.0 before the pin was chosen, so the pin is a recorded measurement, not a guess.
_REQUIRED_APP_ATTRS = ("entrypoint", "add_async_task", "complete_async_task", "run")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _pins(requirements_path: str) -> dict:
    """{package: version} for `name==version` lines, extras stripped."""
    pins = {}
    for raw in _read(requirements_path).splitlines():
        line = raw.split("#", 1)[0].strip()
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        pins[name.split("[", 1)[0].strip().lower()] = version.strip()
    return pins


def _requirement_names(requirements_path: str) -> list:
    """Every declared requirement name, however it is constrained."""
    names = []
    for raw in _read(requirements_path).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        names.append(re.split(r"[=<>!~\[]", line, maxsplit=1)[0].strip().lower())
    return names


def _docker() -> str:
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
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - localhost
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        return None, str(exc)


# --------------------------------------------------------------------------- #
# ALWAYS-ON: the text-level contract nothing checked                          #
# --------------------------------------------------------------------------- #
def test_the_packaging_files_exist():
    """Positive control. Every assertion below reads these; a moved directory would otherwise make
    the module vacuously green."""
    for name in ("Dockerfile", "requirements.txt", "bedrock_entrypoint.py", "runner_loop.py"):
        path = os.path.join(RUNNER_DIR, name)
        assert os.path.isfile(path), f"longrunning/bas-runner/{name} is missing"


def test_every_requirement_is_exactly_pinned():
    """The build must be reproducible, like the four specialists'.

    It was not: `bedrock-agentcore>=1.19.0` / `boto3>=1.43.62`, under a comment conceding "pin exact
    for a release" — while v0.5.1 had already shipped. Measured, the range resolved to
    bedrock-agentcore **1.21.0** (two minors above every specialist's `==1.19.0`) and the built
    image really contained it, so two rebuilds of one commit could ship different code.

    A `>=` here is not a style preference. This is the image that produces BAS evidence; if the
    version is decided by the build date, "which version produced this artifact" is unanswerable.
    """
    path = os.path.join(RUNNER_DIR, "requirements.txt")
    unpinned = []
    for raw in _read(path).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "==" not in line:
            unpinned.append(line)
    assert not unpinned, (
        f"longrunning/bas-runner/requirements.txt has unpinned requirement(s): {unpinned}. "
        "A range makes the image non-reproducible — measured, `bedrock-agentcore>=1.19.0` resolved "
        "to 1.21.0 while every specialist pins 1.19.0. Pin with `==` after verifying the API "
        "surface at the chosen version."
    )
    assert len(_pins(path)) >= 3, (
        f"only {len(_pins(path))} pinned requirement(s) parsed; this check would be near-vacuous"
    )


def test_sentinel_harness_is_installed_not_merely_mentioned():
    """The defect that made the container unstartable.

    `bedrock_entrypoint.py` opens with an UNGUARDED `from sentinel_harness import core` — unlike its
    `bedrock_agentcore` import, which is try/except-guarded on purpose. The requirement was
    COMMENTED OUT with a note that it is "listed here so the intent is explicit", and the Dockerfile
    did not install it either, so the image built and `CMD` died with `ModuleNotFoundError`.

    Checked as a real requirement line, not as a substring: a commented mention satisfies
    `"sentinel-harness" in text` while installing nothing, which is exactly how this survived.
    """
    path = os.path.join(RUNNER_DIR, "requirements.txt")
    entrypoint = _read(os.path.join(RUNNER_DIR, "bedrock_entrypoint.py"))

    # Confirm the premise: the import really is unguarded at module scope. If someone guards it
    # later, this requirement stops being mandatory and the reasoning here must be revisited
    # rather than silently kept.
    imports_at_top = re.search(r"^from sentinel_harness import", entrypoint, re.M) is not None
    if not imports_at_top:
        pytest.skip(
            "bedrock_entrypoint.py no longer imports sentinel_harness at module scope; the hard "
            "requirement may no longer apply. Re-derive this guard's premise before deleting it."
        )

    names = _requirement_names(path)
    assert "sentinel-harness" in names, (
        "longrunning/bas-runner/requirements.txt does not install `sentinel-harness`, but "
        "bedrock_entrypoint.py imports it UNGUARDED at module scope. The image will build and then "
        "`CMD [\"python\",\"bedrock_entrypoint.py\"]` will die with ModuleNotFoundError — verified "
        "inside the built image. A commented-out line stating the intent is not a build step.\n\n"
        f"Declared requirements: {names}"
    )


def test_the_runner_agrees_with_the_specialists_on_the_shared_sdk():
    """bas-runner and the specialists must pin the SAME `bedrock-agentcore`.

    They did not: specialists at `==1.19.0`, bas-runner's range resolving to 1.21.0. Both are on the
    same platform talking to the same control plane, and nothing compared them, so the divergence
    produced no signal at all.

    Deliberately asserted as EQUALITY rather than "both are pinned": two pinned-but-different
    versions is the drift this exists to catch, and it is the shape this repo records most.
    """
    runner_pins = _pins(os.path.join(RUNNER_DIR, "requirements.txt"))
    runner_version = runner_pins.get("bedrock-agentcore")
    assert runner_version, "bas-runner does not pin bedrock-agentcore with `==`"

    specialist_versions = {}
    for name in sorted(os.listdir(SPECIALISTS_DIR)):
        path = os.path.join(SPECIALISTS_DIR, name, "requirements.txt")
        if not os.path.isfile(path):
            continue
        got = _pins(path).get("bedrock-agentcore")
        if got:
            specialist_versions[name] = got
    assert specialist_versions, (
        "no specialist pins bedrock-agentcore — this comparison would verify nothing"
    )

    disagreeing = {n: v for n, v in specialist_versions.items() if v != runner_version}
    assert not disagreeing, (
        f"bas-runner pins bedrock-agentcore {runner_version} but specialist(s) pin something else: "
        f"{disagreeing}. Both run on AgentCore against the same control plane; a split SDK version "
        "means a bug reproduced in one is not necessarily the code running in the other. Bump them "
        "together — Dependabot groups them into one PR for this reason (INV-SUPPLY-1)."
    )


def test_the_dockerfile_targets_arm64_and_drops_privileges():
    """The structural contract, which no test read before.

    AgentCore Runtime is arm64; an image built only for the host's x86 is unbootable there. And a
    BAS workload runs adversary-emulation tooling, so a root container is the wrong default even
    inside a microVM.
    """
    dockerfile = _read(os.path.join(RUNNER_DIR, "Dockerfile"))
    assert "--platform=linux/arm64" in dockerfile, (
        "bas-runner's Dockerfile does not build for linux/arm64. AgentCore Runtime runs arm64 "
        "microVMs, so an x86-only image cannot boot there."
    )
    assert re.search(r"^\s*USER\s+(?!root\b)\S+", dockerfile, re.M), (
        "bas-runner's Dockerfile declares no non-root USER. This image runs adversary-emulation "
        "tooling; the microVM is the isolation boundary, and non-root is the defence in depth."
    )
    assert ":latest" not in dockerfile, "the base image must be tagged, never :latest"
    assert re.search(rf"^\s*EXPOSE\s+{RUNTIME_PORT}\b", dockerfile, re.M), (
        f"bas-runner must EXPOSE {RUNTIME_PORT} — the AgentCore Runtime HTTP contract port. (The "
        "specialists use 9000 for A2A; these are different contracts and must not be conflated.)"
    )


# --------------------------------------------------------------------------- #
# GATED: the real build, the real start                                       #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def built_image():
    docker = _docker()
    build = subprocess.run(
        [docker, "build", "--platform", "linux/arm64", "-t", IMAGE_TAG, "."],
        cwd=RUNNER_DIR, capture_output=True, text=True, timeout=2400,
    )
    if build.returncode != 0:
        pytest.fail(
            f"`docker build --platform linux/arm64` FAILED for longrunning/bas-runner "
            f"(rc={build.returncode}).\n\nLast 3000 chars:\n{(build.stdout + build.stderr)[-3000:]}"
        )
    yield IMAGE_TAG
    subprocess.run([docker, "rmi", "-f", IMAGE_TAG], capture_output=True, timeout=300)


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_image_builds(built_image):
    """Nothing had ever built this image."""
    assert built_image == IMAGE_TAG


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_entrypoint_imports_inside_the_image(built_image):
    """THE defect: this raised `ModuleNotFoundError: No module named 'sentinel_harness'`.

    `CMD ["python","bedrock_entrypoint.py"]` is the image's whole purpose, so an import failure here
    means the container cannot start at all — while `docker build` reports success.

    `_HAS_AGENTCORE` is asserted True as well: that flag is False when `bedrock_agentcore` is
    missing, and the module is written to stay importable in that state for offline tests. Inside
    the IMAGE, False would mean the pinned SDK did not install — a silent degradation to the
    no-Runtime path, which is precisely the "a guard that no-ops must not look like a guard that
    passed" shape.
    """
    docker = _docker()
    script = (
        "import json, bedrock_entrypoint as m\n"
        "print(json.dumps({'has_agentcore': bool(m._HAS_AGENTCORE),\n"
        "                  'app_present': m.app is not None}))\n"
    )
    probe = subprocess.run(
        [docker, "run", "--rm", "--platform", "linux/arm64", "--entrypoint", "python",
         built_image, "-c", script],
        capture_output=True, text=True, timeout=600,
    )
    assert probe.returncode == 0, (
        "`import bedrock_entrypoint` FAILED inside the built image, so the container's CMD cannot "
        f"start:\n{probe.stderr[-2000:]}"
    )
    state = json.loads(probe.stdout.strip().splitlines()[-1])
    assert state["has_agentcore"] is True, (
        "`_HAS_AGENTCORE` is False inside the image, so `bedrock_agentcore` did not install and the "
        "module fell back to its no-Runtime path. The container would come up unable to serve the "
        "AgentCore contract while importing cleanly."
    )
    assert state["app_present"] is True, (
        "`app` is None inside the image — `BedrockAgentCoreApp()` was not constructed, so there is "
        "no HTTP server for the Runtime to talk to."
    )


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_image_contains_the_pinned_versions(built_image):
    """What requirements.txt pins must be what the image has.

    Includes `sentinel-harness`, whose absence was the start-up failure — so this fails loudly if
    the install regresses to a comment again.
    """
    docker = _docker()
    pins = _pins(os.path.join(RUNNER_DIR, "requirements.txt"))
    assert pins, "no `==` pins parsed — this check would verify nothing"

    script = (
        "from importlib.metadata import version, PackageNotFoundError\n"
        "import json\n"
        f"names = {sorted(pins)!r}\n"
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
    assert probe.returncode == 0, f"version probe failed:\n{probe.stderr[-1500:]}"
    installed = json.loads(probe.stdout.strip().splitlines()[-1])

    wrong = {n: (v, installed.get(n)) for n, v in pins.items() if installed.get(n) != v}
    assert not wrong, (
        "the built image does not carry the pinned versions (declared, installed):\n  "
        + "\n  ".join(f"{n}: {d} != {i}" for n, (d, i) in sorted(wrong.items()))
    )


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_container_serves_the_agentcore_ping_contract(built_image):
    """The container starts and answers the endpoint AgentCore Runtime polls.

    Before the fix this could not be reached at all — the process exited on import. The response
    shape is checked loosely on purpose: `bedrock_agentcore` owns this handler (it returns
    `{"status": "Healthy", "time_of_last_update": …}`), so asserting its exact body would make this
    guard fail on an SDK cosmetic change. What matters is 200 plus a status field that says healthy.
    """
    docker = _docker()
    port = _free_port()
    run = subprocess.run(
        [docker, "run", "-d", "--platform", "linux/arm64",
         "-p", f"127.0.0.1:{port}:{RUNTIME_PORT}",
         "-e", "AWS_DEFAULT_REGION=us-east-1",
         "-e", "AWS_ACCESS_KEY_ID=testing",
         "-e", "AWS_SECRET_ACCESS_KEY=testing",
         built_image],
        capture_output=True, text=True, timeout=300,
    )
    assert run.returncode == 0, f"docker run failed:\n{run.stderr[-1500:]}"
    container_id = run.stdout.strip()

    try:
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 120
        status = body = None
        while time.time() < deadline:
            status, body = _get(f"{base_url}/ping", timeout=5)
            if status == 200:
                break
            time.sleep(2)
        else:
            logs = subprocess.run([docker, "logs", container_id],
                                  capture_output=True, text=True, timeout=60)
            pytest.fail(
                f"the container never served /ping on {RUNTIME_PORT} within 120s "
                f"(last: {status} {str(body)[:200]}). AgentCore Runtime polls this endpoint; "
                "without it the Runtime is considered unhealthy and recycled.\n\n"
                f"Logs:\n{(logs.stdout + logs.stderr)[-3000:]}"
            )

        payload = json.loads(body)
        healthy = str(payload.get("status", "")).lower()
        assert "healthy" in healthy, (
            f"/ping returned 200 but status={payload.get('status')!r}: {payload}"
        )

        # Non-root, in the running container rather than only declared in the Dockerfile.
        uid = subprocess.run([docker, "exec", container_id, "id", "-u"],
                             capture_output=True, text=True, timeout=120)
        assert uid.returncode == 0, f"`id -u` failed:\n{uid.stderr[-400:]}"
        assert uid.stdout.strip() != "0", (
            "the bas-runner container runs as ROOT despite the Dockerfile declaring a non-root "
            "USER — something re-escalated after the USER directive."
        )
    finally:
        subprocess.run([docker, "rm", "-f", container_id], capture_output=True, timeout=120)


@pytest.mark.skipif(not _ENABLED, reason=_SKIP_REASON)
def test_the_pinned_sdk_exposes_the_api_the_runner_uses(built_image):
    """The pin's PREMISE, asserted inside the image.

    `1.21.0` was chosen because the range already resolved to it and because these four attributes
    were verified present at both 1.19.0 and 1.21.0. Recording the measurement is not the same as
    keeping it true, so the surface is re-checked against the version that actually shipped — the
    INV-MCP-5 lesson that an import check is not a compatibility check.
    """
    docker = _docker()
    script = (
        "import json\n"
        "from bedrock_agentcore.runtime import BedrockAgentCoreApp\n"
        "app = BedrockAgentCoreApp()\n"
        f"print(json.dumps({{a: hasattr(app, a) for a in {list(_REQUIRED_APP_ATTRS)!r}}}))\n"
    )
    probe = subprocess.run(
        [docker, "run", "--rm", "--platform", "linux/arm64", "--entrypoint", "python",
         built_image, "-c", script],
        capture_output=True, text=True, timeout=600,
    )
    assert probe.returncode == 0, (
        f"could not construct BedrockAgentCoreApp inside the image:\n{probe.stderr[-1500:]}"
    )
    surface = json.loads(probe.stdout.strip().splitlines()[-1])
    missing = sorted(name for name, present in surface.items() if not present)
    assert not missing, (
        f"the pinned bedrock-agentcore is missing {missing}, which bedrock_entrypoint.py uses. "
        "The pin's premise has expired: re-verify the surface and either adjust the code or choose "
        "a version that still provides it."
    )
