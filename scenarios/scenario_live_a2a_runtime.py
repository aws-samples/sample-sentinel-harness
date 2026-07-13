"""
Scenario — LIVE A2A specialist on AgentCore **Runtime**, offline by default
===========================================================================
Layer 3 (foundation) · the repeatable, gated form of the crown-jewel manual proof
captured in ``evidence/live_a2a_runtime_result.json``.

.. warning::
   **The DEFAULT run is 100% OFFLINE and MOCK.** Without ``SENTINEL_A2A_LIVE=1`` it
   injects a *fake* ``bedrock-agentcore-control`` + ``bedrock-agentcore`` (data)
   client and walks the SAME lifecycle steps deterministically — ZERO AWS, ZERO
   network, ZERO compute billed. The ``SENTINEL_A2A_LIVE=1`` path (see
   :func:`run_live`, mirrors the ``SENTINEL_SMOKE_LIVE`` opt-in) drives the REAL
   AgentCore Runtime control + data planes and is NEVER exercised by the test suite.

WHY this scenario exists
------------------------
The manual proof (a real ``CreateAgentRuntime`` → ``linux/arm64`` microVM →
live A2A ``message/send`` → real Bedrock model → teardown) was a **one-off** — run
by hand, captured once. This scenario turns that walk into a *repeatable, gated*
artifact: the exact same step sequence is provable offline on every CI run against
a faithful fake, and a single documented env flag re-runs it against the real API
with a guaranteed teardown. Reproducible, not one-off.

The lifecycle walk (identical offline and live)
-----------------------------------------------
1. ``CreateAgentRuntime`` from an **ECR image** (``SENTINEL_A2A_RUNTIME_IMAGE``),
   ``protocolConfiguration.serverProtocol=A2A``, ``networkConfiguration.networkMode
   =PUBLIC`` → an ``agentRuntimeArn`` + id, initial ``status`` (CREATING).
2. Poll ``GetAgentRuntime`` until ``status == READY`` (bounded; the offline fake
   transitions CREATING → READY deterministically, no real clock).
3. ``InvokeAgentRuntime`` with an A2A JSON-RPC ``message/send`` payload → the
   response envelope carries an HTTP ``statusCode`` and the A2A JSON-RPC body.
4. ASSERT HTTP **200** AND a JSON-RPC ``result`` (never an ``error``) — the
   specialist answered over A2A on managed compute.
5. **ALWAYS** ``DeleteAgentRuntime`` in a ``finally`` — teardown is unconditional so
   a live run NEVER leaks a billed microVM, even if the invoke raises.

What is real vs. mocked
-----------------------
- The DEFAULT run injects two stateful FAKE clients that mirror the real service's
  shapes (create → CREATING; get → READY; invoke → ``statusCode`` + A2A body;
  delete → ok). It records **clearly mock-labeled** evidence to
  ``evidence/live_a2a_runtime_mock_result.json`` (a distinct file so the real
  one-off capture in ``evidence/live_a2a_runtime_result.json`` is never clobbered).
- HONESTY: the offline run proves the request/parse/teardown *contract* against a
  mock — it does NOT prove a real backend. The real end-to-end proof lives in
  ``evidence/live_a2a_runtime_result.json`` (a genuine on-account capture). Set
  ``SENTINEL_A2A_LIVE=1`` (with AWS creds + a pushed ECR image) to reproduce it.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. The default path has zero network I/O — the clients are
  fake objects; no boto3 call leaves the process.
- No secrets, no hardcoded account ids/ARNs. The fake mints ARNs against the
  ``000000000000`` placeholder account, and the evidence writer scrubs any 12-digit
  account id in an ARN down to ``000000000000`` before writing.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
from typing import Any, Callable, Dict, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Placeholder account for the FAKE-minted ARNs (scrubbed again before write).
_PLACEHOLDER_ACCT = "000000000000"
_REGION = os.environ.get("SENTINEL_REGION", "us-east-1")

# The A2A message the specialist is asked to answer (deterministic, offline-safe).
_A2A_PROMPT = "Enrich CVE-2021-44228 (Log4Shell) and return a structured verdict."
# Deterministic ids so the offline walk is byte-reproducible (no uuid/clock).
_MESSAGE_ID = "a2a00000000000000000000000000msg1"
_SESSION_ID = "sentinel-a2a-runtime-session-000000000001"  # >=33 chars (API min)

# Default ECR image ref for the offline walk. A real run overrides this with a
# pushed image via SENTINEL_A2A_RUNTIME_IMAGE. Placeholder account, no real digest.
_DEFAULT_IMAGE = (
    f"{_PLACEHOLDER_ACCT}.dkr.ecr.{_REGION}.amazonaws.com/sentinel/cve-intel:offline-mock"
)

RESULT: Dict[str, Any] = {"scenario": "live_a2a_runtime", "steps": []}

# Account-id scrubber — masks the 12-digit account id inside any ARN or ECR ref to
# the 000000000000 placeholder before evidence is written (public-repo policy).
_ACCT_RE = re.compile(r"(arn:aws[^:]*:[^:]*:[^:]*:)\d{12}(:)")
_ECR_RE = re.compile(r"\b\d{12}(\.dkr\.ecr\.)")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        s = _ACCT_RE.sub(rf"\g<1>{_PLACEHOLDER_ACCT}\g<2>", obj)
        return _ECR_RE.sub(rf"{_PLACEHOLDER_ACCT}\g<1>", s)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def rec(step: str, ok: bool, data: Any) -> None:
    data = _scrub(json.loads(json.dumps(data, default=str)))
    RESULT["steps"].append({"step": step, "ok": ok, "data": data})
    print(f"[{'OK' if ok else '..'}] {step}: "
          f"{json.dumps(data, ensure_ascii=False, default=str)[:240]}", flush=True)


def _build_a2a_request() -> Dict[str, Any]:
    """The A2A JSON-RPC ``message/send`` envelope sent to the Runtime (deterministic)."""
    return {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": _A2A_PROMPT}],
                "messageId": _MESSAGE_ID,
                "kind": "message",
            }
        },
    }


# --------------------------------------------------------------------------
# The FAKE clients — stateful stand-ins for the REAL AgentCore Runtime planes.
#
# FakeControlClient mirrors bedrock-agentcore-control Runtime ops:
#   * create_agent_runtime(...) -> agentRuntimeArn/id, status=CREATING
#   * get_agent_runtime(id)     -> status flips CREATING -> READY (deterministic)
#   * delete_agent_runtime(id)  -> status=DELETING (records the teardown)
# FakeDataClient mirrors bedrock-agentcore (data) InvokeAgentRuntime:
#   * invoke_agent_runtime(...) -> {statusCode: 200, response: <A2A JSON-RPC body>}
#     unless armed to raise (proves teardown still runs when invoke fails).
#
# Both are strict: an unexpected attribute access raises so a wrong code path is
# loud, never a silent no-op. These are the ONLY things injected offline; boto3 is
# never touched.
# --------------------------------------------------------------------------
class _StreamingBody:
    """Minimal StreamingBody stand-in: ``.read()`` yields the response bytes once."""

    def __init__(self, payload: bytes) -> None:
        self._buf = io.BytesIO(payload)

    def read(self, *args: Any) -> bytes:
        return self._buf.read(*args)


class FakeControlClient:
    """Deterministic, in-memory AgentCore Runtime control plane."""

    def __init__(self, ready_after: int = 1) -> None:
        self._runtimes: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._ready_after = ready_after  # GetAgentRuntime polls before READY
        self.calls: list[str] = []

    def _next_id(self, name: str) -> str:
        self._seq += 1
        return f"{name}-{self._seq:04d}fakeRUNTIME0"  # opaque, deterministic

    def create_agent_runtime(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append("create_agent_runtime")
        name = kwargs["agentRuntimeName"]
        # Assert the caller wired the A2A + PUBLIC + container contract we promise.
        proto = kwargs.get("protocolConfiguration", {}).get("serverProtocol")
        net = kwargs.get("networkConfiguration", {}).get("networkMode")
        image = (kwargs.get("agentRuntimeArtifact", {})
                 .get("containerConfiguration", {}).get("containerUri"))
        assert proto == "A2A", f"expected serverProtocol=A2A, got {proto!r}"
        assert net == "PUBLIC", f"expected networkMode=PUBLIC, got {net!r}"
        assert image, "containerConfiguration.containerUri (ECR image) is required"
        rid = self._next_id(name)
        arn = (f"arn:aws:bedrock-agentcore:{_REGION}:{_PLACEHOLDER_ACCT}:"
               f"runtime/{rid}")
        self._runtimes[rid] = {
            "agentRuntimeId": rid, "agentRuntimeArn": arn, "name": name,
            "status": "CREATING", "protocol": proto, "networkMode": net,
            "image": image, "_polls": 0,
        }
        return {
            "agentRuntimeArn": arn, "agentRuntimeId": rid,
            "agentRuntimeVersion": "1", "status": "CREATING",
        }

    def get_agent_runtime(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append("get_agent_runtime")
        rid = kwargs["agentRuntimeId"]
        rt = self._runtimes[rid]
        rt["_polls"] += 1
        if rt["_polls"] >= self._ready_after and rt["status"] == "CREATING":
            rt["status"] = "READY"
        return {
            "agentRuntimeArn": rt["agentRuntimeArn"], "agentRuntimeId": rid,
            "status": rt["status"], "agentRuntimeVersion": "1",
        }

    def delete_agent_runtime(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append("delete_agent_runtime")
        rid = kwargs["agentRuntimeId"]
        rt = self._runtimes.get(rid)
        if rt is not None:
            rt["status"] = "DELETING"
        return {"agentRuntimeId": rid, "status": "DELETING"}

    def __getattr__(self, item: str) -> Any:  # pragma: no cover - defensive
        raise AssertionError(
            f"live-a2a offline run must not touch control.{item}"
        )


class FakeDataClient:
    """Deterministic AgentCore data plane: InvokeAgentRuntime returns an A2A body.

    Set ``raise_on_invoke`` to make the invoke fail — used to prove the scenario
    still tears the Runtime down (delete in ``finally``) when the invoke raises.
    """

    def __init__(self, *, raise_on_invoke: bool = False) -> None:
        self.raise_on_invoke = raise_on_invoke
        self.calls: list[str] = []
        self.last_payload: Optional[Dict[str, Any]] = None

    def invoke_agent_runtime(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append("invoke_agent_runtime")
        if self.raise_on_invoke:
            raise RuntimeError("simulated invoke failure (teardown must still run)")
        # Parse the A2A request the caller sent and answer it deterministically,
        # mirroring the local_a2a server's ``_ok`` envelope shape.
        req = json.loads(kwargs["payload"])
        self.last_payload = req
        text = req["params"]["message"]["parts"][0]["text"]
        m = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        cve_id = m.group(0).upper() if m else None
        verdict = {
            "cve_id": cve_id,
            "cvss": None, "severity": None, "epss": None, "kev": None,
            "summary": (f"Deterministic offline echo for {cve_id} "
                        "(mock model; no tool grounding)."),
            "references": [], "grounded": False, "engine": "echo-mock",
        }
        body = {
            "jsonrpc": "2.0", "id": req.get("id"),
            "result": {
                "role": "agent",
                "parts": [
                    {"kind": "data", "data": verdict},
                    {"kind": "text", "text": verdict["summary"]},
                ],
                "kind": "message", "messageId": _MESSAGE_ID,
            },
        }
        return {
            "statusCode": 200,
            "contentType": "application/json",
            "response": _StreamingBody(json.dumps(body).encode("utf-8")),
        }

    def __getattr__(self, item: str) -> Any:  # pragma: no cover - defensive
        raise AssertionError(
            f"live-a2a offline run must not touch data.{item}"
        )


def _read_response_body(resp: Dict[str, Any]) -> Dict[str, Any]:
    """Read + JSON-parse the InvokeAgentRuntime ``response`` stream (bytes or str)."""
    body = resp["response"]
    raw = body.read() if hasattr(body, "read") else body
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw)


def run(
    control: Any = None,
    data: Any = None,
    *,
    image: Optional[str] = None,
    poll_max: int = 20,
    sleep_fn: Callable[[float], None] = lambda _s: None,
    live_note_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Walk the Runtime A2A lifecycle against injected clients (fake by default).

    ``control``/``data`` default to fresh FAKE clients (zero AWS). Teardown
    (``delete_agent_runtime``) ALWAYS runs in the ``finally`` — even if the invoke
    raises — and records a ``teardown_called`` flag. Returns the RESULT dict; on a
    walk error it still returns (closed=False) after tearing down, so a caller/test
    can assert the teardown happened.
    """
    control = control if control is not None else FakeControlClient()
    data = data if data is not None else FakeDataClient()
    image = image or os.environ.get("SENTINEL_A2A_RUNTIME_IMAGE") or _DEFAULT_IMAGE
    role_arn = (os.environ.get("SENTINEL_EXECUTION_ROLE_ARN")
                or f"arn:aws:iam::{_PLACEHOLDER_ACCT}:role/sentinel-runtime-exec")

    RESULT["mock"] = live_note_text is None
    if live_note_text is None:
        RESULT["mock_note"] = (
            "MOCK RUN — fake AgentCore control+data clients; ZERO AWS/network/compute. "
            "Proves the CreateAgentRuntime(A2A,PUBLIC)->READY->InvokeAgentRuntime("
            "message/send)->assert 200+jsonrpc->delete contract deterministically. "
            "The real one-off end-to-end capture is evidence/live_a2a_runtime_result.json."
        )
        rec("mode", True, {"mock": True, "note": RESULT["mock_note"]})
    else:
        RESULT["live_note"] = live_note_text

    runtime_id: Optional[str] = None
    teardown_called = False
    invoke_http_status: Optional[int] = None
    jsonrpc_ok = False
    walk_error: Optional[str] = None

    try:
        # --- Step 1: CreateAgentRuntime(A2A, PUBLIC) from an ECR image. ---
        created = control.create_agent_runtime(
            agentRuntimeName="sentinel_cve_intel_a2a",
            description="A2A CVE-intel specialist on managed AgentCore Runtime.",
            agentRuntimeArtifact={"containerConfiguration": {"containerUri": image}},
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            protocolConfiguration={"serverProtocol": "A2A"},
        )
        runtime_id = created["agentRuntimeId"]
        runtime_arn = created["agentRuntimeArn"]
        create_ok = (created.get("status") == "CREATING"
                     and runtime_arn.startswith("arn:aws:bedrock-agentcore:"))
        rec("create_agent_runtime", create_ok, {
            "agentRuntimeArn": runtime_arn, "status": created.get("status"),
            "protocol": "A2A", "networkMode": "PUBLIC", "image": image,
        })

        # --- Step 2: poll GetAgentRuntime until READY (bounded). ---
        status = created.get("status")
        polls = 0
        while status != "READY" and polls < poll_max:
            polls += 1
            sleep_fn(0)
            status = control.get_agent_runtime(
                agentRuntimeId=runtime_id
            ).get("status")
            if status in ("CREATE_FAILED", "DELETING", "DELETE_FAILED"):
                raise RuntimeError(f"runtime entered terminal status {status!r}")
        ready = status == "READY"
        rec("wait_ready", ready, {"status": status, "polls": polls})
        if not ready:
            raise RuntimeError(f"runtime not READY after {polls} polls (status={status!r})")

        # --- Step 3: InvokeAgentRuntime with an A2A message/send payload. ---
        a2a_request = _build_a2a_request()
        resp = data.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            runtimeSessionId=_SESSION_ID,
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(a2a_request).encode("utf-8"),
        )
        invoke_http_status = resp.get("statusCode")
        body = _read_response_body(resp)

        # --- Step 4: assert HTTP 200 AND a JSON-RPC result (not an error). ---
        jsonrpc_ok = (
            invoke_http_status == 200
            and body.get("jsonrpc") == "2.0"
            and "result" in body
            and "error" not in body
        )
        verdict = None
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, dict):
            for part in result.get("parts", []):
                if isinstance(part, dict) and part.get("kind") == "data":
                    verdict = part.get("data")
        rec("invoke_agent_runtime", jsonrpc_ok, {
            "http_status": invoke_http_status,
            "jsonrpc": body.get("jsonrpc"),
            "has_result": "result" in body,
            "has_error": "error" in body,
            "verdict_cve_id": (verdict or {}).get("cve_id"),
            "engine": (verdict or {}).get("engine"),
        })
    except Exception as exc:  # never swallow: record, then tear down in finally.
        walk_error = f"{type(exc).__name__}: {exc}"
        rec("walk_error", False, {"error": walk_error})
    finally:
        # --- Step 5: ALWAYS tear down — never leak a billed microVM. ---
        if runtime_id is not None:
            control.delete_agent_runtime(agentRuntimeId=runtime_id)
            teardown_called = True
            rec("teardown_delete_agent_runtime", True,
                {"deleted_runtime": runtime_id})
        else:
            rec("teardown_delete_agent_runtime", False,
                {"note": "no runtime created; nothing to delete"})

    closed = bool(
        walk_error is None
        and invoke_http_status == 200
        and jsonrpc_ok
        and teardown_called
    )
    flags = {
        "create_and_ready": walk_error is None and invoke_http_status == 200,
        "invoke_http_200": invoke_http_status == 200,
        "a2a_jsonrpc_ok": jsonrpc_ok,
        "teardown_called": teardown_called,
        "closed": closed,
    }
    RESULT["flags"] = flags
    RESULT["teardown_called"] = teardown_called
    RESULT["invoke_http_status"] = invoke_http_status
    RESULT["account"] = _PLACEHOLDER_ACCT
    if walk_error is not None:
        RESULT["walk_error"] = walk_error
    RESULT["verdict"] = {
        **flags,
        "note": (
            "Runtime A2A lifecycle: CreateAgentRuntime(protocol=A2A, network=PUBLIC) "
            "from an ECR image -> poll to READY -> InvokeAgentRuntime(A2A message/send) "
            "-> assert HTTP 200 + JSON-RPC result -> ALWAYS DeleteAgentRuntime (teardown). "
            + (RESULT.get("mock_note", "") if RESULT.get("mock")
               else "LIVE run against the real AgentCore Runtime planes.")
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


def run_offline() -> Dict[str, Any]:
    """DEFAULT run: drive the walk against fresh FAKE clients (zero AWS)."""
    return run()


def live_note() -> str:
    """Return what the live path does (real API), without running it."""
    return (
        "LIVE mode (SENTINEL_A2A_LIVE=1) drives the REAL AgentCore Runtime planes: "
        "CreateAgentRuntime(serverProtocol=A2A, networkMode=PUBLIC) from the ECR image "
        "in SENTINEL_A2A_RUNTIME_IMAGE -> poll GetAgentRuntime to READY -> "
        "InvokeAgentRuntime with an A2A message/send payload -> assert HTTP 200 + "
        "JSON-RPC result -> ALWAYS DeleteAgentRuntime (teardown, never leak compute). "
        "Needs AWS credentials + SENTINEL_EXECUTION_ROLE_ARN + a pushed ECR image; it "
        "is NEVER run by the test suite. The offline default proves the same contract "
        "deterministically; the real one-off capture is evidence/live_a2a_runtime_result.json."
    )


def run_live() -> Dict[str, Any]:  # pragma: no cover - opt-in, real AWS, never in CI
    """Drive the walk against the REAL Runtime planes, then tear down.

    Guarded: only reached when ``SENTINEL_A2A_LIVE=1`` on an explicit human
    invocation with AWS credentials + a pushed ECR image. The test suite never sets
    the flag. Teardown is unconditional (delete in the ``run`` ``finally``)."""
    from sentinel_harness import core  # local import: avoids boto3 client build offline

    image = os.environ.get("SENTINEL_A2A_RUNTIME_IMAGE")
    if not image:
        raise SystemExit(
            "SENTINEL_A2A_LIVE=1 requires SENTINEL_A2A_RUNTIME_IMAGE=<ecr-image-uri>"
        )
    import time
    return run(
        core._control, core._data,
        image=image, sleep_fn=time.sleep, live_note_text=live_note(),
    )


def _is_live() -> bool:
    return os.environ.get("SENTINEL_A2A_LIVE") == "1"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live", action="store_true",
        help="drive the REAL AgentCore Runtime planes (also enabled by "
             "SENTINEL_A2A_LIVE=1; needs AWS creds + a pushed ECR image; NEVER in "
             "tests). Default is the offline fake-client walk.")
    args = parser.parse_args()

    if args.live or _is_live():
        print(live_note())
        run_live()
        out_name = "live_a2a_runtime_result.json"
    else:
        run_offline()
        out_name = "live_a2a_runtime_mock_result.json"

    out = os.path.join(REPO_ROOT, "evidence", out_name)
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print(f"\nsaved evidence/{out_name}  ·  verdict:",
          json.dumps(RESULT.get("verdict") or RESULT.get("flags"), ensure_ascii=False))
