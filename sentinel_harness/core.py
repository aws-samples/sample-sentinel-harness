"""
sentinel-harness · core library
================================
A thin, batteries-included wrapper over Amazon Bedrock AgentCore **Harness** for
building production security-operations (SecOps) agents as *configuration* rather
than orchestration code.

Design goals
------------
- Every SecOps *scenario* is a **harness** (declarative: model + system prompt +
  tools + skills + memory + limits). Zero orchestration code.
- **Multi-agent parallelism** = many harnesses + a supervisor that fans out and
  synthesizes (a single harness is single-agent + multi-tool by design).
- **Long-running tasks** (malware detonation, campaign hunts) = managed Memory +
  long sessions (up to the ~8h max lifetime).
- **Human-in-the-loop** (kill hallucination, mandatory analyst review) = an
  ``inline_function`` gate that pauses the loop and hands control back to you.
- **Egress control** = prefer a ``web_search``-style tool over raw download; the
  agent gets the text it needs, not arbitrary network reach.
- **Auth** = an IAM *execution role* governs which internal AWS resources the
  agent may touch (this is standard least-privilege, not per-person mapping);
  human callers use OAuth/JWT (``customJWTAuthorizer``); third-party secrets live
  in the AgentCore Identity token vault — the agent never sees raw credentials.

Configuration (no hardcoded account / role — 12-factor)
------------------------------------------------------
    export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<your-role>"
    export SENTINEL_REGION="us-east-1"            # optional, default us-east-1
    export AWS_PROFILE="<your-non-prod-profile>"  # never run against production

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations
import os, json, time, uuid
import boto3
from botocore.config import Config

REGION = os.environ.get("SENTINEL_REGION", "us-east-1")
EXECUTION_ROLE_ARN = os.environ.get("SENTINEL_EXECUTION_ROLE_ARN")  # required at runtime

_control = boto3.client("bedrock-agentcore-control", region_name=REGION)
_data = boto3.client(
    "bedrock-agentcore",
    region_name=REGION,
    config=Config(read_timeout=180, connect_timeout=15, retries={"max_attempts": 2}),
)

# --- Model IDs: use the cross-region-inference *pattern*; do not pin a version you
#     can't verify. Override via env if you want a specific pinned id. ---
MODEL_SONNET = os.environ.get("SENTINEL_MODEL_SONNET", "global.anthropic.claude-sonnet-4-6")
MODEL_HAIKU = os.environ.get("SENTINEL_MODEL_HAIKU", "global.anthropic.claude-haiku-4-5")
MODEL_OPUS = os.environ.get("SENTINEL_MODEL_OPUS", "us.anthropic.claude-opus-4-5-20251101-v1:0")


def _role() -> str:
    if not EXECUTION_ROLE_ARN:
        raise RuntimeError(
            "Set SENTINEL_EXECUTION_ROLE_ARN to your harness execution role ARN. "
            "See docs/SETUP.md for the least-privilege policy."
        )
    return EXECUTION_ROLE_ARN


# ---------------------------------------------------------------- model configs
def bedrock_model(model_id: str, **extra) -> dict:
    return {"bedrockModelConfig": {"modelId": model_id, **extra}}


# ---------------------------------------------------------------- sessions
def new_session(prefix: str = "sentinel") -> str:
    """runtimeSessionId must be >= 33 chars; a hyphenated UUID (36) is safe."""
    return f"{prefix}-{uuid.uuid4()}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------- harness lifecycle
def create_harness(name, system_prompt, *, model=None, tools=None, skills=None,
                   memory=None, allowed_tools=None, max_iterations=None,
                   max_tokens=None, timeout_seconds=None, **kw) -> dict:
    """Create a SecOps scenario harness.

    ``name`` must match ``[a-zA-Z][a-zA-Z0-9_]{0,39}`` (no hyphens).
    ``system_prompt`` is normalized to the GA list shape ``[{"text": ...}]``.
    """
    args = dict(harnessName=name, executionRoleArn=_role(),
                systemPrompt=[{"text": system_prompt}])
    if model: args["model"] = model
    if tools: args["tools"] = tools
    if skills: args["skills"] = skills
    if memory: args["memory"] = memory
    if allowed_tools: args["allowedTools"] = allowed_tools
    if max_iterations is not None: args["maxIterations"] = max_iterations
    if max_tokens is not None: args["maxTokens"] = max_tokens
    if timeout_seconds is not None: args["timeoutSeconds"] = timeout_seconds
    args.update(kw)
    return _control.create_harness(**args)["harness"]


def wait_ready(harness_id: str, timeout: int = 360) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = _control.get_harness(harnessId=harness_id)["harness"]
        st = h["status"]
        if st == "READY":
            return h
        if st in ("CREATE_FAILED", "FAILED", "UPDATE_FAILED"):
            raise RuntimeError(f"{harness_id} -> {st}: {h.get('failureReason')}")
        time.sleep(8)
    raise TimeoutError(f"{harness_id} not READY within {timeout}s")


def _consume_stream(stream) -> dict:
    """Parse an InvokeHarness event stream into a structured result.

    Also reconstructs any inline_function call the harness paused on: its
    ``toolUseId``/``name`` (from contentBlockStart) and its full ``input`` JSON,
    accumulated from the ``toolUse.input`` string deltas across contentBlockDelta
    events. The reconstructed call is returned as ``tool_use`` so a caller can feed
    a result back via :func:`invoke_with_tool_result` (the HITL resume contract)."""
    out, events, stop, meta, tools_used = "", [], None, None, []
    cur = None          # tool call currently being assembled
    tool_use = None     # the completed pending call (if the loop paused on tool_use)
    for ev in stream:
        for et, payload in ev.items():
            events.append(et)
            if et == "contentBlockStart":
                tu = (payload.get("start") or {}).get("toolUse") or {}
                if tu.get("name"):
                    tools_used.append(tu["name"])
                    cur = {"toolUseId": tu.get("toolUseId"), "name": tu["name"], "_raw": ""}
            elif et == "contentBlockDelta":
                d = (payload.get("delta") or {})
                if d.get("text"): out += d["text"]
                tu = d.get("toolUse") or {}
                if cur is not None and tu.get("input") is not None:
                    cur["_raw"] += tu["input"]   # input arrives as JSON string deltas
            elif et == "contentBlockStop":
                if cur is not None:
                    try: cur["input"] = json.loads(cur.pop("_raw") or "{}")
                    except (ValueError, TypeError): cur["input"] = {"_unparsed": cur.pop("_raw", "")}
                    tool_use = cur; cur = None
            elif et == "messageStop":
                stop = payload.get("stopReason")
            elif et == "metadata":
                meta = json.loads(json.dumps(payload, default=str))
            elif et in ("runtimeClientError", "validationException", "internalServerException"):
                out += f"[STREAM-ERROR {et}: {json.dumps(payload, default=str)[:200]}]"
    return {"text": out, "events": events, "stop_reason": stop,
            "tools_used": tools_used, "tool_use": tool_use if stop == "tool_use" else None,
            "metadata": meta}


def invoke(harness_arn: str, session_id: str, text: str, *, actor_id=None, **overrides) -> dict:
    """Invoke a harness (data plane, streaming). Returns a structured result:
    {text, events, stop_reason, tools_used, tool_use, metadata}. ``actor_id`` scopes
    memory per-analyst/tenant. ``overrides`` may set model/systemPrompt/tools/maxIterations/etc.

    If ``stop_reason == "tool_use"`` the harness paused on an ``inline_function`` (a
    human-in-the-loop gate); ``result["tool_use"]`` holds the reconstructed call
    (``toolUseId``/``name``/``input``). Feed a decision back with
    :func:`invoke_with_tool_result` to resume the loop."""
    kw = dict(harnessArn=harness_arn, runtimeSessionId=session_id,
              messages=[{"role": "user", "content": [{"text": text}]}])
    if actor_id: kw["actorId"] = actor_id
    kw.update(overrides)
    return _consume_stream(_data.invoke_harness(**kw)["stream"])


def invoke_with_tool_result(harness_arn: str, session_id: str, tool_use: dict,
                            result, *, status="success", actor_id=None, **overrides) -> dict:
    """Resume a harness that paused on an inline_function (HITL gate), closing the loop.

    Implements the two-message resume contract: on the SAME ``session_id`` we re-invoke
    with the assistant ``toolUse`` turn FOLLOWED BY a user ``toolResult`` whose
    ``toolUseId`` matches — both must be sent together or the session is left corrupted.

    ``tool_use`` is the dict from a prior ``invoke(...)["tool_use"]``. ``result`` is the
    analyst's decision payload; a dict is JSON-serialized into a text content block
    (the toolResult content block is sent as ``text``). ``status`` is
    ``"success"`` or ``"error"``."""
    tuid = tool_use["toolUseId"]; name = tool_use["name"]; tinput = tool_use.get("input", {})
    result_text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    content = [{"text": result_text}]
    kw = dict(
        harnessArn=harness_arn, runtimeSessionId=session_id,
        messages=[
            {"role": "assistant",
             "content": [{"toolUse": {"toolUseId": tuid, "name": name, "input": tinput}}]},
            {"role": "user",
             "content": [{"toolResult": {"toolUseId": tuid, "content": content, "status": status}}]},
        ])
    if actor_id: kw["actorId"] = actor_id
    kw.update(overrides)
    return _consume_stream(_data.invoke_harness(**kw)["stream"])


# ---------------------------------------------------------------- tool builders
def tool_code_interpreter(name="code_interpreter") -> dict:
    """Sandboxed Python/JS/TS. Deterministic compute (CVSS math, log parsing) — no token guessing."""
    return {"type": "agentcore_code_interpreter", "name": name}


def tool_remote_mcp(name, url, headers=None) -> dict:
    """Connect any MCP server by URL. ``headers`` values may use token-vault ARN
    interpolation ``${arn:...}`` so raw secrets never appear in config."""
    cfg = {"url": url}
    if headers: cfg["headers"] = headers
    return {"type": "remote_mcp", "name": name, "config": {"remoteMcp": cfg}}


def tool_gateway(name, gateway_arn, outbound_auth=None) -> dict:
    """Policy-backed tool surface (SigV4 default, or OAuth). Every tool on the gateway becomes available."""
    cfg = {"gatewayArn": gateway_arn}
    if outbound_auth: cfg["outboundAuth"] = outbound_auth
    return {"type": "agentcore_gateway", "name": name, "config": {"agentCoreGateway": cfg}}


def tool_inline(name, description, input_schema) -> dict:
    """Human-in-the-loop / client-side gate. When the agent calls this tool the harness
    PAUSES the loop (stop_reason=tool_use) and returns the call to your code as
    ``result["tool_use"]``. The loop is fully closed: feed the analyst decision back with
    :func:`invoke_with_tool_result`, which resumes the same session via the two-message
    turn (assistant toolUse + user toolResult with the matching toolUseId). See
    ``scenarios/scenario_hitl_resume.py`` for a live pause→approve→resume round trip.
    Use for high-stakes security decisions (publish / contain / offensive step)."""
    return {"type": "inline_function", "name": name,
            "config": {"inlineFunction": {"description": description, "inputSchema": input_schema}}}


# ---------------------------------------------------------------- memory
def managed_memory(strategies=None, expiry_days=None) -> dict:
    """Managed memory. Omitting memory on create auto-provisions this; declaring it
    is explicit. The ``actorId`` namespace (e.g. /actors/{actorId}/facts/) *is* the
    multi-tenant isolation boundary."""
    cfg = {}
    if strategies: cfg["strategies"] = strategies
    if expiry_days: cfg["eventExpiryDuration"] = expiry_days
    return {"managedMemoryConfiguration": cfg}


def byo_memory(arn, retrieval_config=None) -> dict:
    """Bring-your-own AgentCore Memory by ARN. Optional ``retrieval_config`` is the
    documented BYO tuning knob (per-namespace topK / relevanceScore / strategyId).
    Note: working-window size is a separate *truncation* concern (slidingWindow
    numMessages), not a memory field — so it is intentionally not exposed here."""
    cfg = {"arn": arn}
    if retrieval_config is not None: cfg["retrievalConfig"] = retrieval_config
    return {"agentCoreMemoryConfiguration": cfg}


# ---------------------------------------------------------------- teardown
def delete_harness(harness_id, keep_memory=False):
    kw = {"harnessId": harness_id}
    if keep_memory: kw["deleteManagedMemory"] = False
    return _control.delete_harness(**kw)


def cleanup(prefix: str):
    """Delete every harness whose name starts with ``prefix`` (cascade-deletes managed memory)."""
    deleted = []
    for h in _control.list_harnesses().get("harnesses", []):
        if h["harnessName"].startswith(prefix):
            try:
                delete_harness(h["harnessId"]); deleted.append(h["harnessName"])
            except Exception as e:  # noqa: BLE001 — best-effort teardown
                print("skip", h["harnessName"], str(e)[:60])
    return deleted


def list_harnesses():
    return _control.list_harnesses().get("harnesses", [])
