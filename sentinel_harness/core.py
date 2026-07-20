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

from .logutil import get_logger

_log = get_logger(__name__)

REGION = os.environ.get("SENTINEL_REGION", "us-east-1")
EXECUTION_ROLE_ARN = os.environ.get("SENTINEL_EXECUTION_ROLE_ARN")  # required at runtime

_DATA_CONFIG = Config(read_timeout=180, connect_timeout=15, retries={"max_attempts": 2})
# The control plane does short lifecycle calls; pin an explicit Config for symmetry
# with _data (bounded connect/read + retries) instead of relying on boto defaults.
_CONTROL_CONFIG = Config(read_timeout=60, connect_timeout=15, retries={"max_attempts": 3})

_control = boto3.client("bedrock-agentcore-control", region_name=REGION, config=_CONTROL_CONFIG)
_data = boto3.client("bedrock-agentcore", region_name=REGION, config=_DATA_CONFIG)


def set_region(region: str) -> None:
    """Rebind the module-global boto3 clients to ``region`` at runtime.

    The control/data clients are constructed at import time from ``SENTINEL_REGION``,
    so simply setting the env var later has NO effect on already-built clients. The
    CLI ``--region`` flag and any programmatic override must call this to actually
    move subsequent calls to the new region (it also updates the env var so exported
    code / subprocesses inherit it). Every helper here uses these module globals, so
    one reassignment moves the whole library.
    """
    global REGION, _control, _data
    if not region:
        raise ValueError("region must be a non-empty string")
    REGION = region
    os.environ["SENTINEL_REGION"] = region
    _control = boto3.client("bedrock-agentcore-control", region_name=region, config=_CONTROL_CONFIG)
    _data = boto3.client("bedrock-agentcore", region_name=region, config=_DATA_CONFIG)
    # Sibling modules bind `from .core import _control` at import time, so their
    # local name still points at the OLD client after we reassign ours. Rebind the
    # borrowers explicitly (best-effort: they may not be imported yet) so a runtime
    # region switch actually moves gateway/registry_live calls too.
    import sys as _sys
    for _mod_name in ("sentinel_harness.gateway", "sentinel_harness.registry_live"):
        _mod = _sys.modules.get(_mod_name)
        if _mod is not None and hasattr(_mod, "_control"):
            _mod._control = _control

# --- Model IDs: use the cross-region-inference *pattern*; do not pin a version you
#     can't verify. Override via env if you want a specific pinned id. ---
MODEL_SONNET = os.environ.get("SENTINEL_MODEL_SONNET", "global.anthropic.claude-sonnet-4-6")
MODEL_HAIKU = os.environ.get("SENTINEL_MODEL_HAIKU", "global.anthropic.claude-haiku-4-5-20251001-v1:0")
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
    """Build the ``model`` block for :func:`create_harness` from a Bedrock model id.

    Wraps ``model_id`` (the ``MODEL_SONNET`` / ``MODEL_HAIKU`` / ``MODEL_OPUS`` ids
    or a cross-region-inference id) into the ``{"bedrockModelConfig": {...}}``
    envelope the service expects. Any ``**extra`` keys (e.g. inference params) merge
    into ``bedrockModelConfig`` verbatim."""
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


def update_harness(harness_id, *, system_prompt=None, model=None, tools=None, skills=None,
                   memory=None, allowed_tools=None, max_iterations=None, max_tokens=None,
                   timeout_seconds=None, execution_role_arn=None, **kw) -> dict:
    """Full-replacement update of an existing harness (UpdateHarness semantics: the
    caller supplies the COMPLETE desired config; unspecified fields are not merged
    server-side).

    WHY full-replacement matters: an agent update is a read-modify-write of the
    *whole* config — UpdateHarness does not patch, it replaces. Passing only the one
    field you meant to change would silently drop every other field (tools, memory,
    limits) that lives on the harness today. Callers (e.g. harness_ops) must therefore
    read the current config, mutate it in memory, and pass the full desired shape here.

    ``systemPrompt`` is normalized to the GA list shape ``[{"text": ...}]`` when given
    (same as :func:`create_harness`). ``executionRoleArn`` falls back to :func:`_role`
    since UpdateHarness treats an omitted role as clearing it.
    """
    args = dict(harnessId=harness_id, executionRoleArn=execution_role_arn or _role())
    if system_prompt is not None: args["systemPrompt"] = [{"text": system_prompt}]
    if model is not None: args["model"] = model
    if tools is not None: args["tools"] = tools
    if skills is not None: args["skills"] = skills
    if memory is not None:
        # UpdateHarness.memory is UpdatedHarnessMemoryConfiguration — a SINGLE
        # `optionalValue` member wrapping the same {managed/agentCore/disabled}
        # structure CreateHarness.memory takes DIRECTLY. The memory builders
        # (managed_memory/byo_memory) emit the CREATE shape, so the bare dict passes
        # CreateHarness but ParamValidationErrors on UpdateHarness ("Unknown parameter
        # in memory: managedMemoryConfiguration, must be one of: optionalValue").
        # Wrap it here (idempotent: leave an already-wrapped value untouched).
        args["memory"] = memory if "optionalValue" in memory else {"optionalValue": memory}
    if allowed_tools is not None: args["allowedTools"] = allowed_tools
    if max_iterations is not None: args["maxIterations"] = max_iterations
    if max_tokens is not None: args["maxTokens"] = max_tokens
    if timeout_seconds is not None: args["timeoutSeconds"] = timeout_seconds
    args.update(kw)
    resp = _control.update_harness(**args)
    return resp["harness"] if "harness" in resp else resp


# ---------------------------------------------------------------- harness endpoints (promote-to-production)
def create_harness_endpoint(harness_id, endpoint_name, *, target_version=None,
                            description=None, **kw) -> dict:
    """Create a harness *endpoint* — the promote-to-production mechanism.

    WHY an endpoint (not an env-tag hack): a harness accrues immutable *versions*;
    an endpoint is a stable, named pointer that decides which version production
    traffic reaches. Promoting a passing harness = point an endpoint at it. Pin the
    endpoint to a specific ``target_version`` for a controlled release, or omit it to
    track the latest — the same test→staging→prod staging the eval loop drives
    (ROADMAP §5.3: eval ≥ criteria ∧ human approval → CreateHarnessEndpoint).

    ``targetVersion``/``description`` are sent only when not None so an omitted
    optional never reaches the API as a null. ``kw`` passes straight through."""
    args = dict(harnessId=harness_id, endpointName=endpoint_name)
    if target_version is not None: args["targetVersion"] = target_version
    if description is not None: args["description"] = description
    args.update(kw)
    resp = _control.create_harness_endpoint(**args)
    return resp["endpoint"] if "endpoint" in resp else resp


def get_harness_endpoint(harness_id, endpoint_name) -> dict:
    """Fetch one endpoint (its status + the version it currently points at)."""
    resp = _control.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)
    return resp["endpoint"] if "endpoint" in resp else resp


def update_harness_endpoint(harness_id, endpoint_name, *, target_version=None,
                            description=None, **kw) -> dict:
    """Repoint an EXISTING endpoint at a new version — the v2+ promotion path.

    CreateHarnessEndpoint on a name that already exists raises ConflictException,
    so a self-improvement loop that promotes the same endpoint name twice (v1 then
    an improved v2) MUST update, not re-create. Model-confirmed shape: required
    harnessId+endpointName; optional targetVersion/description (sent only when not
    None so an omitted optional never reaches the API as a null)."""
    args = dict(harnessId=harness_id, endpointName=endpoint_name)
    if target_version is not None: args["targetVersion"] = target_version
    if description is not None: args["description"] = description
    args.update(kw)
    resp = _control.update_harness_endpoint(**args)
    return resp["endpoint"] if "endpoint" in resp else resp


def promote_harness_endpoint(harness_id, endpoint_name, *, target_version=None,
                             description=None) -> dict:
    """Create the endpoint, or update it if it already exists (idempotent promote).

    The create-then-update-on-conflict composition every promotion caller wants:
    first promotion creates the named endpoint; every later promotion repoints it.
    ConflictException is the ONLY error translated into the update path — anything
    else propagates."""
    try:
        return create_harness_endpoint(harness_id, endpoint_name,
                                       target_version=target_version, description=description)
    except _control.exceptions.ConflictException:
        return update_harness_endpoint(harness_id, endpoint_name,
                                       target_version=target_version, description=description)


def list_harness_endpoints(harness_id) -> list:
    """Return EVERY endpoint of a harness, following ``nextToken`` pagination.

    Same drain-all-pages contract as ``_all_harnesses`` — reading only the first
    page silently hides endpoints beyond it (a promotion-audit blind spot). The
    page-count cap guards against a backend that never clears the token."""
    out, token, guard = [], None, 0
    while True:
        args = dict(harnessId=harness_id)
        if token: args["nextToken"] = token
        resp = _control.list_harness_endpoints(**args)
        out.extend(resp.get("endpoints", []))
        token = resp.get("nextToken")
        guard += 1
        if not token or guard > 10_000:
            break
    return out


def list_harness_versions(harness_id) -> list:
    """List a harness's immutable versions — the candidates an endpoint can pin."""
    return _control.list_harness_versions(harnessId=harness_id)["harnessVersions"]


def delete_harness_endpoint(harness_id, endpoint_name) -> dict:
    """Delete an endpoint (teardown). Does not touch the harness or its versions."""
    return _control.delete_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)


def wait_ready(harness_id: str, timeout: int = 360) -> dict:
    """Poll ``GetHarness`` until the harness reaches ``READY``; return that response.

    Harness creation is fire-and-forget, so callers must poll before invoking. Raises
    ``RuntimeError`` on a terminal failure status (``CREATE_FAILED`` / ``FAILED`` /
    ``UPDATE_FAILED``) and ``TimeoutError`` if ``timeout`` seconds elapse first."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = _control.get_harness(harnessId=harness_id)["harness"]
        st = h["status"]
        if st == "READY":
            return h
        if st in ("CREATE_FAILED", "FAILED", "UPDATE_FAILED"):
            raise RuntimeError(f"{harness_id} -> {st}: {h.get('failureReason')}")
        time.sleep(8)  # nosemgrep: arbitrary-sleep -- intentional poll backoff; AWS control-plane is eventually-consistent, loop is timeout-bounded above
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
    pending = []        # ALL completed tool calls in this turn (parallel tool_use)
    error = None        # first stream-level error, surfaced explicitly (not just in text)
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
                    # Capture raw ONCE before parsing: popping inside both the try and
                    # except lost the payload (2nd pop returned the '' default), so the
                    # _unparsed fallback was always empty. Now it preserves the raw text.
                    raw = cur.pop("_raw", "") or ""
                    try:
                        cur["input"] = json.loads(raw or "{}")
                    except (ValueError, TypeError):
                        cur["input"] = {"_unparsed": raw}
                    # APPEND — a turn can pause on MULTIPLE parallel tool_use blocks;
                    # keeping only the last silently dropped earlier HITL gates and
                    # produced a resume message missing a toolResult for each pending id.
                    pending.append(cur)
                    cur = None
            elif et == "messageStop":
                stop = payload.get("stopReason")
            elif et == "metadata":
                meta = json.loads(json.dumps(payload, default=str))
            elif et in ("runtimeClientError", "validationException", "internalServerException"):
                msg = f"{et}: {json.dumps(payload, default=str)[:200]}"
                out += f"[STREAM-ERROR {msg}]"
                if error is None:            # keep the FIRST error; surface it explicitly
                    error = msg
    # Surface token usage as a first-class top-level field (additive; the GA metadata
    # event carries usage={inputTokens,outputTokens,totalTokens}). This is what lets a
    # scenario emit the SentinelHarness/TokensPerScenario signal without re-digging the
    # metadata blob — see sentinel_harness.observability.emit_token_metric. None when a
    # stream carried no usage metadata (e.g. an errored/empty stream).
    usage = (meta or {}).get("usage")
    # Expose the pending HITL calls only when the loop actually paused on tool_use.
    # ``tool_uses`` is the FULL list (>=1 for parallel gates); ``tool_use`` stays the
    # first for backward compatibility with single-gate callers, but a caller that
    # must resume correctly should answer EVERY entry in ``tool_uses``.
    paused = pending if stop == "tool_use" else []
    return {"text": out, "events": events, "stop_reason": stop,
            "tools_used": tools_used,
            "tool_use": paused[0] if paused else None,
            "tool_uses": paused,
            "metadata": meta, "usage": usage, "error": error}


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


def invoke_and_meter(harness_arn: str, session_id: str, text: str, *,
                     scenario: str, log=None, actor_id=None, **overrides) -> dict:
    """:func:`invoke` + emit the token/latency/tool-call/error observability signals.

    This is the single call site that closes the gap where the token metric existed
    but had NO runtime emitter. It times the invoke, then emits (via the structured
    ``observability`` log lines the CloudWatch MetricFilters parse):

    - ``TokensPerScenario`` (input+output tokens),
    - ``InvokeLatencyMs`` (wall-clock),
    - ``ToolCallsPerInvoke`` (len of tools_used),
    - ``InvokeErrors`` tagged ``kind`` on a botocore throttle / other failure.

    ``log`` defaults to the ``sentinel_harness.telemetry`` logger's ``info`` (stderr,
    level-gated) so metering is **silent on stdout** — scenarios keep printing their
    own human output. Pass ``log=print`` (or a LogGroup sink) to route the metric
    lines wherever the MetricFilter reads. Returns the same dict as :func:`invoke`;
    on an invoke exception it emits an error metric and re-raises (never swallows)."""
    from . import observability as _obs
    from .logutil import get_logger

    if log is None:
        log = get_logger("sentinel_harness.telemetry").info

    t0 = time.perf_counter()
    try:
        result = invoke(harness_arn, session_id, text, actor_id=actor_id, **overrides)
    except Exception as exc:  # noqa: BLE001 — meter the failure, then re-raise
        kind = "throttle" if _is_throttle(exc) else "internal"
        _obs.emit_error(scenario, kind, log=log)
        _obs.emit_invoke_latency(scenario, (time.perf_counter() - t0) * 1000.0, log=log)
        raise
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    _obs.emit_token_metric_from_result(scenario, result, log=log)
    _obs.emit_invoke_latency(scenario, elapsed_ms, log=log)
    _obs.emit_tool_calls(scenario, len(result.get("tools_used") or []), log=log)
    # A structured (non-raising) error surfaced by the stream also counts.
    if result.get("error"):
        _obs.emit_error(scenario, "internal", log=log)
    return result


def _is_throttle(exc: Exception) -> bool:
    """True if ``exc`` looks like a botocore throttling/rate error (best-effort)."""
    # `or {}` guards a present-but-None `.response` (e.g. a connection error with
    # response=None): getattr would return None and None.get(...) would raise,
    # masking the original fault.
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    name = type(exc).__name__
    return (
        "Throttl" in code or "TooManyRequests" in code or code == "RequestLimitExceeded"
        or "Throttl" in name or "TooManyRequests" in name
    )


def invoke_with_tool_results(harness_arn: str, session_id: str, answers,
                             *, actor_id=None, **overrides) -> dict:
    """Resume a harness that paused on ONE OR MORE inline_function (HITL) gates.

    The Bedrock/Anthropic protocol requires that a resuming turn re-send the paused
    assistant message containing EVERY ``toolUse`` block, followed by a user message
    carrying a matching ``toolResult`` for EVERY ``toolUseId`` — a missing one is a
    ValidationException / corrupted session. When the model emits parallel gates in
    one turn (``invoke(...)["tool_uses"]`` has >1 entry), answering only the first
    (the old single-gate path) silently dropped the rest. This plural helper answers
    them all in the single required message pair.

    ``answers`` is a list of ``(tool_use, result[, status])`` — one per paused gate;
    ``tool_use`` is an entry from ``invoke(...)["tool_uses"]``, ``result`` the analyst
    decision (a dict is JSON-serialized to a text content block), ``status`` defaults
    to ``"success"``. Order-independent, but every pending toolUseId MUST be present."""
    answers = list(answers)
    if not answers:
        raise ValueError("invoke_with_tool_results requires at least one (tool_use, result) answer")
    tool_use_blocks = []
    tool_result_blocks = []
    for ans in answers:
        if len(ans) == 3:
            tool_use, result, status = ans
        else:
            (tool_use, result), status = ans, "success"
        tuid = tool_use["toolUseId"]; name = tool_use["name"]; tinput = tool_use.get("input", {})
        result_text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        tool_use_blocks.append({"toolUse": {"toolUseId": tuid, "name": name, "input": tinput}})
        tool_result_blocks.append(
            {"toolResult": {"toolUseId": tuid, "content": [{"text": result_text}], "status": status}}
        )
    kw = dict(
        harnessArn=harness_arn, runtimeSessionId=session_id,
        messages=[
            {"role": "assistant", "content": tool_use_blocks},
            {"role": "user", "content": tool_result_blocks},
        ])
    if actor_id: kw["actorId"] = actor_id
    kw.update(overrides)
    return _consume_stream(_data.invoke_harness(**kw)["stream"])


def invoke_with_tool_result(harness_arn: str, session_id: str, tool_use: dict,
                            result, *, status="success", actor_id=None, **overrides) -> dict:
    """Resume a harness that paused on a SINGLE inline_function (HITL) gate.

    Convenience wrapper over :func:`invoke_with_tool_results` for the common
    one-gate case. If a turn paused on MULTIPLE parallel gates
    (``invoke(...)["tool_uses"]`` has >1 entry), use ``invoke_with_tool_results``
    with every gate — answering only one here would leave the others unanswered and
    corrupt the session.

    ``tool_use`` is the dict from a prior ``invoke(...)["tool_use"]``. ``result`` is the
    analyst's decision payload; a dict is JSON-serialized into a text content block.
    ``status`` is ``"success"`` or ``"error"``."""
    return invoke_with_tool_results(
        harness_arn, session_id, [(tool_use, result, status)],
        actor_id=actor_id, **overrides,
    )


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
    """Delete a harness by id. By default its managed memory is cascade-deleted too;
    pass ``keep_memory=True`` to retain the managed memory store across the delete."""
    kw = {"harnessId": harness_id}
    if keep_memory: kw["deleteManagedMemory"] = False
    return _control.delete_harness(**kw)


def _all_harnesses():
    """Return EVERY harness summary, following ``nextToken`` pagination.

    ListHarnesses is paginated; reading only the first page (``.get('harnesses')``)
    silently ignored harnesses beyond page 1, so ``cleanup``/``list_harnesses``
    orphaned them (cost + governance leak). This drains all pages. A page-count cap
    guards against a backend that never clears the token."""
    out, token, guard = [], None, 0
    while True:
        resp = _control.list_harnesses(nextToken=token) if token else _control.list_harnesses()
        out.extend(resp.get("harnesses", []))
        token = resp.get("nextToken")
        guard += 1
        if not token or guard > 10_000:  # no more pages (or runaway guard)
            break
    return out


def cleanup(prefix: str):
    """Delete every harness whose name starts with ``prefix`` (cascade-deletes managed memory).

    Paginates ListHarnesses so harnesses beyond the first page are not orphaned.

    REFUSES an empty/whitespace prefix: ``"".startswith("")`` is True, so an empty
    prefix would match — and delete — EVERY harness in the account (plus its managed
    memory). That is never an intentional call (a stray/unset ``$PREFIX`` in a script
    is the usual trigger), so we fail loud rather than wipe the account."""
    if not isinstance(prefix, str) or not prefix.strip():
        raise ValueError(
            "cleanup: refusing an empty/whitespace prefix — it would match and delete "
            "EVERY harness in the account. Pass a specific non-empty prefix."
        )
    deleted = []
    for h in _all_harnesses():
        if h["harnessName"].startswith(prefix):
            try:
                delete_harness(h["harnessId"]); deleted.append(h["harnessName"])
            except Exception as e:  # noqa: BLE001 — best-effort teardown
                _log.warning("cleanup: skip harness %s: %s", h["harnessName"], e)
                _log.debug("cleanup: skip harness %s (full error)", h["harnessName"], exc_info=True)
    return deleted


def list_harnesses():
    """Return the account's harness summaries (ALL pages of ``ListHarnesses``), or
    ``[]`` if none. Each item carries ``harnessId`` / ``harnessName`` /
    ``status`` / ``arn``."""
    return _all_harnesses()
