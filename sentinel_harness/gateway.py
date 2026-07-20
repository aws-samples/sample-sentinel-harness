"""
sentinel-harness · Gateway wiring
=================================
Thin, batteries-included wrappers over the Amazon Bedrock AgentCore **Gateway**
control plane (``bedrock-agentcore-control``), matching the style of ``core.py``.

Why this exists
---------------
The blueprint's single most important reliability upgrade is exposing discovery +
specialist delegation + public data lookups as **real MCP tools on an AgentCore
Gateway**, so a supervisor harness *calls a tool* rather than authoring HTTP. A
harness references that Gateway via ``core.tool_gateway(name, gateway_arn)``; this
module is how you stand the Gateway (and its tool targets) up in the first place.

Design notes (verified against the live boto3 service model — no AWS calls made to
learn these; ``python`` introspection of the ``bedrock-agentcore-control`` model)
-----------------------------------------------------------------------------------
- ``CreateGateway`` requires ``name`` + ``roleArn`` + ``protocolType`` +
  ``authorizerType``. Only ``MCP`` is a valid ``protocolType`` today.
- ``authorizerType`` is one of ``AWS_IAM`` / ``CUSTOM_JWT`` / ``NONE``. Machine
  callers (harness → gateway over SigV4) use ``AWS_IAM``; human/OAuth callers use
  ``CUSTOM_JWT`` with a ``customJWTAuthorizer`` config (discoveryUrl + audience).
  ``AWS_IAM`` / ``NONE`` take NO ``authorizerConfiguration`` — sending one is an
  error, so we only attach it for ``CUSTOM_JWT``.
- ``GetGateway`` / ``DeleteGateway`` key on ``gatewayIdentifier`` (accepts the id).
  The status enum is CREATING / UPDATING / UPDATE_UNSUCCESSFUL / DELETING / READY /
  FAILED — note there is NO separate ``CREATE_FAILED`` (unlike harnesses).
- ``ListGateways`` returns ``items`` (NOT ``gateways``), each carrying
  ``gatewayId`` / ``name`` / ``status``.
- ``CreateGatewayTarget`` requires ``gatewayIdentifier`` + ``name`` +
  ``targetConfiguration``. The ``targetConfiguration`` envelope exposes ``mcp`` /
  ``http`` / ``inference`` members; the ``mcp`` member (what these builders use)
  selects ONE target kind: ``lambda`` (a Lambda exposed as MCP tools),
  ``openApiSchema`` (an HTTP/OpenAPI target), ``smithyModel``, ``mcpServer`` (a
  remote MCP endpoint), or ``apiGateway``. The builders below produce that
  ``{"mcp": {...}}`` envelope so callers don't hand-assemble it (validated against
  the live CreateGatewayTarget input shape via botocore).

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import re
import time

from .core import _control, _role
from .logutil import get_logger

_log = get_logger(__name__)

# Gateway names do NOT follow the harness name rule. The live CreateGateway API
# enforces ([0-9a-zA-Z][-]?){1,48}: alphanumerics with optional single hyphens
# between them, NO underscores, and at most 48 characters. (Verified against a real
# ValidationException — the offline mocks alone would have missed this.) We check it
# locally so callers get a clear error instead of a server-side round trip.
_NAME_RE = re.compile(r"^[0-9a-zA-Z]([-]?[0-9a-zA-Z]){0,47}$")
# The CreateGatewayTarget API accepts a WIDER name pattern than CreateGateway:
# ([0-9a-zA-Z][-]?){1,100} — up to 100 chars AND a trailing hyphen are allowed.
# Using the stricter gateway regex for targets falsely rejected service-valid
# target names (49-100 chars, or a trailing hyphen) before any AWS call.
_TARGET_NAME_RE = re.compile(r"^([0-9a-zA-Z][-]?){1,100}$")

# Pagination runaway guard, mirroring core._all_harnesses: a backend that never
# clears nextToken must not spin forever. 10k pages is far beyond any real account.
_MAX_PAGES = 10_000

# Terminal statuses from the GetGateway status enum. READY is success; a DELETING
# gateway can NEVER become READY, so it is terminal for a readiness wait too (else
# wait_gateway_ready polls futilely until timeout and raises a misleading
# TimeoutError instead of surfacing the real state). CREATING/UPDATING are transient.
_FAILED_STATUSES = frozenset({"FAILED", "UPDATE_UNSUCCESSFUL"})
_TERMINAL_NOT_READY = _FAILED_STATUSES | {"DELETING", "DELETE_UNSUCCESSFUL"}


def _drain_pages(op, items_key: str = "items", **base_args) -> list:
    """Drain EVERY page of a paginated control-plane list call.

    Same drain-all-pages contract as ``core._all_harnesses`` — reading only the
    first page silently hides resources beyond it, so cleanup/audit orphaned them
    (cost + governance leak). ``op`` is the bound client method (e.g.
    ``_control.list_gateways``); ``base_args`` are forwarded on every page and
    ``nextToken`` is threaded through. The page-count cap (:data:`_MAX_PAGES`)
    guards against a backend that never clears the token."""
    out, token, guard = [], None, 0
    while True:
        args = dict(base_args)
        if token:
            args["nextToken"] = token
        resp = op(**args)
        out.extend(resp.get(items_key, []))
        token = resp.get("nextToken")
        guard += 1
        if not token or guard >= _MAX_PAGES:  # no more pages (or runaway guard)
            break
    return out


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ValueError(
            f"gateway name {name!r} must match {_NAME_RE.pattern} "
            "(alphanumerics with optional single hyphens, no underscores, max 48 chars)."
        )
    return name


def _validate_target_name(name: str) -> str:
    if not isinstance(name, str) or not _TARGET_NAME_RE.match(name):
        raise ValueError(
            f"gateway target name {name!r} must match {_TARGET_NAME_RE.pattern} "
            "(alphanumerics with optional single hyphens, no underscores, max 100 chars)."
        )
    return name


# ---------------------------------------------------------------- gateway lifecycle
def create_gateway(name, *, authorizer_type="AWS_IAM", role_arn=None,
                   protocol="MCP", authorizer_config=None, description=None,
                   search_type=None, interceptor_configurations=None,
                   policy_engine_configuration=None, **kw) -> dict:
    """Create an AgentCore Gateway (the policy-backed MCP tool surface).

    ``authorizer_type`` is ``AWS_IAM`` (SigV4 — machine callers, the default),
    ``CUSTOM_JWT`` (OAuth/JWT — human callers; pass ``authorizer_config`` with a
    ``customJWTAuthorizer`` block), or ``NONE``. Only ``AWS_IAM`` / ``CUSTOM_JWT``
    (with config) are sensible for SecOps; an ``authorizerConfiguration`` is sent
    ONLY for ``CUSTOM_JWT`` because ``AWS_IAM`` / ``NONE`` reject one.

    ``role_arn`` defaults to the shared execution role (``SENTINEL_EXECUTION_ROLE_ARN``).
    ``protocol`` is ``MCP`` (the only value the service accepts today). Pass
    ``search_type="SEMANTIC"`` to enable SEMANTIC tool search in the MCP protocol
    config.

    Request/response hardening (both optional; sent only when given):

    - ``interceptor_configurations`` — a list of Lambda interceptors (build each with
      :func:`lambda_interceptor`). AgentCore Gateway interceptors are **Lambda-based**:
      a guardrail/redaction step runs inside the Lambda (e.g. ``ApplyGuardrail`` on the
      request/response payload). There is NO native "Guardrail interceptor" primitive.
    - ``policy_engine_configuration`` — a Bedrock guardrail **policy engine** binding
      (build with :func:`policy_engine_config`): a guardrail ARN + a ``LOG_ONLY`` or
      ``ENFORCE`` mode applied by the service, no Lambda required.

    Returns the raw create response (carries ``gatewayId`` / ``gatewayArn`` /
    ``status`` — there is NO ``gateway`` wrapper key)."""
    _validate_name(name)
    if authorizer_type not in ("AWS_IAM", "CUSTOM_JWT", "NONE"):
        raise ValueError(
            f"authorizer_type {authorizer_type!r} must be AWS_IAM, CUSTOM_JWT, or NONE."
        )
    args: dict = dict(
        name=name,
        roleArn=role_arn or _role(),
        protocolType=protocol,
        authorizerType=authorizer_type,
    )
    if description:
        args["description"] = description
    # Only CUSTOM_JWT carries an authorizer configuration; AWS_IAM / NONE must not.
    if authorizer_type == "CUSTOM_JWT":
        if not authorizer_config:
            raise ValueError(
                "authorizer_type='CUSTOM_JWT' requires authorizer_config with a "
                "customJWTAuthorizer block (discoveryUrl + allowedAudience/allowedClients)."
            )
        args["authorizerConfiguration"] = authorizer_config
    elif authorizer_config is not None:
        raise ValueError(
            f"authorizer_config is only valid with authorizer_type='CUSTOM_JWT', "
            f"not {authorizer_type!r} (the service rejects a config on AWS_IAM/NONE)."
        )
    if search_type is not None:
        args["protocolConfiguration"] = {"mcp": {"searchType": search_type}}
    if interceptor_configurations is not None:
        # A single interceptor dict is accepted and wrapped into the one-element list
        # the service expects; a list passes through verbatim.
        if isinstance(interceptor_configurations, dict):
            interceptor_configurations = [interceptor_configurations]
        args["interceptorConfigurations"] = list(interceptor_configurations)
    if policy_engine_configuration is not None:
        args["policyEngineConfiguration"] = policy_engine_configuration
    args.update(kw)
    return _control.create_gateway(**args)


def cognito_jwt_authorizer(discovery_url, *, allowed_audience=None,
                           allowed_clients=None) -> dict:
    """Build the ``{"customJWTAuthorizer": {...}}`` block for a ``CUSTOM_JWT`` gateway.

    Slots straight into ``create_gateway(authorizer_type="CUSTOM_JWT",
    authorizer_config=cognito_jwt_authorizer(...))``. The service's
    ``customJWTAuthorizer`` shape is ``discoveryUrl`` plus EXACTLY ONE of
    ``allowedAudience`` / ``allowedClients``:

    - ``allowed_audience`` — for **human** callers presenting a Cognito **ID token**.
      The ID token carries an ``aud`` claim (the app client id), so the gateway
      validates against ``allowedAudience``.
    - ``allowed_clients`` — for **machine** callers using the
      ``client_credentials`` (M2M) flow. Those **access tokens have NO ``aud``
      claim** (verified gotcha), so the gateway must validate the ``client_id``
      claim via ``allowedClients`` instead — ``allowedAudience`` would never match.

    ``discovery_url`` is the OIDC discovery document, e.g.
    ``https://cognito-idp.<region>.amazonaws.com/<poolId>/.well-known/openid-configuration``.
    A single string is accepted for either audience/clients arg and wrapped into a
    one-element list (the service expects a list). Exactly one of the two must be
    given; supplying neither (or both) raises so the misconfig is caught locally
    rather than as a server-side ValidationException."""
    if not discovery_url:
        raise ValueError("cognito_jwt_authorizer requires a discovery_url (OIDC .well-known URL).")
    # Truthiness, not identity: an empty list ([]) is as much "unset" as None, so
    # allowed_audience=[] must not slip through and emit an empty allowedAudience.
    if bool(allowed_audience) == bool(allowed_clients):
        raise ValueError(
            "cognito_jwt_authorizer: give exactly one non-empty of allowed_audience "
            "(human ID tokens carry an aud claim) OR allowed_clients (M2M access tokens "
            "have NO aud claim, so validate client_id instead) — not neither, not both."
        )
    inner: dict = {"discoveryUrl": discovery_url}
    if allowed_audience:
        if isinstance(allowed_audience, str):
            allowed_audience = [allowed_audience]
        inner["allowedAudience"] = list(allowed_audience)
    else:
        if isinstance(allowed_clients, str):
            allowed_clients = [allowed_clients]
        inner["allowedClients"] = list(allowed_clients)
    return {"customJWTAuthorizer": inner}


# ---------------------------------------------------------- request/response hardening
# Valid interception points a Lambda interceptor may hook. The service's own enum is
# authoritative; we keep a local allowlist so a typo is caught here (a clear ValueError)
# rather than as a server-side ValidationException.
INTERCEPTION_POINTS = frozenset({"REQUEST", "RESPONSE"})
# Guardrail policy-engine modes: observe-only vs actively block.
POLICY_ENGINE_MODES = frozenset({"LOG_ONLY", "ENFORCE"})


def lambda_interceptor(lambda_arn, *, interception_points=("REQUEST",),
                       pass_request_headers=None, payload_exclude=None) -> dict:
    """Build one ``interceptorConfigurations`` entry backed by a Lambda.

    Slots into ``create_gateway(interceptor_configurations=[lambda_interceptor(...)])``.
    AgentCore Gateway interceptors are Lambda-based: the Lambda receives the request
    and/or response payload at the chosen ``interception_points`` and can inspect,
    redact (e.g. ``ApplyGuardrail`` on the body), or reject it — this is where a
    guardrail-redaction step lives (there is no native "Guardrail interceptor").

    Envelope shape (matches ``CreateGateway.interceptorConfigurations[]``)::

        {"interceptor": {"lambda": {"arn": <arn>}},
         "interceptionPoints": ["REQUEST" | "RESPONSE", ...],
         "inputConfiguration": {"passRequestHeaders": <bool>,
                                "payloadFilter": {"exclude": [...]}}}

    ``interception_points`` accepts a single string or an iterable; each must be one
    of :data:`INTERCEPTION_POINTS`. ``inputConfiguration`` is emitted only when
    ``pass_request_headers`` is set and/or ``payload_exclude`` is given (the service
    requires ``passRequestHeaders`` inside ``inputConfiguration`` when that block is
    present, so we default it to ``False`` if only ``payload_exclude`` was passed)."""
    if not lambda_arn:
        raise ValueError("lambda_interceptor requires a Lambda ARN.")
    if isinstance(interception_points, str):
        interception_points = [interception_points]
    points = [str(p).upper() for p in interception_points]
    if not points:
        raise ValueError("lambda_interceptor requires at least one interception point.")
    bad = [p for p in points if p not in INTERCEPTION_POINTS]
    if bad:
        raise ValueError(
            f"invalid interception point(s) {bad}; allowed: {sorted(INTERCEPTION_POINTS)}"
        )
    entry: dict = {
        "interceptor": {"lambda": {"arn": lambda_arn}},
        "interceptionPoints": points,
    }
    if pass_request_headers is not None or payload_exclude is not None:
        input_cfg: dict = {"passRequestHeaders": bool(pass_request_headers)}
        if payload_exclude is not None:
            # The CreateGateway model types payloadFilter.exclude as a list of
            # InterceptorPayloadExclusionSelector STRUCTURES ({"field": <jsonpath>}),
            # NOT bare strings — emitting raw strings raised a botocore
            # ParamValidationError against the real service (the redaction feature
            # crashed while offline tests passed). Wrap each entry as {"field": ...};
            # pass an already-shaped {"field": ...} dict through unchanged.
            input_cfg["payloadFilter"] = {
                "exclude": [f if isinstance(f, dict) else {"field": f}
                            for f in payload_exclude]
            }
        entry["inputConfiguration"] = input_cfg
    return entry


def policy_engine_config(guardrail_arn, *, mode="ENFORCE") -> dict:
    """Build a ``policyEngineConfiguration`` binding a Bedrock guardrail to the gateway.

    Slots into ``create_gateway(policy_engine_configuration=policy_engine_config(...))``.
    Unlike :func:`lambda_interceptor` this needs NO Lambda — the service applies the
    guardrail at ``guardrail_arn`` directly, in one of :data:`POLICY_ENGINE_MODES`:

    - ``LOG_ONLY`` — evaluate + record interventions without blocking (safe rollout).
    - ``ENFORCE`` — actively block/redact per the guardrail policy (default).

    Envelope shape: ``{"arn": <guardrail_arn>, "mode": "LOG_ONLY" | "ENFORCE"}``."""
    if not guardrail_arn:
        raise ValueError("policy_engine_config requires a guardrail ARN.")
    mode = str(mode).upper()
    if mode not in POLICY_ENGINE_MODES:
        raise ValueError(
            f"policy engine mode {mode!r} must be one of {sorted(POLICY_ENGINE_MODES)}."
        )
    return {"arn": guardrail_arn, "mode": mode}


def wait_gateway_ready(gateway_id: str, timeout: int = 300) -> dict:
    """Poll ``GetGateway`` until the gateway reaches ``READY`` (provisioning is
    fire-and-forget, so we must poll). Raises on a terminal-failure status or when
    ``timeout`` seconds elapse. Returns the final GetGateway response."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        g = _control.get_gateway(gatewayIdentifier=gateway_id)
        st = g.get("status")
        if st == "READY":
            return g
        # Fail fast on ANY status that can never reach READY (FAILED /
        # UPDATE_UNSUCCESSFUL / DELETING / DELETE_UNSUCCESSFUL) — polling a DELETING
        # gateway would otherwise stall for the full timeout and raise a misleading
        # TimeoutError that hides the real terminal state.
        if st in _TERMINAL_NOT_READY:
            raise RuntimeError(f"{gateway_id} -> {st}: {g.get('statusReasons')}")
        time.sleep(8)  # nosemgrep: arbitrary-sleep -- intentional poll backoff; AWS control-plane is eventually-consistent, loop is timeout-bounded above
    raise TimeoutError(f"{gateway_id} not READY within {timeout}s")


def create_gateway_target(gateway_id, name, target_config, *,
                          description=None, credential_provider_configs=None,
                          **kw) -> dict:
    """Attach a tool target to a Gateway. ``target_config`` is the
    ``targetConfiguration`` envelope produced by :func:`lambda_mcp_target` or
    :func:`openapi_http_target` (or hand-built ``{"mcp": {...}}``). Passes through
    verbatim as ``targetConfiguration`` (the service's required member)."""
    _validate_target_name(name)
    args: dict = dict(
        gatewayIdentifier=gateway_id,
        name=name,
        targetConfiguration=target_config,
    )
    if description:
        args["description"] = description
    if credential_provider_configs is not None:
        args["credentialProviderConfigurations"] = credential_provider_configs
    args.update(kw)
    return _control.create_gateway_target(**args)


# ---------------------------------------------------------- target lifecycle / query
def list_gateway_targets(gateway_id) -> list:
    """List EVERY target attached to a gateway, following ``nextToken`` pagination.

    Model-grounded (botocore ``bedrock-agentcore-control`` ListGatewayTargets):
    input requires ``gatewayIdentifier`` (optional ``maxResults`` / ``nextToken``);
    output is ``items`` + ``nextToken``. Each item carries ``targetId`` / ``name`` /
    ``status`` (enum includes CREATING / UPDATING / READY / FAILED / SYNCHRONIZING /
    *_PENDING_AUTH / *_UNSUCCESSFUL) plus ``targetType`` / ``listingMode`` /
    ``lastSynchronizedAt``. Drains all pages — the first-page-only bug that
    ``core._all_harnesses`` fixed for harnesses would otherwise orphan targets
    beyond page 1 during cleanup."""
    return _drain_pages(_control.list_gateway_targets, gatewayIdentifier=gateway_id)


def delete_gateway_target(gateway_id, target_id) -> dict:
    """Delete one target from a gateway.

    Model-grounded: DeleteGatewayTarget requires ``gatewayIdentifier`` +
    ``targetId`` (both, and nothing else); the response carries ``gatewayArn`` /
    ``targetId`` / ``status`` / ``statusReasons``. Targets must be deleted before
    their gateway — :func:`cleanup_gateways` does this automatically."""
    return _control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)


def update_gateway_target(gateway_id, target_id, target_config, *,
                          name=None, description=None,
                          credential_provider_configs=None, **kw) -> dict:
    """Update an existing gateway target.

    **``target_config`` is a FULL REPLACEMENT, not a patch**: the service model
    marks ``targetConfiguration`` as a REQUIRED member of UpdateGatewayTarget
    (required: ``gatewayIdentifier`` + ``targetId`` + ``targetConfiguration``), so
    every update must resend the complete envelope — there is no way to send a
    partial delta. Fetch the current config first (``GetGatewayTarget`` /
    :func:`list_gateway_targets`) if you only mean to tweak one field.

    The service also rejects updates while the target is in a pending-authorization
    state (``CREATE_PENDING_AUTH`` / ``UPDATE_PENDING_AUTH`` /
    ``SYNCHRONIZE_PENDING_AUTH``) — wait for that to settle first.

    Optional members forwarded only when given: ``name`` (validated locally like
    create), ``description``, ``credentialProviderConfigurations``."""
    args: dict = dict(
        gatewayIdentifier=gateway_id,
        targetId=target_id,
        targetConfiguration=target_config,
    )
    if name is not None:
        args["name"] = _validate_target_name(name)
    if description:
        args["description"] = description
    if credential_provider_configs is not None:
        args["credentialProviderConfigurations"] = credential_provider_configs
    args.update(kw)
    return _control.update_gateway_target(**args)


def synchronize_gateway_targets(gateway_id, target_ids) -> list:
    """Re-fetch the latest tool definitions from target endpoints (DYNAMIC targets).

    This is how a ``listingMode="DYNAMIC"`` :func:`mcp_server_target` picks up
    tools the remote MCP server added/changed since attach — without it the
    gateway keeps serving the stale tool listing.

    Model-grounded: SynchronizeGatewayTargets requires ``gatewayIdentifier`` +
    ``targetIdList``; the list is capped at EXACTLY ONE targetId per call
    (model metadata ``min: 1, max: 1``), so a single string is accepted and
    wrapped, and a multi-id list raises locally instead of as a server-side
    ValidationException. You cannot synchronize a target in a pending-auth state.
    Returns the response ``targets`` list."""
    if isinstance(target_ids, str):
        target_ids = [target_ids]
    target_ids = list(target_ids)
    if len(target_ids) != 1:
        raise ValueError(
            f"synchronize_gateway_targets takes exactly ONE targetId per call "
            f"(the service model caps targetIdList at min=1/max=1), got {len(target_ids)}."
        )
    resp = _control.synchronize_gateway_targets(
        gatewayIdentifier=gateway_id, targetIdList=target_ids
    )
    return resp.get("targets", [])


# ---------------------------------------------------------------- target builders
def lambda_mcp_target(lambda_arn, tool_schema=None, *, inline_tools=None) -> dict:
    """Build a ``targetConfiguration`` for a Lambda exposed as MCP tools.

    Envelope shape: ``{"mcp": {"lambda": {"lambdaArn": ..., "toolSchema": ...}}}``.
    ``toolSchema`` is REQUIRED by the service; supply it directly via
    ``tool_schema`` (an ``{"s3": {...}}`` or ``{"inlinePayload": [...]}`` dict) or
    give ``inline_tools`` (a list of tool definitions) which is wrapped as
    ``{"inlinePayload": inline_tools}``."""
    if not lambda_arn:
        raise ValueError("lambda_mcp_target requires a Lambda ARN.")
    if tool_schema is None and inline_tools is None:
        raise ValueError(
            "lambda_mcp_target requires a toolSchema: pass tool_schema=... or "
            "inline_tools=[...] (the service requires toolSchema on a lambda target)."
        )
    if tool_schema is None:
        tool_schema = {"inlinePayload": inline_tools}
    return {"mcp": {"lambda": {"lambdaArn": lambda_arn, "toolSchema": tool_schema}}}


def openapi_http_target(schema=None, *, url=None, s3_uri=None,
                        bucket_owner=None) -> dict:
    """Build a ``targetConfiguration`` for an HTTP/OpenAPI target.

    Envelope shape: ``{"mcp": {"openApiSchema": {...}}}``. The OpenAPI document is
    supplied EITHER inline (``schema`` — a JSON/YAML string, or ``url`` as a thin
    alias for an inline document reference) or from S3 (``s3_uri`` + optional
    ``bucket_owner``). Exactly one source must be given. The first positional
    ``schema`` string keeps the common inline case terse.

    Note: the historical arg name ``url`` is accepted for the inline document (the
    service takes an ``inlinePayload`` string, not a fetch URL — egress stays
    controlled), so callers migrating from a URL-shaped API get a clear path."""
    inline = schema if schema is not None else url
    if inline is not None and s3_uri is not None:
        raise ValueError("openapi_http_target: give an inline schema OR s3_uri, not both.")
    if inline is None and s3_uri is None:
        raise ValueError("openapi_http_target: supply schema=... (inline) or s3_uri=...")
    if s3_uri is not None:
        s3: dict = {"uri": s3_uri}
        if bucket_owner:
            s3["bucketOwnerAccountId"] = bucket_owner
        open_api = {"s3": s3}
    else:
        open_api = {"inlinePayload": inline}
    return {"mcp": {"openApiSchema": open_api}}


def mcp_server_target(endpoint, *, tool_schema=None, listing_mode=None) -> dict:
    """Build a ``targetConfiguration`` for a remote MCP server endpoint.

    Envelope shape: ``{"mcp": {"mcpServer": {"endpoint": ...}}}``. ``listing_mode``
    is ``DEFAULT`` or ``DYNAMIC`` (dynamic tool discovery)."""
    if not endpoint:
        raise ValueError("mcp_server_target requires an endpoint URL.")
    server: dict = {"endpoint": endpoint}
    if tool_schema is not None:
        server["mcpToolSchema"] = tool_schema
    if listing_mode is not None:
        server["listingMode"] = listing_mode
    return {"mcp": {"mcpServer": server}}


# ---------------------------------------------------------------- teardown / query
def delete_gateway(gateway_id):
    """Delete a Gateway by id. Delete its targets first
    (:func:`delete_gateway_target`) — a gateway with live targets rejects
    deletion. :func:`cleanup_gateways` handles that ordering automatically."""
    return _control.delete_gateway(gatewayIdentifier=gateway_id)


def list_gateways() -> list:
    """List ALL gateways, following ``nextToken`` pagination. Returns the ``items``
    list (NOT ``gateways`` — that is the service's response key), each carrying
    ``gatewayId`` / ``name`` / ``status``. Drains all pages — reading only the
    first page silently hid gateways beyond it, so ``cleanup_gateways`` orphaned
    billed resources (the same cost + governance bug ``core._all_harnesses``
    fixed for harnesses)."""
    return _drain_pages(_control.list_gateways)


def cleanup_gateways(prefix: str) -> list:
    """Delete every gateway whose name starts with ``prefix`` (best-effort teardown).
    Returns the names deleted. Mirrors ``core.cleanup`` for harnesses.

    Each gateway's targets are deleted FIRST (the service rejects deleting a
    gateway with live targets, which used to warning-skip the gateway and orphan
    the billed resource). Target deletion is best-effort per target: a failure is
    surfaced as a WARNING and we still attempt the gateway delete, so one stuck
    target cannot silently abort the rest of the teardown."""
    deleted = []
    for g in list_gateways():
        if g.get("name", "").startswith(prefix):
            # Targets must go before the gateway. Best-effort per target: surface
            # the error, keep going — the gateway delete below will fail loudly
            # (and be warning-logged) if a live target actually remains.
            try:
                targets = list_gateway_targets(g["gatewayId"])
            except Exception as e:  # noqa: BLE001 — best-effort teardown, keep going
                _log.warning("cleanup: could not list targets of %s: %s", g.get("name"), e)
                targets = []
            for t in targets:
                try:
                    delete_gateway_target(g["gatewayId"], t["targetId"])
                except Exception as e:  # noqa: BLE001 — best-effort teardown, keep going
                    _log.warning("cleanup: could not delete target %s of gateway %s: %s",
                                 t.get("name") or t.get("targetId"), g.get("name"), e)
            try:
                delete_gateway(g["gatewayId"])
                deleted.append(g["name"])
            except Exception as e:  # noqa: BLE001 — best-effort teardown, keep going
                _log.warning("cleanup: skip gateway %s: %s", g.get("name"), e)
                _log.debug("cleanup: skip gateway %s (full error)", g.get("name"), exc_info=True)
    return deleted
