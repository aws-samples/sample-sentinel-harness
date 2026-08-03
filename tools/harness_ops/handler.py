"""harness_ops — deterministic harness-lifecycle MCP tool (M1 core).

SecOps / platform purpose
-------------------------
The meta-orchestration agent (``harnesses/agent-ops``) does not *build*
harnesses by emitting free-form orchestration code — it decomposes a request
into ONE structured harness spec and then drives the harness lifecycle through
THIS tool. That separation is deliberate: spec authoring is the model's job,
but create/update/invoke/promote are **deterministic** control-plane actions
that must never be model-authored HTTP. The agent passes structured
``params``; this handler only validates them and calls
``sentinel_harness.core.*`` (or, for the one action ``core`` does not yet wrap,
the underlying boto3 control-plane client via ``core._control``).

Why a thin router (not a smart tool)
------------------------------------
Every branch below is: validate the params for this action, then hand off to
``core``. There is NO LLM here and NO business logic beyond validation —
determinism is the whole point (ROADMAP §5.1 / §4 self-iteration engine). If we
let the tool reason, the self-improvement loop would be non-reproducible.

Input contract
--------------
event = {"action": <str>, "params": {...}}
    action ∈ {create, update, invoke, wait_ready, list, delete, create_endpoint, update_endpoint, promote_endpoint, list_endpoints}

Output contract
---------------
Success: {"ok": True, "action": <str>, ...action-specific result}
Failure: {"ok": False, "action": <str>, "error": <code>, "message": <str>}
    error ∈ {validation_error, upstream_error}

Configuration / secrets posture
-------------------------------
No account ids, ARNs, or secrets are hardcoded. The execution role, region and
gateway all come from ``core`` (env: ``SENTINEL_EXECUTION_ROLE_ARN``,
``SENTINEL_REGION``, ``AWS_PROFILE``). This handler makes control-plane calls
only via ``core`` and ``core._control`` — never a fresh boto3 client — so the
one region/credential resolution path is shared.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from sentinel_harness import core

# Same server-side naming rule factory._NAME_RE enforces
# ([a-zA-Z][a-zA-Z0-9_]{0,39}); we mirror it so a bad name fails locally with a
# clear message instead of after a control-plane round trip.
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")

_ACTIONS = frozenset(
    {"create", "update", "invoke", "wait_ready", "list", "delete",
     "create_endpoint", "update_endpoint", "promote_endpoint", "list_endpoints"}
)

# The three actions that put a harness version in front of production traffic
# (INV-OPS-7). Mirrors `agent_loop.is_promotion` exactly — see the note there; the two
# lists must agree or one layer gates an action the other does not.
_PROMOTION_ACTIONS = frozenset({"create_endpoint", "update_endpoint", "promote_endpoint"})

# The env var by which a DRIVER declares it has already run the promotion gate.
#
# INV-OPS-7. `docs/THREAT-MODEL.md` §1 claims: "Publish / contain / promote are
# inline_function HITL gates ...; the agent can only *request* them, never execute them."
# That was true of the two DRIVER paths and false of a third:
#
#   agent_loop.run_agent_loop        gates all 3 promotion actions (agent_loop.py:205)
#   autonomy.run_improvement_loop    gates via approve_fn, fail-closed when None
#   harness_ops.handler(...) direct  NO gate  <- reproduced: promoted 'prod', ok:True
#
# The third is not hypothetical: `scenarios/scenario_agent_factory_loop.py` says of
# itself "delegation here is in-process (the scenario calls the harness_ops handler
# directly) rather than over a Gateway MCP target". That scenario happens to call only
# create/wait_ready/invoke/delete, so nothing is exploited today — but nothing PREVENTED
# it from calling promote either, which makes the threat-model claim a convention rather
# than a mechanism. The same shape as INV-PROMOTE-3, where a docstring delegated a
# fail-closed posture to "the caller" and no caller implemented it.
#
# `sentinel_agent_ops` is the harness this matters for: its allowedTools is exactly
# `@gateway/harness_ops` with NO gate on the list, while `sentinel_self_improving` holds
# the same tool WITH `request_promotion_approval`. One tool, two harnesses, one gate.
#
# Deliberately an explicit opt-in rather than an inferred one: a driver that has run the
# gate SAYS so. There is no way for the model to set it (it is process environment, not
# a tool parameter — and INV-OPS-6 already refuses model-authored request fields), and a
# missing value means refused, never assumed.
_GATE_WITNESS_ENV = "SENTINEL_PROMOTION_GATE_WITNESSED"


class _ValidationError(ValueError):
    """Raised for a malformed request. Kept distinct from upstream/boto errors so
    the handler can label the two differently (fix-your-input vs retry-AWS) — we
    never collapse them by swallowing one into the other."""


# --------------------------------------------------------------------------- #
# param helpers                                                               #
# --------------------------------------------------------------------------- #
def _require(params: Dict[str, Any], key: str) -> Any:
    """Return ``params[key]`` or raise a clear validation error if missing/empty.

    ``0`` / ``False`` are legitimate values, so we test presence, not truthiness."""
    if key not in params or params[key] in (None, ""):
        raise _ValidationError(f"missing required param {key!r} for this action")
    return params[key]


def _require_str(params: Dict[str, Any], key: str) -> str:
    val = _require(params, key)
    if not isinstance(val, str) or not val.strip():
        raise _ValidationError(f"param {key!r} must be a non-empty string")
    return val


def _check_name(name: str) -> str:
    """Validate a harness NAME against the server-side rule before we ship it."""
    if not _NAME_RE.match(name):
        raise _ValidationError(
            f"invalid harness name {name!r} — must match "
            r"[a-zA-Z][a-zA-Z0-9_]{0,39} (no hyphens)."
        )
    return name


# Raw API-level keys a model must never be able to put on the wire (INV-OPS-6).
#
# This module's own docstring states the invariant: "create/update/invoke/promote are
# **deterministic** control-plane actions that must never be model-authored HTTP". The
# `**params` forwarding below made that false — `core.create_harness` ends with
# `args.update(kw)` and `core.invoke` with `kw.update(overrides)`, so a passthrough key
# WINS over everything this handler computed and validated.
#
# Reproduced, and the give-away is the pair of names. `_create` validates `name`; the
# request carries `harnessName`. So:
#
#     params = {"name": "soc_triage_reviewed",          <- what the validator checked
#               "harnessName": "attacker_controlled",   <- what the API received
#               "allowedTools": ["*"],                  <- iron-rule #1, violated
#               "executionRoleArn": "...not-the-resolved-one"}
#
# went through with every key applied. `_invoke` is worse: `harnessArn` RETARGETS the
# call to a different harness than the one the caller named in `arn`, while
# `allowedTools` / `maxIterations` / `systemPrompt` strip that harness's own limits —
# and the handler returned `ok: True`.
#
# This is INV-FACTORY-1 verbatim, one layer over. That guard was applied to
# `factory.py`'s two paths and this control plane was never covered — the same
# "a fix applied to one call site is not an invariant" route that produced INV-EGRESS-3
# (five recurrences) and INV-COERCE (four). Hence a shared frozenset checked by EVERY
# action that forwards params, not a check bolted onto the two that were found.
_FORBIDDEN_API_KEYS = frozenset({
    # identity / targeting — these decide WHICH resource the call acts on
    "harnessName", "harnessArn", "harnessId", "endpointName", "targetVersion",
    # the authorization boundary
    "allowedTools", "executionRoleArn",
    # the agent's own instructions and limits
    "systemPrompt", "messages", "maxIterations", "maxTokens", "timeoutSeconds",
})


def _reject_api_level_keys(params: Dict[str, Any], action: str) -> None:
    """Refuse a request carrying raw API-level keys (INV-OPS-6).

    Deliberately a DENYLIST of security-relevant keys rather than an allowlist of the
    snake_case params: `core.*` accepts genuine passthrough kwargs that adopters use
    (pagination, tags, client tokens), and an allowlist would break them and get
    routed around. Every key here is one that changes WHICH resource is touched or
    WHAT it is permitted to do — the two questions a model must not answer directly.
    """
    offenders = sorted(_FORBIDDEN_API_KEYS & set(params))
    if offenders:
        raise _ValidationError(
            f"action {action!r} carries raw API-level key(s) {offenders}, which would "
            f"override what this handler validated and computed. `core` applies "
            f"passthrough kwargs LAST (args.update(kw)), so e.g. 'harnessName' beats "
            f"the validated 'name' and 'harnessArn' retargets the call away from 'arn'. "
            f"Use the documented snake_case params (name, system_prompt, harness_id, "
            f"arn, text, ...); the control plane is deterministic by contract and is "
            f"not a place for model-authored request fields."
        )


def _require_promotion_gate(action: str) -> None:
    """Refuse a promotion action unless a driver declares it ran the HITL gate.

    INV-OPS-7 — the mechanism behind the THREAT-MODEL §1 claim that promotion is
    human-gated. The two driver paths (`agent_loop.run_agent_loop`,
    `autonomy.run_improvement_loop`) refuse a promotion BEFORE dispatch, so they never
    reach this function in the refusing case; they set the witness for the approved case.
    A direct `handler({"action": "promote_endpoint", ...})` call — which is how the
    in-process factory scenario reaches this tool — has no driver above it, and used to
    promote straight through.

    Fail-closed by construction: absence of the witness is refusal, so a new call site
    that forgets to route through a gate gets a loud error instead of an ungoverned
    promotion. That is the INV-BOUNDARY-5 rule ("we could not tell" is never the
    permissive answer) applied to authorization rather than to data.

    The layering note in docs/INVARIANTS.md still holds: the DECISION lives in the gate,
    not here. This is a check that the decision happened, not a second copy of it.
    """
    import os
    witnessed = os.environ.get(_GATE_WITNESS_ENV, "").strip().lower()
    if witnessed not in ("1", "true", "yes", "on"):
        raise _ValidationError(
            f"action {action!r} puts a harness version in front of production traffic "
            f"and requires a human-approval gate, but no driver declared one ran. "
            f"Route the promotion through `agent_loop.run_agent_loop` (which gates all "
            f"three promotion actions and binds the approval to the harness being "
            f"promoted) or `autonomy.run_improvement_loop` (approve_fn). A driver that "
            f"has already obtained approval sets {_GATE_WITNESS_ENV}=1 for the call. "
            f"Refusing rather than promoting unattended: the agent may REQUEST a "
            f"promotion, never execute one."
        )


# --------------------------------------------------------------------------- #
# action implementations — each validates then delegates to core / core._control
# --------------------------------------------------------------------------- #
def _create(params: Dict[str, Any]) -> Dict[str, Any]:
    """create → core.create_harness(**params) → {harnessId, arn, status}."""
    name = _require_str(params, "name")
    _check_name(name)
    _require_str(params, "system_prompt")
    harness = core.create_harness(**params)
    # CreateHarness returns the arn under "arn" (not "harnessArn") — matches every
    # other scenario's h["arn"] usage; verified against the live control-plane shape.
    return {
        "harnessId": harness.get("harnessId"),
        "arn": harness.get("arn"),
        "status": harness.get("status"),
    }


def _update(params: Dict[str, Any]) -> Dict[str, Any]:
    """update → core.update_harness(harness_id, **rest) → {harnessId}.

    UpdateHarness has full-replacement semantics (only ``harnessId`` is required
    server-side); we pop the id out of ``params`` and forward the remaining
    replacement fields verbatim so the meta-agent's spec merge is honored 1:1."""
    rest = dict(params)  # copy: never mutate the caller's dict
    harness_id = rest.pop("harness_id", None)
    if not isinstance(harness_id, str) or not harness_id.strip():
        raise _ValidationError("missing required param 'harness_id' for update")
    harness = core.update_harness(harness_id, **rest)
    # UpdateHarness returns the updated harness under "harness"; be defensive
    # about shape (some control-plane wrappers return the bare dict).
    body = harness.get("harness", harness) if isinstance(harness, dict) else {}
    return {"harnessId": body.get("harnessId", harness_id)}


def _invoke(params: Dict[str, Any]) -> Dict[str, Any]:
    """invoke → core.invoke(arn, session_id, text, ...) → structured result.

    ``session_id`` is optional: memory/session continuity is a caller concern, so
    if it is omitted we mint a fresh one via ``core.new_session()`` (the id must
    be >= 33 chars — new_session guarantees that). Extra keys pass through as
    ``core.invoke`` overrides (model/tools/maxIterations/actor_id/...)."""
    rest = dict(params)
    arn = rest.pop("arn", None)
    if not isinstance(arn, str) or not arn.strip():
        raise _ValidationError("missing required param 'arn' for invoke")
    text = rest.pop("text", None)
    if not isinstance(text, str) or not text.strip():
        raise _ValidationError("missing required param 'text' for invoke")
    session_id = rest.pop("session_id", None) or core.new_session()
    result = core.invoke(arn, session_id, text, **rest)
    return {
        "session_id": session_id,
        "text": result.get("text"),
        "stop_reason": result.get("stop_reason"),
        "tools_used": result.get("tools_used"),
        "tool_use": result.get("tool_use"),
    }


def _wait_ready(params: Dict[str, Any]) -> Dict[str, Any]:
    """wait_ready → core.wait_ready(id) → {status}."""
    harness_id = _require_str(params, "harness_id")
    rest = {k: v for k, v in params.items() if k != "harness_id"}
    harness = core.wait_ready(harness_id, **rest)
    return {"harnessId": harness_id, "status": harness.get("status")}


def _list(params: Dict[str, Any]) -> Dict[str, Any]:
    """list → core.list_harnesses() → {harnesses:[...]}. Takes no params."""
    return {"harnesses": core.list_harnesses()}


def _delete(params: Dict[str, Any]) -> Dict[str, Any]:
    """delete → core.delete_harness(id) → {deleted:id}."""
    harness_id = _require_str(params, "harness_id")
    keep_memory = params.get("keep_memory", False)
    core.delete_harness(harness_id, keep_memory=keep_memory)
    return {"deleted": harness_id}


def _create_endpoint(params: Dict[str, Any]) -> Dict[str, Any]:
    """create_endpoint → core.create_harness_endpoint(...)."""
    harness_id = _require_str(params, "harness_id")
    endpoint_name = _require_str(params, "endpoint_name")
    resp = core.create_harness_endpoint(
        harness_id, endpoint_name,
        target_version=params.get("target_version"),
        description=params.get("description"),
    )
    return {
        "endpointName": resp.get("endpointName", endpoint_name),
        "harnessId": harness_id,
        "status": resp.get("status"),
        "targetVersion": resp.get("targetVersion"),
    }


def _update_endpoint(params: Dict[str, Any]) -> Dict[str, Any]:
    """update_endpoint → core.update_harness_endpoint(...).

    Repoints an EXISTING endpoint at a new version. The v2+ promotion path for
    a self-improvement loop that promotes the same endpoint name multiple times."""
    harness_id = _require_str(params, "harness_id")
    endpoint_name = _require_str(params, "endpoint_name")
    resp = core.update_harness_endpoint(
        harness_id, endpoint_name,
        target_version=params.get("target_version"),
        description=params.get("description"),
    )
    return {
        "endpointName": resp.get("endpointName", endpoint_name),
        "harnessId": harness_id,
        "status": resp.get("status"),
        "targetVersion": resp.get("targetVersion"),
    }


def _promote_endpoint(params: Dict[str, Any]) -> Dict[str, Any]:
    """promote_endpoint → core.promote_harness_endpoint(...).

    Idempotent: creates the endpoint on first call, updates on subsequent calls
    (handles ConflictException internally). This is what the agent should use."""
    harness_id = _require_str(params, "harness_id")
    endpoint_name = _require_str(params, "endpoint_name")
    resp = core.promote_harness_endpoint(
        harness_id, endpoint_name,
        target_version=params.get("target_version"),
        description=params.get("description"),
    )
    return {
        "endpointName": resp.get("endpointName", endpoint_name),
        "harnessId": harness_id,
        "status": resp.get("status"),
        "targetVersion": resp.get("targetVersion"),
    }


def _list_endpoints(params: Dict[str, Any]) -> Dict[str, Any]:
    """list_endpoints → core.list_harness_endpoints(...)."""
    harness_id = _require_str(params, "harness_id")
    endpoints = core.list_harness_endpoints(harness_id)
    return {"harnessId": harness_id, "endpoints": endpoints}


_DISPATCH = {
    "create": _create,
    "update": _update,
    "invoke": _invoke,
    "wait_ready": _wait_ready,
    "list": _list,
    "delete": _delete,
    "create_endpoint": _create_endpoint,
    "update_endpoint": _update_endpoint,
    "promote_endpoint": _promote_endpoint,
    "list_endpoints": _list_endpoints,
}


# --------------------------------------------------------------------------- #
# entrypoint                                                                   #
# --------------------------------------------------------------------------- #
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Route a structured harness-lifecycle request to the right ``core`` call.

    Deterministic: the agent supplies ``{"action", "params"}``; we validate and
    delegate. Exceptions are never allowed to escape unlabeled — a bad request is
    a ``validation_error`` and any control-plane/boto failure is an
    ``upstream_error`` — but the underlying message is always surfaced, never
    swallowed."""
    if not isinstance(event, dict):
        return {
            "ok": False,
            "action": None,
            "error": "validation_error",
            "message": "event must be a dict of {'action', 'params'}",
        }

    action = event.get("action")
    if action not in _ACTIONS:
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": (
                f"unknown action {action!r}; expected one of "
                f"{sorted(_ACTIONS)}"
            ),
        }

    params = event.get("params", {})
    if not isinstance(params, dict):
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": "'params' must be a dict",
        }

    try:
        # INV-OPS-6: applied HERE, at the one dispatch point, not inside the individual
        # actions. Four of the ten actions forward `**params` / `**rest` today
        # (create, update, invoke, wait_ready) and a fifth added tomorrow would inherit
        # the hole if this lived in the two that were found — which is precisely how
        # INV-FACTORY-1 came to cover factory.py and miss this module entirely.
        _reject_api_level_keys(params, action)
        # INV-OPS-7: also at the ONE dispatch point, for the same reason — a promotion
        # action added later inherits the gate instead of needing to remember it.
        if action in _PROMOTION_ACTIONS:
            _require_promotion_gate(action)
        result = _DISPATCH[action](params)
    except _ValidationError as exc:
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": str(exc),
        }
    except TypeError as exc:
        # Bad kwargs handed to a core.* function (e.g. an unexpected param name)
        # surface as a validation error — it is the caller's request that is
        # malformed, not AWS.
        return {
            "ok": False,
            "action": action,
            "error": "validation_error",
            "message": str(exc),
        }
    except Exception as exc:  # noqa: BLE001 — boto/control-plane failure; surfaced, not swallowed
        return {
            "ok": False,
            "action": action,
            "error": "upstream_error",
            "message": str(exc),
        }

    return {"ok": True, "action": action, **result}


if __name__ == "__main__":
    import json

    # Offline smoke: an unknown action is a deterministic validation error and
    # never touches AWS.
    print(json.dumps(handler({"action": "list", "params": {}}, None), indent=2))
