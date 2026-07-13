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
    action ∈ {create, update, invoke, wait_ready, list, delete, create_endpoint}

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
    {"create", "update", "invoke", "wait_ready", "list", "delete", "create_endpoint"}
)


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
    """create_endpoint → core._control.create_harness_endpoint(...).

    ``core`` has no endpoint wrapper yet (M2 extends this tool with a promote
    action), so we call the boto3 control-plane client directly. Required by the
    API: ``harnessId`` + ``endpointName``; optional: ``targetVersion`` /
    ``description``. We forward only the documented optional fields so an unknown
    param is a local validation error, not an opaque boto ParamValidationError."""
    harness_id = _require_str(params, "harness_id")
    endpoint_name = _require_str(params, "endpoint_name")
    kw: Dict[str, Any] = {"harnessId": harness_id, "endpointName": endpoint_name}
    if params.get("target_version") is not None:
        kw["targetVersion"] = params["target_version"]
    if params.get("description") is not None:
        kw["description"] = params["description"]
    resp = core._control.create_harness_endpoint(**kw)
    body = resp if isinstance(resp, dict) else {}
    return {
        "endpointName": body.get("endpointName", endpoint_name),
        "harnessId": harness_id,
        "status": body.get("status"),
        "targetVersion": body.get("targetVersion"),
    }


_DISPATCH = {
    "create": _create,
    "update": _update,
    "invoke": _invoke,
    "wait_ready": _wait_ready,
    "list": _list,
    "delete": _delete,
    "create_endpoint": _create_endpoint,
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
