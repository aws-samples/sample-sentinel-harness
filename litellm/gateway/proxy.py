"""
litellm.gateway.proxy — single model entry-point + audit hook (skeleton)
========================================================================
A provider-agnostic **inference gateway**: one place a specialist (or any caller)
points at instead of talking to a model provider directly, so every completion
flows through one audited chokepoint.

What this gives you
-------------------
- **One entry-point** — :meth:`InferenceGateway.complete` (and the module-level
  :func:`complete` convenience). Provider-agnostic because the model id is a
  LiteLLM provider-prefixed id (``bedrock/...``, ``openai/...``, ``anthropic/...``)
  resolved through ``strands.models.litellm.LiteLLMModel``. Swapping providers is
  a config/env change, not a code change (12-factor).
- **A request/response AUDIT hook** — every call emits ONE structured log record
  (:func:`build_audit_record`) capturing *model + token usage + latency + status*
  and **never any secret or message content**. This is the observability seam a
  supervisor/SecOps deployment needs (cost attribution, anomaly detection) without
  leaking prompts, completions, API keys, or headers into logs.

Why the imports are guarded
---------------------------
``litellm`` / ``strands`` are heavy, platform-specific runtime deps that are NOT
needed to inspect or test the skeleton (audit-record shape, the entry-point
contract). They are imported lazily inside :meth:`InferenceGateway._model` so this
module is always importable — CI stays green without ``litellm`` installed, and
the audit record is verifiable offline. The real dep is only touched when you
actually run a completion.

Configuration (12-factor — no hardcoded account / ARN / model / key)
--------------------------------------------------------------------
    export SENTINEL_GATEWAY_MODEL="bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
    # provider credentials are read by LiteLLM from the standard env vars
    # (AWS_*, OPENAI_API_KEY, ...) — this module NEVER reads or logs them.

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

# The LiteLLM model id. Provider-prefixed so the gateway is provider-agnostic; read
# from env (12-factor). Default is a small Bedrock model routed through LiteLLM.
DEFAULT_MODEL_ID = os.environ.get(
    "SENTINEL_GATEWAY_MODEL", "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
)

# Dedicated audit logger. Callers can attach a handler / ship it to CloudWatch; we
# never configure global logging here (library-friendly). The record is emitted at
# INFO with a structured ``extra={"audit": {...}}`` payload plus a compact message.
_audit_log = logging.getLogger("sentinel.litellm.gateway.audit")

# Field names we consider secret-ish and will NEVER copy into an audit record. This
# is belt-and-suspenders: the builder already whitelists only non-sensitive fields,
# but we keep an explicit denylist so a future edit can't accidentally leak one.
_SECRET_HINT_KEYS = frozenset({
    "api_key", "apikey", "authorization", "auth", "token", "secret",
    "password", "aws_secret_access_key", "aws_session_token", "messages",
    "prompt", "input", "content", "headers",
})


def _usage_field(usage: Any, key: str) -> int | None:
    """Pull a token count from a LiteLLM/OpenAI-style usage object or dict.

    LiteLLM returns an OpenAI-shaped ``usage`` that may be a dict or an attribute
    object across versions, so we probe both without importing anything."""
    if usage is None:
        return None
    if isinstance(usage, dict):
        val = usage.get(key)
    else:
        val = getattr(usage, key, None)
    return int(val) if isinstance(val, (int, float)) else None


def build_audit_record(
    *,
    model_id: str,
    usage: Any = None,
    latency_ms: float | None = None,
    status: str = "ok",
    error_type: str | None = None,
) -> dict:
    """Build the structured audit record for one inference call.

    Captures ONLY non-sensitive telemetry: the model id, token usage
    (prompt/completion/total), latency, and outcome. It deliberately does NOT
    accept — and cannot emit — messages, prompts, completions, headers, API keys,
    or any provider credential. That is the whole point of the audit seam: it is
    safe to ship to a shared log sink.

    Returns a flat JSON-serializable dict."""
    record: dict[str, Any] = {
        "event": "inference",
        "model": model_id,
        "prompt_tokens": _usage_field(usage, "prompt_tokens"),
        "completion_tokens": _usage_field(usage, "completion_tokens"),
        "total_tokens": _usage_field(usage, "total_tokens"),
        "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
        "status": status,
    }
    if error_type is not None:
        # Only the exception *type name* — never the message, which can echo inputs.
        record["error_type"] = error_type
    # Hard guard: strip anything that ever looks secret-ish, no matter how it got in.
    return {k: v for k, v in record.items() if k.lower() not in _SECRET_HINT_KEYS}


def audit_record(record: dict) -> None:
    """Emit one audit record through the dedicated audit logger (INFO).

    Kept separate from :func:`build_audit_record` so callers/tests can build a
    record without emitting, and swap the sink by configuring the
    ``sentinel.litellm.gateway.audit`` logger."""
    _audit_log.info("inference audit", extra={"audit": record})


class InferenceGateway:
    """Single, audited, provider-agnostic model entry-point.

    Construct once (``InferenceGateway(model_id=..., audit_sink=...)``) and call
    :meth:`complete` for every inference. Each call is wrapped so exactly one audit
    record is emitted on both success and failure. The heavy ``litellm`` model is
    lazily constructed on first use, so constructing the gateway (and importing
    this module) never requires ``litellm``.
    """

    def __init__(
        self,
        *,
        model_id: str | None = None,
        audit_sink: Callable[[dict], None] = audit_record,
    ) -> None:
        self.model_id = model_id or DEFAULT_MODEL_ID
        # Injectable sink keeps the audit path unit-testable with zero logging config.
        self._audit_sink = audit_sink
        self._model_obj = None  # lazily built LiteLLMModel

    def _model(self):
        """Lazily construct the ``LiteLLMModel``. Heavy deps imported HERE, not at
        module top, so import stays free of ``litellm`` / ``strands``."""
        if self._model_obj is None:
            from strands.models.litellm import LiteLLMModel  # type: ignore

            self._model_obj = LiteLLMModel(model_id=self.model_id)
        return self._model_obj

    def complete(self, messages: Any, **kwargs: Any):
        """Run one completion through the underlying provider and audit it.

        ``messages`` and ``kwargs`` are passed verbatim to the model; NEITHER is
        ever logged. Emits one audit record (model + tokens + latency + status) on
        success, and one with ``status="error"`` (plus the exception *type*) before
        re-raising on failure — we never swallow the error."""
        t0 = time.perf_counter()
        try:
            result = self._model().converse(messages, **kwargs) if hasattr(
                self._model(), "converse"
            ) else self._model()(messages, **kwargs)
        except Exception as exc:  # noqa: BLE001 — audited then re-raised, not swallowed
            self._audit_sink(build_audit_record(
                model_id=self.model_id,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                status="error",
                error_type=type(exc).__name__,
            ))
            raise
        self._audit_sink(build_audit_record(
            model_id=self.model_id,
            usage=_extract_usage(result),
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            status="ok",
        ))
        return result


def _extract_usage(result: Any) -> Any:
    """Best-effort pull of the ``usage`` block from a model result (dict or object)
    across LiteLLM/Strands shapes. Returns ``None`` if absent (audit still emits,
    with null token fields)."""
    if result is None:
        return None
    if isinstance(result, dict):
        return result.get("usage") or (result.get("metadata") or {}).get("usage")
    return getattr(result, "usage", None)


# Module-level convenience: a process-wide default gateway for simple callers.
_default_gateway: InferenceGateway | None = None


def complete(messages: Any, *, model_id: str | None = None, **kwargs: Any):
    """Convenience entry-point using a lazily-created default gateway.

    A specialist can point at the gateway with a one-liner
    (``from litellm.gateway import complete``) instead of managing a
    ``LiteLLMModel``. Pass ``model_id`` to override the env default for one call."""
    global _default_gateway
    if model_id is not None:
        return InferenceGateway(model_id=model_id).complete(messages, **kwargs)
    if _default_gateway is None:
        _default_gateway = InferenceGateway()
    return _default_gateway.complete(messages, **kwargs)
