"""
sentinel-harness · observability helper
========================================
Emit the ``SentinelHarness/TokensPerScenario`` signal that the CDK
``ObservabilityStack`` (``iac-cdk/lib/observability-stack.ts``) already keys on.

WHY this module exists
----------------------
Every harness invoke returns a ``metadata`` stream event carrying model token
``usage`` (``core._consume_stream`` now surfaces it as ``result["usage"]``). The
CDK stack provisions two emit paths for the ``SentinelHarness/TokensPerScenario``
metric, but nothing was actually *emitting* it — so the dashboard graph was
permanently flat. This helper closes that gap.

Two emit paths (matching the CDK stack):
  1. **(default) a structured JSON log line** the CloudWatch ``MetricFilter``
     turns into the metric. The filter uses ``FilterPattern.exists("$.tokens")``
     with ``metricValue: "$.tokens"`` — so the line MUST carry a numeric
     ``tokens`` field, and by contract ``tokens == input_tokens + output_tokens``.
     This path is **zero AWS**: it just writes a line (default ``print`` →
     stdout; pass ``log=`` to route to the scenario LogGroup). No IAM widening.
  2. **(opt-in) direct ``PutMetricData``** behind the ``SENTINEL_TOKEN_METRIC_LIVE``
     env flag. This is GATED and NOT exercised offline: the client is built only
     when the flag is truthy. Per the CDK/IAM notes, a direct emit into the
     ``SentinelHarness`` namespace is DENIED until the execution role is widened
     (the least-privilege policy scopes ``PutMetricData`` to ``bedrock-agentcore``),
     so the MetricFilter path is preferred. The flag exists so a widened-role
     deployment can turn it on without a code change.

Nothing here is customer- or company-specific.
"""
from __future__ import annotations

import json
import os

# --- Kept in lockstep with iac-cdk/lib/observability-stack.ts (METRIC_NAMESPACE /
#     TOKENS_METRIC_NAME). Change both together or the metric/dashboard drift. ---
METRIC_NAMESPACE = "SentinelHarness"
TOKENS_METRIC_NAME = "TokensPerScenario"

# Env flag gating the opt-in direct PutMetricData path. Default OFF => zero AWS.
LIVE_ENV_FLAG = "SENTINEL_TOKEN_METRIC_LIVE"

_TRUTHY = {"1", "true", "yes", "on"}


def _live_enabled() -> bool:
    """True iff the opt-in direct-PutMetricData path is explicitly turned on."""
    return os.environ.get(LIVE_ENV_FLAG, "").strip().lower() in _TRUTHY


def token_metric_line(scenario: str, input_tokens, output_tokens, **extra) -> dict:
    """Build the EXACT structured dict the CDK ``MetricFilter`` parses.

    The MetricFilter extracts ``$.tokens`` as the metric value, so ``tokens`` is
    the load-bearing key and — by contract — equals ``input_tokens + output_tokens``.
    ``input_tokens``/``output_tokens`` are kept alongside for human-readable log
    forensics. ``None`` counts coerce to 0 so a partial/errored invoke still emits a
    well-formed (zero-token) line instead of crashing. ``extra`` merges in any extra
    structured fields (e.g. ``session_id``) without displacing the required keys."""
    it = int(input_tokens or 0)
    ot = int(output_tokens or 0)
    line = {
        "scenario": scenario,
        "tokens": it + ot,      # <- the field the MetricFilter keys on ($.tokens)
        "input_tokens": it,
        "output_tokens": ot,
    }
    line.update(extra)
    # Guard: extra must never clobber the metric contract.
    line["tokens"] = it + ot
    return line


def emit_token_metric(scenario: str, input_tokens, output_tokens, *, log=print, **extra) -> dict:
    """Emit the ``SentinelHarness/TokensPerScenario`` signal for one scenario run.

    Writes the EXACT JSON line the CloudWatch ``MetricFilter`` turns into the metric
    (``tokens == input_tokens + output_tokens``) via ``log`` (default ``print`` →
    stdout; pass a logger/sink bound to the scenario LogGroup to feed the filter).
    **Zero AWS by default.**

    If ``SENTINEL_TOKEN_METRIC_LIVE`` is truthy, ALSO does a gated, opt-in direct
    ``PutMetricData`` — this builds a boto3 client and is therefore never reached
    offline (the flag is unset in tests). Returns the emitted dict so callers/tests
    can assert on it."""
    line = token_metric_line(scenario, input_tokens, output_tokens, **extra)
    log(json.dumps(line, ensure_ascii=False))
    if _live_enabled():  # gated: opt-in, requires a WIDENED execution role
        put_metric(line["tokens"], scenario=scenario)
    return line


def emit_token_metric_from_result(scenario: str, result: dict, *, log=print, **extra) -> dict:
    """Convenience bridge: pull token ``usage`` straight out of an ``invoke(...)`` /
    ``_consume_stream(...)`` result and emit it.

    ``core._consume_stream`` surfaces usage as ``result["usage"]`` (also reachable via
    ``result["metadata"]["usage"]``); this reads either shape, defaulting to a
    zero-token line when a run produced no usage metadata (e.g. an errored/empty
    stream). The GA usage keys are ``inputTokens``/``outputTokens``."""
    usage = None
    if isinstance(result, dict):
        usage = result.get("usage")
        if usage is None:
            usage = (result.get("metadata") or {}).get("usage")
    usage = usage or {}
    return emit_token_metric(
        scenario, usage.get("inputTokens", 0), usage.get("outputTokens", 0), log=log, **extra
    )


def put_metric(tokens, *, scenario=None, region=None, client=None) -> dict:
    """Opt-in direct ``PutMetricData`` into ``SentinelHarness/TokensPerScenario``.

    GATED: only called by :func:`emit_token_metric` when ``SENTINEL_TOKEN_METRIC_LIVE``
    is truthy, and it lazily builds a ``cloudwatch`` client (``_control``-style: no
    module-import-time client, so nothing is constructed offline). Emitted
    DIMENSIONLESS to match the dashboard/MetricFilter metric exactly (the scenario is
    captured in the structured log line, not as a metric dimension). NOTE: this is
    denied until the execution role is widened (see iam.ts / the CDK stack docstring).

    ``client`` may be injected (tests) to avoid any real AWS; otherwise a client is
    built for ``region`` (default ``SENTINEL_REGION`` / us-east-1)."""
    if client is None:
        import boto3  # local import: never imported for the default (offline) path
        region = region or os.environ.get("SENTINEL_REGION", "us-east-1")
        client = boto3.client("cloudwatch", region_name=region)
    return client.put_metric_data(
        Namespace=METRIC_NAMESPACE,
        MetricData=[{
            "MetricName": TOKENS_METRIC_NAME,
            "Value": float(tokens),
            "Unit": "Count",
        }],
    )


# --------------------------------------------------------------------------- #
# Multi-signal emitters — same structured-log contract as the token metric,   #
# so one CloudWatch MetricFilter per field turns each into a metric. All are   #
# ZERO-AWS by default (they only write a JSON line via ``log``); the opt-in    #
# direct PutMetricData stays gated behind SENTINEL_TOKEN_METRIC_LIVE.          #
# --------------------------------------------------------------------------- #
# The metric-bearing field name each emitted line carries (the MetricFilter's
# ``$.<field>``). Kept here as the single source of truth for the CDK filters.
METRIC_FIELDS = {
    "tokens": "TokensPerScenario",
    "latency_ms": "InvokeLatencyMs",
    "tool_calls": "ToolCallsPerInvoke",
    "errors": "InvokeErrors",
    "hitl_gate": "HitlGateHits",
    "eval_score": "EvalScore",
}


def metric_line(name: str, value, *, scenario=None, unit="Count", **dims) -> dict:
    """Build a structured metric line: ``{"metric", <name>: value, "unit", ...dims}``.

    ``name`` is the load-bearing numeric field a CloudWatch ``MetricFilter`` keys on
    (``$.<name>``), mirroring the token line's ``$.tokens`` contract. ``scenario`` and
    any ``dims`` are attached for human forensics / metric dimensions. Non-finite or
    ``None`` values coerce to 0 so a partial/errored run still emits a well-formed
    line rather than crashing."""
    try:
        v = float(value)
        if v != v or v in (float("inf"), float("-inf")):  # NaN/inf -> 0
            v = 0.0
    except (TypeError, ValueError):
        v = 0.0
    line = {"metric": name, name: v, "unit": unit}
    if scenario is not None:
        line["scenario"] = scenario
    line.update(dims)
    line[name] = v  # dims must never clobber the metric-bearing field
    return line


def emit_metric(name: str, value, *, log=print, scenario=None, unit="Count", **dims) -> dict:
    """Emit one structured metric line via ``log`` (default ``print``). Zero AWS.

    The generic sibling of :func:`emit_token_metric` for any signal
    (latency/tool-calls/errors/...). Returns the emitted dict for assertions."""
    line = metric_line(name, value, scenario=scenario, unit=unit, **dims)
    log(json.dumps(line, ensure_ascii=False))
    return line


def emit_invoke_latency(scenario: str, ms, *, log=print, **dims) -> dict:
    """Emit invoke wall-clock latency in milliseconds (``$.latency_ms``)."""
    return emit_metric("latency_ms", ms, log=log, scenario=scenario, unit="Milliseconds", **dims)


def emit_tool_calls(scenario: str, n, *, log=print, **dims) -> dict:
    """Emit the number of tool calls a single invoke made (``$.tool_calls``)."""
    return emit_metric("tool_calls", n, log=log, scenario=scenario, **dims)


def emit_error(scenario: str, kind: str, *, log=print, **dims) -> dict:
    """Emit an error counter tagged by ``kind`` (throttle/validation/internal).

    Always value 1 (a count of one error occurrence); the ``kind`` rides along as a
    dimension so the dashboard can break errors down by class."""
    return emit_metric("errors", 1, log=log, scenario=scenario, kind=kind, **dims)


def emit_hitl_gate(scenario: str, tool_name: str, *, log=print, **dims) -> dict:
    """Emit a human-in-the-loop gate hit (``$.hitl_gate``), tagged with the gate tool."""
    return emit_metric("hitl_gate", 1, log=log, scenario=scenario, gate=tool_name, **dims)


def emit_eval_score(scenario: str, dimension: str, score, passed, *, log=print, **dims) -> dict:
    """Emit an evaluation score (``$.eval_score``) for one judged dimension.

    ``dimension`` (e.g. safety/groundedness) and ``passed`` ride as dimensions so a
    dashboard can trend per-dimension scores and pass-rate."""
    return emit_metric(
        "eval_score", score, log=log, scenario=scenario,
        dimension=dimension, passed=bool(passed), **dims,
    )
