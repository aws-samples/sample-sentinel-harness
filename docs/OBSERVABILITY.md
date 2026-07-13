# Observability

How `sentinel-harness` logs, meters, and traces — and the honest status of each.

## Overview: two channels, kept separate

The library keeps **two output channels** deliberately distinct so wiring one never
pollutes the other:

| Channel | Goes to | Carries | Produced by |
|---|---|---|---|
| **stdout** | the terminal | the human-readable scenario narrative (what a user reads) | scenario `print()` |
| **stderr** | logs / CloudWatch | structured operational logs + metric lines | `sentinel_harness.logutil` + `observability` |

A scenario keeps printing its human output; operational logging and metering ride on
stderr and structured log lines. Tests and demos that parse scenario stdout are never
disturbed by logging.

## Logging (`sentinel_harness.logutil`)

Library code gets a namespaced logger and logs at the right level; it never configures
handlers at import time (a library must not hijack its host's logging).

```python
from sentinel_harness import get_logger, configure_logging

configure_logging()                 # app entry point: sets level + one handler (idempotent)
log = get_logger(__name__)          # library/module code: just get a logger
log.warning("cleanup: skip harness %s: %s", name, err)
```

- `get_logger(name="sentinel_harness")` — returns a logger under the `sentinel_harness`
  root, so a single `configure_logging()` governs everything the library emits. A bare
  `__name__` is reparented under the root.
- `configure_logging(level=None, *, json=None, stream=sys.stderr)` — **idempotent**
  (attaches exactly one handler), defaults to **stderr**, and under AWS Lambda
  (`AWS_LAMBDA_FUNCTION_NAME` set) adds **no** handler — the Lambda runtime's root
  handler already ships records to CloudWatch, so this prevents double emission.

### Env flags

| Env var | Default | Effect |
|---|---|---|
| `SENTINEL_LOG_LEVEL` | `INFO` | Logger level (`DEBUG`/`INFO`/`WARNING`/…). An unknown value falls back to `INFO` rather than crashing. |
| `SENTINEL_LOG_JSON` | off (text) | Truthy → one-line JSON records for ingestion; else compact human text. |

A JSON record (with any `extra=` fields attached by the caller):

```json
{"ts": "2026-07-12T18:58:11+0800", "level": "WARNING", "logger": "sentinel_harness.gateway", "msg": "cleanup: skip gateway sentinel-a: in use", "scenario": "cve"}
```

## Metrics (`sentinel_harness.observability`)

Metrics are emitted as **structured log lines** a CloudWatch `MetricFilter` turns into
a metric — **zero AWS by default** (a line is just written via `log`; no boto3 client
is built). The `iac-cdk/lib/observability-stack.ts` stack provisions the filter,
dashboard, and budget.

The load-bearing contract (unchanged since M11): the token line carries a numeric
`$.tokens` field where `tokens == input_tokens + output_tokens`, and the MetricFilter
keys on `$.tokens`.

### Signals and their metric fields (`METRIC_FIELDS`)

| Log field (`$.<field>`) | Metric name | Emitter |
|---|---|---|
| `tokens` | `TokensPerScenario` | `emit_token_metric` / `emit_token_metric_from_result` |
| `latency_ms` | `InvokeLatencyMs` | `emit_invoke_latency` |
| `tool_calls` | `ToolCallsPerInvoke` | `emit_tool_calls` |
| `errors` | `InvokeErrors` | `emit_error` (tagged `kind`: throttle/validation/internal) |
| `hitl_gate` | `HitlGateHits` | `emit_hitl_gate` (tagged with the gate tool) |
| `eval_score` | `EvalScore` | `emit_eval_score` (tagged `dimension`, `passed`) |

### One call meters an invoke: `core.invoke_and_meter`

The token metric used to have **no runtime emitter** — the graph was permanently flat.
`invoke_and_meter` closes that: it wraps `invoke()`, times it, and emits the token,
latency, tool-call, and (on failure) error signals in one call. Metering is **silent on
stdout** — it defaults to the `sentinel_harness.telemetry` logger — so scenarios keep
printing their own human output.

```python
from sentinel_harness import invoke_and_meter

result = invoke_and_meter(harness_arn, session_id, prompt, scenario="cve_triage")
# emits: TokensPerScenario, InvokeLatencyMs, ToolCallsPerInvoke
# on a botocore throttle it emits InvokeErrors(kind="throttle") and re-raises (never swallows)
```

### Direct PutMetricData (opt-in, gated)

By default nothing calls AWS. Set `SENTINEL_TOKEN_METRIC_LIVE=1` to *also* do a direct
`PutMetricData` into the `SentinelHarness` namespace. This is gated because the
least-privilege execution role scopes `PutMetricData` to `bedrock-agentcore`; a direct
emit needs a widened role (see `iac-cdk/lib/iam.ts` / the CDK stack docstring). The
MetricFilter path (structured log line) is preferred and needs no IAM change.

## Tracing (OTEL / GenAI spans)

**Honest status:** the library does **not** yet emit OpenTelemetry spans from code. What
*is* proven live is the managed path on top of CloudWatch **Transaction Search**:

- `evidence/live_online_evaluation_result.json` — an `OnlineEvaluationConfig` is ACTIVE,
  sampling 100% of AgentCore GenAI sessions from the Transaction Search `aws/spans`
  source and scoring each with built-in **Faithfulness** (groundedness) + **Harmfulness**
  (safety) + **Coherence** evaluators.

To enable that path (one-time, account-level):

1. Put a CloudWatch Logs resource policy granting `xray.amazonaws.com`
   `logs:PutLogEvents` + `logs:CreateLogStream` on `aws/spans`.
2. `xray:UpdateTraceSegmentDestination(Destination=CloudWatchLogs)` — this creates the
   `aws/spans` log group.
3. `xray:UpdateIndexingRule` → 100% sampling.
4. `CreateOnlineEvaluationConfig` with `dataSourceConfig.cloudWatchLogs.logGroupNames = ["aws/spans"]`
   and reference-free `Builtin.*` evaluators.

Emitting OTEL/GenAI spans directly from an invoke (a `SENTINEL_OTEL` code path) is a
documented **future** item, not shipped.

## Env-flag reference

| Env var | Default | Purpose |
|---|---|---|
| `SENTINEL_LOG_LEVEL` | `INFO` | Logger level |
| `SENTINEL_LOG_JSON` | off | JSON vs text log records |
| `SENTINEL_TOKEN_METRIC_LIVE` | off | Opt-in direct `PutMetricData` (needs a widened role) |
| `SENTINEL_REGION` | `us-east-1` | Region for any AWS client |

## Viewing it

- **CloudWatch dashboard + budget** — provisioned by the observability CDK stack; the
  token/latency/error metrics land there once scenarios run through `invoke_and_meter`
  and the metric lines reach the scenario LogGroup.
- **Locally** — scenarios still print their human narrative to stdout regardless of
  logging; set `SENTINEL_LOG_LEVEL=DEBUG` to see the library's operational detail on
  stderr.
