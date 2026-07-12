/**
 * observability-stack.test.ts - synth assertions for the ObservabilityStack.
 * ==========================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * `aws-cdk-lib/assertions` (Template.fromStack) + Node's built-in `assert`,
 * runnable with `npx ts-node test/observability-stack.test.ts`. Exits non-zero on
 * the first failed assertion so it can gate a build.
 *
 * Coverage — the golden-signal observability surface:
 *   - THREE MetricFilters over the scenario LogGroup, each extracting a numeric
 *     structured-log field the sentinel_harness.observability emitters produce:
 *       * $.tokens      -> TokensPerScenario
 *       * $.latency_ms  -> InvokeLatencyMs
 *       * $.errors      -> InvokeErrors
 *   - TWO CloudWatch Alarms (p90 latency, invoke error volume), both
 *     treatMissingData=notBreaching so an idle account stays green.
 *   - A dashboard exists.
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { ObservabilityStack } from "../lib/observability-stack";

const APP_NAME = "sentinel";

function synth(): Template {
  const app = new App();
  const stack = new ObservabilityStack(app, "sentinel-observability", {
    appName: APP_NAME,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

function testMetricFilters(t: Template): void {
  // Three metric filters: tokens (existing) + latency + errors (new golden signals).
  t.resourceCountIs("AWS::Logs::MetricFilter", 3);
  for (const [pattern, metric] of [
    ['{ $.tokens = "*" }', "TokensPerScenario"],
    ['{ $.latency_ms = "*" }', "InvokeLatencyMs"],
    ['{ $.errors = "*" }', "InvokeErrors"],
  ] as const) {
    t.hasResourceProperties("AWS::Logs::MetricFilter", {
      FilterPattern: pattern,
      MetricTransformations: Match.arrayWith([
        Match.objectLike({ MetricName: metric, MetricNamespace: "SentinelHarness" }),
      ]),
    });
  }
}

function testAlarms(t: Template): void {
  t.resourceCountIs("AWS::CloudWatch::Alarm", 2);
  // p90 latency alarm — the p90 statistic makes CDK render the metric under
  // Metrics[].MetricStat.Metric (not a top-level MetricName), so match there.
  t.hasResourceProperties("AWS::CloudWatch::Alarm", {
    AlarmName: `${APP_NAME}-invoke-latency-p90`,
    ComparisonOperator: "GreaterThanThreshold",
    TreatMissingData: "notBreaching",
    Metrics: Match.arrayWith([
      Match.objectLike({
        MetricStat: Match.objectLike({
          Stat: "p90",
          Metric: Match.objectLike({ MetricName: "InvokeLatencyMs", Namespace: "SentinelHarness" }),
        }),
      }),
    ]),
  });
  // Error-volume alarm — a labelled metric also renders under Metrics[].MetricStat.
  t.hasResourceProperties("AWS::CloudWatch::Alarm", {
    AlarmName: `${APP_NAME}-invoke-errors`,
    ComparisonOperator: "GreaterThanThreshold",
    TreatMissingData: "notBreaching",
    Metrics: Match.arrayWith([
      Match.objectLike({
        MetricStat: Match.objectLike({
          Metric: Match.objectLike({ MetricName: "InvokeErrors", Namespace: "SentinelHarness" }),
        }),
      }),
    ]),
  });
}

function testDashboard(t: Template): void {
  t.resourceCountIs("AWS::CloudWatch::Dashboard", 1);
}

function main(): void {
  const t = synth();
  testMetricFilters(t);
  testAlarms(t);
  testDashboard(t);
  // eslint-disable-next-line no-console
  console.log("observability-stack.test.ts: OK (3 metric filters, 2 alarms, 1 dashboard)");
}

try {
  main();
} catch (e) {
  // eslint-disable-next-line no-console
  console.error("observability-stack.test.ts FAILED:", e);
  process.exit(1);
}
assert.ok(true);
