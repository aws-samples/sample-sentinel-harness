/**
 * ObservabilityStack - cost + token visibility for the Sentinel harness.
 * =======================================================================
 * WHY (docs/BLUEPRINT.md observability + core.py `_consume_stream` metadata): every
 * harness invoke emits a `metadata` stream event carrying model usage (token
 * counts). We surface that as a first-class custom CloudWatch metric so operators
 * can watch spend-shaped load per scenario, and we bound real dollar spend with an
 * AWS Budgets alarm. Three surfaces are provisioned:
 *
 *   1. A LogGroup for sentinel scenario runs - short retention + DESTROY removal so
 *      a non-prod account never accretes orphaned logs or cost.
 *   2. A custom metric namespace "SentinelHarness" with a `TokensPerScenario`
 *      metric. Two emit paths are offered so callers can pick whichever is cheaper
 *      operationally:
 *        - **(default) a MetricFilter on the LogGroup** that extracts a `tokens`
 *          field from a structured (JSON) log line - zero extra API calls,
 *          metric-from-logs, and it needs NO extra IAM. The `cloudwatch.Metric`
 *          below references this namespace/metric for the dashboard + alarm.
 *        - direct `PutMetricData` from the harness - only if you WIDEN the execution
 *          role: the least-privilege policy in `iam.ts` scopes `PutMetricData` to the
 *          `bedrock-agentcore` namespace (a `cloudwatch:namespace` condition), NOT
 *          `SentinelHarness`, so a direct emit into `SentinelHarness` is denied until
 *          the role is explicitly broadened. Prefer the MetricFilter path.
 *   3. A Dashboard (token trend graph + latest-value tile + a describing text
 *      panel) and a monthly cost `CfnBudget` (L1) that notifies an email at an 80%
 *      threshold.
 *
 * Everything is env/context-parameterised: account/region come from the standard
 * CDK environment (see bin/sentinel.ts), the budget amount and notification email
 * come from context with safe placeholder defaults. NOTHING is hardcoded.
 */
import {
  Stack,
  StackProps,
  CfnOutput,
  Duration,
} from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as logs from "aws-cdk-lib/aws-logs";
import * as budgets from "aws-cdk-lib/aws-budgets";
import { RemovalPolicy } from "aws-cdk-lib";
import { Construct } from "constructs";

/** Custom CloudWatch namespace all harness metrics live under. */
export const METRIC_NAMESPACE = "SentinelHarness";
/** The token-usage metric name (emitted per scenario run). */
export const TOKENS_METRIC_NAME = "TokensPerScenario";

export interface ObservabilityStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * Scenario log retention in days. Short by default (non-prod hygiene); raise for
   * real casework where run history must be kept longer.
   */
  readonly logRetentionDays?: number;
  /**
   * Monthly cost budget amount in USD (context `sentinel:budgetAmountUsd`, default
   * 50). Small on purpose - a non-prod tripwire, not a production allocation.
   */
  readonly budgetAmountUsd?: number;
  /**
   * Email to notify at the budget threshold (context `sentinel:budgetEmail`). A
   * placeholder default is used when unset so a plain synth stays green; override it
   * before deploy or the notification goes nowhere useful.
   */
  readonly budgetEmail?: string;
  /**
   * Notification threshold as a percentage of the budget (default 80). AWS notifies
   * when ACTUAL spend crosses this percentage of the budgeted amount.
   */
  readonly budgetThresholdPercent?: number;
}

export class ObservabilityStack extends Stack {
  /** LogGroup for sentinel scenario runs. */
  public readonly scenarioLogGroup: logs.LogGroup;
  /** The TokensPerScenario metric (references the SentinelHarness namespace). */
  public readonly tokensMetric: cloudwatch.Metric;
  /** The CloudWatch dashboard. */
  public readonly dashboard: cloudwatch.Dashboard;
  /** The monthly cost budget (L1). */
  public readonly budget: budgets.CfnBudget;

  constructor(scope: Construct, id: string, props: ObservabilityStackProps) {
    super(scope, id, props);

    const retentionDays = props.logRetentionDays ?? 7;
    const budgetAmountUsd = props.budgetAmountUsd ?? 50;
    const budgetThresholdPercent = props.budgetThresholdPercent ?? 80;
    // Placeholder default: valid syntactically, obviously-not-real so a deploy
    // without an override is caught in review. Overridden via context in practice.
    const budgetEmail = props.budgetEmail ?? "sentinel-budget-alerts@example.com";

    const budgetName = `${props.appName}-monthly-cost`;

    // --- 1. LogGroup for scenario runs (short retention, DESTROY for non-prod). ---
    this.scenarioLogGroup = new logs.LogGroup(this, "ScenarioLogGroup", {
      logGroupName: `/sentinel/${props.appName}/scenarios`,
      retention: mapRetention(retentionDays),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // --- 2a. The TokensPerScenario metric. This construct only *references* the
    // custom namespace/metric; the actual data points are published either by the
    // harness (PutMetricData from `_consume_stream` usage metadata) or by the
    // MetricFilter below. `Sum` over a 5-minute period reads as tokens-consumed. ---
    this.tokensMetric = new cloudwatch.Metric({
      namespace: METRIC_NAMESPACE,
      metricName: TOKENS_METRIC_NAME,
      statistic: cloudwatch.Stats.SUM,
      period: Duration.minutes(5),
      label: "Tokens per scenario",
    });

    // --- 2b. Alternative emit path: extract `tokens` from a structured JSON log
    // line so operators get the same metric with zero extra API calls. A harness
    // that logs e.g. {"scenario": "...", "tokens": 1234} to the scenario log group
    // populates SentinelHarness/TokensPerScenario automatically. ---
    new logs.MetricFilter(this, "TokensMetricFilter", {
      logGroup: this.scenarioLogGroup,
      metricNamespace: METRIC_NAMESPACE,
      metricName: TOKENS_METRIC_NAME,
      // JSON selector: pull the numeric `tokens` field out of each matching event.
      filterPattern: logs.FilterPattern.exists("$.tokens"),
      metricValue: "$.tokens",
      defaultValue: 0,
    });

    // --- 3. Dashboard: trend + latest-value tile + a describing text panel. ---
    this.dashboard = new cloudwatch.Dashboard(this, "Dashboard", {
      dashboardName: `${props.appName}-observability`,
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: [
          `# ${props.appName} - Sentinel Harness Observability`,
          "",
          `Token usage per scenario (\`${METRIC_NAMESPACE}/${TOKENS_METRIC_NAME}\`) and a`,
          `monthly cost budget tripwire. Metric data is emitted either directly by the`,
          "harness (PutMetricData from invoke usage metadata) or extracted from the",
          `scenario LogGroup \`${this.scenarioLogGroup.logGroupName}\` via a MetricFilter.`,
        ].join("\n"),
        width: 24,
        height: 4,
      }),
    );

    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: "TokensPerScenario over time",
        left: [this.tokensMetric],
        width: 18,
        height: 6,
        leftYAxis: { label: "tokens", showUnits: false },
      }),
      new cloudwatch.SingleValueWidget({
        title: "Latest tokens",
        metrics: [this.tokensMetric],
        width: 6,
        height: 6,
        setPeriodToTimeRange: true,
      }),
    );

    // --- 4. Monthly cost budget (L1) with an email notification at the threshold. ---
    // MONTHLY COST budget in USD. Notify on ACTUAL spend crossing the percentage
    // threshold - a tripwire, not a hard cap (Budgets does not stop spend).
    this.budget = new budgets.CfnBudget(this, "MonthlyCostBudget", {
      budget: {
        budgetName,
        budgetType: "COST",
        timeUnit: "MONTHLY",
        budgetLimit: {
          amount: budgetAmountUsd,
          unit: "USD",
        },
      },
      notificationsWithSubscribers: [
        {
          notification: {
            notificationType: "ACTUAL",
            comparisonOperator: "GREATER_THAN",
            threshold: budgetThresholdPercent,
            thresholdType: "PERCENTAGE",
          },
          subscribers: [
            {
              subscriptionType: "EMAIL",
              address: budgetEmail,
            },
          ],
        },
      ],
    });

    // --- Outputs (match sibling stacks: descriptive + exportName-prefixed). ---
    new CfnOutput(this, "DashboardName", {
      value: this.dashboard.dashboardName,
      description: "CloudWatch dashboard name (token trend + latest + description).",
      exportName: `${props.appName}-observability-dashboard`,
    });
    new CfnOutput(this, "BudgetName", {
      value: budgetName,
      description: `Monthly cost budget (${budgetAmountUsd} USD, notify at ${budgetThresholdPercent}%).`,
      exportName: `${props.appName}-observability-budget`,
    });
    new CfnOutput(this, "LogGroupName", {
      value: this.scenarioLogGroup.logGroupName,
      description: "Scenario LogGroup - set for harness logging + MetricFilter token extraction.",
      exportName: `${props.appName}-observability-log-group`,
    });
    new CfnOutput(this, "MetricNamespace", {
      value: METRIC_NAMESPACE,
      description: `Custom metric namespace (metric: ${TOKENS_METRIC_NAME}).`,
    });
  }
}

/**
 * Map a day count to the nearest supported `logs.RetentionDays` enum. CloudWatch
 * only accepts a fixed set of retention values, so we clamp to the closest one that
 * is >= the requested days (falls back to the max enum for very large requests).
 */
function mapRetention(days: number): logs.RetentionDays {
  const supported: Array<[number, logs.RetentionDays]> = [
    [1, logs.RetentionDays.ONE_DAY],
    [3, logs.RetentionDays.THREE_DAYS],
    [5, logs.RetentionDays.FIVE_DAYS],
    [7, logs.RetentionDays.ONE_WEEK],
    [14, logs.RetentionDays.TWO_WEEKS],
    [30, logs.RetentionDays.ONE_MONTH],
    [60, logs.RetentionDays.TWO_MONTHS],
    [90, logs.RetentionDays.THREE_MONTHS],
    [120, logs.RetentionDays.FOUR_MONTHS],
    [150, logs.RetentionDays.FIVE_MONTHS],
    [180, logs.RetentionDays.SIX_MONTHS],
    [365, logs.RetentionDays.ONE_YEAR],
  ];
  for (const [threshold, enumValue] of supported) {
    if (days <= threshold) return enumValue;
  }
  return logs.RetentionDays.ONE_YEAR;
}
