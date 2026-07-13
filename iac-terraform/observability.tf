# observability.tf — CloudWatch + Budgets observability for the sentinel-harness.
#
# Mirrors the M4 CDK observability stack:
#   * a CloudWatch log group (short retention to keep cost near zero),
#   * a metric alarm on the custom "SentinelHarness/TokensPerScenario" metric,
#   * a CloudWatch dashboard with a TokensPerScenario graph widget + a text
#     widget, and
#   * a monthly AWS Budget with an 80% notification.
#
# All of these are effectively FREE at this scale (a handful of custom metrics,
# one dashboard, one alarm, one budget), so they are created by a default apply.
# The only standing cost in this config lives behind var.deploy_vpc_endpoints in
# the VPC module.

locals {
  # Namespace + metric for the harness's per-scenario token accounting. These
  # are custom metrics emitted by the harness runtime (PutMetricData), not an
  # AWS-managed namespace.
  metrics_namespace = "SentinelHarness"
  tokens_metric     = "TokensPerScenario"
}

# ---------------------------------------------------------------------------
# Log group — short retention keeps storage cost negligible for a dev harness.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "harness" {
  name              = "/${var.name_prefix}/harness"
  retention_in_days = var.log_retention_days

  tags = {
    Component = "observability"
  }
}

# ---------------------------------------------------------------------------
# Alarm on TokensPerScenario — fires when a scenario burns more tokens than the
# configured budget, catching runaway loops / prompt bloat early.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "tokens_per_scenario" {
  alarm_name          = "${var.name_prefix}-tokens-per-scenario-high"
  alarm_description   = "Fires when SentinelHarness/${local.tokens_metric} exceeds the per-scenario token threshold."
  namespace           = local.metrics_namespace
  metric_name         = local.tokens_metric
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.tokens_per_scenario_threshold
  evaluation_periods  = 1
  period              = 300
  statistic           = "Maximum"
  treat_missing_data  = "notBreaching"

  tags = {
    Component = "observability"
  }
}

# ---------------------------------------------------------------------------
# Dashboard — one time widget (header) + one graph widget for TokensPerScenario.
# The body is rendered as JSON via jsonencode so it stays valid and diff-able.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "harness" {
  dashboard_name = "${var.name_prefix}-harness"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = "# Sentinel Harness\nToken usage and guardrail activity for the sentinel-harness. Metric namespace: `${local.metrics_namespace}`."
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6
        properties = {
          title   = "Tokens per scenario"
          view    = "timeSeries"
          stacked = false
          region  = var.region
          period  = 300
          stat    = "Maximum"
          metrics = [
            [local.metrics_namespace, local.tokens_metric]
          ]
          yAxis = {
            left = {
              label     = "tokens"
              showUnits = false
            }
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Monthly cost budget with an 80% (actual-spend) email notification.
# ---------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
}
