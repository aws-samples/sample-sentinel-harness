# outputs-obs.tf — outputs for the guardrail + observability modules.

output "guardrail_id" {
  description = "ID of the Bedrock guardrail."
  value       = aws_bedrock_guardrail.sentinel.guardrail_id
}

output "guardrail_arn" {
  description = "ARN of the Bedrock guardrail."
  value       = aws_bedrock_guardrail.sentinel.guardrail_arn
}

output "guardrail_version" {
  description = "Published (immutable) version of the Bedrock guardrail."
  value       = aws_bedrock_guardrail_version.sentinel.version
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard."
  value       = aws_cloudwatch_dashboard.harness.dashboard_name
}

output "log_group_name" {
  description = "Name of the harness CloudWatch log group."
  value       = aws_cloudwatch_log_group.harness.name
}

output "budget_name" {
  description = "Name of the monthly AWS Budget."
  value       = aws_budgets_budget.monthly.name
}
