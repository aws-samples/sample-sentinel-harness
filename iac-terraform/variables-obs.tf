# variables-obs.tf — input variables for the guardrail + observability modules
# (guardrail.tf and observability.tf). Common inputs (region, name_prefix, tags)
# live in variables-common.tf and are owned by the bootstrap task.

# --- Guardrail ---

variable "guardrail_blocked_input_messaging" {
  description = "Message returned to the caller when the guardrail blocks a prompt."
  type        = string
  default     = "This request was blocked because it appears to contain sensitive information."
}

variable "guardrail_blocked_outputs_messaging" {
  description = "Message returned when the guardrail blocks a model response."
  type        = string
  default     = "The response was blocked because it appears to contain sensitive information."
}

# --- Observability ---

variable "log_retention_days" {
  description = "Retention for the harness CloudWatch log group. Kept short to minimize storage cost."
  type        = number
  default     = 7
}

variable "tokens_per_scenario_threshold" {
  description = <<-EOT
    Alarm threshold for the SentinelHarness/TokensPerScenario custom metric.
    The alarm fires when a single scenario's Maximum token count exceeds this
    value in a 5-minute period, catching runaway loops or prompt bloat.
  EOT
  type        = number
  default     = 50000
}

# --- Budget ---

variable "budget_limit_usd" {
  description = "Monthly cost budget limit in USD."
  type        = number
  default     = 50
}

variable "budget_email" {
  description = <<-EOT
    Email address that receives the 80% budget notification. The default is a
    non-routable placeholder (example.com is reserved by RFC 2606); override it
    with a real address before applying if you want to receive alerts.
  EOT
  type        = string
  default     = "budget-alerts@example.com"
}
