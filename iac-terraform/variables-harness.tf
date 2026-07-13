# variables-harness.tf — inputs for the Harness module (harness.tf).
#
# The Harness is the declarative form of the agentic triage loop
# (system_prompt + model + limits) that the sentinel_harness Python core creates
# at runtime via core.create_harness(...). These variables mirror the CDK
# HarnessStack props (iac-cdk/lib/harness-stack.ts) so the Terraform mirror
# stands up the SAME thing.
#
# SECURITY: execution_role_arn is a REQUIRED variable with NO default — the
# account-specific role ARN is NEVER hardcoded. Supply it at apply time, e.g.
#   terraform apply -var 'harness_execution_role_arn=arn:aws:iam::000000000000:role/sentinel-harness-exec'
# (000000000000 is a placeholder in docs only).

variable "harness_name" {
  description = <<-EOT
    Name of the Harness. Must match the server-side pattern [a-zA-Z][a-zA-Z0-9_]{0,39}
    (letters/digits/underscores only, no hyphens), so the default uses an underscore.
  EOT
  type        = string
  default     = "sentinel_triage"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,39}$", var.harness_name))
    error_message = "harness_name must match ^[a-zA-Z][a-zA-Z0-9_]{0,39}$ (no hyphens, max 40 chars)."
  }
}

variable "harness_execution_role_arn" {
  description = <<-EOT
    REQUIRED. ARN of the IAM execution role the Harness assumes to run the agent
    loop and invoke Bedrock models. NEVER hardcoded — supplied at apply time.
    Example (placeholder account): arn:aws:iam::000000000000:role/sentinel-harness-exec
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:role/.+$", var.harness_execution_role_arn))
    error_message = "harness_execution_role_arn must be a valid IAM role ARN (arn:aws:iam::<account>:role/<name>)."
  }
}

variable "harness_model_id" {
  description = <<-EOT
    Bedrock model id / cross-region inference-profile for the harness loop.
    Mirrors core.py MODEL_SONNET and the CDK default. No unverifiable version pinned.
  EOT
  type        = string
  default     = "global.anthropic.claude-sonnet-4-6"
}

variable "harness_system_prompt" {
  description = <<-EOT
    System prompt for the triage agent. Rendered into the native GA list shape
    [{ text = ... }] (same normalization core.create_harness applies). Generic
    SecOps alert triage — no customer specifics.
  EOT
  type        = string
  default     = <<-EOT
    You are a SecOps alert-triage agent. Given a security alert, classify it as true-positive, false-positive, or needs-investigation, assign a severity (low/medium/high/critical), cite the concrete signals behind your verdict, and recommend the next action. Be precise and evidence-driven; never fabricate indicators.
  EOT
}

variable "harness_temperature" {
  description = "Sampling temperature for the harness model. Low = deterministic, evidence-driven triage."
  type        = number
  default     = 0
}

variable "harness_max_tokens" {
  description = "Max tokens the model may generate per iteration."
  type        = number
  default     = 4096
}

variable "harness_max_iterations" {
  description = "Max agent-loop iterations per invocation (mirrors the YAML demo default)."
  type        = number
  default     = 15
}

variable "harness_timeout_seconds" {
  description = "Max wall-clock seconds for one agent-loop invocation."
  type        = number
  default     = 300
}
