# harness.tf — a demo SecOps triage Harness via the NATIVE CFN type.
# =============================================================================
# WHY (docs/BLUEPRINT.md "agents as configuration"): a Harness IS the agent — a
# managed agentic loop (system_prompt + model + limits) that the sentinel_harness
# Python core creates at runtime via core.create_harness(...). This mirrors the
# CDK HarnessStack (iac-cdk/lib/harness-stack.ts) declaratively so a triage agent
# can be stood up as version-controlled infrastructure.
#
# -----------------------------------------------------------------------------
# PROVIDER PATH CHOSEN: awscc_bedrockagentcore_harness  (NOT aws_cloudformation_stack)
# -----------------------------------------------------------------------------
# The AWSCC (Cloud Control API) provider — hashicorp/awscc, pinned ~> 1.0 in
# versions.tf (resolved to 1.91.0) — SHIPS a first-class resource for the native
# CFN type AWS::BedrockAgentCore::Harness. Confirmed via:
#     terraform init -backend=false
#     terraform providers schema -json | ... awscc_bedrockagentcore_harness
# The schema exposes: harness_name (req), execution_role_arn (req), model (req,
# single-nested), system_prompt (list of { text }), max_iterations, max_tokens,
# timeout_seconds, tags (list of { key, value }), plus computed harness_id / arn.
#
# Because the resource EXISTS in the pinned provider, we use it directly rather
# than falling back to an aws_cloudformation_stack template_body wrapper. Benefits:
#   - Cleaner HCL (typed attributes, no embedded JSON/YAML template).
#   - Full Terraform lifecycle/drift detection on each attribute.
#   - No stack-in-a-stack indirection.
# The CFN-stack fallback (documented in README) is only needed if a provider
# version LACKS this resource — not the case here.
#
# NOTE ON awscc SYNTAX: awscc single/list-nested attributes are ATTRIBUTES, so
# they are assigned with `=` and object/list literals ({ } / [ ]), NOT bare HCL
# blocks. That is why `model`, `system_prompt`, and `tags` below use `=`.
#
# The execution role ARN comes from var.harness_execution_role_arn (required, no
# default) — it is NEVER hardcoded.

resource "awscc_bedrockagentcore_harness" "triage" {
  # harness_name must match [a-zA-Z][a-zA-Z0-9_]{0,39} server-side (validated on
  # the variable). No hyphens.
  harness_name       = var.harness_name
  execution_role_arn = var.harness_execution_role_arn

  # Required, single-nested. Bedrock cross-region inference profile / model id.
  model = {
    bedrock_model_config = {
      model_id = var.harness_model_id
      # Low temperature: triage wants deterministic, evidence-driven output.
      temperature = var.harness_temperature
      max_tokens  = var.harness_max_tokens
    }
  }

  # system_prompt is a LIST of { text } blocks (GA list shape, same as
  # core.create_harness normalizing system_prompt to [{"text": ...}]).
  system_prompt = [
    {
      text = trimspace(var.harness_system_prompt)
    }
  ]

  # Top-level agent-loop limits.
  max_iterations  = var.harness_max_iterations
  max_tokens      = var.harness_max_tokens
  timeout_seconds = var.harness_timeout_seconds

  # awscc tags are a list of { key, value } objects (not a map). Mirror the
  # aws-provider default_tags so this resource carries the same project tags.
  tags = [for k, v in var.tags : { key = k, value = v }]
}
