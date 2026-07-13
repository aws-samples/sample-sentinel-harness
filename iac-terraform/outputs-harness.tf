# outputs-harness.tf — outputs for the Harness module (harness.tf).
#
# harness_id  — the short id used by InvokeHarness / CreateHarnessEndpoint ops.
# harness_arn — the full ARN; wire this into SENTINEL_HARNESS_ARN for the runtime.
# Both are computed server-side and surfaced from the awscc resource.

output "harness_id" {
  description = "Harness id (awscc harness_id) for InvokeHarness / CreateHarnessEndpoint operations."
  value       = awscc_bedrockagentcore_harness.triage.harness_id
}

output "harness_arn" {
  description = "Harness ARN. Set as SENTINEL_HARNESS_ARN for invoke/endpoint operations."
  value       = awscc_bedrockagentcore_harness.triage.arn
}
