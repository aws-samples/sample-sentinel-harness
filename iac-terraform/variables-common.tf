# variables-common.tf — root/shared input variables for the sentinel-harness IaC.
#
# Module-specific variables live in their own module-suffixed files
# (e.g. variables-identity.tf, variables-vpc.tf). This file holds only the
# common inputs that every module relies on.

variable "region" {
  description = "AWS region to deploy into. Default matches the M4 dev region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to resource names to keep them grouped and identifiable."
  type        = string
  default     = "sentinel"
}

variable "deploy_vpc_endpoints" {
  description = <<-EOT
    COST GATE. When true, the VPC module creates the ~4 INTERFACE VPC endpoints
    (bedrock-agentcore, logs, ecr.api, ecr.dkr, sts) — the only standing cost in
    this config (~$27-34/mo for the endpoints). When false (default), only the
    FREE resources are created (VPC, subnet, security group, and the S3 GATEWAY
    endpoint which is free). Keep false unless you specifically need the
    interface endpoints for a validation run, and destroy afterwards.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Common tags applied to all resources via the aws provider default_tags."
  type        = map(string)
  default = {
    Project   = "sentinel-harness"
    ManagedBy = "terraform"
    Env       = "nonprod"
  }
}
