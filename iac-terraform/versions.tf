# versions.tf — Terraform + provider version pinning for the sentinel-harness IaC.
#
# This root config is a DEPLOYABLE mirror of the M4 CDK foundation, kept in
# Terraform so the team can run `terraform apply` for real, low-cost validation
# in a NON-production account.
#
# State backend: intentionally LOCAL (no backend block below) so that
# `terraform init` works fully offline without a pre-existing remote bucket.
# A commented example S3 backend is provided for teams that want remote state.

terraform {
  required_version = ">= 1.5"

  required_providers {
    # Standard AWS provider — the bulk of resources (Cognito, VPC, CloudWatch, etc.).
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    # Cloud Control API provider — used for native/auto-generated CFN resource
    # types (e.g. AWS::BedrockAgentCore::Harness) not yet in the classic aws provider.
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.0"
    }
  }

  # ---------------------------------------------------------------------------
  # EXAMPLE remote backend (COMMENTED OUT — default is local state).
  #
  # To use remote state, create the bucket + DynamoDB lock table out-of-band,
  # then uncomment and fill in your own (non-hardcoded) values. Never commit
  # real account IDs; the 000000000000 below is a placeholder only.
  #
  #   backend "s3" {
  #     bucket         = "sentinel-harness-tfstate-000000000000-us-east-1"
  #     key            = "sentinel-harness/terraform.tfstate"
  #     region         = "us-east-1"
  #     dynamodb_table = "sentinel-harness-tflock"
  #     encrypt        = true
  #   }
  # ---------------------------------------------------------------------------
}
