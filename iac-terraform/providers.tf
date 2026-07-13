# providers.tf — provider configuration for the sentinel-harness IaC.
#
# Both providers are pinned to the same var.region. The AWS account is NEVER
# hardcoded: it is resolved at plan/apply time from the caller's credentials
# via data.aws_caller_identity. Other modules reference
# data.aws_caller_identity.current.account_id when they need the account ID.

provider "aws" {
  region = var.region

  # Apply common tags to every taggable resource created by the aws provider.
  default_tags {
    tags = var.tags
  }
}

provider "awscc" {
  region = var.region
}

# Resolves the account ID / ARN / user ID of the credentials Terraform is
# running with. Used instead of any hardcoded account number.
data "aws_caller_identity" "current" {}

# Convenience: the current region, resolved from the provider config.
data "aws_region" "current" {}
