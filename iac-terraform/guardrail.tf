# guardrail.tf — Amazon Bedrock Guardrail for the sentinel-harness.
#
# Mirrors the M4 CDK guardrail: a sensitive-information policy that BLOCKs a live
# AWS secret access key (it must never round-trip) and ANONYMIZEs ordinary contact
# PII (EMAIL, NAME) so casework text still flows, plus two custom regexes that
# catch secret-shaped strings (an AWS access-key-id pattern and a generic
# 'sk-'/'ghp_'-style API-token pattern) in both prompts and model responses.
# Paired with an aws_bedrock_guardrail_version so the guardrail can be referenced
# by a pinned, immutable version.
#
# SECURITY NOTE: the regex PATTERNS below are assembled from character classes
# so that NO literal/real credential ever appears in this file. A pattern such
# as "A[KS]IA[0-9A-Z]{16}" is a detector, not a secret; there is no real key
# checked in here. Do not replace these with copy-pasted example keys.

locals {
  # AWS access-key detector. Assembled from char-classes only — this is the
  # canonical shape of an AKIA/ASIA identifier (prefix + 16 upper-alnum chars),
  # never an actual key. Written piecewise to make the "pattern, not secret"
  # intent explicit and grep-safe.
  aws_key_prefix  = "A[KS]IA"      # AKIA (long-term) or ASIA (temporary) prefix
  aws_key_body    = "[0-9A-Z]{16}" # 16 uppercase alphanumeric characters
  aws_key_pattern = "${local.aws_key_prefix}${local.aws_key_body}"

  # Generic long-lived API-token detector: an "sk-" / "ghp_"-style prefix
  # followed by >= 20 body characters (covers many provider API tokens). The
  # prefixes are assembled from fragments so no real token prefix+body pair is
  # embedded here.
  sk_prefix     = join("", ["s", "k-"])  # OpenAI-style secret key prefix
  ghp_prefix    = join("", ["gh", "p_"]) # GitHub personal access token prefix
  token_body    = "[A-Za-z0-9_]{20,}"    # 20+ chars (alnum + underscore)
  token_pattern = "(?:${local.sk_prefix}|${local.ghp_prefix})${local.token_body}"
}

resource "aws_bedrock_guardrail" "sentinel" {
  name        = "${var.name_prefix}-guardrail"
  description = "Sentinel harness guardrail: anonymize PII and secret-shaped strings in prompts and responses."

  blocked_input_messaging   = var.guardrail_blocked_input_messaging
  blocked_outputs_messaging = var.guardrail_blocked_outputs_messaging

  sensitive_information_policy_config {
    # --- PII entities. A live secret access key must never round-trip, so BLOCK
    # it; ordinary contact PII (EMAIL, NAME) is ANONYMIZEd so casework text flows. ---
    pii_entities_config {
      type   = "AWS_SECRET_KEY"
      action = "BLOCK"
    }

    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "NAME"
      action = "ANONYMIZE"
    }

    # --- Custom regexes for secret-shaped strings ---
    regexes_config {
      name        = "aws-access-key-id"
      description = "Masks AWS access key id shaped strings (A[KS]IA + 16 upper/digit chars) leaking through a tool response. Pattern only; no real key stored."
      pattern     = local.aws_key_pattern
      action      = "ANONYMIZE"
    }

    regexes_config {
      name        = "generic-api-token"
      description = "Masks generic long-lived API tokens (sk-… / ghp_… style prefixes + 20+ chars) leaking through a tool response. Pattern only; no real token stored."
      pattern     = local.token_pattern
      action      = "ANONYMIZE"
    }
  }

  tags = {
    Component = "guardrail"
  }
}

# Immutable, pinned version of the guardrail above. Reference this ARN+version
# from an agent/runtime rather than the mutable DRAFT.
resource "aws_bedrock_guardrail_version" "sentinel" {
  guardrail_arn = aws_bedrock_guardrail.sentinel.guardrail_arn
  description   = "Initial published version of the sentinel-harness guardrail."
  skip_destroy  = false
}
