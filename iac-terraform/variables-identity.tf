# variables-identity.tf — inputs for the Cognito JWT identity module.
#
# These configure the OAuth2 / JWT identity provider that the sentinel-harness
# uses to authenticate callers of the Bedrock AgentCore runtime. Common inputs
# (region, name_prefix, tags) live in variables-common.tf and are reused here.

variable "cognito_domain_prefix" {
  description = <<-EOT
    Prefix for the Cognito hosted-UI / OAuth2 domain. The full domain becomes
    https://<prefix>.auth.<region>.amazoncognito.com and MUST be globally
    unique across ALL AWS accounts. If a default apply fails with a
    "domain already exists" error, override this to something unique.
    A domain is REQUIRED for the machine (client_credentials) token endpoint.
  EOT
  type        = string
  default     = "sentinel-harness-dev"

  validation {
    # Cognito domain prefixes: lowercase letters, digits, and hyphens only;
    # cannot start/end with a hyphen; 1-63 chars.
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", var.cognito_domain_prefix))
    error_message = "cognito_domain_prefix must be 1-63 chars of lowercase letters, digits, or hyphens, and cannot start or end with a hyphen."
  }
}

variable "cognito_resource_server_identifier" {
  description = <<-EOT
    Identifier of the Cognito resource server. This becomes the namespace for
    custom OAuth2 scopes: a scope is referenced as "<identifier>/<scope>"
    (e.g. "sentinel/invoke"). Machine (client_credentials) access tokens carry
    these scopes rather than an aud claim — see the aud-claim note in identity.tf.
  EOT
  type        = string
  default     = "sentinel"
}

variable "cognito_invoke_scope_name" {
  description = "Name of the custom OAuth2 scope that authorizes invoking the harness runtime. Combined with the resource server identifier as '<identifier>/<scope>'."
  type        = string
  default     = "invoke"
}

variable "cognito_human_callback_urls" {
  description = <<-EOT
    Allowed OAuth2 redirect (callback) URLs for the HUMAN app client (SRP +
    authorization-code flow). Defaults to a localhost dev URL; override with
    your real hosted-UI callback(s) for a non-dev deployment. No customer or
    company hostnames are baked in.
  EOT
  type        = list(string)
  default     = ["http://localhost:3000/callback"]
}

variable "cognito_human_logout_urls" {
  description = "Allowed OAuth2 sign-out redirect URLs for the human app client."
  type        = list(string)
  default     = ["http://localhost:3000/logout"]
}
