# identity.tf — Cognito JWT identity for the sentinel-harness AgentCore runtime.
#
# Mirrors the M4 CDK foundation: a Cognito user pool that issues JWTs used to
# authorize calls to the Bedrock AgentCore runtime. Two app clients are created:
#
#   * HUMAN client   — no secret, SRP + authorization-code flow (interactive login).
#   * MACHINE client  — has a secret, client_credentials flow (service-to-service).
#
# JWT issuer:    https://cognito-idp.<region>.amazonaws.com/<userPoolId>
# Discovery URL: <issuer>/.well-known/openid-configuration
#
# ---------------------------------------------------------------------------
# aud-claim GOTCHA (READ THIS before wiring the runtime's JWT authorizer):
#
#   HUMAN tokens  (authorization_code flow) are ID/access tokens that DO carry
#                 an `aud` claim equal to the human client_id — validate on aud.
#
#   MACHINE tokens (client_credentials flow) are access tokens that have NO
#                 `aud` claim at all. They instead carry `client_id` and `scope`.
#                 => The runtime authorizer MUST match machine callers on the
#                    `client_id` claim (against aws_cognito_user_pool_client.machine.id)
#                    and/or the `scope` claim ("<identifier>/<scope>"), NOT `aud`.
#
#   client_credentials additionally REQUIRES: a user pool domain (below) + a
#   resource server defining the custom scope + a client that has a secret.
# ---------------------------------------------------------------------------

# --- User pool ---------------------------------------------------------------
resource "aws_cognito_user_pool" "this" {
  name = "${var.name_prefix}-users"

  # Password policy mirrors the CDK IdentityStack: 12-char minimum, all four
  # character classes required (lower/upper/digit/symbol), temp passwords valid 3 days.
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 3
  }

  # Self-signup OFF (admin-created users only) — this is a governance-adjacent dev
  # IdP, not a public sign-up. Mirrors the CDK selfSignUpEnabled: false.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # Email as the auto-verified attribute for the human sign-up flow.
  auto_verified_attributes = ["email"]

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

# --- Hosted OAuth2 domain (REQUIRED for client_credentials) ------------------
resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

# --- Resource server + custom scope ------------------------------------------
# Defines the "sentinel" namespace and its "invoke" scope. Machine tokens
# request "<identifier>/<scope>" (e.g. "sentinel/invoke").
resource "aws_cognito_resource_server" "this" {
  identifier   = var.cognito_resource_server_identifier
  name         = "${var.name_prefix}-resource-server"
  user_pool_id = aws_cognito_user_pool.this.id

  scope {
    scope_name        = var.cognito_invoke_scope_name
    scope_description = "Authorizes invoking the sentinel-harness AgentCore runtime."
  }
}

# --- HUMAN app client (no secret, SRP + authorization-code flow) -------------
resource "aws_cognito_user_pool_client" "human" {
  name         = "${var.name_prefix}-human-client"
  user_pool_id = aws_cognito_user_pool.this.id

  # Public client (e.g. SPA / native) — no client secret.
  generate_secret = false

  # SRP for direct auth + refresh; hosted-UI code flow for interactive login.
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  callback_urls = var.cognito_human_callback_urls
  logout_urls   = var.cognito_human_logout_urls

  supported_identity_providers = ["COGNITO"]

  # The hosted UI / OAuth endpoints require the domain to exist first.
  depends_on = [aws_cognito_user_pool_domain.this]
}

# --- MACHINE app client (secret, client_credentials flow) --------------------
resource "aws_cognito_user_pool_client" "machine" {
  name         = "${var.name_prefix}-machine-client"
  user_pool_id = aws_cognito_user_pool.this.id

  # Confidential client — needs a secret for client_credentials.
  generate_secret = true

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]

  # Only the custom resource-server scope; client_credentials cannot use the
  # standard OIDC scopes (openid/email/profile).
  allowed_oauth_scopes = [
    "${aws_cognito_resource_server.this.identifier}/${var.cognito_invoke_scope_name}",
  ]

  supported_identity_providers = ["COGNITO"]

  # client_credentials tokens are minted at the domain's /oauth2/token endpoint
  # and reference the scope defined by the resource server.
  depends_on = [
    aws_cognito_user_pool_domain.this,
    aws_cognito_resource_server.this,
  ]
}
