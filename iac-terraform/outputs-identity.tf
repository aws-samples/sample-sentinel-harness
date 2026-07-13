# outputs-identity.tf — outputs for the Cognito JWT identity module.
#
# These feed the AgentCore runtime's JWT authorizer config and any client apps.

output "user_pool_id" {
  description = "Cognito user pool ID."
  value       = aws_cognito_user_pool.this.id
}

output "issuer" {
  description = "JWT issuer (iss) URL for this user pool."
  value       = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "discovery_url" {
  description = "OpenID Connect discovery document URL (issuer + /.well-known/openid-configuration)."
  value       = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}/.well-known/openid-configuration"
}

output "human_client_id" {
  description = "App client ID for the human (SRP + authorization-code) client. Human tokens carry this as the aud claim."
  value       = aws_cognito_user_pool_client.human.id
}

output "machine_client_id" {
  description = <<-EOT
    App client ID for the machine (client_credentials) client. NOTE: machine
    tokens have NO aud claim — the runtime authorizer matches machine callers on
    the client_id claim (this value) and/or the scope claim. See identity.tf.
  EOT
  value       = aws_cognito_user_pool_client.machine.id
}

output "domain" {
  description = "Cognito hosted OAuth2 domain prefix. Token endpoint: https://<domain>.auth.<region>.amazoncognito.com/oauth2/token"
  value       = aws_cognito_user_pool_domain.this.domain
}
