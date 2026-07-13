# outputs-vpc.tf — outputs for the VPC module.

output "vpc_id" {
  description = "ID of the isolated VPC."
  value       = aws_vpc.this.id
}

output "subnet_id" {
  description = "ID of the single isolated (private, no-public-IP) subnet."
  value       = aws_subnet.isolated.id
}

output "security_group_id" {
  description = "ID of the security group fronting the interface endpoints (443 intra-VPC)."
  value       = aws_security_group.endpoints.id
}

output "s3_gateway_endpoint_id" {
  description = "ID of the FREE S3 gateway VPC endpoint (always created)."
  value       = aws_vpc_endpoint.s3.id
}

output "interface_endpoint_ids" {
  description = <<-EOT
    Map of service short-name => interface VPC endpoint ID. Empty {} when
    var.deploy_vpc_endpoints is false (the cost gate), since no interface
    endpoints are created in that case.
  EOT
  value       = { for svc, ep in aws_vpc_endpoint.interface : svc => ep.id }
}
