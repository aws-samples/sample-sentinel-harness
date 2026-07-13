# variables-vpc.tf — inputs specific to the VPC module.
#
# NOTE: var.region, var.name_prefix, var.tags, and the cost gate
# var.deploy_vpc_endpoints live in the shared variables-common.tf and are NOT
# redeclared here (that would be a duplicate-definition error). This file holds
# only the VPC-specific inputs.

variable "vpc_cidr" {
  description = "CIDR block for the isolated VPC. Matches the M4 dev foundation."
  type        = string
  default     = "10.20.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the single isolated subnet (must sit within vpc_cidr)."
  type        = string
  default     = "10.20.1.0/24"
}

variable "availability_zone" {
  description = <<-EOT
    AZ for the single isolated subnet. Empty string (default) lets AWS pick an
    AZ in the region, keeping the config region-portable. Set explicitly (e.g.
    "us-east-1a") to pin the subnet to a specific AZ.
  EOT
  type        = string
  default     = ""
}
