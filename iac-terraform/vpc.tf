# vpc.tf — min-cost, private, isolated VPC with gated PrivateLink endpoints.
#
# WHY THIS SHAPE (isolated + PrivateLink, NO NAT / NO IGW):
#   1. COST. A NAT gateway bills ~$0.045/hr (~$32/mo) PLUS ~$0.045/GB processed,
#      24x7, whether or not traffic flows. This design has ZERO always-on NAT
#      cost. The only standing cost is the ~4 INTERFACE endpoints — and those are
#      GATED behind var.deploy_vpc_endpoints (default false), so a default apply
#      costs ~$0/mo. The S3 GATEWAY endpoint is always FREE.
#   2. SECURITY. With no IGW and no NAT, the workload subnet has NO route to the
#      public internet in EITHER direction. Traffic to AWS APIs (bedrock-agentcore,
#      logs, ecr, sts, s3) stays on the AWS backbone via PrivateLink and never
#      transits the internet. This is a smaller blast radius and a stronger
#      posture than "private subnet + NAT" (which still allows arbitrary egress).
#   3. Data exfiltration is constrained: only the specific service endpoints we
#      attach are reachable, each with a restrictive endpoint policy.
#
# The account ID is NEVER hardcoded — it is resolved from
# data.aws_caller_identity.current (declared in providers.tf).

locals {
  vpc_cidr = var.vpc_cidr

  # The set of AWS services the harness needs to reach privately (INTERFACE
  # endpoints). These are the only standing-cost resources, hence the gate.
  interface_endpoint_services = [
    "bedrock-agentcore",
    "logs",
    "ecr.api",
    "ecr.dkr",
    "sts",
  ]
}

# --------------------------------------------------------------------------- #
# VPC (FREE)                                                                   #
# --------------------------------------------------------------------------- #
resource "aws_vpc" "this" {
  cidr_block = local.vpc_cidr

  # DNS support + hostnames are REQUIRED for private_dns_enabled interface
  # endpoints to resolve com.amazonaws.<region>.<service> to private IPs.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

# --------------------------------------------------------------------------- #
# ONE isolated subnet (FREE) — no public IPs, no route to the internet.       #
# --------------------------------------------------------------------------- #
resource "aws_subnet" "isolated" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.subnet_cidr
  availability_zone = var.availability_zone != "" ? var.availability_zone : null

  # Never auto-assign public IPs — this is an isolated, private subnet.
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-isolated-subnet"
    Tier = "isolated"
  }
}

# --------------------------------------------------------------------------- #
# Route table + association (FREE) — deliberately has NO IGW and NO NAT route. #
# The only non-local route added is the S3 gateway endpoint route (below),    #
# injected automatically by aws_vpc_endpoint.s3.route_table_ids.              #
# --------------------------------------------------------------------------- #
resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.this.id

  # Intentionally empty: the implicit local route (VPC CIDR) is the ONLY route,
  # plus the S3 gateway prefix-list route added via the endpoint. No 0.0.0.0/0.

  tags = {
    Name = "${var.name_prefix}-isolated-rt"
  }
}

resource "aws_route_table_association" "isolated" {
  subnet_id      = aws_subnet.isolated.id
  route_table_id = aws_route_table.isolated.id
}

# --------------------------------------------------------------------------- #
# Security group (FREE) — allow HTTPS(443) only from within the VPC.          #
# Interface endpoints terminate TLS on port 443; intra-VPC clients reach them  #
# on 443. Egress is restricted to intra-VPC 443 (no open 0.0.0.0/0 egress).    #
# --------------------------------------------------------------------------- #
resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints-sg"
  description = "HTTPS 443 from within the VPC to interface endpoints; intra-VPC egress only."
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from within the VPC CIDR (clients -> interface endpoints)."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  # No open egress: only intra-VPC 443 is permitted (endpoints -> in-VPC clients
  # and client-to-client on 443). There is no route to the internet anyway, but
  # we keep egress tight rather than the default allow-all.
  egress {
    description = "Intra-VPC HTTPS egress only (no internet-bound egress)."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  tags = {
    Name = "${var.name_prefix}-endpoints-sg"
  }
}

# --------------------------------------------------------------------------- #
# S3 GATEWAY endpoint (ALWAYS FREE) — attached to the route table.            #
# Gateway endpoints have no hourly/data charge and add a prefix-list route to  #
# the route table so S3 access (e.g. ECR image layers) stays on the backbone.  #
# --------------------------------------------------------------------------- #
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.isolated.id]

  tags = {
    Name = "${var.name_prefix}-s3-gateway"
  }
}

# --------------------------------------------------------------------------- #
# INTERFACE endpoints (THE ONLY STANDING COST) — gated by var.deploy_vpc_endpoints.
# for_each over the service set, each guarded so a default apply creates none.  #
# Each has private DNS on, the restrictive SG, and a restrictive endpoint policy.
# --------------------------------------------------------------------------- #
resource "aws_vpc_endpoint" "interface" {
  # COST GATE: empty map when disabled => zero interface endpoints created.
  for_each = var.deploy_vpc_endpoints ? toset(local.interface_endpoint_services) : toset([])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.isolated.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  # Restrictive endpoint policy: allow the service's own actions, but ONLY from
  # principals in THIS account (resolved, never hardcoded). Tightens the default
  # "allow *" endpoint policy to reduce cross-account/exfiltration surface.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowThisAccountOnly"
        Effect    = "Allow"
        Principal = "*"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-${replace(each.value, ".", "-")}-endpoint"
  }
}
