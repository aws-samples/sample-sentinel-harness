# sentinel-harness — Terraform IaC (`iac-terraform/`)

A **deployable Terraform mirror** of the M4 CDK foundation (`../iac-cdk/`). It
lets the team run a real `terraform apply` for low-cost, offline-friendly
infrastructure validation rather than only synthesizing CDK. Both stacks
describe the same SecOps evaluation harness footprint; this one is authored in
plain HCL so it can be validated and applied without the Node/CDK toolchain.

> **Scope:** generic SecOps agent-evaluation infrastructure. No customer,
> company, or environment-specific references. All account-specific values are
> resolved at apply time from your credentials (`data.aws_caller_identity`), not
> hardcoded.

## What gets deployed

The config composes several modules (each in its own `*-<module>.tf` files):

- **Identity** — Cognito user pool + client (client_credentials/M2M) + resource
  server + domain, for JWT-based machine auth.
- **VPC (min-cost)** — one VPC (`10.20.0.0/16`), a single isolated subnet, an
  intra-VPC 443 security group, a **free S3 gateway endpoint**, and — *only when
  opted in* — interface endpoints (see cost flag below). No NAT gateway, no IGW.
- **Guardrail** — a Bedrock guardrail (+ version) with sensitive-information
  policies (PII entities + regex patterns for fake secrets / AWS-key shapes).
- **Observability** — CloudWatch dashboard, log group, a metric alarm on a
  custom `SentinelHarness/TokensPerScenario` metric, and a budget with an 80%
  notification.
- **Harness** — the native `AWS::BedrockAgentCore::Harness` type via the `awscc`
  provider.

## Prerequisites

- Terraform `>= 1.5` (pinned providers: `hashicorp/aws ~> 5.0`,
  `hashicorp/awscc ~> 1.0` — see `versions.tf`).
- For `apply` only: AWS credentials for a **non-production** account
  (`init`/`validate`/`fmt` need no credentials).

## Target account

This config is meant for a **NON-production / sandbox account**. Do not point it
at a production account. The account ID is never written into the config; it is
read from whatever credentials Terraform runs with, and the example remote
backend in `versions.tf` uses `000000000000` purely as a placeholder.

## Cost flag: `deploy_vpc_endpoints`

The VPC **interface** endpoints are the only standing cost in this config
(roughly **$27–34/mo** for ~4 endpoints). They are gated behind the
`deploy_vpc_endpoints` variable (default **`false`**) using `count`/`for_each`:

- **Default apply** (`deploy_vpc_endpoints = false`): creates only the FREE
  resources (VPC, subnet, security group, S3 **gateway** endpoint). ~$0 standing
  cost.
- **Opt-in** (`deploy_vpc_endpoints = true`): additionally creates the interface
  endpoints. Enable only for a validation run, then destroy.

```hcl
# terraform.tfvars (opt in for a validation run, then destroy)
deploy_vpc_endpoints = true
```

## Init / validate / fmt (offline gate)

No remote backend is configured (state is **local**), so `init` works offline:

```bash
cd iac-terraform
terraform init -backend=false   # download providers, no remote state
terraform validate              # must be clean
terraform fmt -check             # must pass (run `terraform fmt` to fix)
```

## Apply / destroy workflow

Requires credentials for a non-prod account.

```bash
cd iac-terraform

# 1. Init (local state; drop -backend=false once you configure a real backend)
terraform init

# 2. Review the plan
terraform plan

# 3. Apply the FREE footprint (endpoints stay off by default)
terraform apply

# 3b. (optional) Apply WITH the paid interface endpoints for a validation run
terraform apply -var 'deploy_vpc_endpoints=true'

# 4. Tear everything down when done to stop any standing cost
terraform destroy
```

Always `terraform destroy` after a validation run — especially if you enabled
`deploy_vpc_endpoints` — to avoid leaving the interface endpoints billing.
