# sentinel-harness · IaC (CDK v2, TypeScript)

Layer-3 foundation stacks for the sentinel-harness SecOps platform: the AgentCore
**Gateway**, **Registry**, and **Memory** primitives plus their least-privilege
execution roles. Everything maps to `docs/BLUEPRINT.md §3` (repo file structure) and
`§5` (customer-concern → design answers).

> **Non-prod target.** These stacks provision security-workload infrastructure and
> are intended for a **non-prod / sandbox account first** (BLUEPRINT is explicit on
> this). Nothing here hardcodes an account, region, or ARN — account/region come
> from your active AWS profile / `CDK_DEFAULT_*`, and everything else is CDK context.

## What gets created

| Stack | Resource | Why |
|---|---|---|
| `sentinel-gateway` | `AWS::BedrockAgentCore::Gateway` (MCP, `SEMANTIC` search) + execution role | Single MCP ingress / egress + guardrail chokepoint. Authorizer defaults to `AWS_IAM` (machine SigV4); `CUSTOM_JWT` fronts human callers via Cognito/OAuth — **no person maps to an IAM principal**. |
| `sentinel-registry` | `AWS::BedrockAgentCore::Registry` (`autoApproval=false`) + DynamoDB tool/skill table | Governance: an agent is live only after human review; a tool is live only if in **both** the registry table and the code `TOOL_FACTORY_MAP`. |
| `sentinel-memory` | `AWS::BedrockAgentCore::Memory` (semantic + summarization strategies) | Feedback loop: facts + rolling summaries, isolated per-tenant via `{actorId}` namespaces. |

### Preview-API note (read before deploy)

AgentCore has **no L2 CDK constructs** yet, so the Gateway, Registry, and Memory are
declared with raw `CfnResource` against these CloudFormation types:

- `AWS::BedrockAgentCore::Gateway`
- `AWS::BedrockAgentCore::Registry`
- `AWS::BedrockAgentCore::Memory`

`cdk synth` renders a valid template offline regardless. The resource **type strings
and property shapes may change** as CloudFormation support for AgentCore evolves — if
a deploy rejects a property, that CfnResource `properties` block (and the `getAtt`
attribute names for the ARN outputs) are the only things to adjust. The IAM roles,
DynamoDB table, wiring, and outputs are all stable, GA CDK.

## Prerequisites

- Node 18+ and npm
- (deploy only) AWS credentials for a **non-prod** account and a bootstrapped
  environment (`npx cdk bootstrap`)

## Synth (offline — no AWS calls, no credentials needed)

```bash
cd iac-cdk
npm install
npx cdk synth            # renders all three stacks to cdk.out/
```

## Deploy (to a non-prod account)

```bash
cd iac-cdk
export AWS_PROFILE=<your-non-prod-profile>   # never a production profile
npx cdk bootstrap                            # once per account/region
npx cdk deploy --all
```

Wire the outputs into the harness runtime (12-factor env, matching `core.py`):

```bash
export SENTINEL_GATEWAY_ARN=$(aws cloudformation describe-stacks \
  --stack-name sentinel-gateway --query "Stacks[0].Outputs[?ExportName=='sentinel-gateway-arn'].OutputValue" --output text)
export SENTINEL_MEMORY_ARN=$(aws cloudformation describe-stacks \
  --stack-name sentinel-memory --query "Stacks[0].Outputs[?ExportName=='sentinel-memory-arn'].OutputValue" --output text)
```

## Configuration (CDK context)

Set in `cdk.json` (`context` block) or per-invocation with `-c key=value`:

| Context key | Default | Meaning |
|---|---|---|
| `sentinel:appName` | `sentinel` | Prefix for all resource names. |
| `sentinel:gatewayAuthorizerType` | `AWS_IAM` | `AWS_IAM` (machine SigV4) or `CUSTOM_JWT` (human OAuth). |
| `sentinel:jwtDiscoveryUrl` | — | OIDC discovery URL — **required** when `CUSTOM_JWT`. |
| `sentinel:jwtAllowedAudience` | — | Comma-separated JWT audiences (`CUSTOM_JWT`). |
| `sentinel:jwtAllowedClients` | — | Comma-separated JWT client ids (`CUSTOM_JWT`). |
| `sentinel:registryAutoApproval` | `false` | Keep `false` for governance. |
| `sentinel:memoryExpiryDays` | `90` | Event retention window (days). |
| `sentinel:environment` | `non-prod` | Value for the `environment` tag. |

Example — front the Gateway with Cognito/OAuth for human callers:

```bash
npx cdk synth -c sentinel:gatewayAuthorizerType=CUSTOM_JWT \
  -c sentinel:jwtDiscoveryUrl=https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/openid-configuration \
  -c sentinel:jwtAllowedAudience=<app-client-id>
```

## Teardown

```bash
npx cdk destroy --all
```

The DynamoDB registry table uses `DESTROY` removal (non-prod). Flip it to `RETAIN`
in `lib/registry-stack.ts` for any environment whose approval history must outlive
the stack.
