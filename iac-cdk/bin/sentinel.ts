#!/usr/bin/env node
/**
 * CDK app entry - wires the three Layer-3 AgentCore governance stacks.
 * ====================================================================
 * Deploy target is a NON-PROD account (docs/BLUEPRINT.md is explicit: security
 * workloads run in a non-prod account first). Account/region come from the
 * standard CDK environment - `CDK_DEFAULT_ACCOUNT`/`CDK_DEFAULT_REGION` or the
 * active AWS profile - NEVER hardcoded. Everything else is tuned via CDK context
 * (see cdk.json `context` block or `-c key=value` on the CLI).
 *
 * Context keys:
 *   sentinel:appName                 logical prefix for all resource names
 *   sentinel:gatewayAuthorizerType   AWS_IAM (default) | CUSTOM_JWT
 *   sentinel:jwtDiscoveryUrl         OIDC discovery URL (required if CUSTOM_JWT)
 *   sentinel:jwtAllowedAudience      comma-separated JWT audiences (CUSTOM_JWT)
 *   sentinel:jwtAllowedClients       comma-separated JWT client ids (CUSTOM_JWT)
 *   sentinel:registryAutoApproval    false (default, governance) | true
 *   sentinel:registryViaCustomResource false (default, raw CfnResource) | true (Lambda CR fallback)
 *   sentinel:memoryExpiryDays        event retention window in days (default 90)
 */
import { App, Environment, Tags } from "aws-cdk-lib";
import { GatewayStack, GatewayAuthorizerType } from "../lib/gateway-stack";
import { RegistryStack } from "../lib/registry-stack";
import { MemoryStack } from "../lib/memory-stack";
import { NetworkStack } from "../lib/network-stack";
import { IdentityStack } from "../lib/identity-stack";
import { GuardrailStack } from "../lib/guardrail-stack";
import { ObservabilityStack } from "../lib/observability-stack";
import { HarnessStack } from "../lib/harness-stack";

const app = new App();

// --- Read context (12-factor: nothing hardcoded). ---
function ctx<T = string>(key: string, fallback: T): T {
  const v = app.node.tryGetContext(key);
  return (v === undefined || v === null || v === "") ? fallback : (v as T);
}

function csv(key: string): string[] | undefined {
  const v = app.node.tryGetContext(key);
  if (v === undefined || v === null || v === "") return undefined;
  return String(v)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const appName = String(ctx("sentinel:appName", "sentinel"));

// CDK resolves account/region from the environment / active profile at synth or
// deploy time. Leaving `env` undefined makes the stacks region-agnostic for synth.
const env: Environment | undefined =
  process.env.CDK_DEFAULT_ACCOUNT && process.env.CDK_DEFAULT_REGION
    ? { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION }
    : undefined;

const authorizerType = String(
  ctx("sentinel:gatewayAuthorizerType", "AWS_IAM"),
) as GatewayAuthorizerType;

// Context booleans may arrive as real booleans (cdk.json) or strings (CLI -c).
const autoApprovalRaw = ctx<unknown>("sentinel:registryAutoApproval", false);
const autoApproval =
  typeof autoApprovalRaw === "boolean" ? autoApprovalRaw : String(autoApprovalRaw) === "true";

// Registry provisioning path: default false = raw CfnResource (synth-only until the
// CFN type is GA); true = Lambda-backed custom-resource fallback (deploy-ready).
const registryViaCrRaw = ctx<unknown>("sentinel:registryViaCustomResource", false);
const registryViaCustomResource =
  typeof registryViaCrRaw === "boolean" ? registryViaCrRaw : String(registryViaCrRaw) === "true";

const memoryExpiryRaw = ctx<unknown>("sentinel:memoryExpiryDays", 90);
const memoryExpiryDays = Number(memoryExpiryRaw) || 90;

const gateway = new GatewayStack(app, `${appName}-gateway`, {
  env,
  appName,
  authorizerType,
  jwtDiscoveryUrl: ctx<string | undefined>("sentinel:jwtDiscoveryUrl", undefined),
  jwtAllowedAudience: csv("sentinel:jwtAllowedAudience"),
  jwtAllowedClients: csv("sentinel:jwtAllowedClients"),
  description: "Sentinel AgentCore Gateway (MCP ingress) + least-privilege execution role.",
});

const registry = new RegistryStack(app, `${appName}-registry`, {
  env,
  appName,
  autoApproval,
  viaCustomResource: registryViaCustomResource,
  description: "Sentinel AgentCore Registry (governance) + DynamoDB tool/skill registry.",
});

const memory = new MemoryStack(app, `${appName}-memory`, {
  env,
  appName,
  expiryDays: memoryExpiryDays,
  description: "Sentinel AgentCore Memory (semantic + summarization, per-tenant namespaces).",
});

// --- M4 (L3 foundation): identity / network / guardrail / observability / harness. ---
// The VPC interface endpoints are the only standing monthly cost, so they are OFF by
// default (context `sentinel:deployVpcEndpoints=true` opts in - see network-stack.ts).
const deployVpcEndpointsRaw = ctx<unknown>("sentinel:deployVpcEndpoints", false);
const deployVpcEndpoints =
  typeof deployVpcEndpointsRaw === "boolean" ? deployVpcEndpointsRaw : String(deployVpcEndpointsRaw) === "true";

const network = new NetworkStack(app, `${appName}-network`, {
  env,
  appName,
  deployVpcEndpoints,
  description: "Sentinel private VPC (isolated subnet, default-deny egress via PrivateLink; no NAT).",
});

const identity = new IdentityStack(app, `${appName}-identity`, {
  env,
  appName,
  cognitoDomainPrefix: ctx<string | undefined>("sentinel:cognitoDomainPrefix", undefined),
  description: "Sentinel Cognito identity (human JWT + M2M client_credentials) for the Gateway CUSTOM_JWT authorizer.",
});

const guardrail = new GuardrailStack(app, `${appName}-guardrail`, {
  env,
  appName,
  description: "Sentinel Bedrock Guardrail - masks secrets/PII in tool responses (injection/exfil defense).",
});

const observability = new ObservabilityStack(app, `${appName}-observability`, {
  env,
  appName,
  budgetEmail: ctx<string | undefined>("sentinel:budgetEmail", undefined),
  budgetAmountUsd: Number(ctx<unknown>("sentinel:budgetAmountUsd", 50)) || 50,
  description: "Sentinel observability - CloudWatch dashboard + TokensPerScenario metric + monthly budget alarm.",
});

const harness = new HarnessStack(app, `${appName}-harness`, {
  env,
  appName,
  executionRoleArn: ctx<string | undefined>("sentinel:harnessExecutionRoleArn", undefined),
  description: "Sentinel demo Harness via the native AWS::BedrockAgentCore::Harness CFN type (no custom resource).",
});

// Tag everything so cost/observability dashboards and the non-prod guardrail can
// filter by project + environment. `environment` defaults to non-prod on purpose.
for (const s of [gateway, registry, memory, network, identity, guardrail, observability, harness]) {
  Tags.of(s).add("project", "sentinel-harness");
  Tags.of(s).add("layer", "layer-3-foundation");
  Tags.of(s).add("environment", String(ctx("sentinel:environment", "non-prod")));
}

app.synth();
