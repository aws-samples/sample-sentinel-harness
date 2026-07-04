/**
 * Shared least-privilege IAM role helpers for the sentinel-harness AgentCore stacks.
 * ===================================================================================
 * WHY this file exists: every AgentCore primitive (Gateway, Registry, Memory,
 * Harness, Runtime) runs under an *execution role* — a MACHINE identity. The house
 * rule (see docs/BLUEPRINT.md §5 "Auth") is that PEOPLE never map to an IAM
 * principal (they use Cognito/OAuth on the Gateway); only services do. These helpers
 * centralise that boundary so no stack hand-rolls an over-broad role.
 *
 * Design notes:
 * - Roles are scoped to the AgentCore service principal and, where the service
 *   supports it, confined to this account via `aws:SourceAccount` so the role
 *   cannot be assumed cross-account by a confused-deputy caller.
 * - We grant Bedrock model *invoke* on inference-profile / foundation-model ARNs
 *   built from the deploy-time account/region — NO hardcoded account IDs.
 * - Nothing here is customer- or company-specific.
 */
import { Stack, Arn, ArnFormat } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

/** The AgentCore service principal that assumes execution roles. */
export const AGENTCORE_SERVICE_PRINCIPAL = "bedrock-agentcore.amazonaws.com";

/**
 * Build the trust policy for an AgentCore execution role: the AgentCore service
 * may assume it, but only on behalf of THIS account (confused-deputy guard via
 * `aws:SourceAccount`). Region is left open because a single role is often shared
 * across the regional endpoints of one account.
 */
export function agentcoreAssumedBy(scope: Construct): iam.ServicePrincipal {
  const stack = Stack.of(scope);
  return new iam.ServicePrincipal(AGENTCORE_SERVICE_PRINCIPAL, {
    conditions: {
      StringEquals: { "aws:SourceAccount": stack.account },
    },
  });
}

/**
 * Create a least-privilege AgentCore execution role. Callers attach only the
 * specific resource grants they need; this seeds the trust policy + optional
 * Bedrock model-invoke (the one permission nearly every harness/runtime needs).
 *
 * @param grantModelInvoke when true, allow `bedrock:InvokeModel*` on the account's
 *        inference-profile + foundation-model ARNs (cross-region inference pattern
 *        used by core.py's `global.*` / `us.*` model IDs). No account is hardcoded —
 *        the ARNs are synthesised from the deploy-time account/region.
 */
export function makeExecutionRole(
  scope: Construct,
  id: string,
  opts: { roleName?: string; grantModelInvoke?: boolean; description?: string } = {},
): iam.Role {
  const stack = Stack.of(scope);
  const role = new iam.Role(scope, id, {
    assumedBy: agentcoreAssumedBy(scope),
    roleName: opts.roleName,
    description:
      opts.description ??
      "sentinel-harness AgentCore execution role (least-privilege, machine identity only).",
  });

  if (opts.grantModelInvoke) {
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: "InvokeBedrockModels",
        actions: [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ],
        // Cross-region inference profiles + underlying foundation models. Account
        // and region come from the deploy target, never hardcoded.
        resources: [
          Arn.format(
            { service: "bedrock", resource: "inference-profile", resourceName: "*" },
            stack,
          ),
          // Foundation models are region-scoped but account-less in their ARN.
          `arn:${stack.partition}:bedrock:${stack.region}::foundation-model/*`,
          // A cross-region profile fans out to sibling regions; allow the wildcard
          // region form so `global.*` / `us.*` profiles resolve.
          `arn:${stack.partition}:bedrock:*::foundation-model/*`,
        ],
      }),
    );
  }

  return role;
}

/**
 * Grant an execution role the observability permissions AgentCore emits by default
 * (CloudWatch Logs + metrics + X-Ray traces). Scoped to the account/region; log
 * groups are confined to the AgentCore namespace so the role cannot write arbitrary
 * groups. Every stack that owns a role should call this so traces show up without
 * granting a broad `logs:*`.
 */
export function grantObservability(role: iam.Role, scope: Construct): void {
  const stack = Stack.of(scope);
  role.addToPolicy(
    new iam.PolicyStatement({
      sid: "Observability",
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
      ],
      resources: [
        Arn.format(
          {
            service: "logs",
            resource: "log-group",
            resourceName: "/aws/bedrock-agentcore/*",
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          },
          stack,
        ),
      ],
    }),
  );
  role.addToPolicy(
    new iam.PolicyStatement({
      sid: "Metrics",
      // PutMetricData has no resource-level scoping; confine it to the AgentCore
      // metric namespace so the role cannot pollute arbitrary namespaces.
      actions: ["cloudwatch:PutMetricData"],
      resources: ["*"],
      conditions: {
        StringEquals: { "cloudwatch:namespace": "bedrock-agentcore" },
      },
    }),
  );
  role.addToPolicy(
    new iam.PolicyStatement({
      sid: "Tracing",
      // X-Ray write APIs do not support resource-level scoping or the namespace
      // condition; the account boundary is the guard. Kept in its own statement so
      // the invalid namespace condition is never attached to these actions.
      actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
      resources: ["*"],
    }),
  );
}
