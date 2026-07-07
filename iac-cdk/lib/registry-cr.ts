/**
 * registry-cr - the DEPLOY-READY custom-resource path for the AgentCore Registry.
 * =============================================================================
 * WHY: `AWS::BedrockAgentCore::Registry` is not yet a GA CloudFormation resource
 * type, so the raw-CfnResource path in registry-stack.ts synths but FAILS on
 * deploy. This helper provisions the same Registry through a provider-framework
 * custom resource backed by a small Node Lambda (lambda/registry-provider) that
 * drives the AgentCore CONTROL plane (`bedrock-agentcore-control`, the plane
 * sentinel_harness/gateway.py uses) on CREATE/UPDATE/DELETE.
 *
 * Least privilege: the handler role gets ONLY the AgentCore Registry control-plane
 * actions, scoped to registry ARNs in this account/region. Account/region come
 * from the CDK env (this.account / this.region via Aws.*), never hardcoded.
 *
 * HONESTY / TODO(confirm-against-GA): the exact IAM action strings + the SDK
 * command names in the Lambda are annotated placeholders (`bedrock-agentcore:*
 * Registry`) to confirm against the live service model before a real deploy. The
 * mechanism, RegistryArn return contract, and scoping shape are correct.
 */
import {
  Aws,
  CustomResource,
  Duration,
  RemovalPolicy,
  Token,
} from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import { Provider } from "aws-cdk-lib/custom-resources";
import { Construct } from "constructs";
import * as path from "path";

export interface RegistryCustomResourceProps {
  /** Registry name (`${appName}-registry`). */
  readonly registryName: string;
  /** Human-readable description surfaced on the Registry. */
  readonly description: string;
  /** Governance default false: an agent is live only after human approval. */
  readonly autoApproval: boolean;
}

/**
 * Provisions the AgentCore Registry via a Lambda-backed custom resource and
 * exposes the resulting RegistryArn. Drop-in replacement for the raw CfnResource.
 */
export class RegistryCustomResource extends Construct {
  /** The underlying custom resource (CREATE/UPDATE/DELETE → control plane). */
  public readonly resource: CustomResource;
  /** RegistryArn returned by the handler (GetAtt on the custom resource). */
  public readonly registryArn: string;

  constructor(scope: Construct, id: string, props: RegistryCustomResourceProps) {
    super(scope, id);

    // --- Handler: Node runtime, no bundled secrets, code from the asset dir.
    // Reads nothing hardcoded - region is injected by the Lambda runtime env. ---
    const onEvent = new lambda.Function(this, "OnEvent", {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "lambda", "registry-provider")),
      timeout: Duration.minutes(5),
      description:
        "AgentCore Registry lifecycle (Create/Update/Delete) via bedrock-agentcore-control.",
    });

    // --- Least-privilege: ONLY the Registry control-plane actions, scoped to
    // registry ARNs in THIS account/region (Aws.* resolve from the CDK env, never
    // hardcoded). TODO(confirm-against-GA): tighten the action list to the exact
    // GA action names once the service model is published. ---
    onEvent.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "AgentCoreRegistryControlPlane",
        effect: iam.Effect.ALLOW,
        actions: [
          // TODO(confirm-against-GA): confirm these action strings against the
          // live bedrock-agentcore-control model before a real deploy.
          "bedrock-agentcore:CreateRegistry",
          "bedrock-agentcore:UpdateRegistry",
          "bedrock-agentcore:DeleteRegistry",
          "bedrock-agentcore:GetRegistry",
          "bedrock-agentcore:ListRegistries",
        ],
        resources: [
          // Scope to registry resources in this account/region only.
          `arn:${Aws.PARTITION}:bedrock-agentcore:${Aws.REGION}:${Aws.ACCOUNT_ID}:registry/*`,
          `arn:${Aws.PARTITION}:bedrock-agentcore:${Aws.REGION}:${Aws.ACCOUNT_ID}:registry`,
        ],
      }),
    );

    // Explicit short-retention log group for the provider framework function
    // (avoids the deprecated `logRetention` prop; keeps CloudWatch cost bounded).
    const providerLogGroup = new logs.LogGroup(this, "ProviderLogs", {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const provider = new Provider(this, "Provider", {
      onEventHandler: onEvent,
      logGroup: providerLogGroup,
    });

    this.resource = new CustomResource(this, "Resource", {
      serviceToken: provider.serviceToken,
      resourceType: "Custom::AgentCoreRegistry",
      properties: {
        Name: props.registryName,
        Description: props.description,
        // Booleans cross the CFN boundary as strings; the handler coerces back.
        AutoApproval: String(props.autoApproval),
      },
    });

    // The handler returns Data.RegistryArn; expose it exactly like the raw path's
    // getAtt("RegistryArn") so the stack outputs are byte-for-byte equivalent.
    this.registryArn = Token.asString(this.resource.getAttString("RegistryArn"));
  }
}
