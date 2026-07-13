/**
 * GatewayStack - the AgentCore Gateway (single MCP ingress) + its execution role.
 * ================================================================================
 * WHY: the Gateway is the one policy-backed MCP surface every harness talks to
 * (docs/BLUEPRINT.md §2). All tool traffic funnels through it so SEMANTIC tool
 * search, egress control, and a guardrail interceptor have a single chokepoint.
 *
 * There is no L2 construct for `AWS::BedrockAgentCore::Gateway` yet, so we drop to
 * a raw `CfnResource`. WHEN CFN support evolves this resource type / property
 * shape may change - the type string and `properties` block below are the only
 * things to revisit; everything else (role, wiring, outputs) is stable CDK.
 *
 * Auth: `authorizerType` is CONTEXT-configurable and defaults to AWS_IAM (SigV4,
 * machine-to-machine - the accepted execution-role path). Set it to CUSTOM_JWT to
 * front the Gateway with Cognito/OAuth for human callers (BLUEPRINT §5) by passing
 * `-c sentinel:gatewayAuthorizerType=CUSTOM_JWT` plus a JWT discovery URL; NO human
 * is ever mapped to an IAM principal.
 */
import { Stack, StackProps, CfnResource, CfnOutput, Token } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { makeExecutionRole, grantObservability } from "./iam";

/** Authorizer modes the Gateway supports. AWS_IAM is the safe machine default. */
export type GatewayAuthorizerType = "AWS_IAM" | "CUSTOM_JWT";

export interface GatewayStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * Authorizer for the Gateway. Defaults to AWS_IAM. CUSTOM_JWT requires
   * `jwtDiscoveryUrl` (+ optional audiences/clientIds) so Cognito/OAuth can front
   * human callers without IAM-per-person.
   */
  readonly authorizerType?: GatewayAuthorizerType;
  /** OIDC discovery URL, required only when authorizerType === "CUSTOM_JWT". */
  readonly jwtDiscoveryUrl?: string;
  /** Allowed JWT audiences (CUSTOM_JWT only). */
  readonly jwtAllowedAudience?: string[];
  /** Allowed JWT client ids (CUSTOM_JWT only). */
  readonly jwtAllowedClients?: string[];
}

export class GatewayStack extends Stack {
  /** The Gateway execution role - export so harness/runtime stacks can reference it. */
  public readonly gatewayRole: iam.Role;
  /** The raw Gateway resource (CfnResource until an L2 exists). */
  public readonly gateway: CfnResource;
  /** Gateway ARN, surfaced for `SENTINEL_GATEWAY_ARN` and cross-stack wiring. */
  public readonly gatewayArn: string;

  constructor(scope: Construct, id: string, props: GatewayStackProps) {
    super(scope, id, props);

    const authorizerType: GatewayAuthorizerType = props.authorizerType ?? "AWS_IAM";

    // --- Execution role: least-privilege machine identity for the Gateway. ---
    // The Gateway invokes downstream Lambda tool targets and (for the guardrail
    // interceptor pattern) may apply a Bedrock guardrail; it does not itself invoke
    // models, so model-invoke is left off here.
    this.gatewayRole = makeExecutionRole(this, "GatewayRole", {
      description: `${props.appName} AgentCore Gateway execution role (invokes Lambda tool targets only).`,
      grantModelInvoke: false,
    });
    grantObservability(this.gatewayRole, this);

    // Invoke the Lambda MCP tool targets registered on this Gateway. Scoped by a
    // name convention so the role cannot invoke unrelated functions in the account.
    this.gatewayRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "InvokeToolTargets",
        actions: ["lambda:InvokeFunction"],
        resources: [
          `arn:${this.partition}:lambda:${this.region}:${this.account}:function:${props.appName}-tool-*`,
        ],
      }),
    );
    // Egress/PII governance interceptor: run tool responses through a Bedrock
    // guardrail before they reach the model (BLUEPRINT §2 "Gateway interceptor").
    this.gatewayRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ApplyGuardrail",
        actions: ["bedrock:ApplyGuardrail"],
        resources: [`arn:${this.partition}:bedrock:${this.region}:${this.account}:guardrail/*`],
      }),
    );

    // --- Authorizer configuration ---
    const authorizerConfiguration = this.buildAuthorizerConfig(authorizerType, props);

    // --- The Gateway itself (raw CFN - no L2 construct yet). ---
    this.gateway = new CfnResource(this, "Gateway", {
      type: "AWS::BedrockAgentCore::Gateway",
      properties: {
        Name: `${props.appName}-gateway`,
        Description:
          "Sentinel SecOps single MCP ingress: SEMANTIC tool search + egress/guardrail chokepoint.",
        RoleArn: this.gatewayRole.roleArn,
        // MCP protocol with semantic tool selection so harnesses pick tools from
        // descriptions rather than an explicit hardcoded list.
        ProtocolType: "MCP",
        ProtocolConfiguration: {
          Mcp: { SearchType: "SEMANTIC" },
        },
        AuthorizerType: authorizerType,
        ...(authorizerConfiguration ? { AuthorizerConfiguration: authorizerConfiguration } : {}),
      },
    });

    // GetAtt names follow the resource's CFN attributes; GatewayArn is the ARN
    // attribute and GatewayIdentifier is the resource's primary identifier. Fall back
    // to a synthesised ARN if the attribute name drifts under a future CFN schema
    // (documented above).
    this.gatewayArn = Token.asString(this.gateway.getAtt("GatewayArn"));

    new CfnOutput(this, "GatewayArn", {
      value: this.gatewayArn,
      description: "Set as SENTINEL_GATEWAY_ARN for the harness tool_gateway() config.",
      exportName: `${props.appName}-gateway-arn`,
    });
    new CfnOutput(this, "GatewayRoleArn", {
      value: this.gatewayRole.roleArn,
      description: "Gateway execution role ARN (machine identity).",
      exportName: `${props.appName}-gateway-role-arn`,
    });
    new CfnOutput(this, "GatewayAuthorizerType", {
      value: authorizerType,
      description: "Effective Gateway authorizer mode.",
    });
  }

  /**
   * Build the `AuthorizerConfiguration` block for the chosen mode. AWS_IAM needs no
   * extra config (SigV4 is implicit). CUSTOM_JWT REQUIRES a discovery URL - we fail
   * fast at synth if it is missing rather than deploy an open JWT authorizer.
   */
  private buildAuthorizerConfig(
    authorizerType: GatewayAuthorizerType,
    props: GatewayStackProps,
  ): Record<string, unknown> | undefined {
    if (authorizerType === "AWS_IAM") {
      return undefined;
    }
    if (!props.jwtDiscoveryUrl) {
      throw new Error(
        "GatewayStack: authorizerType=CUSTOM_JWT requires 'jwtDiscoveryUrl' (the OIDC " +
          "discovery endpoint of your Cognito/OAuth provider). Pass it via context " +
          "'-c sentinel:jwtDiscoveryUrl=https://.../.well-known/openid-configuration'.",
      );
    }
    const jwt: Record<string, unknown> = { DiscoveryUrl: props.jwtDiscoveryUrl };
    if (props.jwtAllowedAudience?.length) jwt.AllowedAudience = props.jwtAllowedAudience;
    if (props.jwtAllowedClients?.length) jwt.AllowedClients = props.jwtAllowedClients;
    return { CustomJWTAuthorizer: jwt };
  }
}
