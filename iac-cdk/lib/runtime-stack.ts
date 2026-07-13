/**
 * RuntimeStack - the specialist / long-running AgentCore Runtime, declaratively.
 * =============================================================================
 * WHY (docs/ARCHITECTURE.md "Harness vs Runtime"): a Runtime is YOUR container in
 * a per-session microVM - full loop control, non-Bedrock models via LiteLLM, and
 * hours-long async jobs that exceed a harness `timeoutSeconds`. It is the compute
 * tier behind the A2A specialists (`specialists/cve-intel`, `threat-hunt`) and the
 * long-running BAS/detonation jobs (`longrunning/`). This stack provisions that
 * Runtime as infrastructure so a specialist can be stood up + version-controlled
 * alongside the Gateway/Registry/Memory/Harness foundation, instead of only via
 * the imperative `create_agent_runtime(...)` control-plane call.
 *
 * There is no L2 construct for `AWS::BedrockAgentCore::Runtime`, so it is a raw
 * `CfnResource`; the container image (ECR `containerUri`) and execution-role ARN
 * come from props/context, never hardcoded.
 *
 * HONEST STATUS - MIRRORS RegistryStack's DEFAULT (PATH A) raw-CfnResource pattern:
 *
 *   The Runtime is a raw CfnResource of type `AWS::BedrockAgentCore::Runtime`.
 *   Unlike `AWS::BedrockAgentCore::Harness` (a registered, FULLY_MUTABLE CFN type),
 *   this Runtime type is NOT YET a registered CloudFormation resource type (`aws
 *   cloudformation describe-type --type RESOURCE --type-name
 *   AWS::BedrockAgentCore::Runtime` returns TypeNotFoundException). This stack
 *   therefore SYNTHS cleanly but would FAIL on deploy until AWS registers the type.
 *
 *   What IS real: the CONTROL-PLANE API itself is live-verified. A real Runtime was
 *   created + torn down via `CreateAgentRuntime` on a non-prod TEST account (PUBLIC
 *   net, A2A protocol) - a live A2A JSON-RPC `message/send` returned HTTP 200 and the
 *   `cve-intel` container invoked the real Bedrock model (see
 *   `evidence/live_a2a_runtime_result.json` + `scenarios/scenario_live_a2a_runtime.py`).
 *   So the SHAPE below (containerConfiguration.containerUri / roleArn /
 *   networkConfiguration=PUBLIC / protocolConfiguration=A2A) is exactly what the
 *   proven control-plane call used; only the CFN *type registration* is pending.
 *
 * No Lambda-backed custom-resource fallback is added here (unlike registry-cr.ts):
 * a documented raw-CfnResource + this honesty note is the proportionate declarative
 * mirror, and the imperative control-plane path is already covered live by the
 * scenario above. WHEN the CFN type reaches GA, only the CfnResource `type` /
 * `properties` block need revisiting; the role, wiring, and outputs are stable CDK.
 */
import { Stack, StackProps, CfnResource, CfnOutput, Token } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { makeExecutionRole, grantObservability } from "./iam";

/** Network modes the Runtime supports. PUBLIC is the A2A-specialist default. */
export type RuntimeNetworkMode = "PUBLIC" | "VPC";
/** Server protocols the Runtime speaks. A2A is the specialist default. */
export type RuntimeServerProtocol = "A2A" | "HTTP";

export interface RuntimeStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * ECR image URI for the specialist container
   * (`containerConfiguration.containerUri`). Supplied via prop or context
   * `sentinel:runtimeContainerUri`. A documented placeholder is used at synth time
   * so `cdk synth` of the whole app stays clean; a real deploy must pass a real URI.
   */
  readonly containerUri?: string;
  /**
   * Optional PRE-EXISTING execution-role ARN (e.g. the `sentinel-runtime-exec` role
   * from `specialists/`, or one exported by another stack / supplied via context
   * `sentinel:runtimeExecutionRoleArn`). When omitted, this stack mints a
   * least-privilege AgentCore execution role with model-invoke + observability
   * grants via the shared iam.ts helpers. Never hardcoded.
   */
  readonly executionRoleArn?: string;
  /** Network mode. Defaults to PUBLIC (the proven A2A-specialist path). */
  readonly networkMode?: RuntimeNetworkMode;
  /** Server protocol. Defaults to A2A (the proven specialist path). */
  readonly serverProtocol?: RuntimeServerProtocol;
}

/**
 * Placeholder ECR image used only when no `containerUri` is supplied, so a
 * whole-app `cdk synth` stays clean. Account is 000000000000 (RFC-5737-style
 * public-repo placeholder); a real deploy MUST override this with a real image.
 */
const PLACEHOLDER_CONTAINER_URI =
  "000000000000.dkr.ecr.us-east-1.amazonaws.com/sentinel-cve-intel:placeholder";

export class RuntimeStack extends Stack {
  /** The execution role - created here unless a pre-existing ARN was supplied. */
  public readonly runtimeRole?: iam.Role;
  /** The raw Runtime resource (CfnResource until the CFN type is GA). */
  public readonly runtime: CfnResource;
  /** Runtime ARN (GetAtt "AgentRuntimeArn"), surfaced for invoke/wiring. */
  public readonly agentRuntimeArn: string;
  /** Runtime id (GetAtt "AgentRuntimeId"), surfaced for InvokeAgentRuntime ops. */
  public readonly agentRuntimeId: string;

  constructor(scope: Construct, id: string, props: RuntimeStackProps) {
    super(scope, id, props);

    const containerUri = props.containerUri ?? PLACEHOLDER_CONTAINER_URI;
    const networkMode: RuntimeNetworkMode = props.networkMode ?? "PUBLIC";
    const serverProtocol: RuntimeServerProtocol = props.serverProtocol ?? "A2A";

    // --- Execution role: use the supplied ARN, else mint a least-privilege one. ---
    // The Runtime container runs the agent loop and invokes Bedrock models (the
    // cve-intel specialist calls the real model over LiteLLM), so it needs
    // model-invoke. Observability grants let traces/metrics flow.
    let executionRoleArn: string;
    if (props.executionRoleArn) {
      executionRoleArn = props.executionRoleArn;
    } else {
      this.runtimeRole = makeExecutionRole(this, "RuntimeRole", {
        description: `${props.appName} AgentCore Runtime execution role (specialist container; invokes Bedrock models).`,
        grantModelInvoke: true,
      });
      grantObservability(this.runtimeRole, this);
      executionRoleArn = this.runtimeRole.roleArn;
    }

    // --- The Runtime itself (raw CFN - type not GA; synths, fails on deploy until
    // registered - see the file header). Property shape mirrors the proven
    // control-plane CreateAgentRuntime call (PascalCase for CFN). ---
    this.runtime = new CfnResource(this, "Runtime", {
      type: "AWS::BedrockAgentCore::Runtime",
      properties: {
        // AgentRuntimeName must match the server-side [a-zA-Z][a-zA-Z0-9_]* shape
        // (no hyphens), so the appName prefix is joined with an underscore.
        AgentRuntimeName: `${props.appName}_specialist`,
        Description:
          "Sentinel specialist / long-running AgentCore Runtime (A2A specialist container / BAS-detonation tier).",
        // The container image (ECR) that AgentCore runs in a per-session microVM.
        AgentRuntimeArtifact: {
          ContainerConfiguration: {
            ContainerUri: containerUri,
          },
        },
        RoleArn: executionRoleArn,
        // PUBLIC by default: the proven A2A-specialist path. Long-running jobs that
        // need egress control run VPC mode (docs/ARCHITECTURE.md "Egress control").
        NetworkConfiguration: {
          NetworkMode: networkMode,
        },
        // A2A by default: JSON-RPC message/send, the specialist delegation protocol.
        ProtocolConfiguration: {
          ServerProtocol: serverProtocol,
        },
      },
    });

    // GetAtt names follow the resource's read-only CFN attributes: AgentRuntimeArn
    // is the ARN, AgentRuntimeId the short id used by InvokeAgentRuntime.
    this.agentRuntimeArn = Token.asString(this.runtime.getAtt("AgentRuntimeArn"));
    this.agentRuntimeId = Token.asString(this.runtime.getAtt("AgentRuntimeId"));

    new CfnOutput(this, "AgentRuntimeArn", {
      value: this.agentRuntimeArn,
      description: "AgentCore Runtime ARN (specialist / long-running container tier).",
      exportName: `${props.appName}-runtime-arn`,
    });
    new CfnOutput(this, "AgentRuntimeId", {
      value: this.agentRuntimeId,
      description: "Runtime id (GetAtt AgentRuntimeId) for InvokeAgentRuntime / teardown.",
      exportName: `${props.appName}-runtime-id`,
    });
    new CfnOutput(this, "RuntimeExecutionRoleArn", {
      value: executionRoleArn,
      description: "Runtime execution role ARN (machine identity; created here or supplied).",
    });
    new CfnOutput(this, "RuntimeNetworkMode", {
      value: networkMode,
      description: "Effective Runtime network mode (PUBLIC default; VPC for egress control).",
    });
    new CfnOutput(this, "RuntimeServerProtocol", {
      value: serverProtocol,
      description: "Effective Runtime server protocol (A2A default for specialist delegation).",
    });
  }
}
