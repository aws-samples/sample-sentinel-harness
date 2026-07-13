/**
 * HarnessStack - a demo SecOps triage Harness via the NATIVE CFN type.
 * =====================================================================
 * WHY (docs/BLUEPRINT.md §1 "agents as configuration"): a harness IS the agent -
 * a managed agentic loop (systemPrompt + model + limits) that the sentinel_harness
 * Python core creates at runtime via `core.create_harness(...)`. This stack
 * provisions the SAME thing declaratively so a triage agent can be stood up as
 * infrastructure and version-controlled alongside the Gateway/Registry/Memory
 * foundation.
 *
 * NATIVE TYPE - NO CUSTOM RESOURCE.
 * ---------------------------------
 * `AWS::BedrockAgentCore::Harness` is a *registered, FULLY_MUTABLE* CloudFormation
 * resource type (verified via `aws cloudformation describe-type --type RESOURCE
 * --type-name AWS::BedrockAgentCore::Harness`). This corrects an earlier ROADMAP
 * assumption that a Lambda-backed custom resource would be needed - it is not. We
 * use a plain CDK L1 `CfnResource` on the native type; CloudFormation drives the
 * create/update/delete lifecycle directly (no bespoke handler, no drift risk).
 *
 * The property/attribute names below are matched EXACTLY to that live CFN schema:
 *   - Required:  HarnessName, ExecutionRoleArn, Model
 *   - SystemPrompt is an ARRAY of {Text: ...} blocks (mirrors core.create_harness
 *     normalizing `system_prompt` to the GA `[{"text": ...}]` list shape).
 *   - Model.BedrockModelConfig.{ModelId,Temperature,MaxTokens} is the model config.
 *   - MaxIterations / MaxTokens / TimeoutSeconds are top-level integers.
 *   - There is NO top-level `Description` property on this type (unlike Gateway /
 *     Memory), so none is set here.
 * Read-only attributes exposed for GetAtt: Arn, HarnessId, Status, Version,
 * CreatedAt, UpdatedAt. `Ref` returns the primaryIdentifier (the ARN).
 *
 * The execution role ARN is supplied via props (from the shared iam.ts helpers or a
 * pre-existing role ARN passed through context) - it is NEVER hardcoded.
 */
import { Stack, StackProps, CfnResource, CfnOutput, Token } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { makeExecutionRole, grantObservability } from "./iam";

export interface HarnessStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * Bedrock model id for the harness loop. Defaults to the cross-region Sonnet
   * inference-profile pattern used by core.py (`SENTINEL_MODEL_SONNET`). Override
   * via context `sentinel:harnessModelId`. No version is pinned that cannot be
   * verified at deploy time.
   */
  readonly modelId?: string;
  /**
   * Optional PRE-EXISTING execution-role ARN (e.g. exported by another stack or
   * supplied via context `sentinel:harnessExecutionRoleArn`). When omitted, this
   * stack creates a least-privilege AgentCore execution role with model-invoke +
   * observability grants via the shared iam.ts helpers. Never hardcoded.
   */
  readonly executionRoleArn?: string;
  /** Max agent-loop iterations per invocation (default 15, mirrors the YAML demo). */
  readonly maxIterations?: number;
  /** Max tokens the model may generate per iteration (default 4096). */
  readonly maxTokens?: number;
  /** Max wall-clock seconds for one agent-loop invocation (default 300). */
  readonly timeoutSeconds?: number;
}

/** Demo triage system prompt - generic SecOps alert triage, no customer specifics. */
const DEMO_TRIAGE_SYSTEM_PROMPT = [
  "You are a SecOps alert-triage agent.",
  "Given a security alert, classify it as true-positive, false-positive, or needs-investigation,",
  "assign a severity (low/medium/high/critical), cite the concrete signals behind your verdict,",
  "and recommend the next action. Be precise and evidence-driven; never fabricate indicators.",
].join(" ");

export class HarnessStack extends Stack {
  /** The execution role - created here unless a pre-existing ARN was supplied. */
  public readonly harnessRole?: iam.Role;
  /** The raw Harness resource (native CFN L1 - no custom resource). */
  public readonly harness: CfnResource;
  /** Harness ARN (GetAtt "Arn"), surfaced for `SENTINEL_HARNESS_ARN` wiring. */
  public readonly harnessArn: string;
  /** Harness id (GetAtt "HarnessId"), surfaced for invoke/endpoint operations. */
  public readonly harnessId: string;

  constructor(scope: Construct, id: string, props: HarnessStackProps) {
    super(scope, id, props);

    // Model id: context/prop override, else the cross-region Sonnet profile pattern
    // (matches core.py MODEL_SONNET). No unverifiable version pinned.
    const modelId = props.modelId ?? "global.anthropic.claude-sonnet-4-6";
    const maxIterations = props.maxIterations ?? 15;
    const maxTokens = props.maxTokens ?? 4096;
    const timeoutSeconds = props.timeoutSeconds ?? 300;

    // --- Execution role: use the supplied ARN, else mint a least-privilege one. ---
    // The harness runs the agentic loop and invokes Bedrock models, so it needs
    // model-invoke (unlike the Gateway). Observability grants let traces/metrics flow.
    let executionRoleArn: string;
    if (props.executionRoleArn) {
      executionRoleArn = props.executionRoleArn;
    } else {
      this.harnessRole = makeExecutionRole(this, "HarnessRole", {
        description: `${props.appName} AgentCore Harness execution role (agent loop; invokes Bedrock models).`,
        grantModelInvoke: true,
      });
      grantObservability(this.harnessRole, this);
      executionRoleArn = this.harnessRole.roleArn;
    }

    // --- The Harness itself (NATIVE CFN type - no custom resource). ---
    // Property names match the live AWS::BedrockAgentCore::Harness schema exactly.
    this.harness = new CfnResource(this, "Harness", {
      type: "AWS::BedrockAgentCore::Harness",
      properties: {
        // HarnessName must match [a-zA-Z][a-zA-Z0-9_]{0,39} server-side (no hyphens),
        // so the appName prefix is joined with an underscore, not a dash.
        HarnessName: `${props.appName}_triage`,
        ExecutionRoleArn: executionRoleArn,
        // Required. Bedrock cross-region inference profile / model id.
        Model: {
          BedrockModelConfig: {
            ModelId: modelId,
            // Low temperature: triage wants deterministic, evidence-driven output.
            Temperature: 0,
            MaxTokens: maxTokens,
          },
        },
        // SystemPrompt is an ARRAY of {Text} blocks (GA list shape, same as
        // core.create_harness normalizing system_prompt to [{"text": ...}]).
        SystemPrompt: [{ Text: DEMO_TRIAGE_SYSTEM_PROMPT }],
        MaxIterations: maxIterations,
        MaxTokens: maxTokens,
        TimeoutSeconds: timeoutSeconds,
      },
    });

    // GetAtt names follow the resource's read-only CFN attributes. `Arn` is the
    // primaryIdentifier; `HarnessId` is the short id used by invoke/endpoint ops.
    this.harnessArn = Token.asString(this.harness.getAtt("Arn"));
    this.harnessId = Token.asString(this.harness.getAtt("HarnessId"));

    new CfnOutput(this, "HarnessArn", {
      value: this.harnessArn,
      description: "Set as SENTINEL_HARNESS_ARN for invoke/endpoint operations.",
      exportName: `${props.appName}-harness-arn`,
    });
    new CfnOutput(this, "HarnessId", {
      value: this.harnessId,
      description: "Harness id (GetAtt HarnessId) for InvokeHarness / CreateHarnessEndpoint.",
      exportName: `${props.appName}-harness-id`,
    });
    new CfnOutput(this, "HarnessExecutionRoleArn", {
      value: executionRoleArn,
      description: "Harness execution role ARN (machine identity; created here or supplied).",
    });
  }
}
