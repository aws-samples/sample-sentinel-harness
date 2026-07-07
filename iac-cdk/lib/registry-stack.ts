/**
 * RegistryStack - AgentCore Registry + the DynamoDB tool/skill registry table.
 * =============================================================================
 * WHY (docs/BLUEPRINT.md §5 "Central skill/tool governance"): a capability is live
 * only if it appears in BOTH the AgentCore Registry AND the code TOOL_FACTORY_MAP
 * (mirrored by sentinel_harness/registry.py). This stack provisions the two
 * governance surfaces:
 *   1. An AgentCore Registry with autoApproval=FALSE - a specialist/agent goes
 *      live only after a human review step (governance, not convenience).
 *   2. A DynamoDB table holding the declarative tool/skill allowlist (the same
 *      shape as registry/tools.yaml: name/owner/status/description), so SecOps can
 *      approve/deprecate a capability without shipping code.
 *
 * No L2 construct exists for `AWS::BedrockAgentCore::Registry`, so it is a raw
 * CfnResource; the DynamoDB table is a normal L2. WHEN CFN support evolves, only
 * the CfnResource `type`/`properties` need revisiting.
 *
 * HONEST STATUS - TWO PATHS behind the `sentinel:registryViaCustomResource` flag:
 *
 *   PATH A (DEFAULT, flag off): the Registry is a raw CfnResource of type
 *     `AWS::BedrockAgentCore::Registry`. Unlike the Gateway/Memory/Harness types,
 *     this is NOT YET a registered CloudFormation resource type (`aws
 *     cloudformation describe-type --type RESOURCE --type-name
 *     AWS::BedrockAgentCore::Registry` returns TypeNotFoundException). This path
 *     therefore SYNTHS cleanly but would FAIL on deploy until AWS registers the
 *     type. Kept as the default so nothing regresses.
 *
 *   PATH B (flag on, `-c sentinel:registryViaCustomResource=true`): the Registry
 *     is provisioned through a Lambda-backed provider-framework CUSTOM RESOURCE
 *     (lib/registry-cr.ts + lambda/registry-provider) that drives the AgentCore
 *     CONTROL plane (`bedrock-agentcore-control`, the plane
 *     sentinel_harness/gateway.py uses) on Create/Update/Delete, with a
 *     least-privilege IAM policy scoped to the Registry control-plane actions.
 *     This is the DEPLOY-READY FALLBACK pending GA of the CFN type. The exact
 *     control-plane action names are annotated TODO(confirm-against-GA) - the
 *     mechanism/IAM/RegistryArn contract are correct; no live deploy has been run.
 *
 * BOTH paths emit the SAME outputs (RegistryArn / RegistryAutoApproval /
 * ToolRegistryTableName) and BOTH provision the fully-deployable DynamoDB
 * governance table (partition on `name`, `by-status` GSI). autoApproval defaults
 * to FALSE (human review required) in either path.
 */
import {
  Stack,
  StackProps,
  CfnResource,
  CfnOutput,
  RemovalPolicy,
  Token,
} from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";
import { RegistryCustomResource } from "./registry-cr";

export interface RegistryStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`). */
  readonly appName: string;
  /**
   * Registry auto-approval. Defaults to FALSE for governance - a registered
   * agent/tool is not live until a human approves it. Overridable only via context
   * for non-prod experimentation; production governance keeps it false.
   */
  readonly autoApproval?: boolean;
  /**
   * Feature flag (context `sentinel:registryViaCustomResource`, default FALSE).
   * FALSE keeps the raw `AWS::BedrockAgentCore::Registry` CfnResource (synth-only
   * until the CFN type is GA - zero regression). TRUE provisions the Registry via
   * the Lambda-backed custom resource (lib/registry-cr.ts), the DEPLOY-READY
   * fallback that drives the `bedrock-agentcore-control` plane directly.
   */
  readonly viaCustomResource?: boolean;
}

export class RegistryStack extends Stack {
  /** The AgentCore Registry as a raw CFN resource (PATH A, default). Undefined on PATH B. */
  public readonly registry?: CfnResource;
  /** The custom-resource-backed Registry (PATH B). Undefined on PATH A. */
  public readonly registryCr?: RegistryCustomResource;
  /** DynamoDB table backing the declarative tool/skill allowlist. */
  public readonly registryTable: dynamodb.Table;
  public readonly registryArn: string;

  constructor(scope: Construct, id: string, props: RegistryStackProps) {
    super(scope, id, props);

    const autoApproval = props.autoApproval ?? false;
    const viaCustomResource = props.viaCustomResource ?? false;
    const registryName = `${props.appName}-registry`;
    const registryDescription =
      "Sentinel specialist/agent registry. autoApproval=false: an agent is live only after human review.";

    // --- AgentCore Registry: governance gate for specialist agents. Two paths
    // behind the flag (see the file header for the HONEST STATUS of each). ---
    if (viaCustomResource) {
      // PATH B: DEPLOY-READY fallback - Lambda-backed custom resource driving the
      // bedrock-agentcore-control plane, with least-privilege IAM (registry-cr.ts).
      this.registryCr = new RegistryCustomResource(this, "Registry", {
        registryName,
        description: registryDescription,
        // Governance-critical: false means a registered agent-card requires manual
        // approval before it can be discovered/invoked.
        autoApproval,
      });
      this.registryArn = this.registryCr.registryArn;
    } else {
      // PATH A (default): raw CfnResource - synths cleanly, fails on deploy until
      // the CFN type is GA. Kept as default so nothing regresses.
      this.registry = new CfnResource(this, "Registry", {
        type: "AWS::BedrockAgentCore::Registry",
        properties: {
          Name: registryName,
          Description: registryDescription,
          // Governance-critical: false means a registered agent-card requires manual
          // approval before it can be discovered/invoked.
          AutoApproval: autoApproval,
        },
      });
      this.registryArn = Token.asString(this.registry.getAtt("RegistryArn"));
    }

    // --- DynamoDB tool/skill registry: the declarative allowlist half of the
    // dual-gate (see sentinel_harness/registry.py). Partition on tool/skill name;
    // a `kind` attribute distinguishes tool vs skill entries. ---
    this.registryTable = new dynamodb.Table(this, "ToolRegistryTable", {
      tableName: `${props.appName}-tool-registry`,
      partitionKey: { name: "name", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      // On-demand + PITR: cheap for a low-write governance table, and the audit
      // history of who-approved-what is worth protecting.
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      // Non-prod target: DESTROY so `cdk destroy` leaves no orphan. Flip to RETAIN
      // for any environment whose approval history must survive stack deletion.
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // GSI to list by lifecycle status (approved/pending/deprecated) - the query a
    // governance dashboard runs ("show everything pending review").
    this.registryTable.addGlobalSecondaryIndex({
      indexName: "by-status",
      partitionKey: { name: "status", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "name", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    new CfnOutput(this, "RegistryArn", {
      value: this.registryArn,
      description: "AgentCore Registry ARN (specialist governance gate).",
      exportName: `${props.appName}-registry-arn`,
    });
    new CfnOutput(this, "RegistryAutoApproval", {
      value: String(autoApproval),
      description: "Registry autoApproval flag (false = human review required).",
    });
    new CfnOutput(this, "ToolRegistryTableName", {
      value: this.registryTable.tableName,
      description: "DynamoDB tool/skill allowlist table (declarative half of the dual-gate).",
      exportName: `${props.appName}-tool-registry-table`,
    });
  }
}
