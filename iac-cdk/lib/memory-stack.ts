/**
 * MemoryStack — AgentCore Memory with semantic + summarization strategies.
 * =========================================================================
 * WHY (docs/BLUEPRINT.md §1 Layer-1 "feedback loop" + core.py `managed_memory`):
 * triage verdicts and FP/whitelist decisions are written to Memory so future
 * research/detection runs are grounded in prior facts rather than confabulated.
 *
 * Two strategies are provisioned:
 *   - SEMANTIC — long-term extracted facts, retrieved by relevance. This is what
 *     grounds "have we seen this IOC / CVE / technique before".
 *   - SUMMARIZATION — rolling session summaries so long-running cases (malware
 *     detonation, campaign hunts) keep context across the ~8h session cap without
 *     replaying the full transcript.
 *
 * Per-tenant namespaces (the multi-tenant isolation boundary): AgentCore namespaces
 * template on the `actorId` supplied at invoke time (core.py `invoke(..., actor_id=)`).
 * We template the strategy namespaces as `facts/{actorId}` and
 * `summaries/{actorId}/{sessionId}` so one tenant/analyst can never read another's
 * memory — the namespace IS the boundary (see core.py `managed_memory` docstring).
 *
 * No L2 construct exists for `AWS::BedrockAgentCore::Memory` yet → raw CfnResource.
 * WHEN CFN support evolves, only the `type`/`properties`/strategy shape need review.
 */
import {
  Stack,
  StackProps,
  CfnResource,
  CfnOutput,
  Token,
} from "aws-cdk-lib";
import { Construct } from "constructs";

export interface MemoryStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`). */
  readonly appName: string;
  /**
   * Event expiry in days (context `sentinel:memoryExpiryDays`, default 90). Short
   * enough to bound retention for a non-prod account; raise for real casework.
   */
  readonly expiryDays?: number;
}

export class MemoryStack extends Stack {
  /** The AgentCore Memory resource (raw CFN until an L2 exists). */
  public readonly memory: CfnResource;
  /** Memory ARN, surfaced for `SENTINEL_MEMORY_ARN` and byo_memory() wiring. */
  public readonly memoryArn: string;

  constructor(scope: Construct, id: string, props: MemoryStackProps) {
    super(scope, id, props);

    const expiryDays = props.expiryDays ?? 90;

    // Per-tenant namespace templates. `{actorId}` is substituted server-side from
    // the invoke-time actorId; it is the isolation boundary between analysts/tenants.
    const factsNamespace = "facts/{actorId}";
    const summaryNamespace = "summaries/{actorId}/{sessionId}";

    this.memory = new CfnResource(this, "Memory", {
      type: "AWS::BedrockAgentCore::Memory",
      properties: {
        Name: `${props.appName}_memory`,
        Description:
          "Sentinel SecOps memory: semantic facts + rolling summaries, per-tenant (actorId) namespaces.",
        // Event retention window (days). Bounds how long raw events persist before
        // only the extracted strategy records remain.
        EventExpiryDuration: expiryDays,
        MemoryStrategies: [
          {
            // Long-term extracted facts, retrieved by semantic relevance. Grounds
            // "have we seen this before" without replaying transcripts.
            SemanticMemoryStrategy: {
              Name: `${props.appName}-semantic-facts`,
              Namespaces: [factsNamespace],
            },
          },
          {
            // Rolling session summaries so long-running cases survive the session
            // cap with compact context.
            SummaryMemoryStrategy: {
              Name: `${props.appName}-session-summary`,
              Namespaces: [summaryNamespace],
            },
          },
        ],
      },
    });

    this.memoryArn = Token.asString(this.memory.getAtt("MemoryArn"));

    new CfnOutput(this, "MemoryArn", {
      value: this.memoryArn,
      description: "Set as SENTINEL_MEMORY_ARN for core.byo_memory() / harness memory config.",
      exportName: `${props.appName}-memory-arn`,
    });
    new CfnOutput(this, "MemoryFactsNamespace", {
      value: factsNamespace,
      description: "Semantic-facts namespace template (per-tenant via {actorId}).",
    });
    new CfnOutput(this, "MemorySummaryNamespace", {
      value: summaryNamespace,
      description: "Session-summary namespace template (per-tenant/session).",
    });
  }
}
