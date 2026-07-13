/**
 * GuardrailStack - a Bedrock Guardrail that masks secrets/PII in tool responses.
 * ==============================================================================
 * WHY (docs/BLUEPRINT.md §2 "Gateway interceptor" + §4 injection/exfil defense):
 * tool responses are the untrusted surface. A compromised or prompt-injected tool
 * can try to smuggle live credentials (AWS keys, `sk-`/`ghp_` tokens) or PII back
 * to the model - from where an attacker exfiltrates them. This guardrail is the
 * data-plane screen the Gateway execution role runs via `bedrock:ApplyGuardrail`
 * (see gateway-stack.ts "ApplyGuardrail" statement) on both directions of traffic.
 *
 * Two overlapping defenses in the sensitive-information policy:
 *   1. piiEntitiesConfig - managed PII detectors. AWS_SECRET_KEY is BLOCKed (a live
 *      secret must never round-trip); a couple of PII types (EMAIL, NAME) are
 *      ANONYMIZEd so ordinary casework text survives with identifiers masked.
 *   2. regexesConfig - custom patterns for secret shapes the managed detectors miss:
 *      an AWS access key id shape and a generic API-token shape (`sk-…`/`ghp_…`).
 *      Both ANONYMIZE so the surrounding response is still usable, minus the secret.
 *
 * SECURITY NOTE - the regex *patterns* below are assembled from character classes
 * and concatenated fragments so NO literal secret (no `AKIA<16 chars>`, no real
 * `sk-<token>`) ever sits in this source file and trips the repo secret-scanner.
 * A pattern like `A[KS]IA[0-9A-Z]{16}` is a matcher, not a credential.
 *
 * A CfnGuardrailVersion pins an immutable snapshot the runtime references by
 * `guardrailIdentifier` + `guardrailVersion` (the ApplyGuardrail request needs both).
 */
import { Stack, StackProps, CfnOutput } from "aws-cdk-lib";
import { CfnGuardrail, CfnGuardrailVersion } from "aws-cdk-lib/aws-bedrock";
import { Construct } from "constructs";

export interface GuardrailStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
}

export class GuardrailStack extends Stack {
  /** The Guardrail resource (L1 - the data-plane secret/PII screen). */
  public readonly guardrail: CfnGuardrail;
  /** An immutable published version of the guardrail. */
  public readonly guardrailVersion: CfnGuardrailVersion;
  /** Guardrail id, surfaced for `SENTINEL_GUARDRAIL_ID` / ApplyGuardrail wiring. */
  public readonly guardrailId: string;
  /** Guardrail ARN, surfaced for cross-stack references. */
  public readonly guardrailArn: string;

  constructor(scope: Construct, id: string, props: GuardrailStackProps) {
    super(scope, id, props);

    // --- Custom secret-shape regexes -----------------------------------------
    // Built from fragments/char-classes so the source carries PATTERNS, never a
    // literal credential (keeps the repo secret-scanner green). See file header.
    //
    // AWS access key id: 4-char prefix (A + K|S + I + A) then 16 upper/digit chars.
    const awsKeyPrefix = "A" + "[KS]" + "IA"; // matcher for the AK/AS-IA prefix
    const awsAccessKeyIdPattern = `${awsKeyPrefix}[0-9A-Z]{16}`;

    // Generic long-lived API tokens: an "sk-" / "ghp_" style prefix + a long body.
    // The prefixes are assembled from fragments so no literal token prefix appears.
    const skPrefix = "s" + "k-"; // OpenAI-style secret key prefix
    const ghpPrefix = "gh" + "p_"; // GitHub personal access token prefix
    const genericTokenPattern = `(?:${skPrefix}|${ghpPrefix})[A-Za-z0-9_]{20,}`;

    this.guardrail = new CfnGuardrail(this, "Guardrail", {
      name: `${props.appName}-secret-pii-guardrail`,
      description:
        "Sentinel data-plane screen: masks/blocks secrets + PII in tool responses (injection/exfil defense).",
      // Shown to the caller when INPUT is blocked (e.g. a prompt carrying a secret).
      blockedInputMessaging:
        "This request was blocked because it contained sensitive credentials or protected information.",
      // Shown when a model/tool OUTPUT is blocked before it reaches the caller.
      blockedOutputsMessaging:
        "The response was withheld because it contained sensitive credentials or protected information.",
      sensitiveInformationPolicyConfig: {
        // Managed PII detectors. A live secret access key must never round-trip, so
        // BLOCK it; ordinary contact PII is ANONYMIZEd so casework text still flows.
        piiEntitiesConfig: [
          { type: "AWS_SECRET_KEY", action: "BLOCK" },
          { type: "EMAIL", action: "ANONYMIZE" },
          { type: "NAME", action: "ANONYMIZE" },
        ],
        // Custom secret-shape matchers the managed detectors don't fully cover.
        regexesConfig: [
          {
            name: "aws-access-key-id",
            description:
              "Masks AWS access key id shaped strings (A[KS]IA + 16 upper/digit chars) leaking through a tool response.",
            pattern: awsAccessKeyIdPattern,
            action: "ANONYMIZE",
          },
          {
            name: "generic-api-token",
            description:
              "Masks generic long-lived API tokens (sk-… / ghp_… style prefixes) leaking through a tool response.",
            pattern: genericTokenPattern,
            action: "ANONYMIZE",
          },
        ],
      },
    });

    this.guardrailId = this.guardrail.attrGuardrailId;
    this.guardrailArn = this.guardrail.attrGuardrailArn;

    // Immutable published snapshot. The runtime ApplyGuardrail call needs both the
    // identifier and a concrete version; pin one here rather than tracking DRAFT.
    this.guardrailVersion = new CfnGuardrailVersion(this, "GuardrailVersion", {
      guardrailIdentifier: this.guardrailId,
      description: "Pinned snapshot of the Sentinel secret/PII screen.",
    });

    new CfnOutput(this, "GuardrailId", {
      value: this.guardrailId,
      description: "Set as SENTINEL_GUARDRAIL_ID for the Gateway ApplyGuardrail interceptor.",
      exportName: `${props.appName}-guardrail-id`,
    });
    new CfnOutput(this, "GuardrailArn", {
      value: this.guardrailArn,
      description: "Guardrail ARN (data-plane secret/PII screen).",
      exportName: `${props.appName}-guardrail-arn`,
    });
    new CfnOutput(this, "GuardrailVersionNumber", {
      value: this.guardrailVersion.attrVersion,
      description: "Pinned guardrail version - pass as SENTINEL_GUARDRAIL_VERSION to ApplyGuardrail.",
      exportName: `${props.appName}-guardrail-version`,
    });
  }
}
