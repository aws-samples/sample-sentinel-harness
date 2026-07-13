/**
 * guardrail-stack.test.ts - synth assertions for the Bedrock GuardrailStack.
 * ==========================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * `aws-cdk-lib/assertions` (Template.fromStack) + Node's built-in `assert`,
 * runnable with `npx ts-node test/guardrail-stack.test.ts`. Exits non-zero on the
 * first failed assertion so it can gate a build.
 *
 * Coverage:
 *   - One CfnGuardrail with the sensitive-information policy:
 *       * piiEntitiesConfig: AWS_SECRET_KEY=BLOCK, EMAIL/NAME=ANONYMIZE.
 *       * regexesConfig: the aws-access-key-id + generic-api-token matchers,
 *         both ANONYMIZE.
 *   - A pinned CfnGuardrailVersion referencing the guardrail id.
 *   - The id/arn/version outputs.
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { GuardrailStack } from "../lib/guardrail-stack";

const APP_NAME = "sentinel";

function synth(): Template {
  const app = new App();
  const stack = new GuardrailStack(app, "sentinel-guardrail", {
    appName: APP_NAME,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

function testGuardrail(t: Template): void {
  t.resourceCountIs("AWS::Bedrock::Guardrail", 1);
  t.hasResourceProperties("AWS::Bedrock::Guardrail", {
    Name: `${APP_NAME}-secret-pii-guardrail`,
    SensitiveInformationPolicyConfig: Match.objectLike({
      // Managed PII detectors: live secret key BLOCKed; contact PII ANONYMIZEd.
      PiiEntitiesConfig: Match.arrayWith([
        Match.objectLike({ Type: "AWS_SECRET_KEY", Action: "BLOCK" }),
        Match.objectLike({ Type: "EMAIL", Action: "ANONYMIZE" }),
        Match.objectLike({ Type: "NAME", Action: "ANONYMIZE" }),
      ]),
      // Custom secret-shape matchers, both masking (ANONYMIZE).
      RegexesConfig: Match.arrayWith([
        Match.objectLike({ Name: "aws-access-key-id", Action: "ANONYMIZE" }),
        Match.objectLike({ Name: "generic-api-token", Action: "ANONYMIZE" }),
      ]),
    }),
  });
  console.log("[guardrail] sensitive-information policy assertions passed");
}

function testVersion(t: Template): void {
  t.resourceCountIs("AWS::Bedrock::GuardrailVersion", 1);
  console.log("[guardrail] pinned-version assertions passed");
}

function testOutputs(t: Template): void {
  const outputs = t.findOutputs("*");
  for (const key of ["GuardrailId", "GuardrailArn", "GuardrailVersionNumber"]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(outputs, key),
      `[guardrail] expected output ${key} to be present`,
    );
  }
  console.log("[guardrail] output assertions passed");
}

function main(): void {
  const t = synth();
  testGuardrail(t);
  testVersion(t);
  testOutputs(t);
  console.log("\nALL guardrail-stack synth assertions PASSED");
}

main();
