/**
 * registry-stack.test.ts - synth assertions for BOTH paths of the RegistryStack.
 * =============================================================================
 * No jest is wired into this package (see package.json), so this is a
 * self-contained, zero-dependency test: it uses `aws-cdk-lib/assertions`
 * (Template.fromStack) plus Node's built-in `assert`, and is runnable with
 * `npx ts-node test/registry-stack.test.ts`. It exits non-zero on the first
 * failed assertion so it can gate a build.
 *
 * Coverage:
 *   PATH A (flag OFF, default): raw AWS::BedrockAgentCore::Registry + DynamoDB
 *     table + 3 outputs.
 *   PATH B (flag ON): Lambda + custom resource + IAM policy + the SAME 3 outputs
 *     + NO raw unsupported type.
 *   BOTH: DynamoDB governance table present with the `by-status` GSI.
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { RegistryStack } from "../lib/registry-stack";

const RAW_TYPE = "AWS::BedrockAgentCore::Registry";
const APP_NAME = "sentinel";

function synth(viaCustomResource: boolean): Template {
  const app = new App();
  const stack = new RegistryStack(app, "sentinel-registry", {
    appName: APP_NAME,
    autoApproval: false,
    viaCustomResource,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

/** Assertions that must hold in BOTH flag states. */
function assertCommon(t: Template, mode: string): void {
  // DynamoDB governance table present.
  t.resourceCountIs("AWS::DynamoDB::Table", 1);
  t.hasResourceProperties("AWS::DynamoDB::Table", {
    TableName: `${APP_NAME}-tool-registry`,
    KeySchema: Match.arrayWith([
      Match.objectLike({ AttributeName: "name", KeyType: "HASH" }),
    ]),
    // by-status GSI present.
    GlobalSecondaryIndexes: Match.arrayWith([
      Match.objectLike({
        IndexName: "by-status",
        KeySchema: [
          { AttributeName: "status", KeyType: "HASH" },
          { AttributeName: "name", KeyType: "RANGE" },
        ],
      }),
    ]),
  });

  // The same three outputs in both modes.
  const outputs = t.findOutputs("*");
  for (const key of ["RegistryArn", "RegistryAutoApproval", "ToolRegistryTableName"]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(outputs, key),
      `[${mode}] expected output ${key} to be present`,
    );
  }
  // autoApproval governance default = false.
  t.hasOutput("RegistryAutoApproval", { Value: "false" });
  console.log(`[${mode}] common assertions passed`);
}

// --- PATH A: flag OFF (default) ---
function testFlagOff(): void {
  const t = synth(false);
  // Raw unsupported CFN type IS present.
  t.resourceCountIs(RAW_TYPE, 1);
  t.hasResourceProperties(RAW_TYPE, {
    Name: `${APP_NAME}-registry`,
    AutoApproval: false,
  });
  // No Lambda / custom resource machinery on this path.
  t.resourceCountIs("AWS::Lambda::Function", 0);
  assertCommon(t, "flag-off");
  console.log("[flag-off] raw-CfnResource path assertions passed");
}

// --- PATH B: flag ON ---
function testFlagOn(): void {
  const t = synth(true);
  // NO raw unsupported type on the deploy-ready path.
  t.resourceCountIs(RAW_TYPE, 0);
  // Custom resource + at least one Lambda (handler; provider adds a framework fn).
  t.resourceCountIs("Custom::AgentCoreRegistry", 1);
  const lambdas = t.findResources("AWS::Lambda::Function");
  assert.ok(
    Object.keys(lambdas).length >= 1,
    "[flag-on] expected at least one Lambda function (custom-resource handler)",
  );
  // Least-privilege IAM policy scoped to the Registry control-plane actions.
  t.hasResourceProperties("AWS::IAM::Policy", {
    PolicyDocument: Match.objectLike({
      Statement: Match.arrayWith([
        Match.objectLike({
          Effect: "Allow",
          Action: Match.arrayWith([
            "bedrock-agentcore:CreateRegistry",
            "bedrock-agentcore:UpdateRegistry",
            "bedrock-agentcore:DeleteRegistry",
          ]),
        }),
      ]),
    }),
  });
  assertCommon(t, "flag-on");
  console.log("[flag-on] custom-resource path assertions passed");
}

function main(): void {
  testFlagOff();
  testFlagOn();
  console.log("\nALL registry-stack synth assertions PASSED");
}

main();
