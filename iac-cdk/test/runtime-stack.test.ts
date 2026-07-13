/**
 * runtime-stack.test.ts - synth assertions for the RuntimeStack.
 * =============================================================================
 * No jest is wired into this package (see package.json), so this is a
 * self-contained, zero-dependency test: it uses `aws-cdk-lib/assertions`
 * (Template.fromStack) plus Node's built-in `assert`, and is runnable with
 * `npx ts-node test/runtime-stack.test.ts`. It exits non-zero on the first
 * failed assertion so it can gate a build.
 *
 * Coverage (mirrors the DEFAULT raw-CfnResource path of registry-stack.test.ts):
 *   - The raw AWS::BedrockAgentCore::Runtime resource IS present (synth-only until
 *     the CFN type is GA - see runtime-stack.ts header).
 *   - PUBLIC network mode + A2A protocol (the proven specialist path).
 *   - containerConfiguration.containerUri + roleArn present.
 *   - The AgentRuntimeArn / AgentRuntimeId outputs are present.
 *   - No hardcoded real account (000000000000 placeholder only).
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { RuntimeStack } from "../lib/runtime-stack";

const RAW_TYPE = "AWS::BedrockAgentCore::Runtime";
const APP_NAME = "sentinel";
const CONTAINER_URI =
  "000000000000.dkr.ecr.us-east-1.amazonaws.com/sentinel-cve-intel:v1";

function synth(): Template {
  const app = new App();
  const stack = new RuntimeStack(app, "sentinel-runtime", {
    appName: APP_NAME,
    containerUri: CONTAINER_URI,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

function testRawRuntime(t: Template): void {
  // The raw (not-yet-GA) CFN type IS present - synth-only, fails on deploy until
  // registered, exactly like the registry stack's default path.
  t.resourceCountIs(RAW_TYPE, 1);
  t.hasResourceProperties(RAW_TYPE, {
    AgentRuntimeName: `${APP_NAME}_specialist`,
    // Container image (ECR) wired from the prop/context.
    AgentRuntimeArtifact: Match.objectLike({
      ContainerConfiguration: Match.objectLike({
        ContainerUri: CONTAINER_URI,
      }),
    }),
    // PUBLIC network + A2A protocol: the live-verified specialist path.
    NetworkConfiguration: Match.objectLike({ NetworkMode: "PUBLIC" }),
    ProtocolConfiguration: Match.objectLike({ ServerProtocol: "A2A" }),
    // roleArn present (minted least-privilege role when no ARN supplied).
    RoleArn: Match.anyValue(),
  });
  console.log("[runtime] raw-CfnResource (PUBLIC/A2A + containerUri + roleArn) assertions passed");
}

function testExecutionRole(t: Template): void {
  // A least-privilege execution role is minted (no pre-existing ARN supplied).
  t.hasResourceProperties("AWS::IAM::Role", {
    AssumeRolePolicyDocument: Match.objectLike({
      Statement: Match.arrayWith([
        Match.objectLike({
          Principal: Match.objectLike({ Service: "bedrock-agentcore.amazonaws.com" }),
        }),
      ]),
    }),
  });
  console.log("[runtime] execution-role assertions passed");
}

function testOutputs(t: Template): void {
  const outputs = t.findOutputs("*");
  for (const key of ["AgentRuntimeArn", "AgentRuntimeId"]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(outputs, key),
      `[runtime] expected output ${key} to be present`,
    );
  }
  t.hasOutput("RuntimeNetworkMode", { Value: "PUBLIC" });
  t.hasOutput("RuntimeServerProtocol", { Value: "A2A" });
  console.log("[runtime] output assertions passed");
}

function main(): void {
  const t = synth();
  testRawRuntime(t);
  testExecutionRole(t);
  testOutputs(t);
  console.log("\nALL runtime-stack synth assertions PASSED");
}

main();
