/**
 * gateway-stack.test.ts - synth assertions for the GatewayStack auth paths.
 * =========================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * `aws-cdk-lib/assertions` (Template.fromStack) + Node's built-in `assert`,
 * runnable with `npx ts-node test/gateway-stack.test.ts`. Exits non-zero on the
 * first failed assertion so it can gate a build.
 *
 * Coverage:
 *   AWS_IAM (default): raw AWS::BedrockAgentCore::Gateway with AuthorizerType
 *     AWS_IAM, NO AuthorizerConfiguration, an execution role, and the
 *     InvokeToolTargets + ApplyGuardrail least-privilege statements.
 *   CUSTOM_JWT + jwtDiscoveryUrl: AuthorizerConfiguration.CustomJWTAuthorizer
 *     with the discovery url + allowed audience/clients.
 *   CUSTOM_JWT WITHOUT jwtDiscoveryUrl: MUST throw at synth (fail-fast, never
 *     deploy an open JWT authorizer).
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { GatewayStack, GatewayAuthorizerType } from "../lib/gateway-stack";

const GW_TYPE = "AWS::BedrockAgentCore::Gateway";
const APP_NAME = "sentinel";

function synth(
  authorizerType: GatewayAuthorizerType,
  extra: Record<string, unknown> = {},
): Template {
  const app = new App();
  const stack = new GatewayStack(app, "sentinel-gateway", {
    appName: APP_NAME,
    authorizerType,
    env: { account: "000000000000", region: "us-east-1" },
    ...extra,
  });
  return Template.fromStack(stack);
}

// --- AWS_IAM (safe machine default) ---
function testAwsIam(): void {
  const t = synth("AWS_IAM");
  // Exactly one Gateway, MCP + SEMANTIC search, AuthorizerType AWS_IAM.
  t.resourceCountIs(GW_TYPE, 1);
  t.hasResourceProperties(GW_TYPE, {
    Name: `${APP_NAME}-gateway`,
    ProtocolType: "MCP",
    ProtocolConfiguration: { Mcp: { SearchType: "SEMANTIC" } },
    AuthorizerType: "AWS_IAM",
  });
  // AWS_IAM path must NOT emit an AuthorizerConfiguration block.
  const gateways = t.findResources(GW_TYPE);
  const gw = Object.values(gateways)[0] as {
    Properties: Record<string, unknown>;
  };
  assert.ok(
    !Object.prototype.hasOwnProperty.call(gw.Properties, "AuthorizerConfiguration"),
    "[aws-iam] AuthorizerConfiguration must be absent on the AWS_IAM path",
  );

  // Execution role exists and carries the two least-privilege statements.
  t.resourceCountIs("AWS::IAM::Role", 1);
  t.hasResourceProperties("AWS::IAM::Policy", {
    PolicyDocument: Match.objectLike({
      Statement: Match.arrayWith([
        Match.objectLike({ Sid: "InvokeToolTargets", Action: "lambda:InvokeFunction" }),
        Match.objectLike({ Sid: "ApplyGuardrail", Action: "bedrock:ApplyGuardrail" }),
      ]),
    }),
  });

  // Effective-mode output is surfaced.
  t.hasOutput("GatewayAuthorizerType", { Value: "AWS_IAM" });
  console.log("[aws-iam] gateway assertions passed");
}

// --- CUSTOM_JWT with a discovery url ---
function testCustomJwtOk(): void {
  const t = synth("CUSTOM_JWT", {
    jwtDiscoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
    jwtAllowedAudience: ["aud-human"],
    jwtAllowedClients: ["client-machine"],
  });
  t.hasResourceProperties(GW_TYPE, {
    AuthorizerType: "CUSTOM_JWT",
    AuthorizerConfiguration: Match.objectLike({
      CustomJWTAuthorizer: Match.objectLike({
        DiscoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
        AllowedAudience: ["aud-human"],
        AllowedClients: ["client-machine"],
      }),
    }),
  });
  t.hasOutput("GatewayAuthorizerType", { Value: "CUSTOM_JWT" });
  console.log("[custom-jwt-ok] gateway assertions passed");
}

// --- CUSTOM_JWT WITHOUT a discovery url: must fail fast at synth ---
function testCustomJwtMissingDiscoveryUrlThrows(): void {
  assert.throws(
    () => synth("CUSTOM_JWT"),
    /CUSTOM_JWT requires 'jwtDiscoveryUrl'/,
    "[custom-jwt-missing] expected synth to throw when jwtDiscoveryUrl is absent",
  );
  console.log("[custom-jwt-missing] fail-fast assertion passed");
}

function main(): void {
  testAwsIam();
  testCustomJwtOk();
  testCustomJwtMissingDiscoveryUrlThrows();
  console.log("\nALL gateway-stack synth assertions PASSED");
}

main();
