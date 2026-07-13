/**
 * identity-stack.test.ts - synth assertions for the Cognito IdentityStack.
 * ========================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * `aws-cdk-lib/assertions` (Template.fromStack) + Node's built-in `assert`,
 * runnable with `npx ts-node test/identity-stack.test.ts`. Exits non-zero on the
 * first failed assertion so it can gate a build.
 *
 * Coverage:
 *   - One User Pool, self-signup OFF, the 12-char symbol/upper/lower/digit
 *     password policy, EMAIL_ONLY recovery.
 *   - A hosted-UI domain + a resource server with the custom `invoke` scope.
 *   - TWO app clients: the confidential machine client (GenerateSecret=true,
 *     client_credentials) and the public human client (GenerateSecret absent /
 *     falsey, authorization_code + SRP).
 *   - The five id/issuer/client outputs the Gateway CUSTOM_JWT context wants.
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { IdentityStack } from "../lib/identity-stack";

const APP_NAME = "sentinel";

function synth(): Template {
  const app = new App();
  const stack = new IdentityStack(app, "sentinel-identity", {
    appName: APP_NAME,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

function testUserPool(t: Template): void {
  t.resourceCountIs("AWS::Cognito::UserPool", 1);
  t.hasResourceProperties("AWS::Cognito::UserPool", {
    UserPoolName: `${APP_NAME}-users`,
    // Self sign-up OFF => only admins create users.
    AdminCreateUserConfig: Match.objectLike({ AllowAdminCreateUserOnly: true }),
    Policies: Match.objectLike({
      PasswordPolicy: Match.objectLike({
        MinimumLength: 12,
        RequireLowercase: true,
        RequireUppercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
      }),
    }),
    AccountRecoverySetting: Match.objectLike({
      RecoveryMechanisms: Match.arrayWith([
        Match.objectLike({ Name: "verified_email" }),
      ]),
    }),
  });
  console.log("[identity] user-pool + password-policy assertions passed");
}

function testDomainAndResourceServer(t: Template): void {
  t.resourceCountIs("AWS::Cognito::UserPoolDomain", 1);
  t.resourceCountIs("AWS::Cognito::UserPoolResourceServer", 1);
  t.hasResourceProperties("AWS::Cognito::UserPoolResourceServer", {
    Identifier: "sentinel",
    Scopes: Match.arrayWith([Match.objectLike({ ScopeName: "invoke" })]),
  });
  console.log("[identity] domain + resource-server assertions passed");
}

function testClients(t: Template): void {
  // Two app clients total (human + machine).
  t.resourceCountIs("AWS::Cognito::UserPoolClient", 2);

  // Confidential machine client: secret + client_credentials grant.
  t.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: `${APP_NAME}-machine`,
    GenerateSecret: true,
    AllowedOAuthFlows: Match.arrayWith(["client_credentials"]),
  });

  // Public human client: NO secret (property absent or false) + authorization_code.
  const clients = t.findResources("AWS::Cognito::UserPoolClient");
  const human = Object.values(clients).find(
    (c) => (c as { Properties: { ClientName?: string } }).Properties.ClientName === `${APP_NAME}-human`,
  ) as { Properties: Record<string, unknown> } | undefined;
  assert.ok(human, "[identity] expected a human app client");
  assert.ok(
    !human!.Properties.GenerateSecret,
    "[identity] human client must be public (GenerateSecret falsey)",
  );
  assert.deepStrictEqual(
    human!.Properties.AllowedOAuthFlows,
    ["code"],
    "[identity] human client must use the authorization-code grant",
  );
  console.log("[identity] confidential + public client assertions passed");
}

function testOutputs(t: Template): void {
  const outputs = t.findOutputs("*");
  for (const key of [
    "UserPoolId",
    "Issuer",
    "DiscoveryUrl",
    "HumanClientId",
    "MachineClientId",
  ]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(outputs, key),
      `[identity] expected output ${key} to be present`,
    );
  }
  console.log("[identity] output assertions passed");
}

function main(): void {
  const t = synth();
  testUserPool(t);
  testDomainAndResourceServer(t);
  testClients(t);
  testOutputs(t);
  console.log("\nALL identity-stack synth assertions PASSED");
}

main();
