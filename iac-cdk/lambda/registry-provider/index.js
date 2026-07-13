/**
 * registry-provider - CloudFormation custom-resource handler for the AgentCore
 * Registry (deploy-ready FALLBACK until AWS::BedrockAgentCore::Registry is a GA
 * CloudFormation type).
 * =============================================================================
 * WHY: `AWS::BedrockAgentCore::Registry` is not (yet) a registered CFN resource
 * type, so a raw CfnResource of that type synths but FAILS on deploy. This handler
 * lets CloudFormation manage the Registry through the AgentCore CONTROL plane
 * (`bedrock-agentcore-control`, the same plane sentinel_harness/gateway.py drives)
 * via a provider-framework custom resource: CREATE/UPDATE/DELETE map to the
 * control-plane Registry lifecycle calls.
 *
 * ACTION NAMES: the control-plane Registry lifecycle action names below
 * (CreateRegistry / UpdateRegistry / DeleteRegistry / GetRegistry) are CONFIRMED
 * against the live `bedrock-agentcore-control` service model (2026-07, us-east-1) -
 * the same plane sentinel_harness/registry_live.py drives on-account. They are no
 * longer guesses.
 *
 * HONESTY (still true, do not remove): the SDK client package
 * `@aws-sdk/client-bedrock-agentcore-control` is REAL (published, v3.1081.0) but is
 * NOT part of the Node 20 Lambda runtime's bundled AWS SDK v3 client set and is NOT
 * in this asset's package.json, so it MUST be bundled into the Lambda asset
 * (npm i into lambda/registry-provider, or switch the construct to NodejsFunction)
 * before a live deploy. Until then loadControl() surfaces a clear, actionable error.
 *
 * SAFETY: no secrets, no hardcoded account/region/ARNs. Region comes from the
 * Lambda runtime env (AWS_REGION, injected by Lambda). Names/flags arrive only via
 * the custom-resource ResourceProperties. Nothing is read from disk.
 */
"use strict";

// AWS SDK v3. The generic bedrock-agentcore-control client package is imported
// lazily so a missing package surfaces as a clear deploy-time error (and so this
// file stays importable during CDK synth / unit tests, which never execute it).
// This is the REAL, published client package (v3.1081.0) that
// sentinel_harness/registry_live.py drives on-account; it is NOT bundled into the
// Node 20 Lambda runtime, so it must be added to this asset before a live deploy.
const CONTROL_CLIENT_PKG = "@aws-sdk/client-bedrock-agentcore-control";

// CONFIRMED against the live bedrock-agentcore-control model (2026-07, us-east-1):
// these are the real Registry lifecycle command names, not guesses. Kept as
// constants so there is ONE place to reference them.
const ACTIONS = {
  create: "CreateRegistryCommand",
  update: "UpdateRegistryCommand",
  delete: "DeleteRegistryCommand",
  get: "GetRegistryCommand",
};

function loadControl() {
  // The Node 20 Lambda runtime bundles only the STANDARD AWS SDK v3 clients;
  // `@aws-sdk/client-bedrock-agentcore-control` is NOT among them, so it must be
  // bundled into this asset (npm install into lambda/registry-provider, or switch
  // the construct to NodejsFunction) before a real deploy. Surface that as a clear,
  // actionable error instead of a raw MODULE_NOT_FOUND if it is missing.
  let mod;
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    mod = require(CONTROL_CLIENT_PKG);
  } catch (err) {
    throw new Error(
      `${CONTROL_CLIENT_PKG} is not available in the Lambda bundle. The Node runtime `
        + `does not ship this client; bundle it into lambda/registry-provider `
        + `(npm i ${CONTROL_CLIENT_PKG}) or use aws-cdk-lib/aws-lambda-nodejs NodejsFunction `
        + `before enabling sentinel:registryViaCustomResource on a live deploy. `
        + `Underlying error: ${err && err.message}`
    );
  }
  const region = process.env.AWS_REGION; // injected by the Lambda runtime; never hardcoded
  const client = new mod.BedrockAgentCoreControlClient({ region });
  return { mod, client };
}

/**
 * Provider-framework onEvent handler.
 * @param {{RequestType: 'Create'|'Update'|'Delete', PhysicalResourceId?: string,
 *          ResourceProperties: Record<string, unknown>}} event
 */
exports.handler = async function handler(event) {
  const props = event.ResourceProperties || {};
  const name = String(props.Name || "");
  const description = props.Description ? String(props.Description) : undefined;
  // AutoApproval arrives as a string over the CFN boundary; coerce explicitly.
  const autoApproval = String(props.AutoApproval) === "true";

  const { mod, client } = loadControl();

  switch (event.RequestType) {
    case "Create": {
      const out = await client.send(
        new mod[ACTIONS.create]({ name, description, autoApproval }),
      );
      // CreateRegistry output field is registryArn (confirmed live 2026-07); the
      // capitalized fallbacks are defensive only.
      const registryArn = out.registryArn || out.RegistryArn;
      const registryId = out.registryId || out.RegistryId || name;
      return {
        PhysicalResourceId: String(registryId),
        Data: { RegistryArn: String(registryArn || ""), RegistryId: String(registryId) },
      };
    }
    case "Update": {
      const registryId = event.PhysicalResourceId;
      const out = await client.send(
        new mod[ACTIONS.update]({ registryIdentifier: registryId, description, autoApproval }),
      );
      const registryArn = out.registryArn || out.RegistryArn;
      return {
        PhysicalResourceId: String(registryId),
        Data: { RegistryArn: String(registryArn || ""), RegistryId: String(registryId) },
      };
    }
    case "Delete": {
      const registryId = event.PhysicalResourceId;
      try {
        await client.send(new mod[ACTIONS.delete]({ registryIdentifier: registryId }));
      } catch (err) {
        // A missing/already-deleted registry must not fail the stack rollback.
        const notFound = err && (err.name === "ResourceNotFoundException" || err.$metadata?.httpStatusCode === 404);
        if (!notFound) throw err;
      }
      return { PhysicalResourceId: String(registryId) };
    }
    default:
      throw new Error(`Unsupported RequestType: ${event.RequestType}`);
  }
};
