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
 * HONESTY / TODO(confirm-against-GA): the exact control-plane action + client
 * package names for the Registry lifecycle are NOT verifiable offline here. The
 * mechanism, event shape, IAM wiring and RegistryArn return contract are correct;
 * the ACTION NAMES below (CreateRegistry / UpdateRegistry / DeleteRegistry /
 * GetRegistry) and the SDK package id are annotated placeholders to confirm against
 * the live `bedrock-agentcore-control` service model before a real deploy. Mirror
 * whatever gateway.py's `_control` client resolves to at that point.
 *
 * SAFETY: no secrets, no hardcoded account/region/ARNs. Region comes from the
 * Lambda runtime env (AWS_REGION, injected by Lambda). Names/flags arrive only via
 * the custom-resource ResourceProperties. Nothing is read from disk.
 */
"use strict";

// AWS SDK v3. The generic bedrock-agentcore-control client package is imported
// lazily so a missing package surfaces as a clear deploy-time error (and so this
// file stays importable during CDK synth / unit tests, which never execute it).
// TODO(confirm-against-GA): package id may differ once the service GAs; align with
// whatever sentinel_harness/gateway.py's control client resolves to.
const CONTROL_CLIENT_PKG = "@aws-sdk/client-bedrock-agentcore-control";

// TODO(confirm-against-GA): confirm these command/action names against the live
// bedrock-agentcore-control model. Kept as constants so there is ONE place to fix.
const ACTIONS = {
  create: "CreateRegistryCommand",
  update: "UpdateRegistryCommand",
  delete: "DeleteRegistryCommand",
  get: "GetRegistryCommand",
};

function loadControl() {
  // eslint-disable-next-line global-require, import/no-dynamic-require
  const mod = require(CONTROL_CLIENT_PKG);
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
      // TODO(confirm-against-GA): field names (registryArn / registryId) per model.
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
