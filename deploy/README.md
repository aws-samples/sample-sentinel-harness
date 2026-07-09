# sentinel-harness · deploy runbook (one-command deploy / destroy)

One-command deploy and teardown for the **M4 Layer-3 foundation** — the CDK
stacks in [`../iac-cdk`](../iac-cdk). This is the human-facing wrapper around
`npx cdk deploy`: it proves your AWS identity, prints the **account + region** it
is about to touch, makes you confirm, and defaults to the **free-tier** stack set
so you don't accidentally start a standing ~$30/mo bill.

> **NON-PROD target.** These stacks provision a security workload and are intended
> for a **sandbox / non-prod account first** (`docs/BLUEPRINT.md` is explicit on
> this). Nothing here hardcodes an account, region, or ARN — account/region come
> from your **active AWS profile**; everything else is CDK context.

---

## Prerequisites

| Tool | Why | Check |
|---|---|---|
| **Node 18+** and `npx` | Runs the pinned CDK (`iac-cdk/package.json`); no global `cdk` install needed. | `node --version` |
| **AWS CLI v2** | `aws sts get-caller-identity` (identity + account), region resolution. | `aws --version` |
| **AWS credentials for a NON-PROD account** | Deploy target. Use `AWS_PROFILE` or `aws sso login`. | `aws sts get-caller-identity` |
| `npm install` in `iac-cdk` | The scripts refuse to run without `iac-cdk/node_modules`. | `ls ../iac-cdk/node_modules` |
| Bootstrapped environment | `cdk deploy` needs the CDKToolkit stack once per account/region. | `npx cdk bootstrap` |

```bash
cd ../iac-cdk && npm install   # once
npx cdk bootstrap              # once per account/region (creates CDKToolkit)
```

The deploy/destroy scripts resolve **account** from `sts get-caller-identity` and
**region** from `SENTINEL_REGION` → `AWS_REGION` → `AWS_DEFAULT_REGION` → the
profile's configured region, then export `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`
for CDK. Keeping `SENTINEL_REGION` aligned with the runtime avoids the region-split
that bit the original M4 deploy (a stray region env once deployed to the wrong
region — see `evidence/m4_live_deploy_result.json`).

---

## What gets deployed, and what it costs

The scripts split the eight-stack app into a **free-tier default** and a single
**cost-gated opt-in**. Costs below are honest, order-of-magnitude estimates for a
lightly-used non-prod account in `us-east-1` — **not** a quote; check the AWS
pricing pages and your own usage.

| Stack | Deployed by default? | Standing cost | Notes |
|---|---|---|---|
| `sentinel-guardrail` | ✅ free-tier | **pennies** | Bedrock Guardrail is billed per-request (text units), so an idle guardrail is ~$0; you pay only when `apply_guardrail` runs. |
| `sentinel-identity` | ✅ free-tier | **$0** | Cognito user pool + hosted-UI domain. Free tier covers typical non-prod MAU; an idle pool is $0. |
| `sentinel-observability` | ✅ free-tier | **~$3/mo** | One CloudWatch dashboard (~$3/mo) + a custom metric + a Budgets alarm (first two budgets are free). |
| `sentinel-network` (endpoints OFF) | ✅ free-tier | **$0** | VPC + isolated subnet + security group + the **free** S3 **gateway** endpoint. No NAT, no IGW → no hourly charge. |
| `sentinel-network` (endpoints ON) | ⛔ opt-in `--with-endpoints` | **~$30/mo** | Adds ~5 PrivateLink **interface** endpoints (`bedrock-agentcore`, `bedrock-agentcore.gateway`, `logs`, `ecr.api`, `ecr.dkr`, `sts`) at ~$7.20/endpoint-AZ/mo + data. **The only meaningful standing cost in the whole foundation.** |

**Free-tier total: roughly a few dollars a month** (essentially just the dashboard).
The `--with-endpoints` flag is the one lever that turns that into **~$30+/mo**.

### Honesty on state

- **Free-tier stacks are live-validated.** Guardrail (masked a fake AWS key + token,
  `GUARDRAIL_INTERVENED`), Cognito identity (OIDC discovery reachable, RS256), and
  the CloudWatch dashboard + budget were all **deployed and verified live** on the
  non-prod dev account in `us-east-1` (`evidence/m4_live_deploy_result.json`, with
  the account id scrubbed).
- **VPC interface endpoints: NOT deployed.** They are cost-gated OFF and were left
  off to avoid standing cost. The endpoint **service names were confirmed to exist**
  in `us-east-1` (`com.amazonaws.us-east-1.{bedrock-agentcore, bedrock-agentcore.gateway,
  logs, ecr.api, ecr.dkr, sts}`), but the interface endpoints themselves have **not**
  been stood up here. `--with-endpoints` is a real, synth-green code path, not a
  live-validated one.
- **`sentinel-gateway` / `sentinel-registry` / `sentinel-memory` / `sentinel-harness`**
  synth green against the native `AWS::BedrockAgentCore::*` CFN types. `deploy.sh`
  intentionally deploys only the four free-tier stacks; `destroy.sh` cleans up all
  eight if present. (`AWS::BedrockAgentCore::Registry` is not yet a registered CFN
  type — see the `iac-cdk` README's preview-API note — so deploying that stack would
  fail until AWS registers it.)

---

## Deploy

```bash
# Point at a NON-PROD account first.
export AWS_PROFILE=<your-non-prod-profile>
export SENTINEL_REGION=us-east-1            # keep deploy + runtime on one region

# Free-tier stacks only (default). Prints account+region, then asks you to type 'yes'.
deploy/deploy.sh

# ...or additionally deploy the ~$30/mo VPC interface endpoints:
deploy/deploy.sh --with-endpoints

# Non-interactive (CI): skips the prompt but STILL prints account+region.
deploy/deploy.sh --yes
```

The script:

1. checks prereqs (`node`, `npx`, `aws`, and `iac-cdk/node_modules`);
2. runs `aws sts get-caller-identity` to get the **account** (and to prove creds);
3. resolves the **region** and exports `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`;
4. prints account + region + caller + stack list, and **requires a typed `yes`**;
5. only then runs `npx cdk deploy <stacks> --require-approval never` (approval is
   waived **after** your explicit consent, not before).

It is **idempotent** — re-running redeploys nothing that is already current.

---

## Verify

- **Guardrail** masks secrets: run the live guardrail scenario / inspect
  `evidence/m4_guardrail_result.json` (`GUARDRAIL_INTERVENED`, masked
  `{aws-access-key-id}` + `{generic-api-token}`).
- **Identity** OIDC is reachable:
  ```bash
  POOL_ID=$(aws cloudformation describe-stacks --stack-name sentinel-identity \
    --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)
  curl -s "https://cognito-idp.${SENTINEL_REGION}.amazonaws.com/${POOL_ID}/.well-known/openid-configuration" | head
  ```
  (RS256, token endpoint present → backs the Gateway `CUSTOM_JWT` authorizer.)
- **Observability**: open the `sentinel-observability` CloudWatch dashboard;
  confirm the `TokensPerScenario` metric and the `sentinel-monthly-cost` budget.
- **End-to-end evidence** lives in [`../evidence`](../evidence) (all account-id
  scrubbed) and the overall M4 verdict in `evidence/m4_live_deploy_result.json`.

The AgentCore two-plane runtime reads its wiring from 12-factor env (matching
`sentinel_harness/core.py`); wire deployed outputs in as shown in the
[`iac-cdk` README](../iac-cdk/README.md#deploy-to-a-non-prod-account).

---

## Destroy

```bash
deploy/destroy.sh          # confirm, then destroy ALL sentinel-* stacks
deploy/destroy.sh --yes    # CI: skip the prompt (account+region still printed)
```

- Destroys **only** `sentinel-*` stacks (`cdk destroy --force`), after a typed `yes`.
- **Does NOT touch the `CDKToolkit` bootstrap stack** — that shared staging
  bucket/roles are kept for future deploys. Remove it yourself only if you are done
  with CDK in the account entirely:
  ```bash
  aws cloudformation delete-stack --stack-name CDKToolkit
  ```
- Idempotent: destroying an absent stack is a no-op.

> If you deployed with `--with-endpoints`, `destroy.sh` removes the endpoints too
> (they belong to `sentinel-network`) — so the ~$30/mo charge stops on teardown.

## Full teardown (non-CDK live resources)

`destroy.sh` covers only the **CDK stacks**, and `sentinel cleanup <prefix>` covers
**harnesses**. A few resources created directly against the control plane during
live validation are **not** owned by either and must be removed by hand. They are all
near-zero cost (a Registry + records = free; an ECR repo = a few cents/month; an IAM
role = free), so there is no urgency — but here is the complete list so nothing is
orphaned. The concrete ids for a given run are recorded in the git-ignored
`.live-resources.json` at the repo root.

```bash
# AgentCore Runtime (the ONLY one with standing compute cost — delete first)
aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id <id>

# AgentCore Registry + its records (records go with the registry)
aws bedrock-agentcore-control delete-registry --registry-id <id>

# ECR repo (force removes any images)
aws ecr delete-repository --repository-name sentinel-cve-intel --force

# IAM execution role (delete the inline policy, then the role)
aws iam delete-role-policy --role-name sentinel-runtime-exec \
  --policy-name sentinel-runtime-least-priv
aws iam delete-role --role-name sentinel-runtime-exec
```

Run these against the **same non-prod account/region** you created them in (check
`aws sts get-caller-identity` first). The Registry/records helpers are also available
programmatically via `sentinel_harness.registry_live.delete_registry(...)`.
