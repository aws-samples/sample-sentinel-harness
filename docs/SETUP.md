# Setup

`sentinel-harness` is 12-factor: nothing is hardcoded. You provide an AWS profile, a
region, and a harness **execution role** ARN via environment variables.

## Prerequisites

- An AWS account (**use a non-production / sandbox account** — never production).
- Amazon Bedrock AgentCore Harness available in your region (GA).
- Python 3.10+ and a recent `boto3`/`botocore` that includes the harness API.
- Model access enabled in Bedrock for the models you plan to use.

## 1. Install

```bash
pip install -e .            # from the repo root
```

## 2. Configure (environment variables)

```bash
export AWS_PROFILE="<your-non-prod-profile>"          # never production
export SENTINEL_REGION="us-east-1"                    # any region where the harness is GA
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<your-harness-role>"

# optional: pin specific model ids (defaults use the cross-region-inference pattern)
# export SENTINEL_MODEL_SONNET="global.anthropic.claude-sonnet-4-6"
# export SENTINEL_MODEL_HAIKU="global.anthropic.claude-haiku-4-5-..."
# export SENTINEL_MODEL_OPUS="us.anthropic.claude-opus-4-5-..."
```

## 3. Execution role (least privilege)

The harness assumes an IAM role you own. This role scopes **which internal AWS
resources the agent may touch** — it is standard least-privilege, *not* a per-person
identity mapping. Human callers authenticate separately via OAuth/JWT
(`customJWTAuthorizer`); third-party API keys live in the AgentCore Identity token
vault so the agent never sees raw credentials.

**Trust policy** (who may assume the role):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "bedrock-agentcore.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

**Permissions policy** (starter — scope down `Resource` for production):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "BedrockInvoke", "Effect": "Allow",
      "Action": ["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream",
                 "bedrock:Converse","bedrock:ConverseStream"],
      "Resource": "*" },
    { "Sid": "AgentCore", "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:InvokeHarness",
        "bedrock-agentcore:InvokeAgentRuntime",
        "bedrock-agentcore:GetWorkloadAccessToken",
        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        "bedrock-agentcore:GetResourceApiKey",
        "bedrock-agentcore:GetResourceOauth2Token"
      ],
      "Resource": "*" },
    { "__comment__": "Deliberately EXCLUDED: bedrock-agentcore:InvokeAgentRuntimeCommand — it runs shell on the microVM as root, bypassing the LLM and allowedTools. Grant it only if a scenario truly needs deterministic shell prep, and understand the risk." },
    { "Sid": "Logs", "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents",
                 "logs:DescribeLogGroups","logs:DescribeLogStreams"],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/*" },
    { "Sid": "Xray", "Effect": "Allow",
      "Action": ["xray:PutTraceSegments","xray:PutTelemetryRecords",
                 "xray:GetSamplingRules","xray:GetSamplingTargets"],
      "Resource": "*" },
    { "Sid": "EcrPublicPull", "Effect": "Allow",
      "Action": ["ecr-public:GetAuthorizationToken","sts:GetServiceBearerToken"],
      "Resource": "*" }
  ]
}
```

> ⚠️ **`allowedTools` cannot restrict `InvokeAgentRuntimeCommand`.** `allowedTools`
> only scopes which tools the *LLM* may pick during `InvokeHarness`.
> `InvokeAgentRuntimeCommand` is a separate data-plane API that runs a shell command
> directly on the microVM (as root), bypassing the model and `allowedTools` entirely.
> The **only** control is to *not grant the IAM action* — which is why the policy above
> omits it. This is the single most important least-privilege decision for a SecOps repo.
>
> **Caller policy vs execution role:** the policy above is the harness **execution role**
> (what the agent may touch). A **caller** additionally needs
> `bedrock-agentcore:InvokeHarness` + `bedrock-agentcore:InvokeAgentRuntime` to invoke.
>
> **Production hardening:** replace each `"*"` with specific ARNs — Bedrock inference
> profiles, your gateway ARN, your memory ARN, your log groups. Deny `sts:AssumeRole`
> on the role if you don't need model-config role switching. Run harnesses in a VPC
> with NAT egress restricted to an allowlist (see `docs/ARCHITECTURE.md` → egress).

## 4. Run a scenario

```bash
python scenarios/scenario_cve_triage.py       # or: sentinel run-scenario cve_triage
python scenarios/scenario_multi_harness.py
python scenarios/scenario_detection_gen.py
```

Results are written to `evidence/`. Tear everything down when done:

```bash
sentinel cleanup sentinel_        # deletes every harness this repo created (cascades managed memory)
```

## Gotchas (learned the hard way, baked into the library)

- `runtimeSessionId` must be **≥ 33 characters** — use a hyphenated UUID (36); `uuid4().hex` (32) fails.
- `harnessName` must match `[a-zA-Z][a-zA-Z0-9_]{0,39}` — **no hyphens** (use underscores).
- `systemPrompt` is a **list** `[{"text": ...}]`, not a dict.
- `InvokeHarness` needs **both** `bedrock-agentcore:InvokeHarness` **and** `InvokeAgentRuntime`.
- Long-term (semantic) memory extraction is **asynchronous (minutes)** — a cross-session
  recall immediately after a write may return empty. Teach first, wait, then recall.
- `UpdateHarness` **replaces** the whole `filesystemConfigurations` list — read-modify-write.
