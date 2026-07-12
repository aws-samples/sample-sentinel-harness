# sentinel-harness v0.2.0 — SecOps agents as configuration, now live on AgentCore Runtime

`sentinel-harness` is a reference implementation of production security-operations agents built as **configuration** — model, prompt, tools, skills, memory, limits — on [Amazon Bedrock AgentCore Harness](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html); you declare the agent and AWS runs the loop. This release delivers milestones **M0–M7** end-to-end: the agent-builds-agents north-star loop runs, a specialist runs on **real AgentCore Runtime** with live end-to-end A2A against a real Bedrock model, the AgentCore **Registry** control-plane governance walk is live-verified, and a dual-track IaC foundation is live-deployed on a non-production dev account. The whole thing is anchored by **1742 offline tests** (+5 skipped when optional deps are absent) across 90 test files — deterministic, hermetic, zero AWS by default — with CI green at `ae3ab6a`.

## Highlights

- **Agent-builds-agents loop is live.** The meta-agent and an llm-judge are real invoked harnesses; `tools/harness_ops` drives the real `core.*` lifecycle to build → score → promote another agent. Promotion is the native `CreateHarnessEndpoint` control-plane op. Evidence: `evidence/agent_factory_loop_result.json`, `evidence/endpoint_promote_result.json`.
- **Live A2A specialist on AgentCore Runtime, end-to-end with a real model.** `CreateAgentRuntime` provisioned a real `linux/arm64` microVM (`PUBLIC` net, `A2A` protocol) from an ECR image; a live A2A JSON-RPC `message/send` returned **HTTP 200** and the `cve-intel` specialist invoked the **real Bedrock Haiku model** (version-pinned id) for a structured Log4Shell verdict (CVSS 10.0). Torn down after the run. Evidence: `evidence/live_a2a_runtime_result.json` (non-prod test account).
- **AgentCore Registry DRAFT→PENDING_APPROVAL governance, live-verified.** A real Registry and an `AGENT_SKILLS` record were created on a non-prod dev account and moved `DRAFT` → `PENDING_APPROVAL` via `submit_for_approval` with `autoApproval=false` — the on-account realization of the offline dual-gate. `registry_live.py` wraps the confirmed-real `bedrock-agentcore-control` Registry ops; the governance walk is proven offline in `evidence/registry_governance_result.json`.
- **Dual-track IaC with three stacks live-deployed.** A CDK project (9 stacks) plus a `terraform validate`-clean Terraform mirror. The **Guardrail**, **Cognito CUSTOM_JWT identity**, and **CloudWatch/Budgets observability** stacks are live-deployed and validated on a real dev account — a Guardrail really masked a fake AWS key (`GUARDRAIL_INTERVENED`), Cognito OIDC/JWKS serves RS256, and the private VPC proves default-deny egress (no IGW / NAT / `0.0.0.0/0`).
- **Backend-pluggable data-plane tools.** `siem_query` / `asset_lookup` / `enrich_ioc` / `ops_query` run an offline mock by default and switch to a real stdlib-HTTP client behind a `*_LIVE` env (env-driven URL + bearer, timeouts, every failure → `upstream_error` with no silent fallback) — proven end-to-end against an in-process `127.0.0.1` mock server, zero external network. Connecting a real backend is a config change, not a rebuild.
- **Honest simulated detonation.** The long-running detonation tier ships a full `QUEUED → … → DESTROYED` lifecycle state machine and `detonate_sample` orchestrator — but is an **honest SIMULATED no-op**: no real malware, VM, or network. Sample-by-reference, sandbox-refused bad actions, HITL-gated, always destroyed after use. Evidence: `evidence/detonation_result.json`.

## By the numbers

| Metric | Count |
|---|--:|
| Offline tests passing (+5 skipped w/o optional deps) | 1742 |
| Test files | 76 |
| Runnable scenarios | 16 |
| Committed evidence JSON artifacts | 23 |
| MCP tool templates | 14 |
| Agent Skills (`SKILL.md`) | 9 |
| Declarative harnesses | 8 |
| A2A specialists | 3 |
| CDK stacks (`iac-cdk/lib/*-stack.ts`) | 9 |

## Live-validated on AWS

All on a **non-production** dev/test account; account IDs are scrubbed to `000000000000` in every committed artifact.

- Gateway `CreateGateway` create → READY → delete on the GA API — `evidence/gateway_lifecycle_result.json`
- Guardrail `GUARDRAIL_INTERVENED` masked a fake AWS key + `sk-` token — `evidence/m4_guardrail_result.json`
- Cognito CUSTOM_JWT OIDC discovery + JWKS, RS256 authorizer contract — `iac-cdk/lib/identity-stack.ts`
- Private VPC default-deny egress (no IGW / NAT / `0.0.0.0/0`, PrivateLink-only) — `evidence/egress_control_result.json`
- On-account combined security check (VPC island + zero plaintext secrets + Guardrail block) — `evidence/live_verify_result.json`
- AgentCore Registry create + records + `DRAFT` → `PENDING_APPROVAL` — `evidence/registry_governance_result.json` (governance walk offline; `registry_live.py` live-verified)
- AgentCore Runtime `CreateAgentRuntime` → arm64 microVM → live A2A `message/send` HTTP 200 → real Bedrock Haiku Log4Shell verdict — `evidence/live_a2a_runtime_result.json`

## Known limitations / not yet

Stated plainly, consistent with the README status matrix (🟢/🟡/🟠) and `docs/FIDELITY-REPORT.md`. Nothing labelled live/real is secretly mocked, and no 🟡 is dressed up as 🟢.

- **No full `cdk deploy` of the Registry/Runtime stacks yet.** Those stacks use raw `AWS::BedrockAgentCore::*` CFN types that are not GA — they synth clean (tsc + `cdk synth`) but a live `cdk deploy` fails until the CFN types are registered, and the Registry custom-resource path additionally needs the `@aws-sdk/client-bedrock-agentcore-control` client bundled into the Lambda asset. The Registry and Runtime control-plane APIs themselves are separately live-verified (see above); no live CDK deploy of these two stacks has run.
- **Real customer backends sit behind the `*_LIVE` seams.** Wiring `siem_query` / `asset_lookup` / `enrich_ioc` / `ops_query` (and ticketing) to a real SIEM / asset / IOC / ticketing backend requires a customer account and credentials; the shipped default is the offline mock.
- **Detonation is a simulated no-op.** No real malware, VM, or network is ever touched — it is a full-lifecycle orchestrator over sandbox-refused, HITL-gated, sample-by-reference actions.
- **`CreateAgentRuntime` is SCP-blocked on the primary dev account.** An org-level SCP blocks the call there — an account control, not a code gap; the live A2A run above was executed on a separate non-prod test account.

## Get started

```bash
git clone https://github.com/neosun100/sentinel-harness && cd sentinel-harness
pip install -e .     # Python 3.10+ ; installs the `sentinel` CLI
make test            # 1742 offline tests — deterministic, no AWS, seconds
make demo            # narrated L1→L4 platform tour, fully offline
```

Live scenarios (create harnesses, invoke, write `evidence/`) are 12-factor — set `AWS_PROFILE` (never production), `SENTINEL_REGION`, and `SENTINEL_EXECUTION_ROLE_ARN`, then run e.g. `python scenarios/scenario_cve_triage.py`. Least-privilege execution-role policy: [`docs/SETUP.md`](SETUP.md).

## Links

- Changelog: [`CHANGELOG.md`](../CHANGELOG.md)
- Overview + status matrix: [`README.md`](../README.md)
- Testing & make targets: [`docs/QUICKSTART.md`](QUICKSTART.md)
- Self-audit / fidelity: [`docs/FIDELITY-REPORT.md`](FIDELITY-REPORT.md)
- Explainer deck (live): show <https://sentinel-harness-deck.pages.dev/> · presenter <https://sentinel-harness-deck.pages.dev/presenter/>

---

### Maintainer: publish this release

```bash
# from a clean checkout at the tagged commit (ae3ab6a)
git tag -a v0.2.0 -m "sentinel-harness v0.2.0"
git push origin v0.2.0

gh release create v0.2.0 \
  --title "v0.2.0 — SecOps agents as configuration, live on AgentCore Runtime" \
  --notes-file docs/RELEASE-v0.2.0.md \
  --latest
```
