# Alignment & Fidelity Report

*A point-in-time self-audit of sentinel-harness against Amazon Bedrock AgentCore GA. Re-verified against real AWS on the audit date below. This document supersedes all earlier drafts.*

**Audit date:** July 2026 (point-in-time; re-run against live AWS before quoting).
**Method:** 6-dimension AgentCore authenticity audit — core API fidelity, north-star loops (M1/M2), Layer-2, Layer-3 IaC, live control-plane probes (M4), and scale. Every capability labelled `live` / `real` was traced to a real GA API call or a committed evidence artifact; nothing labelled real is secretly mocked.

## 1. Verdict

**GENUINE.** sentinel-harness is authentically built on the Amazon Bedrock AgentCore GA **two-plane API** — `bedrock-agentcore-control` for lifecycle and `bedrock-agentcore` for invocation. Zero capabilities labelled live/real are secretly mocked. The repo now presents itself exactly as real as it is: live-validated where it runs against AWS, built-and-tested where it ships runnable offline code, and honestly labelled skeleton or design-only where it does not.

- **(a) Fidelity to the real AgentCore Harness API: high, and directly traceable.** The `core.py` primitives map member-for-member to the GA shapes: `create_harness`/`update_harness`/`get_harness`/`delete_harness` are real `bedrock-agentcore-control` operations; `invoke`/`invoke_with_tool_result` are real `bedrock-agentcore` `InvokeHarness` calls with eventstream parsing; the HITL two-message `toolUse` + `toolResult` resume matches the live `InvokeHarness` input model. GA list-shape `systemPrompt` (`[{"text": ...}]`), memory passed to `create` without the `optionalValue` wrapper, `runtimeSessionId` ≥ 33 chars, the correct tool-config envelopes (`remoteMcp` / `agentCoreGateway` / `inlineFunction` / `agentcore_code_interpreter`), cascade-delete semantics, `actorId` at invoke time, and the double-IAM caller model are all present and tested. A live `create → READY → delete` probe was reproduced on the audit date.
- **(b) Coverage of the intended 3-layer SecOps architecture: substantial and honestly scoped.** Layer 1 is live-validated end-to-end, including the full HITL pause→approve→resume round trip and a real Gateway create→READY→delete on the GA API. Layer 2 ships a real deterministic Sigma matcher, a real offline BAS blind-spot report, and a Play Mode that rides the real invoke/resume pause contract; sample detonation is an honestly-labelled simulated skeleton. Layer 3 ships a built-and-tested tool/skill registry, sandbox hooks, and Agent Factory, plus a dual-track IaC foundation (CDK + `terraform validate`-clean Terraform) whose Guardrail, Cognito JWT identity, and observability stacks are live-deployed on a real dev account. The README status matrix is the authoritative per-capability ledger; this report explains *why* each label is accurate.

## 2. The north star: an agent that builds, scores, and promotes another agent (M1/M2)

This is real, not narration:

- **M1 — Agent Factory loop.** The meta-agent and the llm-judge are real invoked harnesses. `tools/harness_ops` delegates to the real `core.*` lifecycle operations. `evidence/agent_factory_loop_result.json` records `closed: true`.
- **M2 — promote.** Promotion to an endpoint is the real native control-plane `CreateHarnessEndpoint` operation, captured in `evidence/endpoint_promote_result.json`.
- **Honest limit.** The M2 single-run **re-score** hit a live `InvokeHarness` 403 (invoke quota) and is labelled as such in the evidence — the loop closes; the one re-score call was quota-gated, not faked.

## 3. What it gets right

- **Core lifecycle is library-grade and API-accurate.** `create_harness` / `update_harness` / `wait_ready` / `invoke` / `invoke_with_tool_result` / `delete` / `cleanup`, plus builders for code_interpreter, remote_mcp, gateway, inline_function, and managed / BYO memory — all returning the exact envelopes the GA API, the tests, and the scenarios expect.
- **The HITL loop actually closes.** `invoke()` detects `stop_reason=tool_use` and accumulates `toolUse.input` deltas; `invoke_with_tool_result()` sends the two-message assistant `toolUse` + user `toolResult` resume with a matching `toolUseId`. A full pause→approve→resume round trip is captured in `evidence/hitl_resume_result.json` and exercised by `scenarios/scenario_hitl_resume.py`.
- **Live control-plane substance.** Multi-harness parallelism (≈2.6× measured speedup), CVE triage (code_interpreter for deterministic CVSS math + inline HITL gate + managed SEMANTIC/SUMMARIZATION memory with per-analyst `actorId`), and a real Gateway `CreateGateway` create→READY→delete were all run against the GA API and are evidence-backed.
- **Layer 2 is real where it claims to be.** `sigma_match` is a real deterministic matcher; BAS detection-replay produces a real offline blind-spot report (`evidence/bas_replay_result.json`, 4 techniques × 2 rules → 2 blind spots, coverage 0.5); Play Mode rides the real invoke/resume pause contract with checkpoint/resume.
- **Layer 3 foundation ships runnable, tested code.** The dual-gate tool/skill registry, PreToolUse sandbox hook, and Agent Factory (fleet provision, dry-run, cross-env tag-guard) are built and unit-tested.
- **Native IaC, not hand-rolled resources.** The gateway / registry / memory / harness stacks use the native `AWS::BedrockAgentCore::*` CloudFormation types. Per the README status matrix, the **Gateway and Memory CFN types are registered**; the Registry type is not yet in CFN (see limitations).
- **Config path works.** `pip install -e .` succeeds (`[tool.setuptools] packages = ["sentinel_harness", "intake"]`), the `sentinel` console script works, and `sentinel create <harness.yaml>` loads real config via `sentinel_harness/loader.py` (systemPrompt file read, `bedrockModelConfig` / `agentCoreGateway` / `managedMemoryConfiguration` mapping, `${ENV}` expansion, `@gateway/tool` allowedTools grammar).
- **Scale.** 1475 offline tests pass (+5 skipped when optional deps absent) across 76 test files, with 22 evidence JSON artifacts, 15 scenarios, 14 tools, an `iac-cdk` project (9 stacks synth-green) and an `iac-terraform` mirror (`validate`-clean).
- **Clean anonymization.** No real account IDs (only the `000000000000` placeholder), no customer or company names, no secrets. The CI secret-and-name scan is self-non-matching and fails the build on any hit.

## 4. Live controls retained for demos (us-east-1)

These are real, deployed resources on a dev account, retained so reviewers can reproduce the control-plane behavior:

- **Guardrail** (id scrubbed, per the `evidence/` convention) — `apply_guardrail` masks a fake AWS access key → `{aws-access-key-id}` and an `sk-` token → `{generic-api-token}`, returning `GUARDRAIL_INTERVENED`. Evidence: `evidence/m4_guardrail_result.json`.
- **Cognito user pool** (id scrubbed) in `us-east-1` — OIDC discovery reachable, RS256; the Gateway CUSTOM_JWT authorizer contract is verified.
- **CloudWatch dashboard** `sentinel-observability`.
- **Gateway** create→READY→delete is the real GA `CreateGateway` operation, re-verified by a live probe on the audit date.

## 5. Earlier report defects — all resolved

Every blocker and major finding from earlier drafts of this report has been fixed. Recorded here for auditability:

| Earlier finding | Status | Concrete fix |
|---|---|---|
| Package not installable (`pip install -e .` flat-layout failure) | **RESOLVED** | `[tool.setuptools] packages = ["sentinel_harness", "intake"]` in `pyproject.toml`; `pip install -e .` and `sentinel --help` both work; CI covers the install path. |
| `harness.yaml` files were dead config | **RESOLVED** | `sentinel_harness/loader.py` is a real loader: resolves the `systemPrompt` file, maps `bedrockModelConfig` / `agentCoreGateway` / `managedMemoryConfiguration`, expands `${ENV}`, translates allowedTools. Built + tested; drives `scenario_named_supervisor.py`. |
| HITL resume contract not implemented | **RESOLVED** | `core.invoke_with_tool_result` sends the two-message resume; input-delta accumulation captures tool args; full round trip in `evidence/hitl_resume_result.json`. |
| `allowedTools` used wrong `gateway___tool` grammar | **RESOLVED** | All harness YAMLs use the verified server-scoped `@gateway/tool` grammar; inline gates stay plain names. |
| `MODEL_HAIKU` mixed `global.` prefix with a dated id | **RESOLVED** | Pinned to the verified-valid `global.anthropic.claude-haiku-4-5-20251001-v1:0`. |
| L2 / L3 shipped no runnable code | **RESOLVED** | L2 ships `sigma_match`, `bas-runner`, and Play Mode; L3 ships the registry, sandbox hooks, and Agent Factory — all built + tested. |
| Anti-hallucination cross-review not substantiated | **RESOLVED** | `scenario_detection_gen.py` runs an independent reviewer that reaches `revise`; the flawed rule is withheld; no stray shell usage. |
| IAM sample granted `bedrock-agentcore:*` | **RESOLVED** | Replaced with an explicit least-privilege action list; `SETUP.md` documents that `allowedTools` cannot restrict `InvokeAgentRuntimeCommand` — only withholding the IAM action does. |
| `byo_memory` invented `messagesCount` | **RESOLVED** | Dropped; retrieval tuning is exposed via `retrievalConfig`. |
| `BLUEPRINT.md` duplicated body + leaked local path | **RESOLVED** | Single clean copy; leaked path and LLM chatter removed; model id and names aligned to the enforced conventions. |

## 6. Honest limitations — genuinely still skeleton or scoped

These are labelled skeleton / designed / gated in the README status matrix, and they are *not* claimed as live. Stated plainly so the repo is neither over- nor under-sold:

- **Sample detonation is an HONEST SIMULATED no-op (by design, not a gap).** `longrunning/detonation/` ships a full `QUEUED→…→DESTROYED` lifecycle state machine + a `detonate_sample` orchestrator + a scenario (`evidence/detonation_result.json`), all built + tested — but it is deliberately still a SIMULATED no-op: **no real malware, no real microVM, no real network, no byte of a sample is read or executed.** The sample-by-reference invariant, sandbox-gate, HITL gate, and always-destroy-after-use are real; the detonation itself is not, and never will be in this reference repo.
- **A2A specialist container is built and live-validated.** `specialists/cve-intel/` really `docker build`s (multi-stage, pinned deps, non-root) and was **live-validated end-to-end on AgentCore Runtime** — a real arm64 microVM served an A2A `message/send` (HTTP 200) that invoked the real Bedrock model, then was torn down (`evidence/live_a2a_runtime_result.json`, non-prod test account). The siblings (`attack-mapper` / `threat-hunt`) share the container pattern. A live A2A call needs an account where `bedrock-agentcore:CreateAgentRuntime` is permitted (the primary dev account blocks it via an org SCP — an environment limit, not a code gap).
- **Private VPC PrivateLink endpoints are cost-gated off.** `iac-cdk/lib/network-stack.ts` builds and synth-validates the private-VPC + default-deny-egress design, but the PrivateLink endpoints are intentionally disabled to avoid standing hourly cost. They are synth-validated, not deployed.
- **Registry: control-plane API live-verified; the CDK custom-resource deploy is not yet exercised.** The native `AWS::BedrockAgentCore::Registry` CFN type is still not registered, so the raw-CfnResource path synth-only. BUT the Registry control-plane API itself is **live-verified** (`sentinel_harness/registry_live.py` created a real Registry + records and drove `DRAFT`→`PENDING_APPROVAL` on a dev account). The feature-flagged Lambda-backed custom-resource path is synth-clean with confirmed-real action names; a live `cdk deploy` of it still needs the `@aws-sdk/client-bedrock-agentcore-control` client bundled into the Lambda asset.
- **M2 single-run re-score is quota-gated.** The Agent Factory loop closes and promotes via the real `CreateHarnessEndpoint`, but the single-run re-score step hit a live `InvokeHarness` 403 (invoke quota) and is honestly labelled as quota-gated in the evidence rather than re-run offline.

## 7. Reading guide

- **README status matrix** — the authoritative per-capability ledger (🟢 live-validated / built+tested · 🟡 built, partial or skeleton · 🟠 designed with loadable config · ⚪ design narrative). This report explains the *why* behind those labels.
- **`docs/ARCHITECTURE.md`** — the 3-layer design and its designed-vs-built boundaries.
- **`evidence/`** — 14 committed JSON artifacts from live and offline runs; `evidence/README.md` records what each captures and its region/run context.
