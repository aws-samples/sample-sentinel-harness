> Anonymized open-source blueprint. Generic SecOps design — contains no organization-specific data.


# BUILD BLUEPRINT — `sentinel-harness`

A deployable Amazon Bedrock AgentCore **harness-based** platform for a SecOps team (security operations). Reverse-engineered from the SecOps platform's 3-layer target architecture into AgentCore primitives, borrowing verified patterns from the 4 sample repos.

---

## 0. Core design decision — Harness vs Runtime, and why "multi-harness = multi-agent"

AgentCore gives us two agent-hosting primitives (both seen in the samples):

| Primitive | What it is | Source repo | We use it for |
|---|---|---|---|
| **Harness** (`create_harness`) | Managed server-side ReAct loop. You give it model + systemPrompt + tools + allowedTools + Memory ARN + limits (`maxIterations`/`maxTokens`/`timeoutSeconds`). Zero orchestration code. Bedrock-model-only. | image-editing, pluggable | Every **scenario** that is straightforward tool-calling (CVE triage, IOC check, detection-gen supervisor). |
| **Runtime** (`create_agent_runtime`) container | Your own FastAPI/Strands/Claude-SDK container in a per-session microVM. Full orchestration control, non-Bedrock models via LiteLLM, hours-long async loops. | chatbot, pluggable (A2A specialists), long-running | **Specialists** behind A2A, and the **long-running** malware/BAS jobs that exceed harness `timeoutSeconds`. |

**The customer's "multi-agent parallelism via MULTIPLE harnesses" maps to the pluggable-framework pattern:** one **supervisor Harness** per workflow that discovers and delegates to **specialist agents** registered in an **AgentCore Registry**, invoked over **A2A**. New specialists are added without touching the supervisor. That is the reference `sample-pluggable-agentic-ai-framework` design and it is exactly the SecOps platform's "multiple harnesses wired together" ask.

**Key correction we bake in vs the pluggable sample's gotcha:** that sample gave the harness *only* `browser`+`code_interpreter` and made the LLM *write code* to hit Registry/A2A — fragile. We instead expose **discovery + A2A-invoke as real MCP tools on an AgentCore Gateway** (`search_registry` / `invoke_specialist`), so delegation is a deterministic tool call, not model-authored HTTP. This is the single most important reliability upgrade in the blueprint.

---

## 1. Layer → Harness-primitive mapping

### Layer 1 — 策略迭代 (Strategy Iteration) — the flagship, fully built

| the SecOps platform capability | Primitive | Concrete construct |
|---|---|---|
| 策略研究 (ATT&CK / CVE检索 / 样本归因 / 威胁狩猎) | **`research-supervisor` Harness** + specialists | Supervisor delegates to `cve-intel-specialist`, `attack-mapper-specialist`, `threat-hunt-specialist` (A2A Runtimes). Tools: `nvd_lookup`, `epss_kev`, `attack_technique_lookup`, `web_search` (Gateway MCP). |
| 检测规则自动生成 + 多轮Agent交叉Review + 白名单优化 | **`detection-eng` Harness (GRAPH-style fixed pipeline)** | A LangGraph pipeline (chatbot `docker-graph` pattern): `enrich → hypothesize → write_rule → adversarial_review → maybe_revise → lint → publish`. Deterministic nodes for **Sigma/YARA lint** (pure Python, no tokens). Conditional edge on review verdict. |
| 人工合并 (human merge) | **`inline_function` HITL gate** | Between `adversarial_review` and `publish`: an inline_function pauses, posts the diff to a review channel, waits for analyst approve/reject. |
| 告警处置 (TP/FP分诊 / 多源溯源 / 自动响应 / 影响评估) | **`alert-triage` Harness** | Per-alert isolated session. Tools: `siem_query`, `asset_lookup`, `enrich_ioc`, `create_ticket`, `contain_action` (contain is HITL-gated). |
| feedback loop | **AgentCore Memory** (semantic + summary strategies) | Triage verdicts and FP whitelist decisions written to Memory namespaces `facts/{tenant}`, feeding future research/detection. |

### Layer 2 — 验证模拟 (Validation / Simulation) — designed, one scenario built

| the SecOps platform capability | Primitive | Concrete construct |
|---|---|---|
| BAS攻击模拟 / 攻击路径推演 | **`bas-runner` long-running Runtime** (not harness) | Uses the `sample-long-running-app-harness` skeleton: `@app.entrypoint` async generator, `add_async_task` + `HEALTHY_BUSY` ping, git/S3-checkpointed state, WIP-commit + self-restart at session cap. Runs tools in the per-session microVM. |
| AI攻击模拟 (Play Mode 人工确认) | **`inline_function` gate on every offensive action** | Play Mode = every step (`exec_technique`) requires HITL approve before execution. This is the long-running repo's `permission_mode` + PreToolUse hook pattern surfaced as an explicit human gate. |

### Layer 3 — 基础支持 (Foundation)

| the SecOps platform capability | Primitive | Concrete construct |
|---|---|---|
| Agent沙箱隔离 | **One microVM per `runtimeSessionId`** (chatbot invariant) + **PreToolUse security hooks** (long-running `SecurityValidator`) | Each malware/CVE/detonation task = its own disposable microVM. Path confinement + Bash allowlist + read-only AWS CLI hooks are the sandbox boundary. |
| 平台自迭代 (test→staging→prod) | **Agent Factory + provision-at-scale** (chatbot) | `create-runtime-version` Lambda + Step Functions provision fleets per environment; tag-guard prevents cross-env update. |
| AI Coding (LiteLLM推理网关 + 企业MCP网关) | **LiteLLM in specialist containers** (pluggable) + **AgentCore Gateway** (all samples) | Specialists use `LiteLLMModel` for provider-agnostic inference; Gateway is the single MCP ingress with SEMANTIC tool search. |
| cyber-skills 日常提效 | **Agent Skills** (chatbot `AgentSkills` plugin) + **skill/tool Registry** (chatbot DynamoDB registry) | CVE-triage rubric, detection-writing SOP, IOC-vetting procedure encoded as S3 `SKILL.md` skills (progressive disclosure). Central governance via a DynamoDB tool/skill registry — a tool is live only if in BOTH the registry AND the code map. |

---

## 2. Pattern-borrowing map (which repo → which pattern)

| Pattern | Borrowed from | Where used in the SecOps platform |
|---|---|---|
| **Supervisor→specialist multi-harness delegation (pluggable)** via Registry + A2A | `sample-pluggable-agentic-ai-framework` | `research-supervisor` and `alert-triage` supervisors delegating to specialist Runtimes. We upgrade delegation to **real Gateway MCP tools** (`search_registry`/`invoke_specialist`) instead of model-authored code. |
| **Long-running session + Memory + resume across session cap** | `sample-long-running-app-harness` | `bas-runner` and any malware detonation: `@app.entrypoint` async-gen, `add_async_task`, WIP-commit + self-restart, S3/git checkpoint, CloudWatch heartbeat + GHA restart-if-stale. |
| **Zero-orchestration tool selection (config-only harness, SEMANTIC Gateway)** | `sample-serverless-image-editing-agent-bedrock-agentcore-harness` | All Layer-1 harnesses: agent = pure `create_harness` config; tools picked from descriptions via SEMANTIC Gateway; **CloudFormation Custom Resource** manages the preview harness lifecycle. Per-invocation `systemPrompt`/`model` override = scenario/persona switch. |
| **Agent Factory / provision-at-scale + config-driven agent build** | `sample-agentic-chatbot-accelerator` | `create-runtime-version` + Step Functions to provision specialist fleets per env; `factory.py` config-driven builder for specialist containers; `AgentSkills` + DynamoDB tool registry for governance; `evaluation-executor` invoke-parse-cleanup for the scenario runner. GRAPH `docker-graph` for the detection pipeline. |
| **Gateway interceptor → apply_guardrail (egress/PII governance)** | `sample-pluggable-agentic-ai-framework` (L4) | Egress control point: every tool response run through Bedrock Guardrails to strip secrets/PII/customer data before it reaches the LLM. |
| **inline_function HITL** (config-only harness gate) | image-editing (harness inline pattern) + long-running (PreToolUse gate) | Detection publish gate, alert containment gate, Play-Mode offensive gate. |

---

## 3. Repo file structure

```
sentinel-harness/
├── README.md
├── Makefile                       # long-running-repo style: deploy-infra, create/update-harness, seed-registry, reset
├── deploy.sh                      # image-editing style one-command: bundle deps, cdk deploy, seed, smoke-test
├── bin/
│   └── sentinel.ts                  # CDK app entry
├── iac-cdk/
│   ├── lib/
│   │   ├── network-stack.ts        # VPC (private egress via NAT + egress allowlist), no public runtime
│   │   ├── gateway-stack.ts        # AgentCore Gateway (MCP, SEMANTIC), CUSTOM_JWT authorizer (Cognito), guardrail interceptor Lambda
│   │   ├── registry-stack.ts       # AgentCore Registry (autoApproval=false → governance) + DynamoDB tool/skill registry tables
│   │   ├── memory-stack.ts         # AgentCore Memory (summary+semantic+userPref strategies, per-tenant namespaces)
│   │   ├── harness-cr-stack.ts     # CloudFormation Custom Resource for harness lifecycle (image-editing pattern)
│   │   ├── runtime-stack.ts        # specialist + long-running Runtime provisioning (chatbot create-runtime-version pattern)
│   │   ├── observability-stack.ts  # CW GenAI dashboards, X-Ray delivery, cost metrics, budget alarms
│   │   └── iam.ts                   # execution roles (least-priv, per-function), NO people→IAM mapping
│   └── config/
│       └── harnesses.yaml          # declarative harness definitions (model, prompt file, allowedTools, memory, limits)
├── harnesses/                      # one dir per supervisor harness (config-only)
│   ├── research-supervisor/
│   │   ├── system_prompt.md
│   │   └── harness.yaml            # model, tools=[gateway], allowedTools=[search_registry,invoke_specialist,nvd_lookup,...]
│   ├── detection-eng/
│   │   ├── system_prompt.md
│   │   └── graph.py                # LangGraph pipeline (chatbot docker-graph) — runs in a Runtime, not a bare harness
│   └── alert-triage/
│       ├── system_prompt.md
│       └── harness.yaml
├── specialists/                    # A2A Strands Runtime containers (pluggable pattern)
│   ├── cve-intel/
│   │   ├── agent_a2a.py            # Strands Agent + A2AServer + LiteLLMModel + FastAPI /ping
│   │   ├── requirements.txt        # pinned: bedrock-agentcore, strands-agents[a2a,litellm], mcp
│   │   └── Dockerfile
│   ├── attack-mapper/
│   ├── threat-hunt/
│   └── adversarial-reviewer/       # the "cross-review" agent that kills hallucination
├── longrunning/                    # long-running-repo skeleton
│   └── bas-runner/
│       ├── bedrock_entrypoint.py   # @app.entrypoint async-gen, add_async_task, WIP+restart, heartbeat
│       ├── runner_loop.py          # state machine (continuous/run_once/pause), fresh-context-per-turn
│       ├── src/security.py         # PreToolUse/PostToolUse sandbox hooks (path confine, cmd allowlist)
│       └── Dockerfile              # arm64, non-root
├── tools/                          # Lambda tools exposed as Gateway MCP targets
│   ├── nvd_lookup/handler.py       # NVD/CVE + strict input validation (image-editing tool template)
│   ├── epss_kev/handler.py         # EPSS score + CISA KEV enrichment
│   ├── attack_lookup/handler.py    # MITRE ATT&CK technique lookup
│   ├── web_search/handler.py       # EGRESS-CONTROLLED web search (no raw download)
│   ├── siem_query/handler.py       # read-only SIEM query
│   ├── asset_lookup/handler.py     # asset inventory / blast-radius
│   ├── enrich_ioc/handler.py       # IOC reputation (hash/domain/ip)
│   ├── create_ticket/handler.py    # ticketing write
│   ├── sigma_yara_lint/handler.py  # deterministic rule linter (no LLM)
│   ├── search_registry/handler.py  # DISCOVERY tool (upgrade over pluggable's code-writing)
│   └── invoke_specialist/handler.py# A2A message/send wrapper (deterministic delegation)
├── skills/                         # Agent Skills (chatbot S3 skill pattern)
│   ├── cve-triage-rubric/SKILL.md
│   ├── detection-writing-sop/SKILL.md
│   ├── ioc-vetting/SKILL.md
│   └── attack-path-reasoning/SKILL.md
├── hitl/
│   └── inline_functions.py         # HITL gate impls (publish approval, containment approval, play-mode step)
├── scenarios/                      # the runner + flagship scenario defs (chatbot evaluation-executor pattern)
│   ├── runner.py                   # invoke_harness/invoke_agent_runtime + SSE parse + stop_session (Config read_timeout=300)
│   ├── cve_triage.json
│   ├── detection_gen.json
│   └── parallel_scan.json
└── tests/
    ├── validate_config.py          # local config-validation parity (image-editing SILENT-failure guard)
    └── smoke/                      # live smoke tests (see §6)
```

---

## 4. Concrete harnesses & runtimes to create

### 4.1 `research-supervisor` (Harness — config only)

```yaml
# harnesses/research-supervisor/harness.yaml
harnessName: sentinel-research-supervisor
model:
  bedrockModelConfig:
    modelId: global.anthropic.claude-opus-4-8   # deep reasoning for research synthesis
    maxTokens: 8192
    temperature: 0.2
systemPrompt: [{ text: "<contents of system_prompt.md>" }]
tools:
  - { name: gateway, type: agentcore_gateway, config: { agentCoreGateway: { gatewayArn: "${GATEWAY_ARN}" } } }
allowedTools:          # explicit list, NOT ['*'] — tighten per image-editing gotcha
  - sentinel-tools___search_registry
  - sentinel-tools___invoke_specialist
  - sentinel-tools___nvd_lookup
  - sentinel-tools___epss_kev
  - sentinel-tools___attack_lookup
  - sentinel-tools___web_search
memory: { agentCoreMemoryConfiguration: { arn: "${MEMORY_ARN}", messagesCount: 20 } }
maxIterations: 20
timeoutSeconds: 300
```

**systemPrompt intent:** "You are a threat-research supervisor. Decompose the research question. Use `search_registry` to find specialist agents by capability, then `invoke_specialist` to delegate CVE-intel, ATT&CK-mapping, and threat-hunt subtasks in PARALLEL. Ground every claim in tool output or Memory `facts/{tenant}` — if a fact is not retrievable, say so; never confabulate. Emit a structured `ResearchDossier` (JSON)."
**Skills loaded:** `cve-triage-rubric`, `attack-path-reasoning`.
**Memory:** semantic + summary, namespace `facts/{tenant}`, `summaries/{tenant}/{session}`.

### 4.2 Specialists (A2A Runtimes — pluggable pattern)

`cve-intel`, `attack-mapper`, `threat-hunt`, `adversarial-reviewer`. Each = Strands `Agent(tools, system_prompt, name, description)` wrapped in `A2AServer`, `LiteLLMModel(model_id)` (cheaper Haiku for narrow specialists), FastAPI `/ping`, deployed via `bedrock_agentcore_starter_toolkit.Runtime().configure(protocol="A2A").launch()`, self-registers its agent-card into the Registry.

- **`adversarial-reviewer`** is the hallucination-killer: its systemPrompt is "Attack this detection rule / this verdict. Find false-positive sources, logic gaps, unsupported claims. Return `ReviewVerdict{approved:bool, issues:[...]}`." Used by the detection pipeline and optionally by triage.

### 4.3 `detection-eng` (GRAPH pipeline — chatbot `docker-graph`, runs in a Runtime)

LangGraph `StateGraph`:
```
enrich(agent) → hypothesize(agent) → write_rule(agent) → adversarial_review(agent)
   → [conditional: approved? ] → lint(deterministic: sigma_yara_lint) → HITL_publish_gate(inline_function) → publish(deterministic)
   → [not approved] → revise(agent) → adversarial_review (loop, max 2)
```
- `lint` and `publish` are **deterministic nodes** (pure Python, no tokens) per chatbot pattern.
- `adversarial_review` calls the `adversarial-reviewer` specialist via A2A.
- `HITL_publish_gate` = `inline_function` (see §4.5).

### 4.4 `alert-triage` (Harness — config only)

Model: Haiku (cheap, high volume) with per-invocation override to Sonnet for ambiguous alerts. Tools: `siem_query`, `asset_lookup`, `enrich_ioc`, `create_ticket`, `contain_action`. `contain_action` is HITL-gated. Memory writes FP/TP decisions to `facts/{tenant}` (the feedback loop).

### 4.5 HITL `inline_function` gates (`hitl/inline_functions.py`)

Three gates, all same shape — pause, publish a decision request (Lark/Slack/ticket), poll an approval store (DynamoDB/SSM), resume or abort:

```python
def hitl_gate(kind, payload, tenant, session_id):
    """Publish an approval request and block until an authorized human decides.
    kind ∈ {'detection_publish','alert_contain','offensive_step'}."""
    req_id = put_pending_approval(kind, payload, tenant, session_id)   # DynamoDB
    notify_reviewers(kind, req_id, payload)                            # Lark/Slack/ticket
    decision = poll_until_decided(req_id, timeout=3600)               # analyst approves/rejects
    if decision.status != "APPROVED":
        raise HumanRejected(decision.reason)
    return decision   # carries optional analyst edits (e.g. merged rule)
```
- **detection_publish**: analyst reviews the auto-generated rule + reviewer verdict, can hand-merge edits (the SecOps platform's "人工合并").
- **alert_contain**: analyst confirms before any auto-response fires.
- **offensive_step**: Play Mode — every BAS/AI-attack action confirmed before execution.

---

## 5. Every customer concern → design answer

| Concern | Design answer |
|---|---|
| **Auth — dislikes IAM for PEOPLE, wants API key/OAuth; accepts IAM execution role** | People authenticate via **Cognito → CUSTOM_JWT** on the Gateway (OAuth/JWT, no IAM-per-person) — pluggable L1 pattern. Machine-to-machine and runtime→Bedrock use **IAM execution roles** (accepted). Specialists get Bearer JWT for Gateway; A2A between agents uses SigV4 on the execution role. No human is ever mapped to an IAM principal. |
| **Multi-agent parallelism** | Supervisor Harness + Registry + A2A specialists (pluggable). Supervisor fires multiple `invoke_specialist` calls; specialists run in **separate microVMs → true parallelism**. Detection pipeline uses GRAPH `Send()` fan-out for parallel enrichment. |
| **Central skill/tool governance (register/repo)** | **AgentCore Registry** with `autoApproval=false` (a specialist goes live only after review) + **DynamoDB tool/skill registry** where a tool is live only if in BOTH the registry AND the code `TOOL_FACTORY_MAP` (chatbot). Skills are versioned S3 `SKILL.md` bundles. Single source of truth, auditable. |
| **Egress control (web search over raw download)** | Runtimes deploy in a **VPC with no public networkMode** (fixing chatbot's PUBLIC gotcha); NAT egress restricted to an allowlist. Only the `web_search` MCP tool can reach the internet (returns text, never downloads binaries); there is **no raw-download tool**. Malware samples enter via a controlled S3 dropbox, never a live fetch. |
| **HITL to kill hallucination** | Two layers: (1) `adversarial-reviewer` specialist adversarially reviews every rule/verdict; (2) `inline_function` gates require human approve before publish/containment/offensive action. System prompts forbid confabulation and require Memory/tool grounding (pluggable pattern). |
| **Long-running (malware→VM→tools) + Memory across long tasks** | `bas-runner`/detonation Runtimes use the **long-running skeleton**: async-gen entrypoint, `add_async_task`+`HEALTHY_BUSY` ping, S3/git checkpoint, WIP-commit + self-restart at the 7-8h session cap. **AgentCore Memory** carries case context across restarts and sessions. Sync harnesses stay under `timeoutSeconds`; genuinely long jobs run async and are polled (image-editing gotcha respected). |
| **Console observability + cost visibility** | **X-Ray traces + CloudWatch GenAI dashboards** per session (all samples); `MetricsPublisher` custom metrics + `SessionHeartbeat` (long-running); Gateway usage metrics; **per-invocation token usage** parsed from the `metadata` stream event (image-editing) → pushed as a `TokensPerScenario` CW metric with **AWS Budgets alarms** for cost visibility. |
| **Agent sandbox isolation** | One microVM per `runtimeSessionId` (chatbot invariant) = per-task disposal. Untrusted-input tasks add **PreToolUse security hooks** (path confinement, Bash allowlist, read-only AWS CLI, blocked destructive verbs) from the long-running `SecurityValidator`. |
| **Preview-API risk** | Harness has no native CDK construct → managed via **CloudFormation Custom Resource** with adopt-or-delete on `ConflictException`, `AccessDenied` backoff, and delete-and-wait ordering (image-editing). Pin SDK versions; expect API drift (pluggable gotcha). |

---

## 6. Flagship scenarios to BUILD & VALIDATE live (no real malware needed)

All three are provable on a dev account against public data (NVD/EPSS/KEV/ATT&CK) + a mock SIEM.

### Scenario A — CVE-triage harness (single-harness, zero-orchestration)
**Flow:** `invoke_harness(alert-triage or research-supervisor)` with `{cve_id:"CVE-2024-XXXXX", assets:[...]}` → harness calls `nvd_lookup` → `epss_kev` → `asset_lookup` → produces structured `CVETriage{severity, exploited_in_wild, blast_radius, recommended_action}`.
**Proves:** config-only harness, SEMANTIC tool selection, structured output, Memory write, token/cost metric. **Live-provable** with public NVD/EPSS/KEV APIs.

### Scenario B — Detection-strategy-generation harness with HITL merge gate
**Flow:** `detection-eng` GRAPH runs `enrich → hypothesize → write_rule (Sigma) → adversarial_review (A2A reviewer) → lint (deterministic sigma linter) → HITL_publish_gate → publish`. Analyst approves/edits at the gate.
**Proves:** GRAPH pipeline, deterministic nodes, A2A cross-review (anti-hallucination), `inline_function` HITL, human-merge. **Live-provable**: generate a Sigma rule for a known technique, lint it, gate it.

### Scenario C — Multi-harness parallel scan + registry delegation
**Flow:** `research-supervisor` receives a threat-hunt brief → `search_registry` finds `cve-intel` + `attack-mapper` + `threat-hunt` → fires 3 parallel `invoke_specialist` A2A calls → merges into a `ResearchDossier`.
**Proves:** supervisor→specialist multi-harness delegation, Registry discovery, A2A parallelism, deterministic delegation tools (our upgrade over pluggable). **Live-provable** with 3 deployed specialist Runtimes.

*(Optional D — Play-Mode offensive step gate: a single simulated `exec_technique("T1046 network scan")` in a sandboxed microVM, HITL-confirmed before running `nmap` against a dev target. Proves offensive HITL + microVM sandbox without any malware.)*

---

## 7. Validation plan (what to run live to prove it)

**Deploy (one command, image-editing/long-running style):**
```
./deploy.sh            # cdk bootstrap+deploy all stacks; seed Registry + tool registry; build & push specialist images
make seed-registry     # register specialists (autoApproval=false → manual approve step, proves governance)
make create-harnesses  # CFN Custom Resource creates the 3 harnesses; poll get_harness until READY
```

**Live checks (each a smoke test in `tests/smoke/`):**

1. **Harness READY gate** — poll `get_harness` to `READY`; assert non-`*_FAILED`. Proves preview-lifecycle CR works.
2. **Scenario A** — `scenarios/runner.py cve_triage.json` with a real recent CVE; assert structured `CVETriage` returned, EPSS/KEV fields populated from live APIs, and a `TokensPerScenario` CW datapoint appears. (Config `read_timeout=300`, `stop_runtime_session` in finally — chatbot pattern.)
3. **Scenario B** — run detection-gen; assert (a) a lint-valid Sigma rule is produced, (b) the `adversarial-reviewer` returned a verdict, (c) the run **blocks** at `HITL_publish_gate`; approve via the mock reviewer API; assert publish fires only after approval; reject once and assert publish is skipped.
4. **Scenario C** — invoke `research-supervisor`; assert `search_registry` returned ≥3 specialists and ≥2 `invoke_specialist` A2A calls executed concurrently (check X-Ray trace shows overlapping spans → proves parallelism), and a merged `ResearchDossier` is returned.
5. **Egress control** — attempt a raw-download from inside a specialist microVM; assert it fails (no route / no tool), while `web_search` succeeds. Proves egress allowlist.
6. **Guardrail interceptor** — inject a fake secret/PII string into a tool response; assert it's masked before reaching the LLM (check trace). Proves egress/PII governance.
7. **Observability + cost** — open the CloudWatch GenAI dashboard; assert per-session traces, `SessionHeartbeat`, and `TokensPerScenario` are visible; confirm the Budgets alarm exists.
8. **Sandbox/HITL negative test** — in the optional Play-Mode step, assert an offensive action does NOT execute until the `offensive_step` gate is approved, and that PreToolUse hooks block a path-traversal / disallowed-command attempt.
9. **Cleanup ordering** — `make reset`: delete harness → Memory → role in order; assert no `DELETE_FAILED` orphans and the shared X-Ray delivery destination is preserved (pluggable + image-editing cleanup gotchas).

**Pass criteria:** Scenarios A, B, C all green live; egress + guardrail + HITL negative tests all block as designed; dashboards show traces + token cost. That set proves all 7 customer concerns end-to-end on a dev account with zero real malware.

---

## Key gotchas pre-baked into the blueprint (so the build doesn't hit them)
- **allowedTools = explicit list, never `['*']`** (image-editing).
- **runtimeSessionId ≥ 33 chars**; **serialize per-session calls** (concurrent same-session corrupts harness memory) (image-editing).
- **Harness is Bedrock-model-only** → supervisors stay on Bedrock; specialists use LiteLLM for provider flexibility (pluggable).
- **create_harness vs update_harness memory shape differs**; **agent update = full replacement** (read-modify-write full config) (pluggable + chatbot).
- **Provisioning is fire-and-forget → always poll to READY** (chatbot).
- **Server-side config validation is silent → `tests/validate_config.py` local parity** (image-editing).
- **VPC/private networking, not PUBLIC** for security workloads (chatbot explicitly non-prod).
- **Registry autoApproval=false** for governance; **tool live only if in registry AND code map**.
- **Long jobs async + polled**, never awaited inline past `timeoutSeconds`; use long-running skeleton for the malware/BAS tier.

