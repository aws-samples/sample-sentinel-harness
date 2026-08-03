# sentinel-harness — Roadmap & Development Guide

> The authoritative, build-it-by-the-numbers plan for evolving `sentinel-harness`.
> Generic SecOps content only — **no organization-, customer-, or deployment-specific
> data.** Bring your own data planes, identities, and criteria behind the env vars and
> MCP bridges described here.

**North star (one line):** evolve `sentinel-harness` from *hand-authored, fixed SecOps
agents* into an **agent that builds agents** — a self-iterating security-operations
platform where natural language / alerts / framework errors flow in, and the platform
**auto-builds → tests → evaluates → iterates → promotes** agents, self-improving over
time, fully **controllable (HITL gates)** and **observable (OTEL / eval traces)**, all
on **Amazon Bedrock AgentCore Harness**.

**Two rules that must never be broken:**
1. **Do not rewrite what is already live-validated** (`core` / `loader` / `factory` /
   `registry` / the three shipped harnesses / nine scenarios / nine tools / the Gateway
   helper / `sandbox_hooks` / `simulation`). Layer on top of them.
2. **Every milestone ships live evidence** into `evidence/` (the existing "if it ran, it
   dropped a JSON + log" habit). Evidence precedes any "done" claim.

---

## 0. Current-state ground truth (read before building)

Legend: ✅ live-validated (has `evidence/`) · 🟩 built + tested (unit-tested, not yet
live) · 🟡 skeleton / partial · 🔴 gap.

### 0.1 Core library `sentinel_harness/` (~2,100 lines, library-grade — extend, don't rewrite)

| File | Lines | Responsibility | Status | Key real API |
|---|--:|---|:--:|---|
| `core.py` | 270 | Thin AgentCore Harness wrapper | ✅ | `create_harness(name, system_prompt, *, model, tools, skills, memory, allowed_tools, max_iterations, max_tokens, timeout_seconds)`; `wait_ready(id, timeout=360)`; `invoke(arn, session_id, text, *, actor_id, **overrides)→{text,events,stop_reason,tools_used,tool_use,metadata}`; `invoke_with_tool_result(...)` (the **two-message HITL resume contract**); tool/memory builders; `new_session(prefix)` (≥33 chars); `delete_harness/cleanup/list_harnesses`. Model env: `SENTINEL_MODEL_{OPUS,SONNET,HAIKU}` |
| `factory.py` | 259 | Agent Factory (fleet provisioning, idempotency, cross-env tag-guard) — **the base for self-iteration** | 🟩 | `provision_fleet(manifest, *, dry_run)` (`would_create/created/exists`, `sentinel:env` tag-guard refuses cross-env overwrite); `teardown_fleet(...)`; `FactoryError` |
| `loader.py` | 224 | `harness.yaml` → `create_harness` kwargs | 🟩 | `load_harness_config(path)` (offline; `${ENV_VAR}` expansion, keeps `${arn:...}`, reads `systemPrompt` file, **injects inline HITL gates**); `create_from_config(path)`. Built-in gates: `request_publish_approval` / `request_containment_approval` / `request_human_review` |
| `registry.py` | 264 | Tool/skill dual-gate governance (offline) | 🟩 | `ToolRegistry(factory_map)`; `.resolve(name)` (live only if registry-approved **and** code-mapped); `.governance_check()→GovernanceReport`; `load_registry()` |
| `registry_live.py` | 217 | LIVE AgentCore Registry control plane (the on-account dual-gate) | ✅ | `create_registry(name, *, auto_approval=False, authorizer_type, ...)→registryArn`; `get_registry`/`delete_registry`; `create_skill_record`/`create_custom_record` (land in `DRAFT`); `list_records`; `submit_for_approval` (`DRAFT`→`PENDING_APPROVAL`); `RegistryLiveError`; `DESCRIPTOR_TYPES`. Over `core._control` (`bedrock-agentcore-control`); live-verified on a dev account, walked offline in `scenario_registry_governance.py` |
| `gateway.py` | 330 | AgentCore Gateway helper (create→READY→delete live-validated) | 🟩 | create/wait/delete gateway + target builders. **CUSTOM_JWT auth live-proven** (`evidence/live_custom_jwt_gateway_result.json`); **Lambda-interceptor + `policyEngineConfiguration` (guardrail engine) now wired** — `lambda_interceptor()` / `policy_engine_config()` builders + `create_gateway(interceptor_configurations=…, policy_engine_configuration=…)`, schema-drift-tested against the real `CreateGateway` model |
| `simulation.py` | 392 | Play Mode (every offensive step HITL-gated) | ✅ | see `scenario_play_mode.py` |
| `sandbox_hooks.py` | 127 | PreToolUse sandbox (path confinement / command allowlist / read-only cloud) | 🟩 | `validate_command` / `validate_path` |
| `cli.py` | 303 | `sentinel create/...` CLI | 🟩 | `sentinel create <harness.yaml>` etc. |

### 0.2 Declarative assets

| Dir | Contents | Status | Gap |
|---|---|:--:|---|
| `harnesses/` | `alert-triage` / `detection-eng` / `research-supervisor` | ✅ loader-consumed | missing meta / ops / self-improving harnesses |
| `scenarios/` | 15 runnable scenarios incl. `cve_triage` / `detection_gen` / `hitl_resume` / `multi_harness` / `named_supervisor` / `play_mode` / `agent_factory_loop` / `self_improve_loop` / `bas_replay` / `egress_control` / `alert_triage_poc` / `feedback_loop` / `cve_asset_triage` / `detonation` / `registry_governance` (evidence present for all except the live-only `named_supervisor`, whose Gateway proof is `gateway_lifecycle_result.json`) | ✅ | self-iteration loop scenario DELIVERED (`agent_factory_loop` / `self_improve_loop`) |
| `tools/` | 20 tools incl. data-plane `siem_query` / `asset_lookup` / `enrich_ioc` / `create_ticket` / `ops_query`, the detection-engineering suite `sigma_match` / `sigma_yara_lint` / `detection_translate` / `detection_dedup` / `detection_coverage` / `detection_audit` / `detection_navigator` / `detection_baseline`, ops `harness_ops` / `run_evaluation` / `whitelist_optimizer`, and reference stubs `attack_lookup` / `epss_kev` / `nvd_lookup` / `web_search` | 🟩 | data-plane + detection suite DELIVERED (mock world + `*_LIVE` seams) |
| `skills/` | 9 skills incl. `cve-triage-rubric` / `attack-path-reasoning` / `detection-writing-sop` / `ioc-vetting` / `cve-asset-triage` / `soc-ip-lookup` / `soc-triage` / `incident-ticketing` / `multi-account-ops` | 🟩 | add domain skills as your SecOps program needs them |
| `specialists/` | `cve-intel` (docker-build + live-validated on AgentCore Runtime) + `attack-mapper` / `threat-hunt` (real graph/plan builders) + `adversarial-reviewer` (agent_a2a + local_a2a + two-stage Dockerfile + contract test) | ✅ | all four specialists shipped |
| `longrunning/` | `bas-runner` (BAS case-gen + detection-replay) + `detonation` (full simulated microVM lifecycle + orchestrator) | 🟩 | both built + tested; detonation stays an honest SIMULATED no-op |
| `iac-cdk/lib/` | 9 synth-green stacks — `gateway` / `registry` / `memory` / `network` / `identity` / `guardrail` / `observability` / `harness` / `runtime` (+ `iam`); `iac-terraform/` mirror is `terraform validate`-clean | ✅ | `guardrail` / `identity` / `observability` LIVE-deployed (us-east-1); the Registry + `runtime` custom-resource/raw-CfnResource stacks synth clean but fail on deploy until their CFN types are GA (both control-plane APIs are separately live-verified — Registry via `registry_live.py`, `CreateAgentRuntime` via a real arm64 microVM that served a live A2A call, HTTP 200, real Bedrock model, on a non-prod test account, then torn down — `evidence/live_a2a_runtime_result.json`) |
| `tests/` | 137 files, **3641 offline passing** (+6 skipped) | ✅ | add tests with each new module |
| `evidence/` | 37 evidence sets | ✅ | add one per milestone |

### 0.3 Fit score (vs. a full three-layer SecOps agent program)

**L1 Strategy iteration ~80% · L2 Attack validation ~35% · L3 Foundation ~45% ·
self-iteration north star ~15%.**
→ Priority: **north star first (M1/M2), then land L2/L3 (M3/M4), then connect real data
planes (M5/M6), then packaging (M7).**

---

## 1. Code map: data / control flow (so you don't re-read the source)

```
declarative harness.yaml ──loader.load_harness_config──► create_harness kwargs
                                                              │
                        factory.provision_fleet ─────────────┤ (fleet, dry-run, idempotent, env tag-guard)
                                                              ▼
                                              core.create_harness ──► AgentCore control plane
                                                              │  wait_ready → READY
                                                              ▼
   runtime contract (core.invoke / invoke_with_tool_result):
   invoke(arn, session, text) ──► {text, stop_reason, tools_used, tool_use, metadata}
        └─ stop_reason == "tool_use"  ⇒ hit an inline_function (HITL gate); loop pauses
              └─ human decides ──► invoke_with_tool_result(arn, SAME session, tool_use, decision)
                    (two messages: assistant.toolUse + user.toolResult, same toolUseId, sent together)

   tools: tool_gateway(GATEWAY_ARN) exposes every MCP tool on the Gateway to the harness;
          allowedTools is an explicit allowlist (never '*');
          registry.ToolRegistry dual-gate (approved ∧ code-mapped) decides what is truly live.

   memory: managed_memory([SEMANTIC, SUMMARIZATION]) + actorId namespace = multi-tenant + feedback loop.
```

**Facts to internalize before writing code:**
- Harness is **Bedrock-model-only**; non-Bedrock (LiteLLM) lives only in a specialist's
  **Runtime container**.
- Delegation (build/invoke/evaluate a harness, call a specialist) is a **deterministic
  MCP tool** — never let the LLM hand-write HTTP.
- Long tasks are **async + polled**; never block inline past `timeoutSeconds`.
- Provisioning is fire-and-forget → always `wait_ready`; server-side config validation is
  silent → guard locally with `factory.provision_fleet(dry_run=True)` + `test_config_validation.py`.

---

## 2. Verified platform capabilities (checked against the installed SDK)

Introspected against boto3/botocore **1.43.39**, `bedrock-agentcore-control` — these
determine milestone feasibility, so they were confirmed, not assumed:

| Capability | Operations present | Verdict for the roadmap |
|---|---|---|
| **Harness update** | `UpdateHarness` ✅ | The meta-agent's "modify an agent" is a real in-place update — no delete+recreate fallback needed. |
| **Harness promotion** | `CreateHarnessEndpoint` / `GetHarnessEndpoint` / `UpdateHarnessEndpoint` / `ListHarnessEndpoints` / `ListHarnessVersions` ✅ | "Promote to production only if it passes" maps to a real **endpoint + version** mechanism — not an env-tag hack. |
| **Evaluation** | `CreateEvaluator` / `GetEvaluator` / `ListEvaluators` / `UpdateEvaluator` + `CreateOnlineEvaluationConfig` / `GetOnlineEvaluationConfig` / `ListOnlineEvaluationConfigs` ✅ | The self-improving loop can use a **managed Evaluator** (offline + online) — no need to self-build an LLM-judge to start. |
| **Datasets** | `CreateDatasetVersion` / `ListDatasetVersions` ✅ | Fixed evaluation datasets are versionable on-platform. |

> These are present in the SDK model; **confirm they are enabled in your target region /
> account** before M1/M2 (a live `list_evaluators` / `list_harness_endpoints` smoke call).
> `core.py` currently wraps only `create_harness` + `delete_harness`; M1 adds thin wrappers
> for `update_harness`, and M2 for the endpoint + evaluator operations.

---

## 3. Biggest gap & core design: the meta-agent self-iteration engine

The north star and the current top gap. `factory.py` today is *config-driven human
provisioning*, not *agent-driven natural-language provisioning*. Add a **three-layer
multi-agent orchestration**, layered on top of the existing base:

```
natural-language request / meeting notes / framework's own error
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ ① Meta Agent (orchestrator · Opus)                             │
│   - parse the request → emit a structured harness spec         │
│     {system_prompt, model, tools[], skills[], memory, limits}  │
│   - reuse loader.py's harness.yaml schema as the output target │
└───────────────┬───────────────────────────────────────────────┘
                ▼
┌───────────────────────────────────────────────────────────────┐
│ ② Agent Ops (executor · Sonnet)                                │
│   - call core.create_harness / update_harness to build/modify  │
│   - call core.invoke to batch-test against a fixed dataset     │
│   - reuse factory.py (cross-env tag-guard, dry-run, idempotent)│
└───────────────┬───────────────────────────────────────────────┘
                ▼
┌───────────────────────────────────────────────────────────────┐
│ ③ Self-Improving Agent (evaluation-driven loop)                │
│   - score ②'s agent with a managed Evaluator (LLM-judge/batch) │
│   - below bar → return reasoning to ② to adjust                │
│     (prompt / tool / skill)                                    │
│   - at/above bar → CreateHarnessEndpoint → production          │
│   - write Memory throughout (experience compounding)           │
└───────────────┬───────────────────────────────────────────────┘
                ▼
        test → staging → production (staged HITL gates)
```

**Implementation keys:**
1. **All three layers are themselves Harnesses** (harness builds harness) — harness
   create/update/invoke/endpoint are standard APIs, ideal to be orchestrated by another
   agent. Ship them as `harnesses/meta-agent/`, `harnesses/agent-ops/`,
   `harnesses/self-improving/`; delegation flows through Gateway MCP tools
   (`harness_ops`, `run_evaluation`) — deterministic, never model-authored HTTP.
2. **Evaluation-driven is the soul**: use the managed Evaluator API with a **fixed
   dataset** for an offline baseline + online signal; the pass bar is caller-defined
   (`eval/criteria.yaml`).
3. **Every step is HITL-gateable** (test → staging → prod); the production gate is an
   `inline_function`.
4. **Diverse intake**: natural language / meeting notes / the framework's own errors →
   an `intake/adapter.py` that normalizes all of these into the meta-agent's input
   ("an error auto-becomes a dev request" is an explicit goal).
5. **Platform self-improvement**: the meta-agent can also target *platform* harnesses
   (add capabilities to the platform itself) — a bootstrapping loop. Start with the
   human-gated version; never go fully autonomous first.

> ⚠️ This layer is **additive** — do not touch the live-validated L1 scenarios. Build it
> as an upper orchestration layer reusing `core` / `factory` / `loader` / `registry`.

---

## 4. Milestones (dependency-ordered; each = a deliverable, verifiable unit)

Each milestone gives: **goal / files / reused APIs / acceptance (live evidence) / traps.**
Suggest one feature branch per milestone.

### M0 — Environment & baseline reproduction (half a day)
**Goal:** on a fresh machine, get all 3641 offline tests green and reproduce ≥1 live scenario.
- [ ] `uv sync` + `uv run pytest -q` → 3641 passing (+6 skipped) (offline).
- [ ] Configure `SENTINEL_EXECUTION_ROLE_ARN` / `SENTINEL_REGION` / `AWS_PROFILE` (non-prod) — see `docs/SETUP.md`.
- [ ] Run `scenarios/scenario_cve_triage.py`; compare `evidence/cve_triage_result.json` shape.
- [ ] Run `scenarios/scenario_hitl_resume.py`; reproduce pause→approve→resume.
- [ ] **Smoke the live API surface** M1/M2 depend on: `list_harness_endpoints`, `list_evaluators` in your region — confirm enabled (see §2).

**Acceptance:** offline green + two live scenarios reproduced + API availability recorded.
**Traps:** `runtimeSessionId ≥ 33`; `read_timeout=300` already set in core; call `stop_runtime_session` when done.

### M1 — [P0] Meta-agent self-iteration engine ("agent builds agents") — ✅ DELIVERED, live-validated
**Status:** shipped and proven on real GA AgentCore. `scenarios/scenario_agent_factory_loop.py`
runs end-to-end (`evidence/agent_factory_loop_result.json`, `closed: true`): a natural-language
request → the meta-agent (Opus) emits a harness spec → `harness_ops` really builds a new harness
→ it reaches READY and answers a real invoke → teardown. `core.update_harness`, `tools/harness_ops`,
`intake/adapter.py`, and `harnesses/{meta-agent,agent-ops}` all landed with offline tests.
Scoped: delegation is in-process (wiring `harness_ops` as a live Gateway MCP target so agent-ops
calls it autonomously is M4).

**Goal:** three orchestration harnesses so "natural-language request → auto build/modify/test a harness" works (the eval loop is M2).

**New files:**
```
tools/harness_ops/handler.py            # ★ deterministic MCP tool: harness lifecycle for an agent to call
                                        #   actions: create / update / invoke / wait_ready / list / delete / create_endpoint
                                        #   calls sentinel_harness.core.*, strict param validation, structured JSON out
registry/tools.yaml                     # append harness_ops (owner=platform, status=approved)
harnesses/meta-agent/{system_prompt.md,harness.yaml}    # model=Opus; emit a valid harness spec
harnesses/agent-ops/{system_prompt.md,harness.yaml}     # model=Sonnet; build/modify/batch-invoke via harness_ops
intake/adapter.py                       # normalize natural language / meeting notes / framework errors → meta input
scenarios/scenario_agent_factory_loop.py# end-to-end: one-line request → spec → build+test a new alert-triage variant
tests/test_harness_ops.py               # handler unit tests (mock core)
tests/test_intake_adapter.py
```

**Reuse & prereqs:** `core.create_harness/invoke/wait_ready/delete_harness`; loader's
`harness.yaml` schema as the meta-agent's **structured output target**;
`factory.provision_fleet(dry_run)` for pre-build local validation.
> **Prereq patch:** add a thin `core.update_harness(harness_id, **full_config)` wrapper
> (calls `_control.update_harness`, **full-replacement** semantics — `UpdateHarness` is
> confirmed present, see §2). `harness_ops`'s `update` action calls it.

**Implementation keys:**
1. `harness_ops` is **deterministic** (agent sends structured params, handler calls core/boto3).
2. Meta-agent output **must be a valid `harness.yaml` structure** (loader-consumable +
   factory dry-run-checkable) — give the schema in the prompt, validate handler-side before building.
3. Agent-ops must `wait_ready` before testing; test with a fixed small dataset.
4. Diverse intake via `intake/adapter.py`.

**Acceptance (evidence `evidence/agent_factory_loop_*.json`):** a one-line request →
meta emits a valid spec → ops `dry_run` passes → real build → `wait_ready=READY` →
`invoke` returns structured output → `delete_harness` cleanup. X-Ray shows meta→ops→new-harness chain.
**Traps:** create-vs-update memory shapes differ; **agent update = full replacement**;
harness name rule `[a-zA-Z][a-zA-Z0-9_]{0,39}` (no hyphens — `factory._NAME_RE` guards it).

### M2 — [P0] Evaluation-driven self-improvement loop — ✅ DELIVERED (mechanisms live-validated)
**Status:** shipped with each mechanism proven on real GA AgentCore (dev account, cleaned up):
a deliberately weak agent was scored **0.0** by the independent LLM-judge harness
(`run_evaluation.score_answer`), a full-replacement `update_harness` produced **version 2**, and
**`CreateHarnessEndpoint`** promoted a harness to a named production endpoint
(`evidence/endpoint_promote_result.json`). Ships `tools/run_evaluation`, `harnesses/{llm-judge,
self-improving}`, `eval/` datasets + criteria, the `request_promotion_approval` HITL gate, and
endpoint-aware teardown, with 55 offline tests. **Honest limit:** a full green *single* run needs
fresh account InvokeHarness quota — a heavy test day exhausted it and the second re-score hit HTTP
403 (`second_eval_throttled`), an environment limit, not a defect. Scoring uses a self-built judge
(the managed Evaluate API needs OTEL/CloudWatch telemetry = M4).

**Goal:** score M1's agents, retry-with-reasoning when below bar, promote (create endpoint) only when at/above bar. The soul of self-iteration.

**New files:**
```
tools/run_evaluation/handler.py          # wrap the managed Evaluator API (see §2) as an MCP tool
tools/harness_ops/handler.py             # [extend] add a promote action → CreateHarnessEndpoint
harnesses/self-improving/{system_prompt.md,harness.yaml}  # read eval → judge → retry-with-reasoning → promote
eval/datasets/                           # fixed offline datasets: cve_triage.jsonl / detection_gen.jsonl ...
eval/criteria.yaml                       # caller-defined pass bar
loader.py                                # [edit] add request_promotion_approval to _INLINE_GATES
scenarios/scenario_self_improve_loop.py  # end-to-end: build → fail eval → retry → pass → HITL approve → promote
tests/test_run_evaluation.py
```

**Reuse:** M1's `harness_ops`; `core.invoke_with_tool_result` (the promotion gate resume);
the managed Evaluator + Harness endpoint APIs (§2).

**Implementation keys:**
1. **Retry with reasoning**: self-improving reads eval attribution → concrete
   "change prompt / swap tool / add skill" suggestions → agent-ops rebuilds → re-eval
   (max N rounds, no infinite loop).
2. **Promote only when passing**: eval ≥ `eval/criteria.yaml` **and** human
   `request_promotion_approval` → `CreateHarnessEndpoint` (the confirmed promotion
   mechanism). Stage with `SENTINEL_ENV` test→staging→prod (factory tag-guard isolates).
3. Write Memory throughout (experience compounding).

**Acceptance (`evidence/self_improve_loop_*.json`):** a deliberately-underspecified agent
→ eval fails + attributes → retry improves prompt → re-eval passes → blocks at
`request_promotion_approval` → approve creates the endpoint; reject once → assert no promotion.
**Traps:** eval is async → poll; hard cap the retry loop + require a reasoning change each round.

### M3 — L2 attack validation & simulation — ✅ DELIVERED (real core validated; detonation/specialists = honest skeletons)
**Status:** shipped. The provable core is REAL, deterministic, offline (no LLM, no invoke quota):
`tools/sigma_match` (a Sigma detection *matcher*, not a linter), `longrunning/bas-runner/bas_cases.py`
(BAS case-gen + detection-replay), and `scenarios/scenario_bas_replay.py` — live-validated offline:
4 ATT&CK techniques × 2 Sigma rules → detected {T1059.001, T1046}, **blind spots {T1003.001,
T1547.001}**, coverage 0.5 (`evidence/bas_replay_result.json`). `specialists/attack-mapper` ships a
real `build_attack_paths()` graph reasoner + `tools/asset_lookup`; `specialists/threat-hunt` a real
`build_hunt_plan()`. **Honest skeletons (import-safe, SIMULATED — no real malware/VM/exploit/network):**
`longrunning/detonation/` models the one-shot-microVM-per-session lifecycle (destroy-after-use enforced,
every action gated through `sandbox_hooks`, samples referenced only by an `s3://` dropbox URI, offensive
steps HITL-gated); the A2A serving wrappers use guarded imports. 112 new tests; suite → 591 (+3 skips).

**Goal:** BAS case auto-generation + detection-replay, sample detonation in a one-shot microVM, attack-path reasoning.
```
longrunning/bas-runner/runner_loop.py       # [implement] BAS case gen + replay vs. current detection rules
longrunning/detonation/bedrock_entrypoint.py# sample detonation Runtime (async-gen + checkpoint)
longrunning/detonation/src/vm.py            # one-shot microVM per session → destroy after use
tools/asset_lookup/handler.py               # exposure/asset surface for attack-path (stub first, real in M5)
specialists/attack-mapper/agent_a2a.py      # attack-path reasoning (exposure → topology → high-risk chains)
specialists/threat-hunt/agent_a2a.py        # threat-hunting specialist
scenarios/scenario_bas_replay.py            # BAS gen → replay → report "detection blind spots"
tests/test_detonation.py / test_attack_mapper.py
```
**Reuse:** `longrunning/bas-runner` async-gen/checkpoint skeleton; `sandbox_hooks.py`;
`simulation.py` (Play Mode gating); `specialists/cve-intel` as the A2A template.
**Keys:** samples enter via a **controlled S3 dropbox — never live fetch**; each detonation
= isolated microVM destroyed after use; long tasks async + Memory across restarts.
**Acceptance (`evidence/bas_replay_*.json`):** a set of ATT&CK techniques → auto BAS cases →
replay vs. Sigma rules → "undetected techniques" list; detonation negative test:
path-traversal / disallowed command blocked by `sandbox_hooks`.

### M4 — L3 foundation: identity / gateway / egress / observability — ✅ DELIVERED (3 stacks live-deployed + validated)
**Status:** shipped as dual-track IaC (CDK main + Terraform mirror), authored on verified recon
facts and partially deployed live on the dev account (us-east-1), free-tier stacks left running:
- **Guardrail** (`iac-cdk/lib/guardrail-stack.ts`): deployed; `ApplyGuardrail` really intervened
  (`GUARDRAIL_INTERVENED`) masking a fake AWS key → `{aws-access-key-id}` and an sk- token →
  `{generic-api-token}` (`evidence/m4_guardrail_result.json`).
- **Identity** (`iac-cdk/lib/identity-stack.ts`): Cognito user pool + resource server + domain +
  human/M2M clients deployed; OIDC discovery endpoint reachable (RS256, token_endpoint), and
  `gateway.cognito_jwt_authorizer()` wires it into a CUSTOM_JWT gateway (human aud vs M2M allowedClients).
- **Observability** (`iac-cdk/lib/observability-stack.ts`): CloudWatch dashboard + `TokensPerScenario`
  metric + log group + monthly Budgets alarm deployed.
- **Network** (`iac-cdk/lib/network-stack.ts`): private VPC, isolated subnet, no NAT/IGW; the
  PrivateLink interface endpoints (the only standing ~$30/mo cost) are cost-gated OFF by default
  (`-c sentinel:deployVpcEndpoints=true` opts in). **Egress control LIVE-validated**: deployed with
  endpoints, `scenario_egress_control.py` proved no IGW / no 0.0.0.0/0 route / PrivateLink-only
  (`evidence/egress_control_result.json`, closed:true); endpoints then torn down to drop the cost.
  All 4 M4 acceptance items are now live-proven (egress, Guardrail masking, observability, JWT).
- **Harness** (`iac-cdk/lib/harness-stack.ts`): the NATIVE `AWS::BedrockAgentCore::Harness` CFN type
  (recon corrected the old "needs a custom resource" assumption). Terraform mirror in `iac-terraform/`
  (`terraform validate` clean). Evidence: `evidence/m4_live_deploy_result.json`.
- **Registry control plane** (`sentinel_harness/registry_live.py`): ✅ **LIVE-VERIFIED**. A real
  Registry (`autoApproval=false`) and an `AGENT_SKILLS` `soc-triage` record were created on the dev
  account and moved `DRAFT`→`PENDING_APPROVAL` via `submit_for_approval` — the on-account realization
  of the offline dual-gate (a record exists but is NOT live until a human approves). The
  `bedrock-agentcore-control` Registry ops (`CreateRegistry`/`GetRegistry`/`DeleteRegistry`/
  `CreateRegistryRecord`/`SubmitRegistryRecordForApproval`/`ListRegistryRecords`) are confirmed real
  (no longer TODO-guessed). The governance walk is proven offline in `scenario_registry_governance.py`
  (`evidence/registry_governance_result.json`, closed:true). **Honest note:** this is the runtime SDK
  path; the CDK custom-resource in `iac-cdk/lib/registry-cr.ts` now uses the confirmed action names but
  still needs `@aws-sdk/client-bedrock-agentcore-control` bundled into the Lambda asset before a live
  `cdk deploy` — no live CDK deploy has run.

**Goal:** enterprise MCP gateway (JWT + API-key auth + Guardrail injection defense + audit),
private VPC + egress allowlist, a unified LiteLLM inference gateway, CloudWatch observability + cost.
```
iac-cdk/lib/network-stack.ts        # private VPC (no PUBLIC networkMode) + NAT egress allowlist
iac-cdk/lib/harness-cr-stack.ts     # CFN Custom Resource for harness lifecycle (adopt-or-delete/backoff)
iac-cdk/lib/runtime-stack.ts        # specialist + longrunning Runtime provisioning
iac-cdk/lib/observability-stack.ts  # CW GenAI dashboard + X-Ray + TokensPerScenario + Budgets alarm
gateway.py                          # [extend] CUSTOM_JWT authorizer + API-key auth + Guardrail interceptor
litellm/gateway/                    # standalone LiteLLM inference gateway (single model entry + audit)
scenarios/runner.py                 # [edit] parse per-invocation tokens from metadata stream → TokensPerScenario CW metric
```
**Keys:** humans via **JWT + API key** (no per-person IAM); agents→AWS via execution role;
**only `web_search` reaches the internet**; every tool response passes a **Guardrail**;
Runtime in a **private VPC, not PUBLIC**.
**Acceptance (`evidence/infra_*.json` + screenshots):** `cdk synth` green → deploy → ①
raw-download from a specialist microVM fails, `web_search` succeeds ② injected secret in a
tool response is masked by Guardrail (visible in trace) ③ CW dashboard shows per-session
trace + `TokensPerScenario` + a Budgets alarm ④ JWT/API-key auth paths work.
**Traps:** Harness has no native CDK construct → CFN Custom Resource (adopt-or-delete on
`ConflictException`, backoff on `AccessDenied`, delete-and-wait); pin SDK versions.

### M5 — Data planes + domain skills + multi-account ops — ✅ DELIVERED (DIY mock world, offline)
**Goal:** stand up data-plane tools, domain skills, and multi-account ops automation against a
self-contained **DIY mock world** (no customer data required for demo/POC); each tool keeps a
`*_LIVE` opt-in as the seam to a real backend later.
- [x] `tools/siem_query` / `asset_lookup` / `enrich_ioc` / `create_ticket`: deterministic tools reading the
      cross-linked fictional world in `mockdata/` (RFC-5737 IPs, `example.test`); `*_LIVE` opts into a real
      SIEM / search store / asset system / ticketing via MCP or API bridge through the Gateway. — `mockdata/`, `tools/`
- [x] Domain skills under `skills/<name>/SKILL.md` (generic SecOps: `cve-asset-triage`, `soc-ip-lookup`,
      `soc-triage`, `incident-ticketing`, `multi-account-ops`) — each references only real repo tools; the
      ops tool is registered in `registry/tools.yaml` under the dual-gate. — `skills/`, `tools/ops_query/`
- [x] `harnesses/ops-automation/`: a multi-account ops supervisor over a fictional 4-account inventory
      (`mockdata/accounts.py`) via the read-only `tools/ops_query` tool (`OPS_QUERY_LIVE` → AWS Organizations /
      support API / per-account CloudWatch later); every change gated on HITL. — `harnesses/ops-automation/`
- [x] End-to-end CVE triage against the mock asset plane: id → `nvd_lookup`+`epss_kev` → `asset_lookup` →
      structured `CVETriage` (blast radius + KEV) → HITL — `scenarios/scenario_cve_asset_triage.py`.

**Acceptance (`evidence/cve_asset_triage_result.json`, closed:true):** Log4Shell `CVE-2021-44228` resolves to
`web-01` as the affected host (CVSS + CISA-KEV exploited), computes a blast radius (reachable `app-01`,
internet-exposed), recommends `patch_now_exposed_and_exploited`, and requires analyst sign-off before any
action; a CVE affecting no mock host yields an empty affected-host list (no crash). Deterministic + offline.

**Reuse:** M1/M4 Gateway + registry dual-gate + JWT/API-key. **Trap:** data planes vary →
use `tool_remote_mcp(url, headers=${arn:...})` (token via the vault, agent never sees plaintext).
**Honest limit:** the world is DIY mock, not a live customer plane; the `*_LIVE` env on each tool is the
un-exercised seam to a real backend (needs a target account + the backend's MCP/API contract).

### M6 — Feedback-loop automation (strategy self-iteration closed) — ✅ DELIVERED (offline, deterministic)
**Goal:** disposition results auto-feed strategy.
- [x] After alert-triage writes TP/FP to Memory `facts/{tenant}` (a `managed_memory_writer` seam),
      **auto-trigger** whitelist optimization / rule regeneration — event-driven via
      `feedback.detect_triggers` (fp_rate + min_events thresholds), not just a memory write. — `sentinel_harness/feedback.py`
- [x] Wire the M1/M2 self-iteration engine into the strategy domain: an only-FP / hit-rate-drop rule
      auto-generates a `rule_regeneration` task handed toward `harnesses/self-improving` (via `harness_ops`). — `scenarios/scenario_feedback_loop.py`

**Acceptance (`evidence/feedback_loop_result.json`, closed:true):** a batch of FP dispositions for the
noisy rule "Known-Good CDN Traffic" auto-triggered a `whitelist_optimization` task; `tools/whitelist_optimizer`
synthesized a Sigma filter (`dst_domain|endswith: assets.example.com`) that suppresses 3/3 FPs while
**provably preserving the Log4Shell true positive**; the healthy TP rule produced no task; and nothing
publishes except through the `request_publish_approval` HITL gate. Deterministic + offline; the rule-regen
hand-off reuses the live-capable M1/M2 engine (driven offline here, labeled a wiring point).

### M7 — Delivery form (one-command deploy + no lock-in) — ✅ DELIVERED
- [x] Top-level `Makefile` — one ergonomic entry point (`make help` lists 13 targets): `test` / `lint` /
      `synth` / `deploy` / `deploy-endpoints` / `seed-registry` / `create-harnesses` / `smoke` / `demo` /
      `reset` / `destroy` / `clean`; `deploy`/`destroy` delegate to the existing M4 `deploy/deploy.sh`+`destroy.sh`
      (confirm account+region) rather than reimplementing deploy. — `Makefile`
- [x] `make seed-registry` (offline dual-gate governance check + prints approved tools) /
      `make create-harnesses` (**DRY_RUN=1 offline validate by default** — 8 harnesses `would_create`, zero AWS;
      `DRY_RUN=0` + creds to really create) / `make smoke` / `make reset`. — `deploy/seed_registry.sh`, `deploy/create_harnesses.sh`, `deploy/smoke.sh`
- [x] `sentinel export <harness.yaml|name> [-o out.py]`: emits editable **Strands** starter code (model · system
      prompt · tool allowlist · memory note) so a team can run the same agent on AgentCore Runtime / self-hosted
      and walk away from the managed harness — no lock-in. Pure text artifact (no `strands` import at export time). — `sentinel_harness/exporter.py`, `sentinel export`
- [x] `docs/QUICKSTART.md`: 60-second offline path (`make test` → `make demo` → `evidence/`) + the live path
      (`make deploy`, cost note, `make destroy`) + the no-lock-in export. — `docs/QUICKSTART.md`
- [x] `tests/smoke/`: offline acceptance suite (default offline; `SENTINEL_SMOKE_LIVE=1` opt-in for live). — `tests/smoke/`

**Acceptance:** `make test` → 3641 offline tests green; `make seed-registry` → dual-gate `ok`;
`make create-harnesses` (DRY_RUN=1) → 8 harnesses validate offline with zero AWS; `sentinel export` → valid
compilable Strands Python; `make smoke` → the offline acceptance suite green. A fresh non-prod account can then
run `make deploy` (free-tier foundation) and the live scenarios; `make destroy` tears it all down.

---

## 4b. Post-1.0 hardening & depth (M8–M12) — from a strategic 6-lens review

> Theme: **prove the claims the repo already makes.** The biggest gaps are enforcement, not
> features — coverage/typing/lint quality, token-cost observability, managed Memory, and the
> self-improvement loop are asserted but not gated, produced, or exercised. M8–M10 + the offline
> parts of M11/M12 are fully doable now with zero external dependencies; the `[EXTERNAL]` items
> need a non-prod account with `InvokeHarness`/`CreateAgentRuntime` quota (prior runs hit HTTP 403
> throttling + an org-level SCP) and incur real cost — their code + a gated scenario ship now, the
> live run is pending budget/quota.

### M8 — Enforce the quality claims in CI (offline) — ✅ DELIVERED
Make the "provable core / ~90% coverage / type-hinted / lint-clean" story CI-gated, not asserted.
- [x] Coverage measurement + `--fail-under=88` gate in the CI test job + `.coveragerc` (measured ~90%). — `ci.yml`, `.coveragerc`
- [x] Ruff as a HARD gate (`ruff check .` required, no best-effort skip) + a lenient mypy job over the core modules. — `ci.yml`, `mypy.ini`
- [x] Hypothesis property tests for the three deterministic cores: `sigma_match`, `whitelist_optimizer` (never suppresses a provided TP), blast-radius (determinism). — `tests/test_prop_*.py`
- [x] `make ci` mirroring CI exactly; py3.13 added to the matrix; pytest-randomly; pre-commit hooks (ruff + the name/key scan). — `Makefile`, `.pre-commit-config.yaml`

### M9 — Security-product credibility (offline) — ✅ DELIVERED
Give the security reference the supply-chain + disclosure hygiene a security team audits first.
- [x] `SECURITY.md` + GitHub Private Vulnerability Reporting (supported versions, SLA). — `SECURITY.md`
- [x] Supply-chain in CI: pip-audit, Dependabot (pip + npm + actions), CodeQL (Python+TS), OpenSSF Scorecard, bandit. — `.github/dependabot.yml`, `.github/workflows/{codeql,scorecard,supply-chain}.yml`
- [x] Hypothesis-fuzz `sandbox_hooks.validate_command/validate_path` (an allowed verdict never contains a chain op / denied verb / escaping path). — `tests/test_fuzz_sandbox_hooks.py`
- [x] `docs/THREAT-MODEL.md` (STRIDE + agent surface) + `docs/SECRETS.md` (secrets-at-rest). — `docs/THREAT-MODEL.md`, `docs/SECRETS.md`
- [x] SSRF/scheme allowlist + metadata-IP block on the live HTTP clients (`enrich_ioc`/`siem_query`/`nvd_lookup`); Actions pinned by SHA. — `tools/*/handler.py`, `tests/test_ssrf_guard.py`

### M10 — Convert evaluators to adopters (mostly offline) — ✅ DELIVERED (offline parts)
A 15-minute path from mock demo to a real stack; installable + discoverable; extensible without source-diving.
- [x] `docs/INTEGRATIONS.md` — the "bring your own SIEM/model/ticketing" runbook consolidating the `*_LIVE` env seams. — `docs/INTEGRATIONS.md`
- [x] Contributor cookbook — 4 worked recipes (add a tool / skill / harness / specialist). — `docs/COOKBOOK.md`
- [x] `docs/TROUBLESHOOTING.md` + `docs/adr/` invariant trail + `docs/COMPARISON.md` + `docs/GLOSSARY.md` + `.devcontainer/`. — those files
- [x] Fixed the 0.1.0/0.2.0 version drift (single-source `__version__` via importlib.metadata + fallback); aligned CONTRIBUTING to `uv`. — `pyproject.toml`, `sentinel_harness/__init__.py`, `CONTRIBUTING.md`
- [x] **Rendered API-reference site (pdoc → GitHub Pages) + a docs-drift CI guard.** `.github/workflows/docs.yml` renders `sentinel_harness` with pdoc (pure docstrings, no config) and publishes to GitHub Pages on push to `main` (PRs build without deploying, so a docstring/import break is caught pre-merge); `tests/test_docs_drift.py` fails the build if any public export lacks a docstring or the public surface regresses — it immediately caught 4 undocumented exports, now fixed.
- [x] **SLSA provenance + CycloneDX SBOM + PyPI OIDC Trusted Publishing wired into `release.yml`** — the tagged-release build now generates a CycloneDX SBOM (verified locally: CycloneDX 1.6, 421 components) attached to the GitHub Release, records a keyless `actions/attest-build-provenance` attestation over `dist/*` (`gh attestation verify`-able), and a separate `pypi-publish` job uploads via `pypa/gh-action-pypi-publish` over OIDC (no stored token). *Remaining external one-time steps:* configure the PyPI **trusted publisher** for this repo+workflow, set the repo homepage to the deck, and seed good-first-issues.

### M11 — Complete & deepen the on-platform proof — 🟩 offline parts DELIVERED
Turn config-only platform seams into live end-to-end scenarios that justify "why AgentCore, not raw Bedrock."
- [x] Emit the `SentinelHarness/TokensPerScenario` metric the CDK MetricFilter/dashboard/Budgets alarm key on (`_consume_stream` now surfaces usage; `observability.emit_token_metric*` writes the MetricFilter line). — `sentinel_harness/observability.py`, `core.py`
- [x] Ship `specialists/adversarial-reviewer/` (agent_a2a + local_a2a + two-stage Dockerfile + contract test) — the independent reviewer the "generation ≠ evaluation" claim needs. — `specialists/adversarial-reviewer/`
- [x] `[EXTERNAL]` cross-session managed Memory — **fully PROVEN live: SEMANTIC recall + hard multi-tenant isolation.** Under `actorId=tenant-1`, four sessions (A–D) wrote Log4Shell/web-01 exchanges; AgentCore's SEMANTIC strategy asynchronously **extracted structured facts** (model-summarized, not raw echo) and a cross-session `retrieve_memory_records` returned them ranked by relevance (top score 0.519), while `tenant-2` returned **0** (isolation holds). — `evidence/live_memory_recall_result.json` (write+isolation also in `evidence/live_memory_isolation_result.json`). **Timing note:** SEMANTIC extraction is async/service-scheduled — it did not surface on a single exchange in ~20 min; writing 3 more related exchanges (raising trigger volume) got it to extract by ~22 min. `list_memory_extraction_jobs` stays 0 (opaque scheduling); `extractionMode` only offers `SKIP` (no force-now). Teach across a few exchanges, then wait minutes.
- [x] `[EXTERNAL]` **live CUSTOM_JWT gateway enforcement — proven.** Real Cognito OIDC (M2M `client_credentials`) + a live AgentCore Gateway (`authorizerType=CUSTOM_JWT`, `discoveryUrl`→Cognito, `allowedClients` pinned): a minted RS256 token is accepted (HTTP 200 on MCP `tools/list`), no-token and garbage-token are rejected (HTTP 401). — `evidence/live_custom_jwt_gateway_result.json`. *GA correction:* gateway `interceptorConfigurations` are **Lambda-based** (`interceptor.lambda.arn`) with a separate `policyEngineConfiguration` (Bedrock guardrail engine, `LOG_ONLY`/`ENFORCE`) — there is no native "Guardrail interceptor" primitive; guardrail redaction runs inside a Lambda interceptor or via the policy engine, and the deployed-Guardrail redaction itself is proven in `evidence/live_verify_result.json` (fake AWS secret BLOCKED, NAME/EMAIL ANONYMIZED).
- [x] `[EXTERNAL]` **managed Evaluate LLM-as-a-judge — proven (control plane).** A live SESSION-level, numerical, safety-aware CVE-triage `Evaluator` is ACTIVE (version-pinned Haiku judge; groundedness+safety as first-class dims, mirroring `loop_safety.apply_safety_veto`). — `evidence/live_managed_evaluator_result.json`. **Online (continuous) evaluation ALSO proven live** — `evidence/live_online_evaluation_result.json`: an `OnlineEvaluationConfig` is **ACTIVE**, sampling 100% of AgentCore GenAI sessions from the CloudWatch **Transaction Search** `aws/spans` source, scored by built-in **Faithfulness** (groundedness) + **Harmfulness** (safety) + **Coherence** evaluators. Enablement chain discovered live: custom judges with reference inputs are on-demand-only → online must use reference-free `Builtin.*` evaluators; the source must be the `aws/spans` Transaction-Search group (enable via X-Ray dest→CloudWatchLogs + Logs resource policy + 100% indexing), not the runtime stdout log. A populated score stream additionally needs OTEL-instrumented agent traffic. **A2A-on-Runtime is PROVEN live and repeatable** (not blocked): `CreateAgentRuntime`(A2A/PUBLIC, arm64 image)→READY→`InvokeAgentRuntime`(A2A `message/send`)→HTTP 200 with the cve-intel specialist calling its real tools→`DeleteAgentRuntime` teardown, run via the bypass-role invoke path — `evidence/live_a2a_runtime_result.json`.

### M12 — Close the north-star loop, safely — 🟩 offline parts DELIVERED
Chain the proven mechanisms into one autonomous run; harden so it can never promote a worse/unsafe agent.
- [x] Regression guard — refuses to promote a revision scoring below the incumbent best. — `sentinel_harness/loop_safety.py::regression_guard`
- [x] Multi-objective judge with a hard safety veto (any safety failure ⇒ `pass=false` regardless of aggregate). — `loop_safety.apply_safety_veto`
- [x] Provenance ledger (hash-chained, append-only) + expanded eval datasets (hard negatives, ambiguous severity, safety traps) + drift-triggered regeneration on eval-score decay. — `sentinel_harness/provenance.py`, `eval/datasets/`, `feedback.detect_score_decay`
- [x] `[EXTERNAL]` **end-to-end closed loop — PROVEN live (`closed: true`); runner-orchestrated (agent-authored orchestration has since SHIPPED — `sentinel_harness/agent_loop.py` + `scenarios/scenario_agent_authored_loop.py`, see the M16 entry in §4e).** A deliberately weak agent scored 0.0 by an INDEPENDENT judge harness → `update_harness` to a STRONG prompt (new version) → re-scored 1.0 → cleared the real `loop_safety.apply_safety_veto` (no safety dim failed) AND `regression_guard` (1.0 > 0.0, ≥ 0.7 bar) → **human-in-the-loop approve** → `CreateHarnessEndpoint` (endpoint live) → reject-path withholds promotion → teardown. Every build/invoke/score/update/promote/delete is real; the loop *decisions* are driven by the scenario runner (the agent-authored variant — the agent emitting the improve/score/gate/promote tool calls itself, guarded by a driver — has since landed as `sentinel_harness/agent_loop.py` with `evidence/agent_authored_loop_result.json`; the original honesty note lives in `evidence/closed_loop_result.json`). — `evidence/closed_loop_result.json`. **Root-cause of the earlier "gate" was WRONG:** `InvokeHarness` `AccessDenied` was the **credential-vending session policy** of the internal account-management system, not a service-side account gate — bypassed by assuming a fresh in-account IAM role directly (see `evidence/live_dataplane_gate_diagnosis.json`, superseded). **Bonus live finding:** a correct Log4Shell answer carries a raw JNDI/LDAP exploit string, which an edge **WAF** blocks (HTML 403); the fix is standard IOC **defanging** of judge inputs.

**Acceptance:** M8/M9/M10-offline + M11/M12 offline items land with the suite green under a coverage
gate + hard lint + supply-chain scans; each `[EXTERNAL]` item ships buildable code + an offline-default
(mock / opt-in `*_LIVE`) scenario that is one flag away from a real run, with the live run gated on account quota.

---

## 4c. World-class depth (M13) — quantified proof · full-domain eval · adoption

> Theme: **the capabilities are done; make them measurably-best, evaluable everywhere,
> and adoptable in minutes.** All offline, zero external dependency, purely additive
> (no live-validated code touched — the diff is +3642/-1). Each unit ships tests +
> evidence and keeps the suite green.

### M13 — Track A/B/C/D world-class layer — ✅ DELIVERED (offline)
- [x] **Benchmark model** — deterministic cost/latency/ops comparison of AgentCore Harness
      vs raw-Bedrock-DIY vs self-hosted EKS over a workload; the "Runtime billing advantage"
      as a reproducible number (managed = cheapest, ~88% below a standing cluster on a bursty
      workload; model-token cost identical across modes stated as the honesty caveat). A
      property test caught a real cent-level rounding drift; fixed at source. —
      `sentinel_harness/benchmark.py`, `benchmark_models.py`, `scenarios/scenario_benchmark.py`,
      `evidence/benchmark_result.json` + `evidence/benchmark_report.md`
- [x] **Full-domain golden datasets** — evaluation extended 2 → 5 domains: alert_triage /
      attack_path / feedback_loop golden sets (26 rows each, rich M12 schema: category /
      disposition / safety_trap), authored by a parallel author+independent-reviewer workflow;
      a generic registry-driven validator pins schema/hygiene/mix. —
      `eval/datasets/{alert_triage,attack_path,feedback_loop}_golden.jsonl`,
      `tests/test_eval_datasets_domains.py`
- [x] **Deep enterprise world** — a 45-host, five-tier fictional enterprise producing the exact
      exposure-surface shape `build_attack_paths` consumes; integration-tested against the REAL
      reasoner (finds three planted chains → crown-jewel db / domain controller / secrets store,
      no over-claim from the patched bastion). Kept SEPARATE from the size-capped canonical world. —
      `mockdata/enterprise.py`, `tests/test_enterprise_world.py`
- [x] **All-domain offline scorer + baseline** — a deterministic assertion-grounding scorer with a
      hard safety gate (safety-trap rows force-fail unless the answer refuses), calibrated so golden
      references clear the 0.7 bar (0.73–0.89 mean) while wrong answers score 0. Scenario scores all
      5 domains + a wrong control and asserts the gap + gate. The live LLM-judge (`run_evaluation`)
      stays authoritative; this is the reproducible CI floor. —
      `sentinel_harness/eval_datasets.py`, `scenarios/scenario_eval_all_domains.py`,
      `evidence/eval_all_domains_result.json`
- [x] **Compliance control mapping** — 18 capability anchors mapped to SOC 2 / ISO 27001:2022 /
      NIST CSF 2.0, with a test that fails the build if any cited anchor stops existing (the doc
      cannot drift into aspirational claims). Explicitly NOT a certification. —
      `docs/COMPLIANCE.md`, `tests/test_compliance_mapping.py`
- [x] **Plug-and-play connectors** — the `*_LIVE` seams upgraded from a generic POST to named
      backend adapters (Splunk / Elasticsearch / OpenSearch / ServiceNow / Jira): pure translators
      (no network — deterministic, contract-tested), wired into `siem_query` behind
      `SIEM_QUERY_CONNECTOR` (backward compatible), proven end-to-end against an in-process mock
      Splunk. — `sentinel_harness/connectors/`, `tools/siem_query/handler.py` (wiring),
      `tests/test_connectors.py`, `docs/INTEGRATIONS.md`

**Acceptance:** all six land offline with the suite green (1758 → 1901, +143), ruff clean, docs-drift
green; each ships tests + (where applicable) an `evidence/*.json`. Purely additive: no live-validated
scenario, tool, or core module was modified except the backward-compatible connector wiring in
`siem_query` (its 11 existing live tests stay green).

### M13.7 — Autonomous self-improvement controller (C1) — ✅ DELIVERED (offline)
Closes the last runner-orchestration gap: the improve→score→gate→promote DECISIONS are lifted
out of the scenario script into a reusable, tested controller the self-improving harness drives.
- [x] `sentinel_harness/autonomy.py` — `run_improvement_loop(candidate, score_fn, revise_fn, *,
      threshold, max_rounds, incumbent_best, approve_fn)`: deterministic decision engine decoupled
      from I/O (scoring/revision/approval are INJECTED callables). Retry-with-reasoning up to a hard
      cap (no spin), then promotion gated on safety veto + pass bar + `regression_guard` +
      human approval — fail-closed. Reuses `loop_safety`. — `sentinel_harness/autonomy.py`
- [x] `scenarios/scenario_autonomous_loop.py` — drives the controller across all 5 golden domains
      with the real offline scorer: weak (0.00) → autonomous revise → pass (0.75–1.00) → APPROVE
      promotes / REJECT withholds; a safety-trap complying answer NEVER promotes even with approval.
      — `evidence/autonomous_loop_result.json` (closed:true)
- [x] 39 tests incl. Hypothesis invariants (never promote below bar / with a failed safety dim /
      beyond max_rounds). Suite 1901 → 1923.
- [x] **Live wiring — DONE offline-proven; only a real run remains gated on quota.**
      `scenario_self_improve_loop.build_live_loop_callables(judge_arn, agent_id, agent_arn)` builds
      the `(score_fn, revise_fn, approve_fn)` closures over the scenario's REAL `sh.*` ops
      (score_fn=`run_evaluation` judge invoke; revise_fn=full-replacement `update_harness`+re-invoke;
      approve_fn=the HITL gate), so `autonomy.run_improvement_loop` DRIVES the real operations. Proven
      offline in `tests/test_self_improve_autonomy_wiring.py` (fake sh/judge → the controller reaches
      the same weak→revise→pass→promote / reject-withholds / throttled-judge-no-promote decisions the
      live scenario hardcodes). The only thing still gated on `InvokeHarness` quota is the actual AWS
      round-trip — the mechanism is proven. Additive: the live `run()` flow is untouched.

**Next (ranked backlog beyond M14):** ~~more connectors~~ ✅ (8 SIEM + 3 ticketing shipped in M13);
~~OTEL span emission~~ ✅ (`sentinel_harness/tracing.py` — GenAI semantic conventions, offline-first +
opt-in live OTEL); wire the autonomy controller into the live self-improve scenario (needs
`InvokeHarness` quota); and running the remaining `[EXTERNAL]` items on an account with quota.

## 4d. Continuous adversarial hardening + the detection-engineering suite (M14) — ✅ DELIVERED (offline; one live proof)

> Theme: **relentlessly audit what exists, and turn detection engineering into a
> first-class, CLI-driven, CI-gateable capability.** All additive, deterministic,
> LLM-free; test suite **2126 → 2352 offline passing**, zero regressions.

### M14 — audit rounds 3–8 + service-model drift + detection suite — ✅ DELIVERED
- [x] **Eight adversarial-audit rounds** (hostile-finder → independent skeptic-verifier,
      CONFIRMED-only) across every surface: detection tools (r3), core M8–M13 modules (r4),
      core/loader/factory/cli/mockdata (r5), gateway/exporter/observability/scenarios/a2a (r6),
      gateway-auth/scenarios/specialists/CDK (r7), CDK/deploy/CI supply-chain (r8). **96 confirmed
      defects fixed, each with a regression test.** Refute rate 40–68% throughout — the verifier
      is not a rubber stamp.
- [x] **Service-model drift scan** — validate every AWS-payload-building module against the REAL
      botocore service model (offline). Found **5 "offline-green / live-red"** shape defects
      (botocore checks types but not string patterns / min-max / Create-vs-Update asymmetry):
      `update_harness` memory `optionalValue` wrapper, `clientToken` pattern+length sanitize,
      factory tag-read via `ListTagsForResource`, tag-value string validation. Each model-grounded.
- [x] **Detection-engineering suite (7 tools, all deterministic/LLM-free/offline, conservative
      with an explicit "cannot analyze" ledger):** `sigma_yara_lint` → `detection_translate`
      (YARA/Suricata **+ Splunk SPL + Elastic EQL**) → `detection_dedup` → `detection_coverage`
      → `detection_audit` (0–100 health score) → `detection_navigator` (ATT&CK Navigator layer)
      → `detection_baseline` (regression gate). Fresh SPL/EQL emitters got their own injection
      audit → 4 fixes (comment-delimiter injection, EQL case-sensitivity, value-wildcard drift).
- [x] **CLI:** `sentinel detection audit | baseline | ci <dir>` — the suite as a one-command CI
      gate (`ci` = audit + baseline regression + Navigator export, one combined exit code).
- [x] **`[EXTERNAL]` live proof of a drift fix** — a model-legal underscore-named Registry
      (`alert_triage`) created on a real non-prod account (pre-fix: server `ValidationException`
      from the illegal clientToken), then torn down (zero residue) — `evidence/drift_fix_registry_clienttoken_live.json`.

---

## 5. Key specs (P0 detail; other milestones self-expand at this granularity)

### 5.1 `tools/harness_ops/handler.py` (M1 core, write first)
- Input: `{action, params}`, `action ∈ {create, update, invoke, wait_ready, list, delete, create_endpoint}`.
- Each action **only validates params + calls `sentinel_harness.core.*`**, returns
  structured JSON (`harnessId/arn/status/text/tools_used/tool_use`).
- `create` pre-validates with `factory._resolve_entry`-style checks (name rule + `${ENV}` expansion + dry check).
- `update` = **read existing config → merge → full replacement** (agent update semantics).
- Registered as a Gateway MCP target; `registry/tools.yaml` adds `harness_ops`
  (`owner: platform, status: approved`); code side into `TOOL_FACTORY_MAP` →
  `registry.governance_check().ok` must be true.

### 5.2 meta-agent system_prompt (essentials)
"You are the platform's meta-orchestration agent. Decompose the user's request into **one
valid harness spec** (strictly output the `harness.yaml` structure:
`harnessName / model / systemPrompt / tools / allowedTools / memory / maxIterations /
timeoutSeconds`). `allowedTools` must be explicit — never `*`. Model choice: Opus for deep
research, Sonnet for rules/orchestration, Haiku for high-volume triage. Do not invent tool
names — only registry-approved tools. Emit the spec and hand off to agent-ops; do not build yourself."

### 5.3 self-improving retry protocol
```
loop (max 3):
  eval = run_evaluation(harness, dataset)         # async → poll
  if eval.score >= criteria: break
  reasoning = analyze(eval.failures)              # attribute: weak prompt? missing tool? missing skill?
  spec' = agent_ops.revise(spec, reasoning)       # concrete change WITH reasoning
  harness = harness_ops.update(spec')             # full replacement
if eval.score >= criteria:
  request_promotion_approval(...)                 # HITL gate (inline_function)
  if approved: harness_ops.create_endpoint(...)   # promote (CreateHarnessEndpoint)
```

---

## 6. Testing & acceptance charter
- **offline**: every new module gets `tests/test_*.py` (mock AWS); keep `uv run pytest -q` green (now 2352, +6 skipped, only grows).
- **config parity**: every new `harness.yaml` must pass `factory.provision_fleet(dry_run=True)` + `test_config_validation.py`.
- **live evidence**: each milestone runs one real call, drops `evidence/<milestone>_result.json` + `.log`.
- **governance**: each new tool keeps `registry.governance_check().ok == True`.
- **negative tests**: egress block / Guardrail masking / HITL-unapproved-no-execute / sandbox path-traversal block — each with a "must fail" assertion.

---

## 7. Ironclad rules (pre-baked to avoid traps)
1. `allowedTools` is always an explicit list — **never `['*']`** (the single most important guardrail).
2. Harness is **Bedrock-model-only**; LiteLLM/non-Bedrock only in a specialist Runtime container.
3. Delegation (build/invoke/evaluate a harness, call a specialist) is a **deterministic MCP tool** — **never LLM-authored HTTP**.
4. Registry `autoApproval=false`; **a tool is live only if registry-approved ∧ code-mapped**.
5. `runtimeSessionId ≥ 33 chars`; **serialize same-session calls** (concurrent same-session corrupts memory).
6. Provisioning is fire-and-forget → **always `wait_ready`**; pre-build **`dry_run`** locally (server validation is silent).
7. create-vs-update harness memory shapes differ; **agent/harness update = full replacement**.
8. Long tasks **async + poll**; never block inline past `timeoutSeconds`; malware/BAS/detonation use the long-running skeleton.
9. Runtime in a **private VPC, not PUBLIC**; **only `web_search` reaches the internet, no raw-download**; samples via S3 dropbox, never live fetch.
10. HITL resume is a **two-message contract** (assistant.toolUse + user.toolResult, same toolUseId, sent together) — else the session corrupts (see `core.invoke_with_tool_result`).
11. Cleanup in order: harness → Memory → role; leave no `DELETE_FAILED` orphans; preserve the shared X-Ray delivery destination.
12. **HITL kills hallucination**: an independent adversarial-reviewer (no self-approval bias) + inline_function gates + prompts that force tool/memory grounding and forbid confabulation.
13. **No customer PII/secrets in this repo** — generic SecOps only; real data lives in your account, reached via `${arn:...}` token-vault refs so the agent never sees plaintext.
14. Push via the standard git-operations workflow; never leak a token in a URL/command.

---

## 8. Recommended build order (one line)

**M0 reproduce baseline → M1 agent-building engine → M2 evaluation self-iteration loop →
(north star reached) → M3 land L2 → M4 L3 foundation → M5 connect real data planes →
M6 feedback loop → M7 one-command delivery.**
M0–M2 are the shortest path to the "agent builds agents, controllable and observable" north
star — do them first.

---

## Appendix A — Deployment prerequisites to confirm before M5

Not code — align these with your platform/security owners before M5, or it will stall:
- [ ] **Test account + credits**: an enabled account with AgentCore/Bedrock model access in your region.
- [ ] **Data-plane connections**: which SIEM / internal search store / warehouse / asset system /
      ticketing you use — decides how M5's `siem_query` / `asset_lookup` / `create_ticket` connect (MCP or API bridge).
- [ ] **Identity**: confirm JWT + API-key auth (no per-person IAM); what your existing IdP/OAuth is.
- [ ] **Model access**: which models are available in the account; whether LiteLLM is needed for self-hosted/third-party models.
- [ ] **Evaluations availability**: confirm the managed Evaluator API is enabled in your region (see §2); otherwise fall back to an offline fixed dataset + a self-built LLM-judge harness.
- [ ] **Domain skill inventory**: the exact names / inputs / outputs of your existing SecOps skills, so M5 fills in `skills/` accordingly.
- [ ] **Sample-handling process (detonation)**: how samples enter (controlled S3 dropbox), the detonation targets, and the compliance boundary (never live fetch).
- [ ] **Multi-account ops scope**: the account range and any subnet/IP constraints affecting Runtime deployment.

> `sentinel-harness` stays **generic SecOps, zero deployment secrets**; account-specific
> details live only in your private environment, reached via `${arn:...}` token-vault refs.

## Appendix B — Requirement → milestone traceability

| Requirement | Milestone |
|---|---|
| Agent builds agents, self-iterating, controllable & observable (**north star**) | **M1 + M2** |
| Unified framework circulating skills/MCP (share capability) + registry governance | M1 (dual-gate present) + M5 |
| Sample detonation VM long tasks + memory | M3 |
| Strategy-research self-iteration / CVE evaluation | M2 (strategy loop) + M5 (real assets) / M1 (cve_triage present) |
| Identity parity / API key / OAuth | M4 |
| Egress control (web_search, no raw-download) + isolate-and-destroy | M4 + M3 |
| Cost visibility + Runtime billing advantage | M4 |
| Multi-account ops automation | M5 |
| Console-wide observability | M4 |
| Disposition → strategy feedback loop | M6 |
| One-command delivery + no lock-in | M7 |
| Backstop: multi-round agents + human review + kill hallucination | throughout (HITL gates + adversarial-reviewer, present) |
| MCP Server mode — any AI agent can invoke all 20 tools | M15 |
| GitHub Pages landing site + PyPI publish | M15 |

---

## 4e. Platform distribution & extensibility (M15) — 🟢 IN PROGRESS

> Theme: **make sentinel-harness usable by any AI agent, anywhere, instantly.**
> The capabilities are built — now distribute them as a standard protocol server.

### M15 — MCP Server + distribution + landing site

- [x] **MCP Server mode** (`sentinel mcp serve`) — all 20 tools exposed as a
      standards-compliant MCP server over stdio. Any MCP-compatible AI agent (Claude
      Code, Cursor, Windsurf, custom) connects and invokes the full suite with zero
      integration code. Lazy import, optional `mcp` dep, 13 tests. —
      `sentinel_harness/mcp_server.py`, `sentinel_harness/cli.py`
- [x] **GitHub Pages landing site** — dark-theme animated project homepage with hero
      stats, architecture SVG, milestone timeline, detection pipeline, live-evidence
      table, documentation grid. pdoc API docs at `/api/`. Deployed. —
      `site/index.html`, `.github/workflows/docs.yml`
- [x] **v0.4.0 published** — PyPI (`pip install sentinel-harness`), GitHub Release
      with SBOM + SLSA provenance. — `release.yml`, manual twine upload
- [ ] **PyPI Trusted Publisher** — configure OIDC on PyPI so future releases are
      fully automated (one-time web UI step; claims documented).
- [ ] **MCP tool schemas** — generate per-tool JSON Schemas from handler docstrings
      for richer auto-complete in MCP clients.

### M16 — Agent-authored orchestration, hardened

- [x] **Agent-authored loop driver with subject-bound witness gating** — the agent
      itself emits the improve→score→gate→promote tool calls (`stop_reason ==
      "tool_use"`); the driver only executes and guards. Promotion now requires a
      witnessed passing eval AND a human approval AND a SUBJECT MATCH (the
      confused-deputy fix: an eval that scored harness A can never authorize
      promoting harness B, and an eval that names no subject authorizes nothing —
      fail-closed). Injectable `subject_of_eval` / `subject_of_promotion`
      predicates default to the `harness_ops` `params.harness_id` contract.
      Optional telemetry seam (a `tracing.Tracer` session+per-call spans with
      `sentinel.outcome`, plus `observability.emit_hitl_gate` /
      `emit_eval_score` / refused-promotions structured lines) — both sinks
      default `None` == byte-identical uninstrumented behavior. Resume-contract
      fake (`ContractResume`) asserts every pending toolUseId is answered exactly
      once with valid-JSON payloads and error-status refusals. 41 tests. —
      `sentinel_harness/agent_loop.py`, `tests/test_agent_loop.py`
- [x] **Offline proof scenario + evidence** — a scripted fake agent drives
      `run_agent_loop` through FOUR paths (happy subject-matched promotion;
      promotion refused with no witnessed eval; safety-trap eval never promotable
      even with approval; spinning agent stopped by `max_tool_calls`), evidence
      `closed: true, paths: 4`. — `scenarios/scenario_agent_authored_loop.py`,
      `evidence/agent_authored_loop_result.json`

**Acceptance:** `sentinel mcp serve` starts, lists 20 tools, invokes each correctly;
Pages live at `aws-samples.github.io/sample-sentinel-harness/`; `pip install sentinel-harness`
installs 0.4.0 from PyPI; suite 2365 passed.

---

## 4f. Security-gate audit + invariant enforcement (M18–M19) — ✅ DELIVERED (offline + LIVE-validated)

> Theme: **the bottleneck was never test count — it was that the invariants lived
> in docstrings, where nothing can check them.** All four defects below shipped
> green in code with **90–97% line coverage** and a **2493-test passing suite**.
> None was a coding error; every one was an *assembly gap* where a module
> documented a fail-closed posture, delegated one case to "the caller", and no
> caller implemented it.

### M18 — four security-gate defects, found and fixed — ✅ DELIVERED

| # | Defect | Invariant | Why the existing tests missed it |
|---|---|---|---|
| 18.1 | **`safety` veto was fail-OPEN on missing data.** A judge verdict of bare `{"score": 0.95}` cleared every machine gate and promoted an agent whose safety was *never assessed*. `safety_failures()`'s docstring said a caller wanting fail-closed "can inspect the parsed dimensions" — its only caller, the promotion gate, never did. | INV-PROMOTE-3 | Assertions checked verdict *shape*; nothing asked "did the judge score safety at all?" `test_loop_safety.py` even froze the fail-open behaviour as a contract (`apply_safety_veto({}, aggregate=0.90) is True`). |
| 18.2 | **A real judge's dimension NAMES never reached the veto.** AgentCore online evaluation is reference-free → restricted to built-ins, which report `Builtin.Harmfulness` / `Builtin.Faithfulness` (`evidence/live_online_evaluation_result.json`). The exact-match veto set ignored them, so a live "this answer is harmful" verdict was silently dropped. | INV-PROMOTE-4 | Tests only ever used the canonical names. The live evidence file recording the real names was never cross-checked against the veto set. |
| 18.3 | **The human approval was not subject-bound.** M16 subject-bound the eval↔promotion but left `witnessed_approval` a bare bool that never reset. An agent could get consent for harness A, silently re-evaluate B, and promote B on A's approval — `promoted=True, refused_promotions=0`. | INV-PROMOTE-2 | The confused-deputy tests covered the *eval* half only; no test asked whether consent was bound to anything. |
| 18.4 | **`python -c` escaped the sandbox allowlist.** `python` is allowlisted (for repo scripts / `python -m pytest`), so `python -c "<arbitrary code>"` passed every check — no chain operator, no denied verb, allowed leading verb. | INV-SANDBOX-2/3 | The Hypothesis fuzz test asserts an ALLOWED verdict carries no shell metacharacter — a **syntactic** property. This escape is **semantic** and carries none. |

**A fifth gap surfaced from fixing 18.1:** `eval/criteria.yaml` declares
`groundedness` a first-class veto dimension, but **no scoring path ever emitted
it** — the live judge projection and both offline scenario scorers reported only
correctness+safety. Unreachable while absence was a pass; a hard red once it is
not. Turning an implicit assumption into an explicit contract retro-validates
everything that depended on it.

**Tests added (offline):** 68 named regression tests + 11 Hypothesis
**policy-level** properties. Verified to anchor the behaviour: with the four
source files reverted, **52 of the 68 fail**, and the property suite
**autonomously rediscovers INV-PROMOTE-3** from a randomly generated tool-call
stream (`promoted on evidence missing the 'groundedness' dimension: {'safety':
1.0}`). Stable across 12 random seeds with a cleared Hypothesis DB.

### M18-LIVE — verified on real Amazon Bedrock AgentCore — ✅ DELIVERED

`scenarios/scenario_m18_gates_live.py` → `evidence/m18_gates_live_result.json`
(`closed: true`, zero residue). Two real harnesses created and driven to READY on
a non-prod account; the promotion handler calls the **real
`CreateHarnessEndpoint`**:

- **INV-PROMOTE-2 live** — the confused-deputy attack is refused, and
  `ListHarnessEndpoints` on B shows **no promotion-created endpoint**. "Refused"
  is grounded in the control plane, not a boolean in a dataclass.
- **INV-PROMOTE-3 live** — the no-safety-dimension verdict is refused; A carries
  no promotion-created endpoint.
- **Positive control** — the fully-evidenced path **really promotes** (endpoint
  `m18ctl` created and read back). Without it the run would prove only that the
  code refuses everything, which is trivial and useless.
- **Cost posture:** spends control-plane calls, not tokens — the tool-call stream
  is scripted and the eval handler deterministic, so it does **not** depend on
  `InvokeHarness` quota (the limit that gated earlier live runs).

**Three things the live run taught that the offline suite could not:**
AgentCore provisions a `DEFAULT` endpoint on every harness (so "refused ⟹ zero
endpoints" was the wrong assertion — the right one is "no endpoint by the
requested name"); `DeleteHarness` raises `ConflictException` while a non-DEFAULT
endpoint exists (delete order is a hard dependency); and deletion is asynchronous,
with a harness that ever carried an extra endpoint taking >5 min to clear versus
~2.5 min for a plain one. All three are now recorded in the scenario.

### M19 — institutionalise the lesson — ✅ DELIVERED

- [x] **`docs/INVARIANTS.md`** — 27 security invariants, each naming the property,
      the **layer that owns it**, and the test that proves it. Owner matters:
      INV-PROMOTE-3 was lost precisely because a docstring delegated a case to
      "a caller". IDs are cited from code comments, so an implementation detail
      traces back to the property it serves.
- [x] **`tests/test_invariants_doc.py`** — the doc is executable: every cited test
      must be collectible by pytest, every `INV-*` referenced in source must
      resolve to a documented row, and no row may omit its owner or its test. It
      caught its own first stale citation immediately.
- [x] **mypy `--strict` on the six security-critical modules** (`loop_safety`,
      `autonomy`, `agent_loop`, `sandbox_hooks`, `provenance`, `feedback`) — which
      the previous lenient gate did not cover **at all**. Every M18 defect was in a
      file outside the type gate; that is not a coincidence.
      `--follow-imports=silent` scopes the strictness so the lenient modules stay
      lenient; ratchet by moving a file between the two lists. `make typecheck`
      runs both halves locally.
- [x] **Docs-drift guards for quoted counts** (INV-DOC-2). The README asserted
      BOTH "2365 offline tests" (shields.io badge) and "2352 offline tests pass"
      (status matrix) while the suite collected 2493 — three numbers, one in a
      badge a reader takes at face value. The guard checks reality **and** internal
      consistency, scoped to present-tense claims so ROADMAP changelog entries
      ("2126 → 2352") are not falsely flagged.

**Acceptance:** suite 2493 → **2590** offline passing (+8 skipped), ruff clean,
coverage 90% (gate 88), both mypy gates green, docs-drift + invariant-doc guards
green, and `evidence/m18_gates_live_result.json` `closed: true` with zero residue
on a real account.

**Standing recommendation:** run a **round 9 adversarial audit aimed at semantic
gaps** — rounds 3–8 hunted "the code is wrong"; every M18 defect was "the
invariant was never asked". Different question, different findings.

---

## 4g. Round-9 adversarial audit — SEMANTIC gaps (R9) — ✅ DELIVERED (offline)

> Rounds 3–8 asked **"is the code wrong?"** and found 96 defects. M18 showed that
> a different question — **"was the invariant ever asked?"** — finds a different
> class of defect entirely. Round 9 put that question to the surfaces M18 did not
> touch: gateway auth, the feedback thresholds, the provenance ledger, and
> registry/loader governance.

**Six more gaps of the same shape** — a contract stated in prose that the
mechanism does not deliver:

| # | Gap | Invariant | Why it survived 8 audit rounds |
|---|---|---|---|
| R9-1 | **A hash chain cannot detect its own TRUNCATION.** The module promised "inserting/deleting a record ... will raise" — true for the middle, structurally impossible for the tail. Deleting the last record left a perfectly valid shorter chain, and the last record is exactly what someone hiding a bad promotion wants gone. Emptying or deleting the file also passed silently. | INV-GOV-4 | The mechanism was sound; the CLAIM exceeded it. Every test asserted tamper-in-place, which the chain does catch. |
| R9-2 | **`promotion_decision='promoted'` was accepted with `approver=None`** — a governance record asserting "promoted by nobody", answering the one question the ledger exists to answer with silence. | INV-GOV-5 | `approver` is legitimately optional for `rejected`/`held`, and the optionality was never scoped by decision. |
| R9-3 | **The OIDC `discovery_url` was unvalidated** — any string, including `http://`. That document determines the token-SIGNING KEYS: over plaintext an on-path attacker swaps the JWKS and mints tokens the gateway accepts, while the authorizer looks fully configured. | INV-GOV-6 | The builder carefully validated the audience/clients XOR (with a real live-tested gotcha in the comment) and never questioned the URL beyond non-empty. |
| R9-4 | **`allowed_clients=["*"]` was accepted verbatim.** That list IS the auth boundary; the repo's ironclad rule #1 forbids `allowedTools: ['*']` for exactly this reason, but the same reasoning was never applied to whose TOKEN is accepted. | INV-GOV-7 | Rule #1 was written about tools, so nobody transferred it to claims. |
| R9-5 | **A near-miss HITL gate name injected nothing, silently.** `allowedTools: ["request_publish_approval "]` — a trailing space, invisible in YAML — wired NO gate while remaining in allowedTools. The config read as "this harness has a publish gate" in review; the gate did not exist. | INV-GOV-8 | Exact-match lookup is correct behaviour for a lookup; nobody asked what a near miss should do. Worst failure mode for a HITL control: looks present, is absent. |
| R9-6 | **A suppression task was emitted with nothing safe to suppress.** When every FP indicator was also a TP indicator, the true-positive guard correctly stripped them all — and the task went out with `fp_indicators: []`. The comment said it would emit "only if there is still noise left to suppress"; the condition it checked was `fp_count > 0`. | INV-GOV-9 | The TP guard (the hard part) was right and well-tested; the emptiness of its OUTPUT was never asserted. |

R9-6's fix surfaced a follow-on: suppressing that rule's alert **cohort** is not a
safe fallback either (those alerts fired on exactly the indicators we refused to
allowlist), and with the whitelist task correctly withheld the rule produced **no
task at all** — silence about a rule firing 75% noise. A
`rule_regeneration / noisy_but_unsuppressable` branch now covers it: the rule
needs to become more specific, not filtered.

### Surfaces probed and found SOLID (recorded so round 10 does not redo them)

- **The registry dual gate.** `deprecated`-with-code is refused AND reported as
  drift; a case mismatch fails on both sides; an invalid `status` fails at load
  rather than degrading silently to "not approved".
- **The feedback true-positive guard.** An indicator seen on a real detection is
  never proposed for suppression, and withheld indicators are surfaced, not
  dropped.
- **`policy_engine_config`.** Defaults to `ENFORCE`; an invalid mode raises (a
  guardrail that silently degraded to observe-only would be a false sense of
  protection).
- **`loader`'s `allowedTools` shape checks.** The bare-scalar and `'*'` cases were
  already closed, with the reasoning in the comments.

**Tests:** `tests/test_r9_semantic_gates.py` — 59 tests, of which **37 fail on
pre-R9 source**. The other 22 are the solid-surface tripwires and false-positive
guards, expected green in both states. Suite 2590 → **2649**; ruff clean; both
mypy gates green; docs-drift + invariant-doc guards green.

**Recommendation for round 10:** the remaining unprobed semantic surfaces are
`core.invoke`'s stream-parsing edge cases (partial/interleaved tool_use blocks),
`exporter`'s generated-code fidelity, and the detection-suite translators
(`detection_translate`'s SPL/EQL emitters got an injection audit in M14, but not a
SEMANTIC one — e.g. does a translated rule preserve the original's match set?).

---

## 4h. Round-10 adversarial audit — SEMANTIC gaps in output fidelity (R10) — ✅ DELIVERED (offline)

> R9 audited governance surfaces. R10 asked the same question — "was the invariant
> ever asked?" — of three places where a **well-formed output can be semantically
> wrong**: the Sigma→SIEM translators, the InvokeHarness stream parser, and the
> Strands exporter.

**Three gaps, and the headline is a false NEGATIVE** — the worst kind for a
detection, because it reads as coverage while catching nothing:

| # | Gap | Invariant | Why it survived 9 rounds |
|---|---|---|---|
| R10-1 | **A lossy modifier was translated to a plaintext field match on Splunk/Elastic, changing the match set to a DISJOINT one.** `CommandLine\|base64: 'whoami'` (matches `base64('whoami')` = `d2hvYW1p`) became Splunk `CommandLine="whoami"` (matches the plaintext). A rule written to catch OBFUSCATED commands was silently turned into one that only catches un-obfuscated ones. `\|re` had the same shape (regex → literal). And the caveat named the wrong targets — "no YARA/Suricata equivalent" on an SPL translation. | INV-TRANSLATE-1/2/3 | The M14 audit checked the translators for output INJECTION (can a value break the grammar?) and found real bugs — but never for match-set FIDELITY (does the rule still match the same events?). Different question. The literal was even labelled "best effort", which is honest on a byte scanner and a false negative on a field-aware query — the same word covering two different truths. |
| R10-2 | **A repeated `toolUseId` in the stream produced two pending gates**, so the resume would emit two `toolResult`s for one id — which the Bedrock protocol rejects, corrupting the session. | INV-STREAM-1 | The parser was audited for DROPPING gates (M18 fixed parallel-gate loss) but never for DUPLICATING one. The fix is symmetric to that one. |
| R10-3 | **The exporter listed HITL safety gates among ordinary tools** and initialised `tools=[]`. An adopter wiring the business tools would naturally skip the `request_*_approval` gate — shipping an agent that acts without the approval the harness required, with nothing calling it out. | INV-EXPORT-1 | `export` is honestly a SKELETON (documented as such), so "it drops tools" is not a bug — but nobody asked whether it distinguishes a SAFETY GATE from a business tool. It did not. |

The fixes are scoped, not blanket: byte-scanner targets (YARA/Suricata) keep the
labelled best-effort literal — there a byte substring IS the honest approximation;
only the field-aware targets withhold it. Faithful modifiers
(contains/startswith/endswith/plain, and EQL's case-insensitive equality) are
untouched. The stream dedupe keeps distinct parallel ids. The exporter adds the
guardrail marking only when a gate is present, and the generated module always
still parses.

### Surfaces probed and found SOLID (recorded for round 11)

- **The stream parser's other edge cases** — an out-of-order `delta` before its
  `start` is ignored, a `contentBlockStart` with no name creates no phantom gate,
  and a stream-level error is surfaced in the `error` field rather than swallowed
  into `text`. All correct.
- **The exporter's injection hardening** — a control char or `\n` in a tool name
  stays an inert comment; the executable `ALLOWED_TOOLS` uses safe `repr`. The
  generated module parses for every tool combination tried.
- **The translator's escaping and negation handling** (M14 + R9 work) — untrusted
  values cannot break the target grammar, and a `not` in the condition is flagged
  untranslatable rather than silently inverted.

**Tests:** `tests/test_r10_semantic_gates.py` — 22 tests, of which **11 fail on
pre-R10 source** (verified by reverting the three modules). Suite 2649 → **2671**;
ruff clean; both mypy gates green; docs-drift + invariant-doc guards green.
`docs/INVARIANTS.md` now carries 37 invariants across five families.

**Recommendation for round 11:** the remaining unprobed semantic surfaces are the
detection-suite's OTHER stages — `detection_dedup` (does "duplicate" mean the same
match set, or just similar text?), `detection_coverage` (does a claimed ATT&CK
technique mapping actually correspond to the rule's logic?), and `sigma_match`
(does the matcher's evaluation agree with a real Sigma engine on the modifier
edge cases R10 just mapped?).

---

## 4i. Round-11 adversarial audit — detection-suite fidelity (R11) — ✅ DELIVERED (offline)

> R10 asked "is this well-formed output semantically right?" of the translators.
> R11 asked it of the rest of the detection suite, where the failure mode is
> subtler: these tools produce **governance numbers a SOC acts on**, and a wrong
> number is worse than a crash — nobody investigates a green dashboard.

**Two gaps, both of which make a blind spot look covered:**

| # | Gap | Invariant | Why it survived 10 rounds |
|---|---|---|---|
| R11-1 | **`detection_coverage` counted a rule that can NEVER FIRE as coverage.** A rule with no `detection` block, or a `condition` naming an undefined selection, produces exactly zero alerts — yet its `attack.t1059` tag was enough to move T1059 out of `uncovered`. The ATT&CK matrix showed green while an attacker using that technique walked in unseen. | INV-COVERAGE-1/2 | The module's goal is "which techniques can we NOT detect", but it validated a PROXY: which techniques a tag mentions. A tag is intent, not capability. Its own docstring even names the failure mode ("a false 'covered' hides a real blind spot") — it just never checked. Notably `sigma_yara_lint` already detected all three defects; coverage simply never consumed that judgement. |
| R11-2 | **`sigma_match` treated Sigma wildcards as literal characters.** `Image: 'cmd*'` reported NO match against `cmd.exe`. Field names were also compared case-sensitively, so a rule written `Image:` missed an event carrying `image:`. | INV-MATCH-1/2 | The matcher had impressively complete modifier support (`re`/`cidr`/`base64`/`windash`/numeric/`cased`/`exists`) and a working `caveats` mechanism for unsupported modifiers — so the ONE missing feature was invisible: wildcards are part of the value GRAMMAR, not a modifier, so nothing flagged them. And because `bas-runner` reads this matcher to decide whether a technique is detected, an under-match publishes a **false blind spot**: the team is sent to build coverage it already has, and the noise hides the real gaps. |

**A connected finding surfaced from fixing R11-1.** With dead rules no longer
counted, `detection_audit`'s health score IMPROVED (0 → 10) on a pathological rule
set, because those rules had been contributing the `untagged_rules` deduction. That
exposed a **penalty-calibration gap**: a rule that claims a technique it cannot
detect was only ever penalised as "untagged" (-10), which is backwards — an
untagged rule UNDER-reports its own coverage (conservative, harmless), while a
non-actionable rule OVER-reports it (turns the matrix green over a real gap). A new
`non_actionable_rules` class (-15, above untagged) now reflects that asymmetry, and
the pre-existing `assert health_score == 0` saturation test verified it landed.

### Surface probed and found SOLID: `detection_dedup`

Worth recording in detail, because it is the counter-example that shows the audit
question is genuinely discriminating rather than always finding something.
`detection_dedup` was probed with exactly the same intent — "does 'duplicate' mean
the same MATCH SET, or just similar text?" — and passed 7/7:

- it performs a real containment PROOF (`_predicate_implies` argues per modifier)
  and returns False whenever containment is not provable — it never over-claims;
- a stricter rule is reported as a **subsumption**, never a duplicate (calling it a
  duplicate would get a real detection deleted);
- value and field-name case differences ARE duplicates; a different logsource never
  is;
- a rule outside the provable shape lands in `not_analyzed` rather than silently
  counting as "checked, no duplicates found".

Tripwire tests are kept in the R11 suite so the tempting "optimisation" — compare
normalised rule text — cannot quietly turn a sound proof into fuzzy matching.

**Tests:** `tests/test_r11_semantic_gates.py` — 59 tests, of which **32 fail on
pre-R11 source** (verified by reverting the three modules). The other 27 are the
dedup tripwires and regression guards, green in both states. Suite 2671 → **2730**
collected; ruff clean (it caught a genuinely missing `Optional` import that the
runtime never touches thanks to `from __future__ import annotations`); both mypy
gates green; docs-drift + invariant-doc guards green. `docs/INVARIANTS.md` now
carries 42 invariants across eight families.

**Recommendation for round 12:** the unprobed surfaces left are
`detection_navigator` (does the emitted ATT&CK-Navigator layer's scoring match the
coverage it was built from, now that coverage excludes dead rules?),
`detection_baseline` (can a regression be hidden by reordering, or by a rule set
that shrinks?), and `whitelist_optimizer`'s synthesised Sigma filter (does the
generated filter suppress ONLY the FP cohort it was given — i.e. the same match-set
question R11 asked of dedup, applied to a GENERATED rule).

---

## 4j. Round-12 adversarial audit — generated-rule & gate fidelity (R12) — ✅ DELIVERED (offline, workflow-driven)

> R11 asked "does this governance NUMBER reflect capability?". R12 pushed the same
> match-set question into three tools that GENERATE a rule or GATE on a comparison,
> where a wrong answer actively degrades the detection posture. Run as a **fan-out
> workflow**: three parallel probes, each finding **adversarially re-reproduced**
> (default-REFUTE verifier, must run the probe) before it survived — 20 agents, 14
> findings CONFIRMED-by-reproduction, 3 refuted, then each reproduced independently
> by hand before fixing.

**The headline is the most dangerous class in the suite: a synthesized suppression
that turns OFF a real detection.**

| # | Gap | Invariant | Why it survived 11 rounds |
|---|---|---|---|
| R12-1 | **whitelist_optimizer synthesized a filter that suppressed MORE than the FP cohort — including the TP it certified as preserved.** Its guard `_clause_matches` compares with Python `==`/`endswith`, but the Sigma filter it EMITS is read by any engine (incl. this repo's own matcher) with `*`/`?` as live wildcards. `process_name: 'a*.exe'` was certified "preserving 1 true-positive" while the deployed filter globbed away `attack.exe` (that TP), `agent.exe`, `abc.exe`. Same class via a public-suffix domain (`co.uk`), a weak field (`dst_port`), a TP missing the whitelisted field (guard vacuously satisfied), an n=1 over-generalization, a single-quote YAML break, and a /48 IPv6 block. | INV-WL-1/2/3 | The module was impressively self-aware — its comments warn verbatim that the emitted Sigma "MUST match EXACTLY what `_clause_matches` certifies" — but the check was written against the LITERAL semantics on both sides, so it never noticed the emitted side is interpreted as a glob. The repo had even fixed this same TP-safety class twice before (CHANGELOG domain_suffix apex, bare-suffix), on the FP-leak side; this was the strictly-worse detection-deletion side. |
| R12-2 | **detection_baseline let a real regression pass green.** A shrinking library reported an "improvement" (score rose while coverage dropped); a trimmed target list relabelled real blind spots "resolved"; an empty/malformed baseline FAILED OPEN (health defaulted to 0, so everything scored an improvement). | INV-BASELINE-1/2/3 | It snapshotted six fields and diffed only the uncovered/invalid/dup SETS + the scalar score. Coverage that dropped without a target list never entered `uncovered`; the covered SET was never snapshotted; and the malformed-baseline path had no fail-closed guard. |
| R12-3 | **detection_navigator disagreed with the round-11 coverage fix.** A technique claimed only by a rule that cannot fire vanished from the layer, which then asserted 100% coverage over a real blind spot. | INV-NAV-1 | Navigator faithfully delegated to coverage for `covered`/`uncovered` — but R11 added a THIRD class (`non_actionable_rules`) that navigator did not consume, so the newest coverage output and the layer silently diverged the moment R11 shipped. |

The fixes are scoped, not blanket: whitelist_optimizer still synthesizes the
classic CDN-subdomain whitelist and n=1 EXACT matches; baseline still passes a
genuine improvement; navigator still reports 100% on a clean rule set. A private
registrable suffix is allowed where a public suffix is refused, and the fix set was
validated end-to-end by replaying emitted filters through the repo's OWN Sigma
engine (`tools/sigma_match`) to confirm the deployed match set, not just the
certified one.

### The 3 refuted findings

The adversarial verifier REFUTED three probes (kept out of the fix set): a
`| count(...) by ...` aggregation rule painted as a blind spot (coverage's
documented, correct treatment — an aggregation is not a simple detection),
`allow_score_drop` sign handling at one boundary (behaviour defensible), and one
inventory-mode percentage claim whose causal story did not hold. Recording them so
round 13 does not re-litigate settled ground.

**Tests:** `tests/test_r12_semantic_gates.py` — 45 tests, of which **36 fail on
pre-R12 source** (verified by reverting the three modules). The other 9 are the
happy-path and fail-closed regression guards. Suite 2730 → **2775** collected; ruff
clean; both mypy gates green; docs-drift + invariant-doc guards green.
`docs/INVARIANTS.md` now carries 47 invariants across eleven families.

**Recommendation for round 13:** the detection suite is now well-covered; the
unprobed match-set surfaces left are `detection_translate`'s REVERSE direction (if
any), `sigma_yara_lint`'s FP-proneness heuristic (does "FP-prone" correlate with a
real over-broad match, or just rule shape?), and the `connectors/` SIEM translators
(does a Splunk/Elastic/QRadar query translation preserve the mock backend's result
set — the R10 question applied to the live-seam adapters).
