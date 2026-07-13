# Glossary

One-page reference for the domain and platform terms used across this repo. Terms are
grouped: **platform primitives** (Amazon Bedrock AgentCore), **this repo's constructs**,
and **SecOps / simulation** vocabulary. Where a term maps to code, the path is given.

## Platform primitives (Amazon Bedrock AgentCore)

- **Harness** — the AgentCore primitive this repo is built on. A **managed, server-side
  agent loop**: you declare `model · system prompt · tools · skills · memory · limits`
  and AWS runs the loop. Zero orchestration code. Bedrock-model-only. Created via
  `create_harness` (`sentinel_harness/core.py`).
- **Runtime** — the *other* AgentCore agent-hosting primitive: **your own container** in a
  per-session microVM, with full loop control, non-Bedrock models via LiteLLM, and
  hours-long async jobs. Used here for A2A specialists and long-running simulation/
  detonation tiers. Created via `CreateAgentRuntime`.
- **Two-plane API** — AgentCore splits into two APIs: **`bedrock-agentcore-control`** for
  lifecycle (create/update/get/delete a harness, endpoints, gateways, registry) and
  **`bedrock-agentcore`** for invocation (`InvokeHarness`, streaming eventstream). "Control
  plane" = manage; "data plane" = invoke/stream.
- **inline_function HITL gate** — an inline function tool that **pauses the managed loop**
  for human sign-off before a high-stakes action (publish a rule, contain a host, execute
  an offensive step). The loop stops with `stop_reason=tool_use`; a human approves; the
  caller resumes with the two-message `toolUse` + `toolResult` contract (matching
  `toolUseId`). See `core.invoke_with_tool_result` and `scenario_hitl_resume.py`.
- **Gateway / MCP target** — an **AgentCore Gateway** is the single MCP ingress that exposes
  tools to a harness. A **target** is one backend behind it — a Lambda MCP target, an
  OpenAPI/HTTP target, or an MCP-server target. Delegation and tool calls are deterministic
  MCP tool calls, not model-authored HTTP. See `sentinel_harness/gateway.py`.
- **Managed Memory + actorId** — AgentCore **Memory** (strategies: `SEMANTIC`,
  `SUMMARIZATION`) persisted across sessions, keyed by **`actorId`** so each analyst gets
  their own memory namespace (`facts/{actor}`). Passed at `create`; `actorId` supplied at
  invoke time. See `core.managed_memory` / `core.byo_memory`.
- **allowedTools** — the explicit allowlist scoping *which* tools the LLM may choose in a
  given harness (server-scoped grammar `@gateway/tool`; inline gates use plain names). It
  narrows the model's tool choice but **cannot** gate `InvokeAgentRuntimeCommand` — the
  only control there is withholding the IAM action. Never `['*']`.
- **A2A** (Agent-to-Agent) — the JSON-RPC protocol (`message/send`) by which a supervisor
  harness invokes a **specialist** running on AgentCore Runtime. Live-validated
  end-to-end here (HTTP 200 → real Bedrock model) — `evidence/live_a2a_runtime_result.json`.
- **Guardrail** — a Bedrock Guardrail that masks secrets/PII in tool responses; a
  `GUARDRAIL_INTERVENED` result means it fired (live-deployed here — masked a fake AWS key +
  token). See `iac-cdk/lib/guardrail-stack.ts`.
- **session id (`runtimeSessionId`)** — must be **≥ 33 chars** or the invoke silently
  misbehaves; a hyphenated UUID (36) is safe (`core.py`).

## This repo's constructs

- **harness** (lowercase, this repo) — a declarative agent under `harnesses/<name>/`:
  a `system_prompt.md` + a `harness.yaml`. `sentinel create harnesses/<name>/harness.yaml`
  (or `loader.load_harness_config`) turns it into a live AgentCore Harness. 8 ship.
- **Registry dual-gate (DRAFT → PENDING_APPROVAL)** — a tool/skill is **live only if it
  appears in both** the SecOps allowlist (`registry/tools.yaml`, with `owner`/`status`) **and**
  the engineering code factory map (`name → callable`). Neither gate alone makes it live —
  deliberate separation of duties. On-account, this is realised as AgentCore Registry records
  moving `DRAFT` → `PENDING_APPROVAL` with `autoApproval=false` (a human must approve before a
  record is live). See `sentinel_harness/registry.py`, `registry_live.py`,
  [`docs/GOVERNANCE.md`](GOVERNANCE.md).
- **specialist** — a narrow, single-purpose agent (e.g. `cve-intel`, `attack-mapper`,
  `threat-hunt`) packaged as an A2A Runtime **container** (multi-stage Dockerfile, pinned
  deps, non-root) that a supervisor delegates to over A2A. 4 specialist dirs under
  `specialists/` (`cve-intel` is live-validated on Runtime; siblings share the pattern).
- **Agent Factory** — config-driven fleet provisioning: create/validate a fleet of harnesses
  with dry-run, idempotency, and a **cross-env tag-guard** (prevents a test agent updating a
  prod one). Also the *north-star* loop — an **agent that builds agents**: a meta-agent
  normalizes a natural-language spec → authors → validates → creates → invokes a genuinely new
  harness. See `sentinel_harness/factory.py`, `harnesses/meta-agent/`.
- **BAS** (Breach-and-Attack Simulation) — **detection-replay**: a deterministic **Sigma
  matcher** replays attack techniques against your detection rules to surface **blind spots**
  and a coverage number (offline; 4 techniques × 2 rules → 2 blind spots, coverage 0.5). See
  `tools/sigma_match/`, `longrunning/bas-runner/`, `scenario_bas_replay.py`.
- **detonation** — the sample-detonation long-running tier: a full
  `QUEUED → … → DESTROYED` microVM lifecycle state machine + `detonate_sample` orchestrator.
  It is an **honest SIMULATED no-op** — no real malware, VM, network, or sample bytes are ever
  read/executed; the sample-by-reference invariant, sandbox refusal, HITL gate, and
  always-destroy-after-use are real. See `longrunning/detonation/`.
- **Play Mode** — L2 adversary-emulation mode where **every** offensive step is human-gated
  by an `inline_function` before execution, with checkpoint/resume; a reject halts the run and
  nothing real is ever touched (simulated no-ops). See `sentinel_harness/simulation.py`,
  `scenario_play_mode.py`.

## SecOps / operational vocabulary

- **HITL** (human-in-the-loop) — a mandatory human approval gate before a high-stakes action;
  here always realised as an `inline_function` pause. The core anti-hallucination control.
- **Layers L1 / L2 / L3 / L4** — the SecOps architecture this repo maps onto AgentCore:
  **L1 Strategy** (triage, detection-gen, multi-harness supervisor, HITL),
  **L2 Simulation** (Play Mode, BAS detection-replay, detonation),
  **L3 Foundation** (registry, Agent Factory, identity, Guardrail, egress),
  **L4 Observability** (CloudWatch dashboard + Budgets).
- **supervisor** — a harness that fans work out to multiple harnesses/specialists and
  synthesizes the results; how "multi-agent" is done here (multiple harnesses + a supervisor,
  not one mega-agent). Measured ≈2.6× wall-clock speedup vs. serial.
- **egress control** — the private-VPC default-deny topology: no IGW, no NAT, no `0.0.0.0/0`
  route, PrivateLink-only (endpoints cost-gated off). See `iac-cdk/lib/network-stack.ts`,
  `scenario_egress_control.py`.
- **evidence** — the account-scrubbed JSON each scenario drops into `evidence/` (30 artifacts):
  the reproducible proof behind every claim. Account ids scrubbed to `000000000000`.
- **CVE / EPSS / KEV / ATT&CK / Sigma / YARA / IOC** — standard defensive references:
  CVE = a catalogued vulnerability; EPSS = exploit-prediction score; KEV = CISA
  Known-Exploited-Vulnerabilities catalog; ATT&CK = MITRE technique taxonomy; Sigma = generic
  detection-rule format; YARA = malware-pattern rules; IOC = indicator of compromise.
