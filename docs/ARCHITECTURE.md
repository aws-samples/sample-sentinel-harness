# Architecture

`sentinel-harness` reverse-engineers a three-layer SecOps agent platform into
Amazon Bedrock AgentCore **Harness** primitives. The guiding idea: a security team
already has models, MCP servers, and skills — what's missing is a framework to
*circulate* them. The harness is that framework: you declare an agent and AWS runs
the loop.

## Harness vs Runtime

AgentCore gives two agent-hosting primitives; we use both:

| Primitive | What it is | Used for |
|---|---|---|
| **Harness** (`create_harness`) | Managed server-side agent loop. Declare model + system prompt + tools + memory + limits. Zero orchestration code. | Every straightforward tool-calling scenario (CVE triage, alert triage, research supervisor, detection generation). |
| **Runtime** (container) | Your own container in a per-session microVM; full loop control, non-Bedrock models via LiteLLM, hours-long async jobs. | Long-running simulation/detonation jobs that exceed a harness `timeoutSeconds`; A2A specialists. |

**"Multi-agent" = multiple harnesses + a supervisor.** A single harness is
single-agent + multi-tool by design. Parallelism and role-decomposition come from
running many harnesses concurrently and synthesizing with a supervisor harness
(validated live at ~2.3–2.6× wall-clock speedup vs serial — see `evidence/`).

## Layer → primitive mapping

### Layer 1 — Strategy iteration (the core loop)

| Capability | Harness construct |
|---|---|
| Research (ATT&CK / CVE lookup / sample attribution / threat hunting) | `research-supervisor` harness + specialist harnesses, delegated in parallel |
| Detection-rule generation + cross-review + human merge | `detection-eng`: generator harness → **independent adversarial-reviewer harness** → deterministic Sigma/YARA lint → `inline_function` publish gate (human merge) |
| Alert triage (TP/FP, multi-source correlation, response, impact) | `alert-triage` harness; containment behind a human gate |
| Feedback loop | verdicts and whitelist decisions persisted to AgentCore **Memory** (`facts/{actor}`), feeding future research/detection |

### Layer 2 — Simulation

| Capability | Construct |
|---|---|
| BAS / attack-path / adversary emulation | long-running **Runtime** skeleton (async entrypoint, checkpoint, self-restart at the session cap) |
| Play Mode (human-confirmed) | an `inline_function` gate on **every** offensive step |

### Layer 3 — Foundation

| Capability | Construct |
|---|---|
| Sandbox isolation | one microVM per `runtimeSessionId` + PreToolUse security hooks (path confinement, command allowlist, read-only cloud access) |
| Platform self-iteration | Agent Factory provisioning across test → staging → prod, tag-guarded |
| AI coding | LiteLLM in specialist containers + an AgentCore **Gateway** as the single MCP ingress (semantic tool search) |
| cyber-skills | versioned S3 `SKILL.md` skills (progressive disclosure) + a central tool/skill **registry** (a tool is live only if in *both* the registry and the code map) |

## Cross-cutting design decisions

- **Human-in-the-loop kills hallucination.** Two layers: (1) an independent
  adversarial-reviewer harness attacks generated rules/verdicts (generation ≠
  evaluation — the reviewer is a *separate* harness, so it has no self-approval bias);
  (2) `inline_function` gates require analyst sign-off before publish / containment /
  offensive action.
- **Egress control.** Runtimes run in a VPC with no public network mode; NAT egress
  is allowlisted. Only a `web_search`-style tool reaches the internet and it returns
  **text only** — there is no raw-download tool. (See `tools/web_search`.)
- **Auth.** The execution role scopes internal AWS resource access (least privilege,
  not per-person mapping). Humans authenticate via OAuth/JWT (`customJWTAuthorizer`
  with `discoveryUrl`/`allowedClients`/`allowedScopes`). Third-party secrets sit in
  the AgentCore Identity token vault (`${arn:...}` header interpolation) — the agent
  never sees raw credentials. **Note:** per-user identity propagation to downstream
  tools requires the JWT inbound path, not SigV4.
- **No lock-in.** When configuration isn't enough, `agentcore export harness` emits
  editable Strands code that runs on the same compute / observability / identity.

## Borrowed patterns

The design borrows verified patterns from four AWS sample repos (see
`docs/BLUEPRINT.md` for the full mapping):

| Pattern | Source sample |
|---|---|
| supervisor → specialist delegation (registry + A2A) | `sample-pluggable-agentic-ai-framework` |
| long-running session + memory + self-restart at the session cap | `sample-long-running-app-harness` |
| zero-orchestration tool selection (config-only harness, semantic gateway) | `sample-serverless-image-editing-agent-bedrock-agentcore-harness` |
| Agent Factory / provision-at-scale + config-driven builder + skills/registry governance | `sample-agentic-chatbot-accelerator` |

## Live-validation status

See `evidence/` for captured results. Currently proven end-to-end on a
non-production account: CVE triage (deterministic compute + human gate), multi-harness
parallelism (measured speedup), and detection generation with an independent
adversarial reviewer + publish gate. Layer 2/3 constructs are designed and partially
built; contributions welcome.
