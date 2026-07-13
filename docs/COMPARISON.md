# How this compares

`sentinel-harness` is a **reference implementation you fork** — a config-as-agent SecOps
platform on [Amazon Bedrock AgentCore **Harness**](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html),
where AWS runs the agent loop server-side and the agent itself is declarative YAML
(`model · prompt · tools · skills · memory · limits`). This page is an honest,
specific comparison against three neighbours people evaluate alongside it. None of
them is a bad choice — they solve different problems at different layers. The goal
here is to make the trade-offs legible, not to disparage.

Read this next to [`docs/FIDELITY-REPORT.md`](FIDELITY-REPORT.md) (the self-audit of
what is live-validated vs. built vs. designed) and the README
[status matrix](../README.md#-status-validated--designed--missing). Where a capability
is partial, it is marked 🟡 here exactly as it is there.

## What the three neighbours are

- **(a) Raw [Strands](https://strandsagents.com/)** — an open-source agent SDK/framework. You write Python,
  define tools with `@tool`, choose a model provider, and **run the loop yourself**
  (in your own process, container, or Lambda). Excellent, unopinionated, portable.
- **(b) [LangGraph](https://langchain-ai.github.io/langgraph/)** — a graph/state-machine orchestration library for
  multi-step, multi-agent flows. You model nodes/edges and **run the graph yourself**
  (or on LangGraph Platform). Very strong for explicit branching, cycles, and
  human-in-the-loop interrupts you wire by hand.
- **(c) Hand-rolled DIY on the Bedrock API** — you call `bedrock-runtime`
  `Converse`/`InvokeModel` directly, write your own tool-dispatch loop, your own
  pause/resume, your own memory store, your own governance. Maximum control, maximum
  surface area to own.

## Dimension-by-dimension

| Dimension | sentinel-harness (config-as-agent on AgentCore Harness) | (a) Raw Strands | (b) LangGraph | (c) Hand-rolled DIY on Bedrock API |
|---|---|---|---|---|
| **Who runs the agent loop** | AWS runs it server-side in a per-session Firecracker microVM; you ship no orchestration code | You run it (your process/container) | You run the graph (self-host or LangGraph Platform) | You run it — you write the dispatch loop |
| **Human-in-the-loop (HITL)** | Built-in: an `inline_function` gate pauses the managed loop; resume via the two-message `toolUse`+`toolResult` contract; full pause→approve→resume is live-validated | You build it (interrupt + persist + resume) | First-class `interrupt()` / checkpointer interrupts — strong, but you host the checkpointer | You build all of it |
| **Governance / registry** | Built-in dual-gate: a tool is live only if in **both** `registry/tools.yaml` (SecOps allowlist) **and** the code factory map; AgentCore Registry `DRAFT`→`PENDING_APPROVAL` (`autoApproval=false`) live-verified | Not included — bring your own | Not included — bring your own | Not included — bring your own |
| **Memory** | Managed AgentCore Memory (SEMANTIC / SUMMARIZATION) keyed by `actorId` per analyst; passed at `create`/invoke | Session state is yours; add a store | Checkpointer + store (you host/select the backend) | You design the store |
| **Observability** | CloudWatch dashboard + a `TokensPerScenario` metric + Budgets stack (live-deployed) | Your own tracing/metrics | LangSmith (excellent) or your own | Your own |
| **Infrastructure-as-Code** | Dual-track: 9 CDK stacks + a `terraform validate`-clean Terraform mirror (Guardrail / Cognito JWT identity / observability / private-VPC egress live-deployed on a non-prod account) | None shipped | None shipped | None shipped |
| **Evidence / reproducibility** | 16 runnable scenarios each write an account-scrubbed JSON to `evidence/` (30 artifacts); 1742 offline, deterministic tests (zero AWS by default) | Your tests | Your tests | Your tests |
| **Lock-in** | Low by design: `sentinel export <harness.yaml>` emits editable Strands starter code (model · prompt · tool allowlist · memory) so you can walk off the managed harness | None (it *is* the portable layer) | Framework-level; portable model providers | None (you own everything) |
| **Code you own/maintain** | Least — agents are YAML; the heavy lifting is the AWS-managed loop + a tested library | Moderate — the loop is yours | Moderate–high — graph topology + hosting | Most — everything |
| **Security-ops opinionation** | High — three-layer SecOps blueprint, Play Mode, BAS detection-replay, sandbox hooks, egress control ship in the box | None (general-purpose) | None (general-purpose) | None |

Numbers above (1742 tests, 16 scenarios, 30 evidence artifacts, 14 tools, 9 skills,
8 harnesses, 9 CDK stacks) match the README and are all offline/deterministic unless a
row says **live-validated**; live claims were validated on a **non-production dev/test
account** with every account id scrubbed to `000000000000`.

## The framing: a reference implementation you fork

This is **not** a product or a framework you take a dependency on — it is a
**reference implementation you fork**. The value is the *mapping*: a common
three-layer SecOps architecture (Strategy / Simulation / Foundation) reverse-engineered
onto AgentCore primitives, with the boring-but-critical parts already wired and tested —
the HITL resume contract, the registry dual-gate, the least-privilege execution-role
policy, the Guardrail/identity/observability/egress IaC, and a demo that replays real
`evidence/*.json`. You clone it, delete what you don't need, point the four
backend-pluggable tools (`siem_query` / `asset_lookup` / `enrich_ioc` / `ops_query`) at
your own SIEM / asset / IOC / ticketing systems via their `*_LIVE` env seams, and ship.

Because agents are configuration, the neighbours are **compatible, not mutually
exclusive**: Strands is literally the export target (no lock-in), and an A2A specialist
here is a container you can build on Strands+LiteLLM and run on AgentCore Runtime.

## When *not* to use this

Be honest with yourself — pick another tool when:

- **You need arbitrary graph topology** — cyclic state machines, complex conditional
  fan-out/fan-in, or fine-grained control over every transition. LangGraph models that
  directly; a config-declared single harness (single-agent + multi-tool) plus a
  supervisor is deliberately simpler and will fight you here.
- **You can't run on AWS / Bedrock.** The managed loop *is* AgentCore Harness. If you're
  multi-cloud, on-prem, or standardised on another model provider without going through
  Bedrock, raw Strands (or DIY) travels better. (You can still `export` to Strands and
  leave.)
- **You want a turnkey, supported product.** This is a public **reference sample and
  educational scaffold** under MIT-0, not a supported SaaS. You own operating it.
- **You're not doing defensive security.** The whole thing is opinionated around SecOps —
  Play Mode gates, BAS detection-replay, detonation-as-a-simulated-no-op, sandbox hooks.
  For a general chatbot or a non-security agent, that opinionation is dead weight; reach
  for raw Strands or LangGraph.
- **You need capabilities this repo still marks 🟡 as of today.** A full end-to-end
  `cdk deploy` of the Registry/Runtime raw-`CfnResource` stacks waits on those CFN types
  going GA; the `*_LIVE` tool seams need a real backend account to exercise; sample
  detonation is a deliberate **SIMULATED no-op** (never real malware/VM/network). If your
  evaluation hinges on one of those being 🟢 today, check the
  [status matrix](../README.md#-status-validated--designed--missing) first.
- **You want to hand-tune every token of the loop.** If squeezing the prompt/dispatch
  loop is your core differentiator, DIY on the Bedrock API gives you that control — at
  the cost of owning HITL, memory, governance, and observability yourself.

## Bottom line

If your problem is *"stand up governed, human-gated, observable SecOps agents on AWS
without writing and maintaining an orchestration loop, and keep an escape hatch"* — this
is a strong starting point. If your problem is *"model an intricate custom graph"*,
*"run anywhere but AWS"*, or *"own every layer myself"* — LangGraph, raw Strands, or DIY
respectively are the more honest fit, and this repo is happy to `export` you toward them.
