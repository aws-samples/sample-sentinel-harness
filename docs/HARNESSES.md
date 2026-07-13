# Harnesses

`sentinel-harness` builds production SecOps agents as **configuration, not
orchestration code**. Each harness is a declarative bundle — model + system prompt +
tools + allowed-tools + memory + limits — created via
`sentinel_harness.core.create_harness()`. This document explains the Layer 1
(Strategy Iteration) supervisor harnesses that ship under `harnesses/`.

Every harness lives in its own directory:

```
harnesses/<name>/
├── system_prompt.md   # the agent's operating instructions
└── harness.yaml       # declarative config, consumed by the loader (see below)
```

> **Status — live, loader-consumed.** These `harness.yaml` files are parsed by
> `sentinel_harness.loader.load_harness_config` and created via the CLI:
>
> ```bash
> sentinel create harnesses/alert-triage/harness.yaml
> ```
>
> The loader reads `systemPrompt` (a path relative to the harness dir) and wraps it
> as the `[{text: ...}]` shape, expands `${ENV_VAR}` references from the environment
> (12-factor; `${arn:...}` token-vault refs are left for AgentCore Identity to
> resolve server-side), injects the inline-function HITL gates named in
> `allowedTools` (their input schema lives in code), and passes
> `model` / `tools` / `memory` / `allowedTools` / `maxIterations` / `timeoutSeconds`
> through to `create_harness()`. A missing `${ENV_VAR}` fails loudly, naming the
> variable. For runnable end-to-end flows (invoke + HITL resume), see `scenarios/`.
> The Gateway tools these supervisors reference (`search_registry`, `siem_query`,
> `enrich_ioc`, …) have reference-stub handlers under `tools/`; point
> `SENTINEL_GATEWAY_ARN` at a Gateway that hosts them to run against live data.

All content is generic security-operations material. There are no organization-,
customer-, or company-specific references, no hardcoded AWS account IDs, and no role
ARNs. Identity and placement come entirely from environment variables (12-factor):

| Env var | Purpose |
|---|---|
| `SENTINEL_EXECUTION_ROLE_ARN` | IAM execution role the harness assumes (least-privilege). |
| `SENTINEL_REGION` | AWS region (default `us-east-1`). |
| `AWS_PROFILE` | Local credentials profile — always a non-production profile. |
| `SENTINEL_GATEWAY_ARN` | AgentCore Gateway ARN backing the MCP tool surface. |
| `SENTINEL_MODEL_OPUS` / `SENTINEL_MODEL_SONNET` / `SENTINEL_MODEL_HAIKU` | Model-id overrides (see below). |

## Model configuration is overridable

Each `harness.yaml` pins a `bedrockModelConfig.modelId` that mirrors the default
resolved by `core.py` from the matching `SENTINEL_MODEL_*` environment variable. The
ids use the **cross-region-inference pattern**; they are defaults, not hard pins.
Override them by exporting the env var (to pin a specific model version fleet-wide)
or by passing a per-invocation `model=` override to `core.invoke()` (e.g. escalating
an ambiguous alert from Haiku to Sonnet for a single call).

## Shared design rules

- **`allowedTools` is always an explicit list — never `['*']`.** The agent can call
  only the tools named in `allowedTools`; everything else on the Gateway is invisible
  to it. This is the single most important reliability/safety guardrail.
- **Tools are declared, capabilities are gated.** Data lookups and specialist
  delegation live behind an **AgentCore Gateway** (policy-backed MCP surface).
  Deterministic compute (math, lint) uses the sandboxed **code interpreter** so the
  model never guesses numbers.
- **Human-in-the-loop where stakes are high.** High-consequence actions (publishing a
  detection rule, containing a host) go through an `inline_function` gate that pauses
  the loop (`stop_reason=tool_use`) and returns the call to your code. Gates are
  declared with `core.tool_inline(...)` (their input schema lives in code) and passed
  to `create_harness(tools=[...])`. The **full contract is closed**: `core.invoke()`
  reconstructs the paused call as `result["tool_use"]` (toolUseId + accumulated input),
  and `core.invoke_with_tool_result(...)` resumes the same session with the two-message
  `toolUse`→`toolResult` turn. See `scenarios/scenario_hitl_resume.py` for a live
  pause→approve→resume round trip (evidence in `evidence/hitl_resume_result.json`).
- **Managed memory with SEMANTIC + SUMMARIZATION.** Every harness declares
  `managedMemoryConfiguration` with both strategies. `actorId` namespaces isolate
  memory per analyst / per tenant, and verdicts persist as a team feedback loop.

---

## research-supervisor (`sentinel_research_supervisor`)

**Purpose.** Deep-reasoning threat-research supervisor. Decomposes a research
question (about a CVE, campaign, adversary technique, etc.), delegates independent
sub-questions to specialist agents and public-data tools **in parallel**, then
synthesizes a grounded, structured `ResearchDossier`.

| Field | Value | Why |
|---|---|---|
| Model | Opus (`SENTINEL_MODEL_OPUS`), `maxTokens: 8192`, `temperature: 0.2` | Deep synthesis across many sources. |
| Tools | `agentcore_gateway` | Discovery, delegation, and public-data lookups behind one policy-backed surface. |
| `allowedTools` | `search_registry`, `invoke_specialist`, `nvd_lookup`, `epss_kev`, `attack_lookup`, `web_search` | Discover specialists, delegate to them, and pull CVE / EPSS-KEV / ATT&CK / web facts. |
| Memory | SEMANTIC + SUMMARIZATION, 90-day expiry | Recall prior findings; roll up long research sessions. |
| `maxIterations` | 20 | Fan-out plus synthesis needs headroom. |
| `timeoutSeconds` | 300 | Stays under the sync ceiling; genuinely long jobs run async. |

**Anti-hallucination.** The system prompt forbids confabulating CVE IDs, scores,
KEV status, or ATT&CK technique IDs — every claim must trace to a tool result or
retrieved memory, and `unknowns` are stated plainly. The supervisor produces
research, never decisions or actions.

---

## detection-eng (`sentinel_detection_eng`)

**Purpose.** Detection-engineering supervisor driving the full
`generate → adversarial review → lint → human merge` flow: writes a Sigma rule, has
an **independent** reviewer specialist attack it, lints it deterministically, then
gates on a human before publish.

| Field | Value | Why |
|---|---|---|
| Model | Sonnet (`SENTINEL_MODEL_SONNET`), `maxTokens: 8192`, `temperature: 0.1` | Strong rule authoring; low temperature keeps rules deterministic. |
| Tools | `agentcore_code_interpreter`, `agentcore_gateway` | Deterministic lint math; delegation to the reviewer + hosted linter. |
| `allowedTools` | `code_interpreter`, `invoke_specialist`, `sigma_yara_lint`, `request_publish_approval` | Lint locally, delegate the adversarial review, run the hosted linter, gate publish on a human. |
| Memory | SEMANTIC + SUMMARIZATION, 90-day expiry | Recall prior rules / FP decisions; summarize the review loop. |
| `maxIterations` | 18 | Generate + up to 2 review/revise rounds + lint + gate. |
| `timeoutSeconds` | 300 | Sync ceiling headroom. |

**Generation ≠ evaluation.** The harness never approves its own rule: the
adversarial-reviewer specialist (reached via `invoke_specialist`) independently
enumerates false-positive sources, logic gaps, and evasion bypasses and returns an
`approve` / `revise` verdict. `request_publish_approval` is a human-in-the-loop
`inline_function` gate — nothing is published without analyst sign-off, and the
analyst may hand-merge edits.

---

## alert-triage (`sentinel_alert_triage`)

**Purpose.** High-volume per-alert triage. Reaches a TP/FP verdict, corroborates
across SIEM / asset / IOC sources, assesses blast radius, and recommends a response.
Containment is human-gated; verdicts feed back into detection.

| Field | Value | Why |
|---|---|---|
| Model | Haiku (`SENTINEL_MODEL_HAIKU`), `maxTokens: 4096`, `temperature: 0.1` | Cheap + fast for volume; escalate ambiguous alerts to Sonnet via a per-invocation `model=` override. |
| Tools | `agentcore_code_interpreter`, `agentcore_gateway` | Deterministic event math; enrichment + ticketing + containment surface. |
| `allowedTools` | `code_interpreter`, `siem_query`, `asset_lookup`, `enrich_ioc`, `create_ticket`, `request_containment_approval` | Corroborate, count, open tickets, and *request* (never execute) containment. |
| Memory | SEMANTIC + SUMMARIZATION, 90-day expiry | Recall prior TP/FP verdicts; FP whitelist rationale tunes future detections. |
| `maxIterations` | 12 | Enrichment + verdict + optional containment gate; kept tight. |
| `timeoutSeconds` | 180 | High-volume path — short ceiling. |

**Containment is never autonomous.** The raw contain action is intentionally not
exposed. The agent can only call `request_containment_approval` — an
`inline_function` gate that pauses for analyst sign-off before any host isolation,
account disable, or indicator block. TP/FP decisions are written to memory as the
feedback loop into detection engineering.

---

## Relationship to the runnable scenarios

The harnesses above are the reusable, declarative Layer 1 building blocks. The
scripts under `scenarios/` exercise the same patterns end-to-end and are the live
proof points:

- `scenario_cve_triage.py` — single-harness CVE triage with a deterministic-compute
  step and a mandatory human-review gate.
- `scenario_multi_harness.py` — multi-harness parallelism: specialist harnesses run
  concurrently and a supervisor synthesizes (the `research-supervisor` pattern).
- `scenario_detection_gen.py` — generator + independent adversarial-reviewer harness
  + human publish gate (the `detection-eng` pattern).
