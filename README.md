<div align="center">

<img src="assets/logo.svg" width="140" alt="sentinel-harness logo"/>

# sentinel-harness

**Production security-operations agents, built as _configuration_ — on Amazon Bedrock AgentCore Harness.**

<sub>Declare an agent (model · prompt · tools · skills · memory · limits); AWS runs the loop. Zero orchestration code.</sub>

<p>
  <img alt="license" src="https://img.shields.io/badge/license-MIT--0-30d158"/>
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-2997ff"/>
  <img alt="bedrock-agentcore" src="https://img.shields.io/badge/Amazon%20Bedrock-AgentCore%20Harness-ff9900"/>
  <img alt="tests" src="https://img.shields.io/badge/offline%20tests-591%20passing-1D8102"/>
  <img alt="status" src="https://img.shields.io/badge/live--validated-CVE%20%C2%B7%20multi--harness%20%C2%B7%20HITL%20%C2%B7%20Play%20Mode-8b5cf6"/>
</p>

[Quickstart](#-quickstart) · [Architecture](#-architecture) · [Scenarios](#-scenarios--evidence) · [Status matrix](#-status-validated--designed--missing) · [Design principles](#-design-principles) · [Extending](#-extending) · [Roadmap](#-roadmap) · [Docs](docs/)

</div>

---

## Why

A security team usually already has models, internal MCP servers, and a pile of skills — what's missing is a **framework to circulate them** so that "what one analyst has, everyone has." `sentinel-harness` is a reference implementation of that framework on the [Amazon Bedrock AgentCore **Harness**](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html). You declare an agent as configuration and AWS runs the whole agent loop — so swapping a model, adding a tool, or replacing a skill is **a config change, not a rebuild**.

Everything here is **generic SecOps content** built and tested against a **non-production** account — no proprietary data, no real vulnerable assets, no real malware. It reverse-engineers a common three-layer SecOps agent architecture into AgentCore primitives, borrowing verified patterns from four AWS samples.

> **What's real vs. aspirational — read this first.** Layer 1 ships **live-validated scenarios** (including a real Gateway create→READY→delete on the GA API) and a library-grade core. Layer 2 Play Mode is live-validated, and BAS detection-replay is real (a deterministic Sigma matcher finds detection blind spots offline); sample detonation stays an import-safe SIMULATED skeleton (no real malware/VM/network). Layer 3 ships a built+tested tool/skill registry, sandbox hooks, and Agent Factory, plus a synth-validated CDK stack and an import-safe A2A specialist skeleton (container deps/Docker not built). The [status matrix](#-status-validated--designed--missing) is precise about what's proven, built, designed, or skeleton — 🟡 rows are honest about their limits. This honesty is deliberate — see the self-audit in [`docs/FIDELITY-REPORT.md`](docs/FIDELITY-REPORT.md).

## 🏛 Architecture

<div align="center"><img src="assets/architecture.png" width="960" alt="sentinel-harness architecture"/></div>

Callers authenticate via OAuth/JWT (humans) or SigV4 (services); third-party secrets sit in the AgentCore Identity token vault (the agent never sees raw credentials). A **two-plane API** (control + streaming data) drives a **managed harness** running in a per-session Firecracker microVM — the agent loop, config fields, primitives (Memory / Gateway / Browser / Code Interpreter), an `inline_function` human-in-the-loop gate, egress control, and the multi-harness + supervisor pattern. On the right, the three SecOps layers. Full write-up: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); layer→primitive mapping and borrowed patterns: [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md).

## 📊 Status: validated / designed / missing

Honest build status per capability — mirrors the self-audit.

| Layer | Capability | Status | Where |
|---|---|:--:|---|
| **L1 Strategy** | CVE triage (deterministic calc + HITL pause + memory) | 🟢 **live-validated** | `scenarios/scenario_cve_triage.py` |
| **L1 Strategy** | Multi-harness parallel + supervisor (≈2.6× speedup) | 🟢 **live-validated** | `scenarios/scenario_multi_harness.py` |
| **L1 Strategy** | Detection-gen + independent adversarial reviewer + publish gate | 🟢 **live-validated** (independent reviewer reached `revise`; flawed rule withheld; no stray shell) | `scenarios/scenario_detection_gen.py` |
| **L1 Strategy** | **Human-in-the-loop full pause→approve→resume** | 🟢 **live-validated** | `scenarios/scenario_hitl_resume.py`, `core.invoke_with_tool_result` |
| **L1 Strategy** | Alert triage (TP/FP, correlate, contain) | 🟠 **designed** (loadable harness.yaml) | `harnesses/alert-triage/` |
| **L1 Strategy** | Gateway wiring + end-to-end named-supervisor scenario | 🟢 **live-validated** (real Gateway create→READY→delete on GA API; named-supervisor loads from `harness.yaml`) | `sentinel_harness/gateway.py`, `scenarios/scenario_named_supervisor.py` |
| **L1 Strategy** | Research supervisor → specialist delegation via registry/A2A | 🟠 **designed** (loadable harness.yaml; A2A specialist skeleton) | `harnesses/research-supervisor/`, `specialists/cve-intel/` |
| **L1 Strategy** | Feedback loop closure (teach → recall) | 🟠 **designed** (memory writes proven; recall async) | `docs/BLUEPRINT.md` |
| **L2 Simulation** | Adversary emulation, Play Mode (every step human-gated) + checkpoint/resume | 🟢 **live-validated** | `scenarios/scenario_play_mode.py`, `sentinel_harness/simulation.py` |
| **L2 Simulation** | BAS detection-replay + blind-spot report (real Sigma matcher) | 🟢 **live-validated** (offline, deterministic; 4 techniques × 2 rules → 2 blind spots, coverage 0.5) | `tools/sigma_match/`, `longrunning/bas-runner/bas_cases.py`, `scenarios/scenario_bas_replay.py` |
| **L2 Simulation** | Attack-path reasoning + threat-hunt planning | 🟢 **built + tested** (real `build_attack_paths` / `build_hunt_plan`; A2A serving = skeleton) | `specialists/attack-mapper/`, `specialists/threat-hunt/`, `tools/asset_lookup/` |
| **L2 Simulation** | Sample detonation (one-shot microVM, long-running tier) | 🟡 **skeleton** (import-safe, SIMULATED no-ops; destroy-after-use + sandbox-gated + HITL) | `longrunning/detonation/`, `longrunning/bas-runner/` |
| **L3 Foundation** | Tool/skill registry (dual-gate governance) + PreToolUse sandbox hook | 🟢 **built + tested** | `sentinel_harness/registry.py`, `sentinel_harness/sandbox_hooks.py` |
| **L3 Foundation** | Agent Factory (fleet provision, dry-run, cross-env tag-guard) | 🟢 **built + tested** | `sentinel_harness/factory.py` |
| **L3 Foundation** | LiteLLM A2A specialist Runtime (container skeleton) | 🟡 **skeleton** (import-safe, agent-card tested; deps/Docker not built) | `specialists/cve-intel/` |
| **L3 Foundation** | Gateway/Registry/Memory CDK stack | 🟡 **synth-validated** (Gateway/Memory CFN types registered; Registry type not yet in CFN) | `iac-cdk/` |
| **Config** | YAML→harness loader (`sentinel create <harness.yaml>`) | 🟢 **built + tested** | `sentinel_harness/loader.py` |
| **Core** | Harness lifecycle library + builders (create/invoke/HITL-resume/tools/memory) | 🟢 **library-grade, tested** | `sentinel_harness/core.py` |
| **Tools** | `sigma_yara_lint` (real, deterministic, LLM-free) | 🟢 **functional + unit-tested** | `tools/sigma_yara_lint/`, `tests/test_sigma_yara_lint.py` |
| **Tools** | `nvd_lookup` / `epss_kev` / `attack_lookup` / `web_search` | 🟡 **reference stubs** (offline-safe, contract-tested) | `tools/`, `tests/test_tool_handlers.py` |

🟢 built & validated · 🟡 built, partial · 🟠 designed with loadable config · ⚪ design narrative only. **591 offline tests pass** (+3 skipped when optional A2A deps absent).

## 🚀 Quickstart

```bash
git clone https://github.com/neosun100/sentinel-harness && cd sentinel-harness
pip install -e .          # Python 3.10+ ; installs the `sentinel` CLI

# offline tests need no AWS
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test pytest tests/ -q   # 591 passing

# configure for live runs (12-factor — nothing hardcoded)
export AWS_PROFILE=<your-non-prod-profile>          # never production
export SENTINEL_REGION=us-east-1
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<your-harness-role>"

# run a live-validated scenario (creates harnesses, invokes, writes evidence/)
python scenarios/scenario_cve_triage.py
python scenarios/scenario_multi_harness.py
sentinel cleanup sentinel_        # tear down every harness this repo created
```

Execution-role policy (least-privilege, and **why** it omits `InvokeAgentRuntimeCommand`): [`docs/SETUP.md`](docs/SETUP.md).

## 🔬 Scenarios & evidence

Each scenario is runnable end-to-end and writes a result JSON to [`evidence/`](evidence/) (account IDs scrubbed). Captured live-run outcomes:

| Scenario | What it proves | Result |
|---|---|---|
| **CVE triage** | one harness = deterministic compute (code interpreter) + a mandatory HITL pause + managed memory, zero orchestration code | HITL gate fired; CVSS math ran in-sandbox |
| **Multi-harness parallel** | "a harness is single-agent" → parallelism via multiple harnesses + a supervisor | **≈2.6×** wall-clock speedup vs serial |
| **Detection-gen** | generation ≠ evaluation: an **independent** reviewer harness + publish control | reviewer reached `revise` with concrete FP/logic objections; flawed rule **withheld from publish**; no stray `shell` (allowedTools-scoped) |
| **HITL resume** | full pause→approve→resume via the two-message `toolUse`+`toolResult` contract | `closed_hitl_loop: true` — analyst approval flows back, agent finishes |
| **Play Mode (L2)** | adversary emulation, every offensive step human-gated + checkpoint/resume | every step gated; reject halts; simulated no-ops (nothing real touched) |

## 🧭 Design principles

- **Multi-agent = multiple harnesses + a supervisor.** One harness is single-agent + multi-tool; parallelism and role-decomposition come from running many and synthesizing.
- **Human-in-the-loop kills hallucination.** High-stakes actions pass through an `inline_function` gate; an independent reviewer harness attacks generated artifacts (no self-approval bias).
- **Egress is controlled.** Prefer a `web_search`-style tool (text only) over raw download; there is no raw-download tool.
- **Auth done right.** An IAM *execution role* scopes internal AWS access (least privilege — not per-person mapping). Humans use OAuth/JWT; secrets live in the token vault. `allowedTools` scopes the LLM's tool choice but **cannot** gate `InvokeAgentRuntimeCommand` — the only control there is withholding the IAM action.
- **No lock-in.** When config isn't enough, `agentcore export harness` emits editable Strands code on the same compute / observability / identity.

## 🧩 Extending

- **New scenario** → add `scenarios/scenario_<name>.py` using `sentinel_harness.core` (see existing three for the pattern); write evidence to `evidence/`; leave teardown to `sentinel cleanup`.
- **New tool** → drop a handler under `tools/<name>/` (keep deterministic tools LLM-free, like `sigma_yara_lint`) and wire it into an AgentCore Gateway as an MCP target.
- **New skill** → add `skills/<name>/SKILL.md` (AgentSkills.io format: YAML frontmatter + body); attach via `create_harness(skills=[...])`.
- **New harness** → follow `harnesses/<name>/` (a `system_prompt.md` + an illustrative `harness.yaml`); until the YAML loader lands (roadmap), construct via `core.create_harness(...)` in a scenario.

Borrowed patterns (see [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md)): supervisor→specialist delegation (pluggable-agentic-ai-framework), long-running session + self-restart (long-running-app-harness), zero-orchestration tool selection (serverless-image-editing-harness), Agent Factory provisioning (agentic-chatbot-accelerator).

## 🗺 Roadmap

- [x] **YAML→harness loader** so `harnesses/*.yaml` are live (`sentinel create <harness.yaml>`; env interpolation, `system_prompt.md` resolution, gateway/allowedTools mapping). — `loader.py`
- [x] **Close the HITL loop** — `invoke_with_tool_result()` two-message resume + a full live pause→approve→resume trace. — `scenario_hitl_resume.py`
- [x] **Layer 2** — Play Mode adversary emulation: every offensive step human-gated + checkpoint/resume, live-validated. — `simulation.py` / `scenario_play_mode.py`
- [x] **Layer 3** — tool/skill registry (dual-gate governance) + a PreToolUse sandbox hook, with tests. — `registry.py` / `sandbox_hooks.py`
- [x] **Gateway wiring + named-supervisor scenario** — `gateway.py` (create/target/teardown helpers, live-validated create→READY→delete on the GA API) + `scenario_named_supervisor.py` (loads `research-supervisor` from `harness.yaml`, wires it to a Gateway). — `gateway.py`
- [x] **Agent Factory** — config-driven fleet provisioning with dry-run validation, idempotency, and a cross-env tag-guard. — `factory.py`
- [x] **Gateway/Registry/Memory CDK stack** — synth-validated TypeScript CDK (Gateway/Memory CFN types are registered; the Registry CFN type is not yet GA, so that stack is synth-only for now). — `iac-cdk/`
- [x] **LiteLLM A2A specialist** — import-safe Strands+A2A+LiteLLM Runtime container skeleton with a tested agent-card (deps/Docker not built here). — `specialists/cve-intel/`
- [x] **BAS long-running tier** — async-gen entrypoint, HITL-gated offensive steps (reusing Play Mode), checkpoint + self-restart skeleton, tested. — `longrunning/bas-runner/`
- [ ] Deploy the CDK stack end-to-end once the Registry CFN type is GA; build & push the specialist container; run a live 3-specialist parallel A2A scan.

## 📁 Repo layout

```
sentinel-harness/
├── sentinel_harness/     core · loader · gateway · factory · registry · CLI  🟢 tested
├── scenarios/            runnable, live-validated scenarios     🟢
├── evidence/             captured live-run results (scrubbed)   🟢
├── tools/                MCP tool templates (sigma-lint real)   🟡 reference
├── skills/               Agent Skills (SKILL.md)                🟡 reference
├── harnesses/            declarative configs (loader-consumed)  🟢
├── specialists/          A2A LiteLLM specialist container       🟡 skeleton
├── longrunning/          BAS long-running Runtime tier          🟡 skeleton
├── iac-cdk/              Gateway/Registry/Memory CDK stack      🟡 synth-validated
├── docs/                 ARCHITECTURE · BLUEPRINT · SETUP · HARNESSES · FIDELITY-REPORT
├── tests/                offline unit + config tests (591)      🟢
└── .github/workflows/    CI incl. a customer-name / secret gate
```

## 🔐 Safety & scope

A reference implementation and educational sample for **authorized, defensive** security operations. Ships stubbed/offline-safe tools and only public threat examples (ATT&CK, public CVEs). Bring your own least-privilege role, VPC, and data controls before any real use.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Ground rules: no proprietary data, no hardcoded secrets/account IDs, defensive scope only, English. CI enforces a name/secret scan.

## 📄 License

[MIT-0](LICENSE) © 2026 sentinel-harness contributors.
