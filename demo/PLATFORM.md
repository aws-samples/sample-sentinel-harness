# The sentinel-harness platform — guided tour (L1 → L4)

**A security team's whole agent platform, told in one guided walk.**

`platform_demo.py` is a single, promotion-quality, **offline** narrated walk of
the *entire* platform — every layer, in story order. Each beat prints **what** it
demonstrates, **how** it is backed (which real component/mechanism), and **where**
the evidence lives. It is the *map*; the committed `evidence/*.json` (captured from
real runs against the GA Amazon Bedrock AgentCore API) and the live scenarios are
the *proof*.

```bash
# the whole platform story, offline, deterministic, seconds — no AWS, no network:
python demo/platform_demo.py
```

Exit code `0` on success. No third-party dependencies (stdlib + this repo only).

---

## What the platform is

A security team usually already has models, internal MCP servers, and a pile of
skills — what's missing is a **framework to circulate them** so "what one analyst
has, everyone has." `sentinel-harness` is a reference implementation of that
framework on the [Amazon Bedrock AgentCore **Harness**](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html):
you **declare an agent as configuration** and AWS runs the whole agent loop —
swapping a model, adding a tool, or replacing a skill is *a config change, not a
rebuild*. On top of that core, the platform layers self-iteration (agents that
build and improve agents), attack-simulation validation, and a governed, observable
foundation.

---

## The L1 → L4 map (and the beats that tell it)

| Beat | Layer | What it shows |
|---|---|---|
| 1 | **L1 · Strategy Iteration** | Declare an agent as config → CVE triage with deterministic compute, managed memory, and a **mandatory HITL gate** (pause → approve → resume). |
| 2 | **L1** | **Multi-harness parallelism** — a single harness is single-agent; parallelism comes from many harnesses + a supervisor that synthesizes (~2.6× vs. serial). |
| 3 | **L1** | **Detection-gen with an independent adversarial reviewer** — generation ≠ evaluation; a separate reviewer harness attacks the rule; a human publish gate is the only path to production. |
| 4 | **M1 · Self-iteration** | **An agent BUILDS an agent** — a natural-language request → the meta-agent emits a structured harness spec → the deterministic `harness_ops` tool builds a brand-new working harness on the GA control plane. |
| 5 | **M2 · Evaluation-driven** | **Score → improve → promote-to-endpoint** — an independent LLM-judge scores a weak agent (FAIL), it self-improves (PASS), a human approves, and only then is it promoted to a `prod` endpoint. |
| 6 | **L2 · Attack Validation & Simulation** | **BAS detection-replay** finds detection blind spots (real Sigma matcher, executed offline) + **Play Mode** adversary emulation where *every* offensive step is human-gated + checkpointed. Sample detonation is an honest SIMULATED skeleton. |
| 7 | **L3/L4 · Foundation & Governance** | **Gateway** (policy-backed MCP tool surface) reached over **Cognito CUSTOM_JWT** identity, every tool response masked by a **Guardrail**, all **observable** (CloudWatch + Budgets) and cost-guarded (private VPC, PrivateLink, no NAT). |

The tour is scrupulously honest about status — every capability is one of:

- **live-validated** — proven on real AWS; the tour **replays the committed
  `evidence/*.json`** from that run.
- **built+tested** — the mechanism is proven by unit tests (not a live cloud
  deploy).
- **skeleton** — import-safe, honestly *not-yet-live* (e.g. sample detonation:
  SIMULATED no-ops, no real malware/VM/network).

Two beats are not replayed but **genuinely executed in-process** because their core
is pure deterministic Python: the **L2 BAS detection-replay** (real `sigma_match`
matcher over simulated telemetry → a real, non-empty blind-spot list, coverage 0.5)
and the **Play Mode decision logic** (approve resumes, reject halts).

---

## How to run

### Offline guided tour (default) — no AWS, deterministic, seconds

```bash
python demo/platform_demo.py
```

Prints `BEAT 1 … BEAT 7`, then a **capability → status → evidence** summary table
and an honest live/built/skeleton tally. It makes **zero** AWS calls: live beats
replay committed evidence, and the two L2 cores run as pure Python.

### The live scenarios (the real proof)

The tour is the map; the individual scenarios produce the proof (each writes its
own account-scrubbed `evidence/*.json`). Print the run-book with:

```bash
python demo/platform_demo.py --live
```

Then run them against a **non-production** dev account:

```bash
export AWS_PROFILE=<non-prod>
export SENTINEL_REGION=us-east-1
export SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/<harness-role>

python scenarios/scenario_cve_triage.py          # L1: CVE triage + HITL gate
python scenarios/scenario_hitl_resume.py         # L1: pause → approve → resume
python scenarios/scenario_multi_harness.py       # L1: multi-harness + supervisor
python scenarios/scenario_detection_gen.py       # L1: detection-gen + adversarial reviewer
python scenarios/scenario_agent_factory_loop.py  # M1: an agent builds an agent
python scenarios/scenario_self_improve_loop.py   # M2: score → improve → promote
python scenarios/scenario_play_mode.py           # L2: Play Mode, every step HITL-gated
python scenarios/scenario_bas_replay.py          # L2: BAS replay (pure/offline by default)
python scenarios/scenario_named_supervisor.py    # L1/L3: Gateway-wired named supervisor (needs SENTINEL_GATEWAY_ARN)

sentinel cleanup sentinel_                        # tear everything down
```

The M2 loop also has its own runnable, narrated offline demo:
[`demo/m2_self_improving_demo.py`](m2_self_improving_demo.py).

---

## Evidence

The live proof is committed under [`evidence/`](../evidence/) (see
[`evidence/README.md`](../evidence/README.md)). Each `*_result.json` is written by
the matching `scenarios/scenario_*.py` run against the GA API on a non-production
dev account; **account ids are scrubbed to `<ACCOUNT_ID>`**. Highlights the tour
replays:

| Capability | Evidence |
|---|---|
| CVE triage + HITL gate | `evidence/cve_triage_result.json`, `evidence/hitl_resume_result.json` |
| Multi-harness + supervisor | `evidence/multi_harness_result.json` |
| Detection-gen + adversarial reviewer | `evidence/detection_gen_result.json` |
| An agent builds an agent (M1) | `evidence/agent_factory_loop_result.json` |
| Score → improve → promote (M2) | `evidence/self_improve_loop_result.json`, `evidence/endpoint_promote_result.json` |
| BAS replay + Play Mode (L2) | `evidence/bas_replay_result.json`, `evidence/play_mode_result.json` |
| Gateway create → READY → delete | `evidence/gateway_lifecycle_result.json` |
| Guardrail masking (L3) | `evidence/m4_guardrail_result.json` |
| Cognito JWT + observability (L3/L4) | `evidence/m4_live_deploy_result.json` |

For the full status matrix, honest limitations, and the self-audit, see the
top-level [`README.md`](../README.md) and [`docs/FIDELITY-REPORT.md`](../docs/FIDELITY-REPORT.md).

---

## Test

The tour is covered by an offline test that runs it in mock mode and asserts it
exits `0`, hits every beat (1..7 across L1/M1/M2/L2/L3/L4), and prints the summary
table — with a belt-and-suspenders check that it makes no real boto calls:

```bash
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
    python -m pytest tests/test_platform_demo.py -q
```
