# threat-hunt — A2A specialist Runtime

A narrow **specialist** agent behind [A2A](https://github.com/google/A2A)
(agent-to-agent). A supervisor harness delegates threat-hunting subtasks to it
instead of doing the work itself. It mirrors the reference implementation of the
pluggable "supervisor → specialist" pattern in
[`docs/BLUEPRINT.md`](../../docs/BLUEPRINT.md) §4.2 — the same skeleton as
[`specialists/cve-intel`](../cve-intel/) — and it is part of milestone **M3**
(L2 attack validation & simulation).

## What this specialist does

Given a hunting **hypothesis** in natural language
(e.g. *"possible credential dumping on domain controllers"*), it returns a
structured, testable **hunt plan**:

- `abductive_questions` — the questions a hunter needs to answer,
- `observables_to_query` — the log sources / telemetry to pull,
- `attack_techniques` — the implicated MITRE ATT&CK technique ids,
- `suggested_queries` — concrete starter queries.

## Real vs. simulated (be precise)

| Part | Status | Notes |
|---|---|---|
| `build_hunt_plan(hypothesis)` | **REAL, deterministic, offline** | Pure Python. No LLM, no tokens, no network. Same input → same output. Fully unit-tested. This is the provable core. |
| A2A serving wrapper (`build_agent`/`build_app`/`serve`) | **skeleton** | Heavy deps (`strands`/`litellm`/`bedrock-agentcore`) are import-guarded; the LLM only narrates and *must* call `build_hunt_plan` for the actual mapping. |

The observable/technique mapping lives in a small built-in **TTP library**
(credential dumping, persistence, lateral movement, exfiltration, phishing,
privilege escalation). A hypothesis that matches nothing yields a **safe generic
reconnaissance plan** (`matched=False`) — the function never raises for an
unknown hypothesis and never confabulates a specific technique id.

## Why a specialist (and not just more tools on the supervisor)?

| | Supervisor | Specialist (this) |
|---|---|---|
| Primitive | AgentCore **Harness** (config-only) | AgentCore **Runtime** container |
| Model | Bedrock-only (harness constraint) | Any, via `LiteLLMModel` (cheaper/narrower) |
| Isolation | shared harness loop | **its own microVM** → true parallelism |
| Added by | — | register a new one; supervisor untouched |

The heavy deps (`strands`, `litellm`, `bedrock-agentcore`) are imported **lazily
inside the factory**, so `agent_a2a.py` imports (and both its agent-card and the
`build_hunt_plan` core are inspectable/testable) even where the specialist stack
is not installed — CI stays green.

## Configuration (12-factor — nothing hardcoded)

| Env var | Purpose | Default |
|---|---|---|
| `SENTINEL_SPECIALIST_MODEL` | LiteLLM model id (provider-prefixed) | `bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0` |
| `SENTINEL_GATEWAY_URL` | Gateway MCP endpoint the tools live on | *(unset → no tools)* |
| `SENTINEL_A2A_HOST` / `SENTINEL_A2A_PORT` | bind address | `0.0.0.0` / `9000` |
| `SENTINEL_EXECUTION_ROLE_ARN` | Runtime → Bedrock/Gateway IAM role | *(required to deploy)* |

## How it registers into the Registry

The specialist self-registers its agent-card so a supervisor discovers it without
code change. Governance stays intact: the Registry runs with `autoApproval=false`
(BLUEPRINT §5), so a newly launched specialist is **pending** until a SecOps owner
approves it.

```bash
# Build & push (arm64), then configure + launch the Runtime with the A2A protocol.
# The starter toolkit publishes the agent-card and creates the Registry entry.
docker build --platform linux/arm64 -t threat-hunt:0.1.0 .
# ... push to your ECR repo ...

python - <<'PY'
from bedrock_agentcore_starter_toolkit import Runtime
from agent_a2a import agent_card, SPECIALIST_NAME
rt = Runtime()
rt.configure(protocol="A2A", agent_name=SPECIALIST_NAME)   # A2A, not HTTP
rt.launch()                                                # → Registry entry (pending)
print(agent_card())                                        # what gets published
PY
```

## What a supervisor's `invoke_specialist` call looks like

The supervisor never authors HTTP. Discovery and delegation are **deterministic
Gateway MCP tools**. From the supervisor's point of view:

```jsonc
// 1. discover by capability
search_registry({ "capability": "hunt.plan" })
// → [{ "name": "threat-hunt", "url": "...", "capabilities": ["hunt.plan", ...] }]

// 2. delegate the whole subtask (A2A message/send under the hood)
invoke_specialist({
  "name": "threat-hunt",
  "message": "Build a hunt plan for possible credential dumping on domain controllers."
})
// → { "hypothesis": "...", "matched": true,
//     "attack_techniques": ["T1003", "T1003.001", "T1003.003"],
//     "observables_to_query": ["process_access events targeting lsass.exe ...", ...],
//     "abductive_questions": ["..."], "suggested_queries": ["..."], "grounded": true }
```

Multiple such calls run concurrently across specialist microVMs; the supervisor
merges the plans into its investigation.

## Local checks

```bash
# Offline: agent-card / capability metadata / factory contract + the pure
# build_hunt_plan core (no network, no deps).
python -m pytest tests/test_threat_hunt.py -q

# Structural Docker validation (does NOT pull the base image):
docker build --check .        # or: hadolint Dockerfile
```
