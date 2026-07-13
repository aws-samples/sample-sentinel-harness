# attack-mapper — A2A specialist Runtime (L2 attack-path reasoning)

A narrow **specialist** agent behind [A2A](https://github.com/google/A2A)
(agent-to-agent). A supervisor harness delegates *attack-path reasoning*
subtasks to it instead of doing the work itself. It mirrors the
[`specialists/cve-intel`](../cve-intel/) skeleton exactly and adds a **real,
deterministic attack-path reasoner** (`build_attack_paths`) that is the provable
core of this specialist. It is one of the M3 (Layer-2 attack validation &
simulation) building blocks in [`docs/ROADMAP.md`](../../docs/ROADMAP.md).

## Real vs. skeleton vs. simulated (read this first)

| Piece | Status | Notes |
|---|---|---|
| `build_attack_paths(surface)` | **REAL** | Pure-python graph reasoning. No LLM, no network, no tokens. Same surface → same ranked chains. Fully unit-testable offline. |
| `build_agent` / `build_app` / `serve` | **SKELETON** | Guarded A2A serving wrapper; heavy deps imported lazily so the module + card + reasoner import without the specialist stack. |
| Exploitation / scanning / detonation | **NOT DONE HERE** | This specialist reasons over asset *metadata* only. It never exploits, scans, or touches a live target. |

Any downstream *validation* of a chain stays **HITL-gated behind the existing
Play Mode** (`sentinel_harness/simulation.py`); sample detonation is a separate
**simulated** one-shot-microVM skeleton. Nothing in this specialist is
offensive.

## The deterministic reasoner

`build_attack_paths(surface) -> [chain, ...]` turns an exposure surface (from the
`asset_lookup` tool) into ranked high-risk attack chains:

1. **Entry** — find hosts that are *both* internet-exposed *and* run a service
   flagged `known_vuln` (initial access, ATT&CK **T1190**). A fully-patched or
   non-exposed surface yields **`[]`**.
2. **Traverse** — DFS along directed `trust_edges` (`ssh_key_reuse`,
   `shared_admin_cred`, `service_account`, `flat_network`), cycle-safe and
   depth-bounded. A chain is emitted at every reachable node.
3. **Score** — `exploitability × impact`. Exploitability starts at 1.0 for the
   known-vuln entry and decays by each edge's traversal cost; impact is the
   value of the deepest host reached.
4. **Rank** — descending by score, with a deterministic tie-break so output is
   stable.

Each chain reports `entry`, `path`, per-step `techniques`, `edges`, `score`, an
`impact` label, the `entry_cve`, and a human `rationale`. The **ranking is the
reasoner's, not the model's** — the LLM only orchestrates the tool calls and
explains the result; it must not reorder or re-score chains.

## What this container is (A2A skeleton)

`agent_a2a.py` builds a Strands `Agent` (LiteLLM model + Gateway MCP tools),
wraps it in an `A2AServer`, and mounts a FastAPI `/ping` liveness endpoint. It
publishes a self-describing **agent-card** so a supervisor can discover it *by
capability* rather than by a hardcoded address.

- **Model** — `LiteLLMModel(SENTINEL_SPECIALIST_MODEL)`; default is a small
  Bedrock model routed through LiteLLM.
- **Tools** — pulled from the AgentCore **Gateway** MCP endpoint (`asset_lookup`
  for the surface, `attack_lookup` to attach ATT&CK techniques). The specialist
  never reaches the internet directly.
- **Output** — a single grounded JSON envelope; `grounded=false` if the surface
  did not come from a tool response (anti-confabulation).

The heavy deps (`strands`, `litellm`, `bedrock-agentcore`) are imported **lazily
inside the factory**, so `agent_a2a.py` imports (and its agent-card and the
reasoner are usable) even where the specialist stack is not installed — CI stays
green.

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
docker build --platform linux/arm64 -t attack-mapper:0.1.0 .
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

```jsonc
// 1. discover by capability
search_registry({ "capability": "attack.path" })
// → [{ "name": "attack-mapper", "url": "...", "capabilities": ["attack.path", ...] }]

// 2. delegate the whole subtask (A2A message/send under the hood)
invoke_specialist({
  "name": "attack-mapper",
  "message": "Map high-risk attack paths for subnet 10.0.0.0/16."
})
// → { "query": "10.0.0.0/16",
//     "chains": [{ "entry": "web-01", "path": ["web-01","app-01","db-01"],
//                  "techniques": ["T1190","T1021","T1078"], "score": 0.6,
//                  "impact": "critical", "rationale": "..." }],
//     "grounded": true }
```

## Local checks

```bash
# Offline: reasoner + agent-card / capability metadata / factory contract
# (no network, no deps).
python -m pytest tests/test_attack_mapper.py -q

# Structural Docker validation (does NOT pull the base image):
docker build --check .        # or: hadolint Dockerfile
```
