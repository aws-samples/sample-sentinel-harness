# adversarial-reviewer — A2A specialist Runtime (L1 detection review)

A narrow **specialist** agent behind [A2A](https://github.com/google/A2A)
(agent-to-agent). The `detection-eng` supervisor harness *generates* a detection
rule and then delegates the *evaluation* to this specialist over the Gateway
(`@gateway/invoke_specialist`) instead of grading its own work. It mirrors the
[`specialists/cve-intel`](../cve-intel/) skeleton exactly and adds a **real,
deterministic critique reasoner** (`review_detection`) that is the provable core
of this specialist. It is the M11 building block that closes the
"generation != evaluation" claim referenced across
[`docs/BLUEPRINT.md`](../../docs/BLUEPRINT.md),
[`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md), and
[`docs/HARNESSES.md`](../../docs/HARNESSES.md).

## Why an independent reviewer (generation != evaluation)

The single most reliable way to catch a generator's blind spots is to have a
**separate** agent attack the output. Because this reviewer runs in its own
Runtime microVM and is reached only by A2A, the thing being reviewed and the
thing doing the reviewing are structurally distinct — **no self-approval bias**.
An `approve` verdict is a *recommendation only*: a human
`request_publish_approval` inline_function gate is still the only path to
production. This specialist never authors, edits, publishes, or deploys a rule.

## Real vs. skeleton vs. advisory (read this first)

| Piece | Status | Notes |
|---|---|---|
| `review_detection(rule)` | **REAL** | Pure-python static analysis. No LLM, no network, no tokens. Same rule → same verdict. Adversarial by construction: any objection or logic flaw blocks approval. Fully unit-testable offline. |
| `build_agent` / `build_app` / `serve` | **SKELETON** | Guarded A2A serving wrapper; heavy deps imported lazily so the module + card + reasoner import without the specialist stack. |
| Publish / edit / deploy | **NOT DONE HERE** | The reviewer only critiques. A human publish gate downstream owns whether anything ships. |

## The deterministic critique reasoner

`review_detection(rule) -> verdict` takes a generated detection rule (a Sigma/YARA
string, or an already-parsed dict artifact) and adversarially attacks it:

1. **Metadata** — flags a missing `title` / `logsource` / `level` (the rule must
   be self-describing enough to triage and route).
2. **Condition** — flags a missing `condition:` (matches nothing/everything) and
   a lone-wildcard selection (`'*'`, the classic alert cannon).
3. **False-positive scoping** — flags a rule with neither an exclusion filter
   (`and not <filter>`) nor a documented `falsepositives:` block; downgrades to a
   hygiene note when a filter exists but FPs are undocumented.
4. **Logic flaws** — flags a `condition` that references a selection/filter
   identifier that is never defined in the detection map (the rule cannot match
   as written).

Each objection carries a stable `code`, a `severity`, and a human `detail`.
`fp_risk` is `high` if any breadth/scoping objection fired, `medium` for
documentation-only gaps, else `low`. The `verdict` is `revise` whenever there is
**any** objection or logic flaw, else `approve`. The **verdict is the reasoner's,
not the model's** — the LLM only orchestrates the tool calls and explains the
result; it must not downgrade an objection or approve out of politeness.

```python
{"artifact_kind": "sigma", "verdict": "revise",
 "objections": [{"code": "broad_selection", "severity": "high", "detail": "..."}],
 "fp_risk": "high", "logic_flaws": ["condition references 'selection2', ..."],
 "rationale": "Withholding approval: ..."}
```

## What this container is (A2A skeleton)

`agent_a2a.py` builds a Strands `Agent` (LiteLLM model + Gateway MCP tools),
wraps it in an `A2AServer`, and mounts a FastAPI `/ping` liveness endpoint. It
publishes a self-describing **agent-card** so a supervisor can discover it *by
capability* rather than by a hardcoded address.

- **Model** — `LiteLLMModel(SENTINEL_SPECIALIST_MODEL)`; default is a small
  Bedrock model routed through LiteLLM.
- **Tools** — pulled from the AgentCore **Gateway** MCP endpoint
  (`sigma_yara_lint` to confirm the rule parses, `attack_lookup` to validate a
  claimed ATT&CK mapping). The specialist never reaches the internet directly.
- **Output** — a single grounded JSON verdict; `grounded=false` if the verdict
  did not come from the deterministic reasoner (anti-confabulation).

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
docker build --platform linux/arm64 -t adversarial-reviewer:0.1.0 .
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
search_registry({ "capability": "detection.review" })
// → [{ "name": "adversarial-reviewer", "url": "...", "capabilities": ["detection.review", ...] }]

// 2. delegate the whole subtask (A2A message/send under the hood)
invoke_specialist({
  "name": "adversarial-reviewer",
  "message": "Attack this Sigma rule and return your verdict:\n<rule yaml>"
})
// → { "artifact_kind": "sigma", "verdict": "revise",
//     "objections": [{ "code": "no_fp_scoping", "severity": "high", "detail": "..." }],
//     "fp_risk": "high", "logic_flaws": [], "grounded": true }
```

The generator harness then addresses the objections (up to a bounded number of
revise rounds); nothing reaches production except through the human
`request_publish_approval` gate.

## Local checks

```bash
# Offline: reasoner + agent-card / capability metadata / factory contract
# (no network, no deps).
python -m pytest tests/test_adversarial_reviewer.py -q

# Structural Docker validation (does NOT pull the base image):
docker build --check .        # or: hadolint Dockerfile
```
