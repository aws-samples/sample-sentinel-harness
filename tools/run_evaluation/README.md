# run_evaluation

Deterministic **evaluation-scoring** MCP tool — the M2 self-improvement scoring
gate (see `docs/ROADMAP.md` §4 layer ③ / §5.3).

## Purpose

After `harnesses/agent-ops` builds a harness, the `harnesses/self-improving`
loop must **score** that agent's answers against caller-defined criteria, retry
with reasoning when below bar, and promote only at/above bar. This tool is that
scoring gate: it invokes a **self-built LLM-judge harness** and parses a
structured verdict out of the reply.

### Why a self-built LLM-judge harness (not the managed Evaluate API)

The managed Evaluate API scores *live traces* (OTEL sessionSpans / CloudWatch
Logs) — that telemetry pipeline is M4 infrastructure, out of scope for M2. So M2
uses the ROADMAP-sanctioned fallback: an **offline fixed dataset + a self-built
LLM-judge harness** (a Sonnet harness whose system prompt is "score this agent
answer against these criteria and return a structured verdict"). The judge
harness is provisioned like any other harness (via `harness_ops` /
`core.create_harness`); **this tool only invokes it and parses the verdict**.
`CreateEvaluator` remains available as an OPTIONAL governance record — it is not
the scoring path here.

Wire it into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"action": <str>, "params": {...}}`
- `context`: Lambda-style context (unused).

## Actions

| action | params (required **bold**, optional italic) | does | result |
|---|---|---|---|
| `score_answer` | **judge_arn**, **agent_answer**, **criteria** (str or list), *expected, session_id (auto-minted `judge` prefix), actor_id, model/tools/...* | builds a judge prompt → `core.invoke(judge_arn, session, prompt)` → parses verdict | `score, passed, reasons, suggestions, raw` |
| `parse_verdict` | **text** | PURE offline parse of a judge reply — no model call | `score, passed, reasons, suggestions` |

`score_answer` is the only path that reaches a model, and it makes **exactly one**
`core.invoke` call to the judge harness. `parse_verdict` is fully offline.

## Verdict schema & parsing

The judge is instructed to return ONLY a JSON object with keys:

```jsonc
{"score": 0.0..1.0, "pass": true|false, "reasons": [...], "suggestions": [...]}
```

`parse_verdict` is **tolerant** of how a model actually replies:

1. a bare JSON object,
2. a ` ```json ` fenced block,
3. JSON embedded in surrounding prose (brace-balanced scan).

Coercion: `score` → float clamped to `[0, 1]`; `pass` → bool;
`reasons`/`suggestions` → lists of strings. If **no** JSON can be parsed it falls
back to a prose scan (the same robust approach `scenario_detection_gen.py` uses):
`passed` is true iff the word "pass" appears and the word "fail" does not, and
`score` then defaults to `1.0` (pass) or `0.0` (fail). It never raises on a bad
reply — the deterministic scoring loop always gets a decision.

## Output contract

```jsonc
// success
{"ok": true,  "action": "<action>", ...action-specific fields}
// failure
{"ok": false, "action": "<action>", "error": "validation_error"|"upstream_error", "message": "..."}
```

- **validation_error** — the request is malformed (unknown action, missing
  required param, `criteria` not a str/list, unexpected `core.invoke` kwarg). Fix
  the input.
- **upstream_error** — a model / control-plane / boto failure. The underlying
  message is always surfaced (never swallowed); retry / check AWS.

## Determinism & egress posture

- The handler is **deterministic**: it validates + parses; the only
  non-deterministic step is the single `core.invoke` to the judge harness. The
  verdict parser is a **pure function** — reproducible so the M2 self-improvement
  loop is reproducible.
- All model traffic goes through `core.invoke`, so the single region + credential
  resolution path is shared. No account ids, ARNs, or secrets are hardcoded; they
  come from `SENTINEL_EXECUTION_ROLE_ARN`, `SENTINEL_REGION`, `AWS_PROFILE`, and
  the caller-supplied `judge_arn`.

## Run locally

```bash
python handler.py   # offline smoke: parse_verdict over a fenced judge reply
```
