# eval/ — fixed evaluation datasets + pass-bar criteria

The **offline baseline the self-improving loop scores against** (ROADMAP M2 / §3
key #2 / §5.3). These assets are the *soul* of evaluation-driven self-iteration:
a candidate agent is only promoted to production if it clears this bar on a
fixed, versioned dataset — and then only through a human gate.

Everything here is **generic SecOps only**: public CVEs, published ATT&CK
techniques, Sigma-rule-quality expectations. No customer data, no account ids,
no ARNs, no secrets.

## Why a self-built LLM-judge (not the managed Evaluate API)

M2 scores answers with a **self-built LLM-judge harness** — a Sonnet harness
whose system prompt is *"score this agent answer against these criteria and
return a structured verdict"*. This is the ROADMAP M2 fallback (offline fixed
dataset + self-built LLM-judge). The managed `Evaluate` API is intentionally
**not** the scoring path here: it consumes OTEL `sessionSpans` / CloudWatch Logs
telemetry, which is M4 infrastructure and out of scope for M2. `CreateEvaluator`
may still be created as an optional governance record, but it is not what
produces the score the loop gates on.

## Dataset schema (`datasets/*.jsonl`)

One JSON object per non-empty line (JSON Lines). Each object has exactly these
keys:

| Key | Type | Meaning |
|---|---|---|
| `input` | string | The prompt/task handed to the agent under test (e.g. a CVE-triage request or a "write a Sigma rule for T…" task). |
| `expected` | string | A prose description of a good answer. The LLM-judge checks the agent's answer *against this*, not by exact string match — SecOps answers are open-ended. |
| `assertions` | list[string] | Concrete, individually-checkable claims the answer must satisfy (mechanism identified, correct severity, safe remediation, ATT&CK technique mapped, false-positive source acknowledged, …). These are what the judge verifies point-by-point. |

`expected` and `assertions` together are the rubric: `expected` is the holistic
target, `assertions` are the must-haves that stop a fluent-but-wrong answer from
passing.

Shipped datasets:

- **`cve_triage.jsonl`** — public-CVE triage quality (severity call grounded in
  KEV/EPSS/exploitation, correct vulnerability mechanism, safe and durable
  remediation, risk-based prioritization).
- **`detection_gen.jsonl`** — detection-rule-generation quality (valid Sigma
  YAML, correct ATT&CK technique mapping, specific detection logic rather than a
  bare process-name match, explicit false-positive awareness).

## How `criteria.yaml` is consumed

`criteria.yaml` is the caller-defined pass bar. The self-improving harness
(ROADMAP §5.3) uses it like this:

```
loop (max = criteria.max_retries):
  for each line in dataset:
    answer  = agent_under_test(line.input)                 # via harness_ops invoke
    verdict = llm_judge(answer, line.expected, line.assertions)
              # -> {score: 0..1 float, pass: bool, reasons: [...], suggestions: [...]}
  aggregate_score = mean(verdict.score over lines)
  if aggregate_score >= criteria.pass_threshold: break     # passed
  reasoning = judge.reasons + judge.suggestions            # attribute the failure
  spec'     = agent_ops.revise(spec, reasoning)            # concrete change WITH reasoning
  harness   = harness_ops.update(spec')                    # full replacement
if aggregate_score >= criteria.pass_threshold and criteria.require_human_promotion:
  request_promotion_approval(...)                          # HITL inline_function gate
  if approved: harness_ops.create_endpoint(...)            # CreateHarnessEndpoint -> production
```

`criteria.yaml` keys:

| Key | Type | Purpose |
|---|---|---|
| `pass_threshold` | float in `0..1` | Minimum aggregate LLM-judge score to be considered passing. |
| `max_retries` | int `>= 1` | Hard cap on retry-with-reasoning rounds (the loop can never spin forever). |
| `dimensions` | list[string] | Scoring axes: `correctness`, `groundedness`, `safety`. |
| `require_human_promotion` | bool | If true, passing the bar still requires a human to clear `request_promotion_approval` before `CreateHarnessEndpoint` runs. |

## Verdict parsing

The judge harness returns a structured JSON verdict — keys `score` (0..1 float),
`pass` (bool), `reasons` (list), `suggestions` (list). The loop parses it with
the same robust structured-tool-first / prose-fallback approach that
`scenarios/scenario_detection_gen.py` already uses for review verdicts, so a
model that answers in prose instead of the structured shape still yields a
usable decision.
