# sigma_match — deterministic offline Sigma detection matcher

`sigma_match` answers the one question BAS (Breach & Attack Simulation)
detection-replay depends on:

> Given this log **event**, does this Sigma **rule** fire?

Its sibling `tools/sigma_yara_lint` only *lints* rule syntax. This tool
*evaluates* a rule's `detection` block against a real log event, so the
BAS replay loop can enumerate **detection blind spots**: run each simulated
attack telemetry event against the current rule set and flag the ATT&CK
techniques that no rule catches.

## Provable core (real vs simulated)

This matcher is the **real, provable core** of Layer-2 attack validation:
100% deterministic, pure Python, no LLM, no tokens, no network. The
condition boolean is evaluated by a hand-written tokenizer + recursive-descent
parser — there is **no `eval()`** and no dynamic code execution. Same
`(rule, log_event)` in, same result out.

(The sample *detonation* side of M3 is, by contrast, a simulated no-op
skeleton — see the roadmap. This matcher is not simulated; it is the exact
logic that decides catches.)

## Contract

```python
handler(event, context)
# event = {
#     "rule": "<sigma yaml string>"  OR  {<parsed dict>},
#     "log_event": {"<field>": "<value>", ...},
# }
```

Success:

```json
{
  "ok": true,
  "matched": true,
  "matched_selections": ["selection"],
  "condition": "selection"
}
```

Bad input:

```json
{"ok": false, "error": "validation_error", "message": "..."}
```

## Supported Sigma semantics

Selections are maps of `field -> value` or `field|modifier -> value`.
A selection matches only if **all** of its keys match (AND). A field that is
**absent** from the log event simply fails that key (no crash).

| Modifier      | Meaning                                                    |
|---------------|------------------------------------------------------------|
| *(plain)*     | equality; a **list** value means OR (any element matches)  |
| `contains`    | field value contains the substring                         |
| `startswith`  | field value starts with the substring                      |
| `endswith`    | field value ends with the substring                        |
| `re`          | the value is a regex searched against the field            |
| `all`         | the value is a **list** and **every** element must match   |

Modifiers compose, e.g. `CommandLine|contains|all: [foo, bar]`.
Value comparison is **case-insensitive** by default (Sigma's default);
`re` compiles with `IGNORECASE`.

### Condition expression

Over the selection names:

- `and` / `or` / `not`, with parentheses.
- `1 of them` / `any of them` / `all of them`.
- `1 of selection_*` / `all of selection_*` (wildcard by prefix).
- a bare selection name → whether that selection matched.

A malformed condition (undefined name, unbalanced parens, dangling
quantifier) returns a `validation_error` rather than a misleading `matched`.

## Egress & secrets

Zero egress, zero secrets. `SENTINEL_EXECUTION_ROLE_ARN`, `SENTINEL_REGION`
and `AWS_PROFILE` are honored for harness consistency but are **not required**
to run this tool.

## YAML parsing reuse

The rule parser is reused from `tools/sigma_yara_lint/handler.py` (`_parse_yaml`,
PyYAML with a dependency-free minimal fallback). It is imported by path; if the
sibling is unavailable a local copy of the same minimal parser is used, so the
tool stays self-contained and fully offline.

## Registry

To make this tool live, add it to `registry/tools.yaml` (SecOps-owned
allowlist) — this tool does **not** edit the registry itself:

```yaml
  - name: sigma_match
    owner: detection-engineering
    status: approved
    description: >-
      Deterministic, LLM-free Sigma detection matcher: decides whether a log
      event is caught by a Sigma rule. Core engine for BAS detection-replay
      blind-spot analysis. Makes no network calls.
```

## Run the demo / tests

```bash
python tools/sigma_match/handler.py
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
  python -m pytest tests/test_sigma_match.py -q
```
