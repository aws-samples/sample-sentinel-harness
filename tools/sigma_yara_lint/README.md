# sigma_yara_lint

Deterministic Sigma / YARA detection-rule linter template for a security
operations (SecOps) team.

## Purpose

Before publishing a detection rule, run a cheap, deterministic structural
check. This tool is **pure Python** — no LLM, no tokens, no network — so it
can act as a mandatory gate in an automated detection pipeline: an LLM may
draft a rule, but this linter (not another model) decides whether the rule
is structurally valid. Wire it into an Amazon Bedrock AgentCore Gateway as an
MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"rule_type": "sigma" | "yara", "content": "<rule text>"}`
- `context`: Lambda-style context (unused).

## What it checks

**Sigma** (fully implemented):
- Valid YAML (PyYAML if installed, else a built-in minimal parser — so the
  tool is dependency-free).
- Required top-level keys: `title`, `logsource`, `detection`.
- `detection` has a `condition` plus at least one selection.
- Every identifier referenced in `condition` resolves to a defined selection
  (supports `selection_*` wildcard prefixes and `all of` / `1 of` / `them`
  aggregates).
- `level` must be one of `informational|low|medium|high|critical` when set.
- Warnings for missing `id`/`level`/`status` and thin `logsource`.

**YARA** (lightweight structural check):
- At least one `rule <name> { ... }` block.
- Balanced braces.
- Each rule has a `condition:` section.
- Warns if `$` string identifiers are used with no `strings:` section.

## Output

```json
{
  "ok": true,
  "rule_type": "sigma",
  "valid": true,
  "errors": [],
  "warnings": ["missing recommended key: 'id'"]
}
```

`ok` means the tool ran; `valid` means the rule passed all hard checks.
Invalid input (bad `rule_type`, empty `content`) returns `validation_error`.

## Egress & secrets control

- Zero egress, zero secrets, zero tokens. Deterministic by construction.
- For consistency the harness still references `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`, though this tool needs no AWS access.

## Run locally

```bash
python handler.py
```
