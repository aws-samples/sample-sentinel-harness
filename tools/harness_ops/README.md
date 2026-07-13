# harness_ops

Deterministic **harness-lifecycle** MCP tool for a platform / meta-orchestration
agent (M1 core — see `docs/ROADMAP.md` §5.1).

## Purpose

The meta-agent (`harnesses/agent-ops`) decomposes a request into ONE structured
harness spec, then drives the lifecycle through this tool. Spec *authoring* is
the model's job; **create / update / invoke / promote are deterministic
control-plane actions** and must never be model-authored HTTP. The agent passes
structured `params`; this handler only validates them and calls
`sentinel_harness.core.*` (or `core._control.create_harness_endpoint` for the
one action `core` does not wrap yet).

Wire it into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"action": <str>, "params": {...}}`
- `context`: Lambda-style context (unused).

## Actions

| action | params (required **bold**, optional italic) | delegates to | result |
|---|---|---|---|
| `create` | **name**, **system_prompt**, *model/tools/skills/memory/allowed_tools/max_iterations/max_tokens/timeout_seconds/tags* | `core.create_harness(**params)` | `harnessId, arn, status` |
| `update` | **harness_id**, *any UpdateHarness field (full replacement)* | `core.update_harness(harness_id, **rest)` | `harnessId` |
| `invoke` | **arn**, **text**, *session_id (auto-minted if absent), actor_id, model/tools/...* | `core.invoke(arn, session_id, text, **rest)` | `session_id, text, stop_reason, tools_used, tool_use` |
| `wait_ready` | **harness_id**, *timeout* | `core.wait_ready(harness_id, ...)` | `harnessId, status` |
| `list` | — | `core.list_harnesses()` | `harnesses: [...]` |
| `delete` | **harness_id**, *keep_memory* | `core.delete_harness(harness_id, ...)` | `deleted` |
| `create_endpoint` | **harness_id**, **endpoint_name**, *target_version, description* | `core._control.create_harness_endpoint(...)` | `endpointName, harnessId, status, targetVersion` |

`update` uses UpdateHarness **full-replacement** semantics: only `harnessId` is
required server-side; every other field the meta-agent supplies replaces the
prior value.

## Output contract

```jsonc
// success
{"ok": true,  "action": "<action>", ...action-specific fields}
// failure
{"ok": false, "action": "<action>", "error": "validation_error"|"upstream_error", "message": "..."}
```

- **validation_error** — the request is malformed (unknown action, missing
  required param, bad harness name `[a-zA-Z][a-zA-Z0-9_]{0,39}`, unexpected
  kwarg). Fix the input.
- **upstream_error** — a control-plane / boto failure. The underlying message is
  always surfaced (never swallowed); retry / check AWS.

## Determinism & egress posture

- No LLM, no business logic beyond validation — reproducible so the M1
  self-iteration loop is deterministic.
- All control-plane traffic goes through `core` / `core._control`, so the single
  region + credential resolution path is shared. No account ids, ARNs, or
  secrets are hardcoded; they come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`.

## Run locally

```bash
python handler.py   # offline smoke: routes a `list` request through core
```
