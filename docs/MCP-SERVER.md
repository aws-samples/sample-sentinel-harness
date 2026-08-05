# sentinel-harness MCP Server

> **Any MCP-compatible AI agent can invoke all 20 sentinel tools — zero integration code.**

## What is this?

`sentinel mcp serve` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server
over **stdio** that exposes the full sentinel-harness tool suite:

| Category | Tools |
|---|---|
| **Detection engineering** | `sigma_yara_lint`, `detection_translate`, `detection_dedup`, `detection_coverage`, `detection_audit`, `detection_navigator`, `detection_baseline` |
| **Security enrichment** | `enrich_ioc`, `nvd_lookup`, `epss_kev`, `attack_lookup`, `web_search` |
| **SecOps automation** | `siem_query`, `asset_lookup`, `create_ticket`, `ops_query`, `allowlist_optimizer` |
| **Platform ops** | `harness_ops`, `run_evaluation`, `sigma_match` |

All tools are **deterministic, LLM-free, offline** (no AWS credentials needed for the default
mock path). They run in-process with no network calls.

## Quick start

```bash
# Install with MCP support
pip install sentinel-harness[mcp]

# Test it works
sentinel mcp serve  # starts stdio server; Ctrl-C to stop
```

## Connect from Claude Code

Add to your Claude Code `settings.json` (user or project level):

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel",
      "args": ["mcp", "serve"]
    }
  }
}
```

After restarting Claude Code, all 20 tools will appear in your tool list.

## Connect from Cursor / Windsurf / custom agents

Any MCP-over-stdio client works. The server follows the standard MCP protocol:

```json
{
  "command": "sentinel",
  "args": ["mcp", "serve"],
  "env": {
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/placeholder"
  }
}
```

The `SENTINEL_EXECUTION_ROLE_ARN` env is needed for the import path but is not
used when tools run in offline/mock mode (the default).

## Tool invocation format

Each tool accepts a JSON `event` object. Example:

```json
{
  "name": "sigma_yara_lint",
  "arguments": {
    "event": {
      "rule_type": "sigma",
      "content": "title: My Rule\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\nlevel: high"
    }
  }
}
```

The response is a JSON object with tool-specific output.

## Running without installing

```bash
# Using uvx (no install needed)
uvx --from 'sentinel-harness[mcp]' sentinel mcp serve

# Using uv run from a clone
uv run --extra mcp sentinel mcp serve
```

## Architecture

```
AI Agent (Claude Code / Cursor / custom)
    │ stdio (JSON-RPC)
    ▼
sentinel mcp serve
    │ auto-discovers tools/ directory
    ▼
20 tool handlers (deterministic, pure Python)
```

The server lazily imports each `tools/<name>/handler.py` at startup, registers
them as MCP tools, and dispatches calls through the standard `handler(event, context)`
interface. No tool code is modified — the MCP layer is purely additive.
