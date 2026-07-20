"""
sentinel-harness · MCP Server
==============================
Exposes all 20 sentinel-harness tools as a standards-compliant MCP (Model Context
Protocol) server over **stdio**. Any MCP-compatible AI agent (Claude Code, Cursor,
Windsurf, custom agents) can connect and invoke the full detection-engineering
suite, security enrichment, and SecOps automation tools — zero integration code.

Usage
-----
::

    # Start the MCP server (stdio mode)
    sentinel mcp serve

    # Or directly:
    uv run python -m sentinel_harness.mcp_server

    # In Claude Code settings.json:
    {
      "mcpServers": {
        "sentinel": {
          "command": "sentinel",
          "args": ["mcp", "serve"]
        }
      }
    }

Architecture
------------
Each tool's ``handler(event, context) -> dict`` is wrapped as an MCP tool with:
- Tool name derived from the directory name (``sigma_yara_lint``, ``detection_audit``, etc.)
- Description from the module docstring's first line
- Input schema: a single JSON object parameter (``event``) — the same shape the
  handler already expects
- The ``context`` argument receives a minimal stub (tools are pure/deterministic)

The server imports tools lazily at startup from ``tools/*/handler.py`` using the
same registry discovery as ``sentinel_harness/cli.py``.

Dependencies
------------
Requires ``mcp`` (the reference Python SDK). Added as an optional extra:
``pip install sentinel-harness[mcp]``.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Discover the tools directory relative to this file or the repo root.
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parent
_TOOLS_DIR = _REPO_ROOT / "tools"

# Minimal context stub — tools are pure/deterministic, they don't use context.
_STUB_CONTEXT: Any = None

# Control-plane tools that can create/modify/delete AWS resources or invoke
# models (= cost). Default OFF for the MCP server; opt-in via env flag.
_CONTROL_PLANE_TOOLS = frozenset({"harness_ops", "run_evaluation"})
_EXPOSE_CONTROL_ENV = "SENTINEL_MCP_EXPOSE_CONTROL_PLANE"

# Env flag to bypass registry governance (dev/testing escape hatch).
_ALLOW_PENDING_ENV = "SENTINEL_MCP_ALLOW_PENDING"

_TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _load_approved_set() -> frozenset:
    """Load the set of registry-approved tool names (status=approved).

    Falls back to empty (= no filtering) if the registry YAML is unreachable
    (the MCP server should still start, not crash on a missing file)."""
    try:
        from .registry import load_registry
        reg = load_registry()
        return frozenset(
            entry.name for entry in reg._entries.values() if entry.status == "approved"
        )
    except Exception:
        return frozenset()


def _discover_tools() -> Dict[str, Dict[str, Any]]:
    """Walk tools/ and import each handler, filtered by registry governance.

    Enforcement rules (ROADMAP iron-rule #4: a tool is live only if
    registry-approved AND code-mapped):
    - A tool with ``status != approved`` in ``registry/tools.yaml`` is excluded
      unless ``SENTINEL_MCP_ALLOW_PENDING=1`` (dev escape hatch).
    - Control-plane tools (``harness_ops``, ``run_evaluation``) are excluded
      unless ``SENTINEL_MCP_EXPOSE_CONTROL_PLANE=1`` (explicit opt-in).
    """
    tools: Dict[str, Dict[str, Any]] = {}
    if not _TOOLS_DIR.is_dir():
        return tools

    approved = _load_approved_set()
    allow_pending = os.environ.get(_ALLOW_PENDING_ENV, "").lower() in _TRUTHY_VALUES
    expose_control = os.environ.get(_EXPOSE_CONTROL_ENV, "").lower() in _TRUTHY_VALUES

    for entry in sorted(_TOOLS_DIR.iterdir()):
        handler_path = entry / "handler.py"
        if not handler_path.is_file():
            continue

        tool_name = entry.name

        # Registry governance gate
        if approved and tool_name not in approved and not allow_pending:
            continue

        # Control-plane tools require explicit opt-in
        if tool_name in _CONTROL_PLANE_TOOLS and not expose_control:
            continue

        try:
            spec = importlib.util.spec_from_file_location(
                f"tools.{tool_name}.handler", str(handler_path)
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"tools.{tool_name}.handler"] = mod
            spec.loader.exec_module(mod)

            if not hasattr(mod, "handler"):
                continue

            doc = (mod.__doc__ or "").strip().split("\n")[0]
            tools[tool_name] = {"module": mod, "description": doc}
        except Exception as exc:
            tools[tool_name] = {"module": None, "description": f"[LOAD ERROR: {exc}]"}

    return tools


def _tool_input_schema(tool_name: str) -> Dict[str, Any]:
    """Generate a permissive JSON Schema for the tool's event parameter."""
    return {
        "type": "object",
        "properties": {
            "event": {
                "type": "object",
                "description": f"Input event for the {tool_name} tool. Pass the tool-specific parameters as keys.",
            }
        },
        "required": ["event"],
    }


def _invoke_tool(tool_name: str, mod: Any, event: Dict[str, Any]) -> str:
    """Call the handler and return JSON-serialized result."""
    try:
        result = mod.handler(event, _STUB_CONTEXT)
        return json.dumps(result, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": type(exc).__name__, "message": str(exc)})


def create_server():
    """Create and configure the MCP server with all sentinel tools registered."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
    except ImportError:
        print(
            "ERROR: The 'mcp' package is required for MCP server mode.\n"
            "Install it with: pip install sentinel-harness[mcp]\n"
            "Or: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    server = Server("sentinel-harness")
    tools_registry = _discover_tools()

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        """Return all available sentinel tools as MCP tool definitions."""
        result = []
        for name, info in tools_registry.items():
            if info["module"] is None:
                continue
            result.append(
                Tool(
                    name=name,
                    description=info["description"],
                    inputSchema=_tool_input_schema(name),
                )
            )
        return result

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        """Dispatch an MCP tool call to the matching sentinel handler."""
        if name not in tools_registry:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "unknown_tool", "message": f"Tool {name!r} not found. Available: {sorted(tools_registry)}"}),
            )]

        info = tools_registry[name]
        if info["module"] is None:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "load_error", "message": info["description"]}),
            )]

        event = arguments.get("event", arguments)
        output = _invoke_tool(name, info["module"], event)
        return [TextContent(type="text", text=output)]

    return server, stdio_server


async def main():
    """Run the MCP server over stdio."""
    server, run_stdio = create_server()
    async with run_stdio(server.create_initialization_options()) as streams:
        await server.run(
            streams[0],
            streams[1],
            server.create_initialization_options(),
        )


def run():
    """Synchronous entry point for the CLI."""
    import asyncio
    asyncio.run(main())


if __name__ == "__main__":
    run()
