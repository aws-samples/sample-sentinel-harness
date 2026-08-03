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

from .logutil import get_logger

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


class GovernanceUnavailable(RuntimeError):
    """The registry could not be read, so the approved set is UNKNOWN.

    Distinct from "the approved set is empty" — that is a governance decision, this is
    the absence of one. Conflating them is INV-MCP-1's whole subject.
    """


def _load_approved_set() -> frozenset:
    """Load the set of registry-approved tool names (status=approved).

    Raises :class:`GovernanceUnavailable` when the registry cannot be read.

    INV-MCP-1. This used to swallow every exception and return an empty frozenset, and
    the caller's gate read ``if approved and tool not in approved`` — so an empty set
    made the whole condition falsy and EVERY tool in ``tools/`` was exposed, including
    the ones the registry marks pending. Reproduced: with the registry unreachable the
    server exposed 18 tools instead of 17, the extra one being ``web_search`` — the only
    non-approved entry, and the single tool whose job is to fetch attacker-influenceable
    content.

    That was not an edge case but the DEFAULT on the packaged install path.
    ``DEFAULT_REGISTRY_PATH`` is ``"registry/tools.yaml"``, relative to the CWD, and the
    wheel did not ship ``registry/`` at all — verified by building one. So
    ``pip install sentinel-harness && sentinel-mcp`` from any directory other than a repo
    checkout failed open every time. Both halves are fixed: the packaging (``registry``
    is now included and the path resolves against the installed package as a fallback)
    and this function, which no longer reports a governance decision it did not obtain.

    The docstring's original justification — "the MCP server should still start, not
    crash on a missing file" — had the trade-off backwards. This server's job is to
    expose a governed subset of tools over stdio to an arbitrary MCP client; a server
    that starts while ungoverned is worse than one that refuses to start, because the
    operator has no way to tell the two apart. INV-BOUNDARY-5's rule: "we could not tell"
    must never render as the permissive answer.
    """
    try:
        from .registry import load_registry
        reg = load_registry()
    except Exception as exc:
        raise GovernanceUnavailable(
            f"cannot read the tool registry, so which tools are approved is UNKNOWN "
            f"({type(exc).__name__}: {exc}). Refusing to serve rather than exposing "
            f"every tool in tools/ — including the ones the registry marks pending. "
            f"Set SENTINEL_REGISTRY_PATH to the registry YAML, or run from a checkout. "
            f"To serve an ungoverned tool set deliberately, set "
            f"{_ALLOW_PENDING_ENV}=1, which says so explicitly."
        ) from exc
    return frozenset(
        entry.name for entry in reg._entries.values() if entry.status == "approved"
    )


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

    allow_pending = os.environ.get(_ALLOW_PENDING_ENV, "").lower() in _TRUTHY_VALUES
    expose_control = os.environ.get(_EXPOSE_CONTROL_ENV, "").lower() in _TRUTHY_VALUES

    # INV-MCP-1: an unreadable registry is refused, not treated as "no filtering".
    # The dev escape hatch already exists and is explicit, so it — and only it — may
    # proceed without a governance decision.
    if allow_pending:
        try:
            approved = _load_approved_set()
        except GovernanceUnavailable as exc:
            get_logger(__name__).warning(
                "%s=1 and the registry is unreadable (%s): serving EVERY tool in "
                "tools/, governed or not.", _ALLOW_PENDING_ENV, exc,
            )
            approved = frozenset()
    else:
        approved = _load_approved_set()  # raises GovernanceUnavailable, by design

    for entry in sorted(_TOOLS_DIR.iterdir()):
        handler_path = entry / "handler.py"
        if not handler_path.is_file():
            continue

        tool_name = entry.name

        # Registry governance gate.
        #
        # INV-MCP-1: NO leading `if approved and ...`. That truthiness test made an
        # empty approved set skip the whole gate, so "the registry says nothing is
        # approved" and "we could not read the registry" both meant "expose
        # everything". The unreadable case now raises above; a genuinely empty approved
        # set is a governance decision and must exclude every tool, which is what this
        # unconditional membership test does.
        if tool_name not in approved and not allow_pending:
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
    """Generate a permissive JSON Schema for the tool's event parameter.

    The ``event`` key is the canonical wrapper, but it is NOT required — when
    absent, the entire arguments dict is treated as the event (bare-arguments
    fallback). This keeps the MCP protocol layer from rejecting valid direct
    calls while preserving the structured {event: ...} path for clients that
    use it."""
    return {
        "type": "object",
        "properties": {
            "event": {
                "type": "object",
                "description": f"Input event for the {tool_name} tool. Pass the tool-specific parameters as keys. You may also pass parameters directly without the event wrapper.",
            }
        },
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
