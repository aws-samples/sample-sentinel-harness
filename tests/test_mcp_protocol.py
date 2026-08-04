"""MCP protocol-level round-trip tests for the sentinel-harness MCP server.

These exercise the ACTUAL MCP protocol layer (initialize → list_tools → call_tool)
using the SDK's in-memory transport — the same wire format a real client sends.
Without these, an mcp SDK signature change would break the headline feature with
the entire test suite still green (the existing test_mcp_server.py only tests the
pre-protocol helper functions).

Requires the ``mcp`` package (optional dep). Skip-guarded so the offline suite
stays green without it installed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp", reason="mcp SDK not installed (optional dep)")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def anyio_backend():
    return "asyncio"


pytestmark = pytest.mark.anyio


# `_create_session(monkeypatch, env_overrides)` used to live here. It was DEAD — defined,
# never called; every test below builds its own server inline. Removed while routing the
# eight inline `create_connected_server_and_client_session` imports through
# `tests/mcp_session.py`, because a helper nobody calls still has to be migrated on every SDK
# change and still reads as supported. It was also the only caller of `raise_exceptions=True`,
# so nothing else depends on that behaviour.


class TestMcpProtocolRoundTrip:
    """Full protocol-level tests via in-memory transport."""

    async def test_initialize_handshake(self):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            assert session is not None

    async def test_list_tools_returns_governance_filtered_set(self):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.list_tools()
            tool_names = {t.name for t in result.tools}
            # Default: pending tools (web_search) and control-plane (harness_ops,
            # run_evaluation) are excluded by governance gate.
            assert "web_search" not in tool_names, "pending tool should be excluded"
            assert "harness_ops" not in tool_names, "control-plane tool should be excluded"
            assert "run_evaluation" not in tool_names, "control-plane tool should be excluded"
            # Approved non-control tools must be present.
            assert "sigma_yara_lint" in tool_names
            assert "detection_audit" in tool_names
            assert "enrich_ioc" in tool_names
            assert len(tool_names) >= 17

    async def test_list_tools_with_control_plane_enabled(self, monkeypatch):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        monkeypatch.setenv("SENTINEL_MCP_EXPOSE_CONTROL_PLANE", "1")
        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.list_tools()
            tool_names = {t.name for t in result.tools}
            assert "harness_ops" in tool_names
            assert "run_evaluation" in tool_names

    async def test_call_tool_sigma_yara_lint_valid(self):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.call_tool("sigma_yara_lint", arguments={
                "event": {
                    "rule_type": "sigma",
                    "content": (
                        "title: Test\n"
                        "logsource:\n  product: windows\n"
                        "detection:\n  sel:\n    EventID: 1\n  condition: sel\n"
                        "level: high\nstatus: test\n"
                        "id: 12345678-1234-1234-1234-123456789012"
                    ),
                }
            })
            assert len(result.content) == 1
            payload = json.loads(result.content[0].text)
            assert payload["ok"] is True
            assert "errors" in payload

    async def test_call_tool_unknown_returns_structured_error(self):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.call_tool("nonexistent_tool_xyz", arguments={})
            assert len(result.content) == 1
            payload = json.loads(result.content[0].text)
            assert payload["error"] == "unknown_tool"

    async def test_call_tool_bare_arguments_fallback(self):
        """When event key is absent, arguments are passed directly as the event."""
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.call_tool("sigma_yara_lint", arguments={
                "rule_type": "sigma",
                "content": (
                    "title: Bare\n"
                    "logsource:\n  product: windows\n"
                    "detection:\n  sel:\n    EventID: 1\n  condition: sel\n"
                    "level: high\nstatus: test\n"
                    "id: 12345678-aaaa-bbbb-cccc-123456789012"
                ),
            })
            assert len(result.content) == 1
            payload = json.loads(result.content[0].text)
            assert payload["ok"] is True

    async def test_call_tool_detection_audit_empty_rules(self):
        from mcp_session import connected_session
        from sentinel_harness.mcp_server import create_server

        server, _ = create_server()
        async with connected_session(server) as session:
            result = await session.call_tool("detection_audit", arguments={
                "event": {"rules": []}
            })
            assert len(result.content) == 1
            payload = json.loads(result.content[0].text)
            assert isinstance(payload, dict)
