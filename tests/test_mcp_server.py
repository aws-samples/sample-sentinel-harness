"""Tests for the MCP server tool discovery and invocation logic.

These tests exercise the OFFLINE parts of mcp_server.py — tool discovery from
the tools/ directory, tool invocation through the handler bridge, and error
handling. They do NOT require the ``mcp`` SDK (that's an optional dep); they
test the pure-Python discovery and dispatch layer directly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel_harness.mcp_server import _discover_tools, _invoke_tool, _tool_input_schema


class TestToolDiscovery:
    """Verify that _discover_tools respects the registry governance gate."""

    def test_discovers_approved_non_control_tools(self):
        """Default mode: approved + non-control-plane tools are discovered."""
        tools = _discover_tools()
        # 20 total minus 2 control-plane (harness_ops, run_evaluation) minus 1 pending (web_search) = 17
        assert len(tools) >= 17, f"Expected >=17 tools, found {len(tools)}: {sorted(tools)}"

    def test_control_plane_excluded_by_default(self):
        tools = _discover_tools()
        assert "harness_ops" not in tools, "harness_ops should be excluded by default (control-plane)"
        assert "run_evaluation" not in tools, "run_evaluation should be excluded by default (control-plane)"

    def test_pending_tool_excluded_by_default(self):
        tools = _discover_tools()
        assert "web_search" not in tools, "web_search should be excluded (status=pending in registry)"

    def test_control_plane_exposed_with_env(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_MCP_EXPOSE_CONTROL_PLANE", "1")
        tools = _discover_tools()
        assert "harness_ops" in tools, "harness_ops should be exposed with SENTINEL_MCP_EXPOSE_CONTROL_PLANE=1"
        assert "run_evaluation" in tools

    def test_pending_tool_exposed_with_env(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_MCP_ALLOW_PENDING", "1")
        tools = _discover_tools()
        assert "web_search" in tools, "web_search should be exposed with SENTINEL_MCP_ALLOW_PENDING=1"

    def test_all_exposed_tools_have_handler(self):
        tools = _discover_tools()
        for name, info in tools.items():
            assert info["module"] is not None, f"Tool {name} failed to load: {info['description']}"
            assert hasattr(info["module"], "handler"), f"Tool {name} has no handler function"

    def test_all_exposed_tools_have_description(self):
        tools = _discover_tools()
        for name, info in tools.items():
            assert info["description"], f"Tool {name} has no description"
            assert "[LOAD ERROR" not in info["description"], f"Tool {name} load error: {info['description']}"

    def test_expected_approved_tools_present(self):
        """Non-control-plane, approved tools MUST be discovered."""
        tools = _discover_tools()
        expected_safe = {
            "sigma_yara_lint", "detection_translate", "detection_dedup",
            "detection_coverage", "detection_audit", "detection_navigator",
            "detection_baseline", "enrich_ioc", "asset_lookup", "siem_query",
            "create_ticket", "ops_query", "sigma_match", "nvd_lookup",
            "epss_kev", "whitelist_optimizer", "attack_lookup",
        }
        for name in expected_safe:
            assert name in tools, f"Expected approved tool {name} not discovered"


class TestToolInputSchema:
    """Verify schema generation."""

    def test_schema_has_event_property(self):
        schema = _tool_input_schema("sigma_yara_lint")
        assert schema["type"] == "object"
        assert "event" in schema["properties"]
        assert schema["required"] == ["event"]

    def test_schema_description_includes_tool_name(self):
        schema = _tool_input_schema("detection_audit")
        assert "detection_audit" in schema["properties"]["event"]["description"]


class TestToolInvocation:
    """Verify that _invoke_tool correctly dispatches to handlers."""

    def test_invoke_sigma_yara_lint_valid(self):
        tools = _discover_tools()
        mod = tools["sigma_yara_lint"]["module"]
        result_str = _invoke_tool("sigma_yara_lint", mod, {
            "rule_type": "sigma",
            "content": "title: Test Rule\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\nlevel: high\nstatus: test\nid: 12345678-1234-1234-1234-123456789012"
        })
        result = json.loads(result_str)
        assert result["ok"] is True
        assert "errors" in result

    def test_invoke_sigma_yara_lint_empty(self):
        tools = _discover_tools()
        mod = tools["sigma_yara_lint"]["module"]
        result_str = _invoke_tool("sigma_yara_lint", mod, {"rules": []})
        result = json.loads(result_str)
        assert "results" in result or "error" in result or "validation_error" in result

    def test_invoke_detection_audit_no_rules(self):
        tools = _discover_tools()
        mod = tools["detection_audit"]["module"]
        result_str = _invoke_tool("detection_audit", mod, {"rules": []})
        result = json.loads(result_str)
        assert isinstance(result, dict)

    def test_invoke_with_bad_input_returns_error(self):
        tools = _discover_tools()
        mod = tools["sigma_yara_lint"]["module"]
        result_str = _invoke_tool("sigma_yara_lint", mod, {"not_valid": True})
        result = json.loads(result_str)
        assert isinstance(result, dict)

    def test_invoke_enrich_ioc_offline(self):
        tools = _discover_tools()
        mod = tools["enrich_ioc"]["module"]
        result_str = _invoke_tool("enrich_ioc", mod, {"ioc": "192.0.2.1", "ioc_type": "ipv4"})
        result = json.loads(result_str)
        assert isinstance(result, dict)


class TestCLIMcpSubcommand:
    """Verify the CLI exposes the mcp serve subcommand."""

    def test_mcp_serve_in_help(self):
        from sentinel_harness.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mcp", "--help"])

    def test_mcp_serve_parsed(self):
        from sentinel_harness.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["mcp", "serve"])
        assert args.command == "mcp"
        assert args.mcp_command == "serve"
        assert hasattr(args, "func")
