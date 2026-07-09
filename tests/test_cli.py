"""
Offline tests for the `sentinel` CLI
====================================
The CLI is the user-facing entry point (`sentinel create|invoke|list|delete|cleanup|
run-scenario`). Its config-translation logic (alias→model, tool-spec→builder,
memory-spec→config, flat-config→kwargs) is pure and deserves direct coverage; the
AWS-touching commands are tested with the core client monkeypatched so nothing leaves
the process.

HARD RULE: ZERO AWS. Dummy env is set before import (client construction is offline),
and `core` entry points are stubbed per-test.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import cli  # noqa: E402
from sentinel_harness import core as sh  # noqa: E402


# --------------------------------------------------------------------------- #
# _resolve_model — alias / passthrough / dict                                 #
# --------------------------------------------------------------------------- #
def test_resolve_model_alias():
    cfg = cli._resolve_model("sonnet")
    assert cfg["bedrockModelConfig"]["modelId"] == sh.MODEL_SONNET


def test_resolve_model_full_id_passthrough():
    cfg = cli._resolve_model("global.anthropic.some-future-model")
    assert cfg["bedrockModelConfig"]["modelId"] == "global.anthropic.some-future-model"


def test_resolve_model_none():
    assert cli._resolve_model(None) is None


def test_resolve_model_dict_is_returned_as_is():
    d = {"bedrockModelConfig": {"modelId": "x"}}
    assert cli._resolve_model(d) is d


# --------------------------------------------------------------------------- #
# _build_tool — every supported type + errors                                 #
# --------------------------------------------------------------------------- #
def test_build_tool_code_interpreter():
    t = cli._build_tool({"type": "code_interpreter"})
    assert t["type"] == "agentcore_code_interpreter"


def test_build_tool_inline():
    t = cli._build_tool({"type": "inline", "name": "gate",
                         "description": "d", "input_schema": {"type": "object"}})
    assert t["type"] == "inline_function" and t["name"] == "gate"


def test_build_tool_gateway_and_remote_mcp():
    g = cli._build_tool({"type": "gateway", "name": "gw",
                         "gateway_arn": "arn:aws:x:::gateway/g"})
    assert g["type"] == "agentcore_gateway"
    m = cli._build_tool({"type": "remote_mcp", "name": "intel",
                         "url": "https://example.org/mcp"})
    assert m["type"] == "remote_mcp"


def test_build_tool_unknown_type_raises():
    with pytest.raises(ValueError):
        cli._build_tool({"type": "banana"})


def test_build_tool_missing_type_raises():
    with pytest.raises(ValueError):
        cli._build_tool({"name": "x"})


# --------------------------------------------------------------------------- #
# _build_memory — managed vs bring-your-own                                   #
# --------------------------------------------------------------------------- #
def test_build_memory_managed():
    m = cli._build_memory({"strategies": ["SEMANTIC"], "expiry_days": 90})
    assert "managedMemoryConfiguration" in m


def test_build_memory_byo_uses_retrieval_config():
    """Regression: the CLI must pass retrieval_config (the current core.byo_memory
    knob), not the removed messages_count field."""
    m = cli._build_memory({"arn": "arn:aws:x:::memory/m",
                           "retrieval_config": {"topK": 5}})
    cfg = m["agentCoreMemoryConfiguration"]
    assert cfg["arn"] == "arn:aws:x:::memory/m"
    assert cfg["retrievalConfig"] == {"topK": 5}


def test_build_memory_none():
    assert cli._build_memory(None) is None


# --------------------------------------------------------------------------- #
# _config_to_kwargs — the flat legacy schema                                  #
# --------------------------------------------------------------------------- #
def test_config_to_kwargs_full():
    name, sysp, kwargs = cli._config_to_kwargs({
        "name": "sentinel_demo",
        "system_prompt": "you are a demo",
        "model": "haiku",
        "max_iterations": 12,
        "allowed_tools": ["a", "b"],
        "tools": [{"type": "code_interpreter"}],
        "memory": {"strategies": ["SEMANTIC"]},
    })
    assert name == "sentinel_demo"
    assert sysp == "you are a demo"
    assert kwargs["model"]["bedrockModelConfig"]["modelId"] == sh.MODEL_HAIKU
    assert kwargs["max_iterations"] == 12
    assert kwargs["allowed_tools"] == ["a", "b"]
    assert kwargs["tools"][0]["type"] == "agentcore_code_interpreter"


def test_config_to_kwargs_missing_required_raises():
    with pytest.raises(ValueError):
        cli._config_to_kwargs({"name": "x"})  # no system_prompt


# --------------------------------------------------------------------------- #
# _load_config — JSON works with pure stdlib                                  #
# --------------------------------------------------------------------------- #
def test_load_config_json(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"name": "x", "system_prompt": "y"}))
    assert cli._load_config(str(p)) == {"name": "x", "system_prompt": "y"}


def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        cli._load_config("/nonexistent/path/c.json")


def test_load_config_non_mapping_raises(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(ValueError):
        cli._load_config(str(p))


# --------------------------------------------------------------------------- #
# Parser wiring + command dispatch                                            #
# --------------------------------------------------------------------------- #
def test_parser_requires_a_subcommand():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_run_scenario_rejects_unknown_name(capsys):
    # argparse enforces the choices= list, so an unknown scenario exits non-zero.
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run-scenario", "does_not_exist"])


def test_list_command_offline(monkeypatch, capsys):
    monkeypatch.setattr(sh, "list_harnesses", lambda: [
        {"status": "READY", "harnessName": "sentinel_demo", "harnessId": "hid-1"}])
    rc = cli.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sentinel_demo" in out and "hid-1" in out


def test_cleanup_command_offline(monkeypatch, capsys):
    seen = {}
    def fake_cleanup(prefix):
        seen["prefix"] = prefix
        return ["sentinel_a", "sentinel_b"]
    monkeypatch.setattr(sh, "cleanup", fake_cleanup)
    rc = cli.main(["cleanup", "sentinel_"])
    assert rc == 0
    assert seen["prefix"] == "sentinel_"
    assert "deleted 2 harness(es)" in capsys.readouterr().out


def test_main_reports_error_and_exits_nonzero(monkeypatch, capsys):
    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setattr(sh, "list_harnesses", boom)
    rc = cli.main(["list"])
    assert rc == 1
    assert "kaboom" in capsys.readouterr().err


def test_region_override_sets_env(monkeypatch):
    monkeypatch.setattr(sh, "list_harnesses", lambda: [])
    cli.main(["--region", "eu-west-1", "list"])
    assert os.environ["SENTINEL_REGION"] == "eu-west-1"


def test_region_override_rebinds_boto3_client(monkeypatch):
    """--region must actually move the boto3 clients, not just set the env var.

    Regression for a silent no-op: the clients are built at import from
    SENTINEL_REGION, so setting the env var alone left calls on the old region.
    """
    monkeypatch.setattr(sh, "list_harnesses", lambda: [])
    original = sh._control.meta.region_name
    try:
        cli.main(["--region", "eu-west-1", "list"])
        assert sh._control.meta.region_name == "eu-west-1"
        assert sh._data.meta.region_name == "eu-west-1"
    finally:
        sh.set_region(original)  # restore so later tests keep the default region


def test_set_region_rejects_empty():
    with pytest.raises(ValueError):
        sh.set_region("")
