"""
Offline tests for the harness → Strands export (no-lock-in escape hatch)
========================================================================
``export_harness_to_strands`` turns a loaded harness config into editable Strands
Agent Python source. These tests assert the emitted artifact is:

  * valid, compilable Python (ast.parse + py_compile),
  * carries the model id, system prompt, and every allowedTool entry,
  * deterministic (byte-identical across runs),
  * emitted as TEXT — importing the exporter never pulls in `strands`.

Plus a CLI-level test: ``sentinel export harnesses/alert-triage/harness.yaml``
returns 0 and prints code (and writes it with ``-o``). All offline; the CLI's
AWS surface is not touched by export (it only reads a yaml).

HARD RULE: ZERO AWS, ZERO network. Runs fully offline.
"""
from __future__ import annotations

import ast
import os
import py_compile
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("SENTINEL_GATEWAY_ARN", "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/g")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import cli  # noqa: E402
from sentinel_harness.exporter import export_harness_to_strands  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ALERT_TRIAGE = os.path.join(_REPO_ROOT, "harnesses", "alert-triage", "harness.yaml")


# --------------------------------------------------------------------------- #
# fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def sample_config() -> dict:
    """A representative loaded-harness config (shape of load_harness_config)."""
    return {
        "name": "sentinel_alert_triage",
        "system_prompt": 'You are a Tier-1 SOC analyst.\nTriage alerts. Say "TP" or "FP".',
        "model": {
            "bedrockModelConfig": {
                "modelId": "global.anthropic.claude-haiku-4-5-20251001-v1:0",
                "maxTokens": 4096,
                "temperature": 0.1,
            }
        },
        "allowed_tools": [
            "code_interpreter",
            "@gateway/siem_query",
            "request_containment_approval",
        ],
        "memory": {
            "managedMemoryConfiguration": {
                "strategies": ["SEMANTIC", "SUMMARIZATION"],
                "eventExpiryDuration": 90,
            }
        },
        "max_iterations": 12,
        "timeout_seconds": 180,
    }


# --------------------------------------------------------------------------- #
# valid, compilable Python                                                    #
# --------------------------------------------------------------------------- #
def test_output_is_valid_python_ast(sample_config):
    code = export_harness_to_strands(sample_config)
    ast.parse(code)  # raises SyntaxError on failure


def test_output_py_compiles(sample_config, tmp_path):
    code = export_harness_to_strands(sample_config)
    f = tmp_path / "exported_agent.py"
    f.write_text(code)
    # doraise=True turns a compile failure into an exception.
    py_compile.compile(str(f), doraise=True)


# --------------------------------------------------------------------------- #
# content: model id + system prompt + each allowedTool                        #
# --------------------------------------------------------------------------- #
def test_includes_model_id(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "global.anthropic.claude-haiku-4-5-20251001-v1:0" in code
    # The full version suffix must survive (unversioned ids invoke-fail silently).
    assert "MODEL_ID" in code


def test_includes_system_prompt(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "Tier-1 SOC analyst" in code
    assert "SYSTEM_PROMPT" in code


def test_each_allowed_tool_present_as_comment_and_binding(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "ALLOWED_TOOLS = [" in code
    for tool in sample_config["allowed_tools"]:
        # As a documented comment line...
        assert f"#   - {tool}" in code
        # ...and as a real list binding entry (repr'd string).
        assert repr(tool) in code


def test_memory_note_emitted(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "SEMANTIC" in code
    assert "managed memory" in code.lower()


def test_loop_guardrails_noted(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "max_iterations  = 12" in code
    assert "timeout_seconds = 180" in code


def test_no_lock_in_documented(sample_config):
    code = export_harness_to_strands(sample_config)
    assert "NO-LOCK-IN" in code
    # Round-trip note: the artifact tells you how to run it off-harness.
    assert "pip install strands-agents" in code


# --------------------------------------------------------------------------- #
# determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_deterministic(sample_config):
    a = export_harness_to_strands(sample_config)
    b = export_harness_to_strands(dict(sample_config))
    assert a == b


# --------------------------------------------------------------------------- #
# emits text — never imports strands at runtime                               #
# --------------------------------------------------------------------------- #
def test_exporter_does_not_import_strands():
    # The module must not have pulled strands into sys.modules by importing it.
    assert "strands" not in sys.modules
    # And the emitted code carries the import as TEXT, to run later.
    code = export_harness_to_strands({"name": "x", "system_prompt": "hi"})
    assert "from strands import Agent" in code


# --------------------------------------------------------------------------- #
# edge shapes                                                                 #
# --------------------------------------------------------------------------- #
def test_minimal_config_still_valid_python():
    code = export_harness_to_strands({"name": "bare", "system_prompt": "do a thing"})
    ast.parse(code)
    assert "No memory was configured" in code


def test_bare_string_model_and_prompt_list():
    code = export_harness_to_strands({
        "name": "n",
        "system_prompt": [{"text": "line one"}, {"text": "line two"}],
        "model": "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    })
    ast.parse(code)
    assert "line one" in code and "line two" in code
    assert "global.anthropic.claude-sonnet-4-5-20250929-v1:0" in code


def test_byo_memory_note():
    code = export_harness_to_strands({
        "name": "n",
        "system_prompt": "p",
        "memory": {"agentCoreMemoryConfiguration": {"arn": "arn:aws:x:::memory/m"}},
    })
    ast.parse(code)
    assert "bring-your-own" in code and "arn:aws:x:::memory/m" in code


def test_system_prompt_with_triple_quotes_is_escaped():
    # A prompt containing the triple-quote delimiter must not break the literal.
    tricky = 'say """hello""" and a trailing backslash \\'
    code = export_harness_to_strands({"name": "n", "system_prompt": tricky})
    ast.parse(code)  # would raise if the string literal were malformed


# --------------------------------------------------------------------------- #
# CLI-level: sentinel export (offline — only reads a yaml)                     #
# --------------------------------------------------------------------------- #
def test_cli_export_prints_code(capsys):
    rc = cli.main(["export", _ALERT_TRIAGE])
    assert rc == 0
    out = capsys.readouterr().out
    assert "from strands import Agent" in out
    assert "SYSTEM_PROMPT" in out
    ast.parse(out)  # stdout is valid Python


def test_cli_export_by_harness_name(capsys):
    # A bare name maps to harnesses/<name>/harness.yaml.
    rc = cli.main(["export", "alert-triage"])
    assert rc == 0
    assert "from strands import Agent" in capsys.readouterr().out


def test_cli_export_writes_out_file(tmp_path):
    dest = tmp_path / "agent.py"
    rc = cli.main(["export", _ALERT_TRIAGE, "-o", str(dest)])
    assert rc == 0
    text = dest.read_text()
    ast.parse(text)
    assert "from strands import Agent" in text


def test_cli_export_unknown_harness_errors(capsys):
    rc = cli.main(["export", "no_such_harness_xyz"])
    assert rc == 1
    assert "could not resolve harness" in capsys.readouterr().err
