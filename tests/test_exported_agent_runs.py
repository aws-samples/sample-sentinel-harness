"""INV-EXPORT-2 — exported agent code CONSTRUCTS against the real Strands SDK.

`sentinel export <harness>` is the no-lock-in promise: README, QUICKSTART and COMPARISON all
say you can walk off the managed harness with the emitted code. The entire value of that promise
is that the code **runs**.

`tests/test_exporter.py` is thorough about the text: valid AST, `py_compile` clean, model id
present, prompt escaped, deterministic output, no `strands` import at export time. All
necessary — and all satisfied by code that calls a constructor which does not exist, or passes a
keyword the SDK renamed. Syntax is not an API contract.

That gap is not hypothetical in this repo. INV-MCP-5 records `mcp` 2.0.0 removing
`Server.list_tools()` while `from mcp.server import Server` kept resolving — "an import check is
not a compatibility check". The exported code depends on exactly that kind of surface:

    from strands import Agent
    from strands.models import BedrockModel
    Agent(model=..., system_prompt=..., tools=[...])
    BedrockModel(model_id=..., max_tokens=..., temperature=...)

If a future `strands-agents` renames a keyword, the emitted code stops working and the only
place that surfaces is a user following the README — after they have committed to the migration.

Measured, all 8 shipped harnesses, against the pinned `strands-agents[a2a,litellm]==1.9.1` the
specialist containers use: 8/8 exec + `build_agent()` produce `Agent`/`BedrockModel`. This module
turns that from a fact into a check.

Why it lives here and not in `test_exporter.py`
-----------------------------------------------
It needs the real SDK, which is in no extra (see INV-PKG-1). It therefore skips locally and RUNS
in the `real-stack` CI job, where a skip is a hard failure. Keeping it in a separate module makes
that gating obvious rather than buried in a 20-test file that otherwise runs everywhere.

ZERO network, ZERO AWS: constructing a `BedrockModel` resolves no credentials and calls no API.
"""
from __future__ import annotations

import ast
import importlib.util
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESSES_DIR = os.path.join(REPO_ROOT, "harnesses")

# The exported code reads these at import time when the harness references them.
_TWELVE_FACTOR_ENV = {
    "SENTINEL_GATEWAY_ARN": "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test",
    "SENTINEL_GATEWAY_URL": "https://gw.example.internal/mcp",
    "SENTINEL_MEMORY_ID": "mem-test-000",
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/test",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
}

# Gated on the REAL SDK. `strands` is declared in no extra, so this skips on a normal dev machine
# and runs in the `real-stack` CI job — which treats any skip as a job failure (INV-PKG-1).
strands = pytest.importorskip(
    "strands", reason="needs the real specialist stack; runs in CI's `real-stack` job"
)


@pytest.fixture(autouse=True)
def _twelve_factor_env(monkeypatch):
    for key, value in _TWELVE_FACTOR_ENV.items():
        monkeypatch.setenv(key, value)


def _harness_names() -> list:
    return sorted(
        name for name in os.listdir(HARNESSES_DIR)
        if os.path.isfile(os.path.join(HARNESSES_DIR, name, "harness.yaml"))
    )


def _export(name: str) -> str:
    """Exported source for a harness, via the same code path the CLI uses."""
    from sentinel_harness.exporter import export_harness_to_strands
    from sentinel_harness.loader import load_harness_config

    cfg = load_harness_config(os.path.join(HARNESSES_DIR, name, "harness.yaml"))
    return export_harness_to_strands(cfg)


def _load_exported(name: str, source: str, tmp_path):
    """exec the exported code under a UNIQUE module name and return the module.

    Unique names matter: eight exported modules all define `build_agent`, and a shared name
    would let whichever loaded first win the `sys.modules` cache — the collision pattern the
    path-loaded tests in this repo already guard against.
    """
    path = tmp_path / f"exported_{name.replace('-', '_')}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(
        f"exported_agent_{name.replace('-', '_')}", str(path)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mentions_a_tool_name(node: ast.AST) -> bool:
    """Does this expression plausibly hold a TOOL NAME (as opposed to generated text)?

    Structural: collects identifiers and string literals from the subtree by node type, and asks
    whether any names a tool. Deliberately NOT `ast.dump()` + substring — see the comment at the
    call site and `test_r18_guard_the_guards.py::test_no_test_substring_matches_an_ast_dump`.
    """
    hints = {"name", "names", "tool", "tools", "gate", "gates", "entry", "allowed_tools"}
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id.lower() in hints:
            return True
        if isinstance(child, ast.Attribute) and child.attr.lower() in hints:
            return True
        # `t.get("name")` / `entry["name"]`
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if child.value.lower() in hints:
                return True
    return False


def test_the_sdk_surface_the_exporter_targets_exists():
    """Positive control AND the compatibility check, in the form INV-MCP-5 says is required.

    Not `importorskip` — the imports are exercised and the CALLABLES are inspected, because
    `from strands import Agent` succeeding says nothing about `Agent(model=..., system_prompt=...)`
    still being accepted. That distinction is exactly what let mcp 2.0 break this repo silently.
    """
    import inspect

    from strands import Agent
    from strands.models import BedrockModel

    agent_params = inspect.signature(Agent).parameters
    for required in ("model", "system_prompt", "tools"):
        assert required in agent_params, (
            f"strands.Agent no longer accepts `{required}` — the exported code passes it. "
            f"Accepted: {sorted(agent_params)}. Update sentinel_harness/exporter.py and this "
            "guard together."
        )

    model_params = inspect.signature(BedrockModel).parameters
    accepts_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD
                         for p in model_params.values())
    if not accepts_kwargs:
        for required in ("model_id", "max_tokens", "temperature"):
            assert required in model_params, (
                f"strands.models.BedrockModel no longer accepts `{required}`, and it takes no "
                f"**kwargs. Accepted: {sorted(model_params)}."
            )


@pytest.mark.parametrize("harness", _harness_names())
def test_exported_code_constructs_a_real_agent(harness, tmp_path):
    """The contract that makes the no-lock-in promise real: the emitted code RUNS.

    `test_exporter.py` proves the text compiles. This proves `build_agent()` returns a live
    `Agent` backed by a live model object, against the pinned SDK the containers ship.
    """
    module = _load_exported(harness, _export(harness), tmp_path)
    assert hasattr(module, "build_agent"), (
        f"exported code for {harness} has no build_agent(): {[n for n in dir(module) if not n.startswith('_')]}"
    )

    agent = module.build_agent()
    from strands import Agent
    assert isinstance(agent, Agent), (
        f"build_agent() returned {type(agent).__name__}, not a strands Agent"
    )
    assert agent.model is not None, "the constructed agent carries no model"
    assert type(agent.model).__name__ == "BedrockModel", (
        f"expected a BedrockModel, got {type(agent.model).__name__}"
    )


@pytest.mark.parametrize("harness", _harness_names())
def test_the_exported_agent_carries_the_configured_prompt_and_model(harness, tmp_path):
    """Constructing successfully is not enough — it must carry the HARNESS's configuration.

    An exporter that emitted a valid but empty agent would satisfy the test above while
    silently discarding the model id and system prompt, which are the whole payload of the
    migration. Checked against the config rather than against the generated text, so a
    formatting change cannot make this pass vacuously.
    """
    from sentinel_harness.loader import load_harness_config

    cfg = load_harness_config(os.path.join(HARNESSES_DIR, harness, "harness.yaml"))
    module = _load_exported(harness, _export(harness), tmp_path)

    assert module.MODEL_ID, f"{harness}: exported MODEL_ID is empty"
    assert module.SYSTEM_PROMPT.strip(), f"{harness}: exported SYSTEM_PROMPT is empty"

    # The model id must be the one the harness declares, not a default the exporter invented.
    declared = cfg.get("model")
    declared_id = declared.get("modelId") if isinstance(declared, dict) else declared
    if declared_id:
        assert module.MODEL_ID == declared_id, (
            f"{harness}: exported MODEL_ID is {module.MODEL_ID!r} but the harness declares "
            f"{declared_id!r} — the migration would run against the wrong model."
        )


@pytest.mark.parametrize("harness", _harness_names())
def test_a_human_gate_in_the_harness_is_warned_about_in_the_export(harness, tmp_path):
    """A safety property, not a smoke test.

    Several harnesses list human-in-the-loop approval tools in their allowlist. The exported
    code ships `tools=[]` for the user to fill in — so an operator who wires the business tools
    and skips the gates gets an agent taking high-stakes actions without the approval the
    harness required. The exporter emits a warning comment for exactly this; if that warning
    were dropped, the export would quietly become less safe than the harness it replaced.
    """
    source = _export(harness)
    from sentinel_harness.exporter import is_hitl_gate
    from sentinel_harness.loader import load_harness_config

    cfg = load_harness_config(os.path.join(HARNESSES_DIR, harness, "harness.yaml"))
    tools = cfg.get("tools") or []
    # Uses the PRODUCTION predicate, not a local re-implementation. My first version tested
    # `"approval" in name.lower()`, which happens to agree on all four shipped gates — and is a
    # second definition of a safety rule that would diverge the moment one is named differently.
    # A gate this checker misses is a gate the exported code does not warn about: a silent safety
    # regression in the artifact. `is_hitl_gate` was extracted from the exporter's inline
    # expression for exactly this reason.
    gate_names = [
        t.get("name", "") for t in tools
        if isinstance(t, dict) and is_hitl_gate(t.get("name", ""))
    ]
    if not gate_names:
        pytest.skip(f"{harness} declares no human-approval tool")

    assert "WARNING" in source, (
        f"{harness} declares human-approval gate(s) {gate_names} but the exported code carries "
        "no WARNING. Wiring the business tools without the gates yields an agent that acts "
        "without the analyst approval the harness required."
    )
    for gate in gate_names:
        assert gate in source, (
            f"{harness}: the exported warning does not name the gate {gate!r}, so a reader "
            f"cannot tell which tool must stay blocking.\n{source[:400]}"
        )


def test_the_hitl_gate_rule_has_ONE_implementation():
    """Guard the guard: no test may re-derive "is this a human-approval gate?".

    The rule decides whether the exported code carries a safety warning, so two implementations
    of it is two answers to a safety question. INV-COERCE records the same lesson for boolean
    coercion — three copies that agreed until one was edited.
    """
    from sentinel_harness import exporter

    assert callable(exporter.is_hitl_gate), "the canonical predicate is gone"

    # It must actually classify the shipped gates, or the "one implementation" is the wrong one.
    for gate in ("request_containment_approval", "request_publish_approval",
                 "request_promotion_approval"):
        assert exporter.is_hitl_gate(gate), f"{gate} is not recognised as a HITL gate"
    for business in ("siem_query", "create_ticket", "asset_lookup", "", None, 42):
        assert not exporter.is_hitl_gate(business), f"{business!r} misclassified as a gate"

    # And no test file may hand-roll the rule again — detected via AST, not text.
    #
    # My first version grepped for `'"approval" in'` and it FAILED on two false positives: this
    # file's own comment describing the anti-pattern, and the scanner's own literal. A substring
    # scan for "someone used a substring scan" is the same mistake one level up, and it is worth
    # recording rather than quietly fixing.
    #
    # The AST version asks the structural question: is there a comparison whose right side is a
    # name/attribute suggesting a TOOL NAME, testing membership of the literal "approval"? Text
    # inside comments and strings cannot match, because comments are not in the AST at all.
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    offenders = []
    for name in sorted(os.listdir(tests_dir)):
        if not name.startswith("test_") or not name.endswith(".py"):
            continue
        path = os.path.join(tests_dir, name)
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        if "is_hitl_gate" in source:
            continue  # already delegates to the canonical predicate
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover - the suite would not import either
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            if not any(isinstance(op, ast.In) for op in node.ops):
                continue
            if not (isinstance(node.left, ast.Constant)
                    and isinstance(node.left.value, str)
                    and node.left.value.lower() in ("approval", "approve")):
                continue
            # Right-hand side must look like it holds a TOOL NAME — `name`, `tool`,
            # `t.get("name")`, `entry.name.lower()`. `code.lower()` (generated TEXT) does not
            # qualify, which is why test_r10_semantic_gates.py is correctly not flagged.
            #
            # Inspected by NODE TYPE AND ATTRIBUTE, never by substring-matching `ast.dump()`.
            # My first version did exactly that, and `test_r18_guard_the_guards.py`'s
            # `test_no_test_substring_matches_an_ast_dump` failed it — correctly. `ast.dump()`
            # embeds `ctx=Load()` on every node, so a marker like 'load' matches any expression
            # and the matcher reports a clean tree while distinguishing nothing. I had written
            # "use the AST instead of substrings" and then substring-matched the AST's text dump.
            if _mentions_a_tool_name(node.comparators[0]):
                offenders.append(f"{name}:{node.lineno}")
    assert not offenders, (
        f"test file(s) classify a TOOL as a human-approval gate with a substring test instead "
        f"of calling `sentinel_harness.exporter.is_hitl_gate`: {offenders}. Two definitions of "
        "a safety rule agree until one is edited."
    )
