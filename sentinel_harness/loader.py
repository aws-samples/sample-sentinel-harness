"""
sentinel-harness · YAML → harness config loader
================================================
Turns a shipped ``harnesses/<name>/harness.yaml`` into a kwargs dict ready for
``core.create_harness(**kwargs)`` — this is what makes the declarative harness
files *live* (via ``sentinel create <harness.yaml>``) rather than illustrative.

Design
------
- **12-factor.** ``${ENV_VAR}`` references inside string values are expanded from
  ``os.environ`` (an all-caps ``[A-Z0-9_]`` name). A missing env var raises a
  clear error naming it. Token-vault ``${arn:...}`` interpolation is left
  UNTOUCHED — those are resolved server-side by AgentCore Identity, not here.
- **systemPrompt.** If it is a path string it is read relative to the yaml's
  directory and returned as a plain string (``core.create_harness`` normalizes it
  to the GA ``[{"text": ...}]`` shape). If it is already a list it passes through.
- **Pass-through.** ``model`` / ``tools`` / ``memory`` / ``allowedTools`` are
  already in the shapes ``core`` and the control plane expect, so they pass
  through verbatim (mapped to the ``allowed_tools=`` kwarg name etc.).
- **inline_function gates.** A HITL gate (e.g. ``request_publish_approval``) is
  listed in ``allowedTools`` but its input schema lives in code, not config. The
  loader injects the matching inline tool definition into ``tools`` from a small
  built-in registry, so ``sentinel create`` wires the gate automatically. A yaml
  may also declare an inline tool explicitly (``type: inline_function`` with a
  ``config.inlineFunction`` block); that is respected and not double-injected.

No AWS calls happen here — ``load_harness_config`` is pure/offline; only
``create_from_config`` reaches the control plane (via ``core.create_harness``).

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import os
import re

from . import core

# ${NAME} where NAME is an all-caps env var (letters, digits, underscore, must
# start with a letter or underscore). This deliberately does NOT match
# ${arn:...} (lowercase + colon) so token-vault interpolation is left untouched.
_ENV_REF = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")

# Built-in inline_function HITL gates whose input schema lives in code. A yaml
# lists the gate name in `allowedTools`; the loader injects the matching tool
# definition into `tools` so `sentinel create` wires the pause-the-loop gate
# without the schema having to live in config. Keep in sync with the scenarios.
_INLINE_GATES: dict[str, dict] = {
    "request_publish_approval": {
        "description": (
            "Request analyst sign-off before publishing a detection rule to "
            "production. Carries the rule and the reviewer verdict; the analyst "
            "may hand-merge edits."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_title": {"type": "string"},
                "reviewer_verdict": {"type": "string"},
                "rule_yaml": {"type": "string"},
            },
            "required": ["rule_title", "reviewer_verdict"],
        },
    },
    "request_containment_approval": {
        "description": (
            "Request analyst sign-off before any containment action (isolate "
            "host / disable account / block indicator). The AI may only request "
            "containment, never execute it unattended."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "target": {"type": "string"},
                "justification": {"type": "string"},
            },
            "required": ["action", "target", "justification"],
        },
    },
    "request_human_review": {
        "description": (
            "Mandatory analyst review gate — high-stakes security decisions are "
            "not made by the AI alone. Pauses the loop and returns the call."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "recommendation": {"type": "string"},
            },
            "required": ["summary"],
        },
    },
    "request_promotion_approval": {
        "description": (
            "Request analyst sign-off before promoting a harness to production by "
            "creating a harness endpoint (CreateHarnessEndpoint). Carries the harness "
            "id, the intended endpoint name, and the rationale (passing score + what "
            "changed). The AI may only request promotion, never promote unattended."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "harness_id": {"type": "string"},
                "endpoint_name": {"type": "string"},
                "rationale": {"type": "string"},
            },
            "required": ["harness_id"],
        },
    },
}


# --------------------------------------------------------------------- env expand
def _expand_str(value: str, *, where: str) -> str:
    """Expand ``${ENV_VAR}`` refs in a single string. Missing var -> clear error.
    ``${arn:...}`` and other non-uppercase tokens are left untouched by the regex."""
    def _sub(m: re.Match) -> str:
        name = m.group(1)
        if name not in os.environ:
            raise KeyError(
                f"environment variable ${{{name}}} referenced by {where} is not set — "
                f"export it (12-factor config) before loading this harness."
            )
        return os.environ[name]

    return _ENV_REF.sub(_sub, value)


def _expand(node, *, where: str = "config"):
    """Recursively expand ${ENV_VAR} in every string value of a nested structure."""
    if isinstance(node, str):
        return _expand_str(node, where=where)
    if isinstance(node, dict):
        return {k: _expand(v, where=f"{where}.{k}") for k, v in node.items()}
    if isinstance(node, list):
        return [_expand(v, where=f"{where}[{i}]") for i, v in enumerate(node)]
    return node


# --------------------------------------------------------------------- yaml read
def _read_yaml(path: str) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "PyYAML is required to load harness.yaml files (pip install pyyaml)."
        ) from exc
    if not os.path.isfile(path):
        raise FileNotFoundError(f"harness config not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"harness config must be a mapping, got {type(data).__name__}")
    return data


def _resolve_system_prompt(system_prompt, harness_dir: str):
    """A path string -> read that file (relative to the yaml dir) and return its
    text (a string; core wraps it as [{"text": ...}]). An existing list passes
    through unchanged."""
    if isinstance(system_prompt, list):
        return system_prompt
    if not isinstance(system_prompt, str):
        raise ValueError(
            f"systemPrompt must be a path string or a list, got {type(system_prompt).__name__}"
        )
    # CONTAINMENT: the systemPrompt path must resolve to a file INSIDE harness_dir.
    # An absolute path or a '..' escape would let a malicious/mistaken harness.yaml
    # read any process-readable file and ship its contents to the model — reject
    # both. (Docstring: "read relative to the yaml's directory".)
    if os.path.isabs(system_prompt):
        raise ValueError(
            f"systemPrompt must be a path RELATIVE to the harness dir, got absolute "
            f"path {system_prompt!r}"
        )
    prompt_path = os.path.realpath(os.path.join(harness_dir, system_prompt))
    base = os.path.realpath(harness_dir)
    if prompt_path != base and not prompt_path.startswith(base + os.sep):
        raise ValueError(
            f"systemPrompt path {system_prompt!r} escapes the harness directory "
            f"(resolved to {prompt_path!r}); '..' traversal is not allowed"
        )
    if not os.path.isfile(prompt_path):
        raise FileNotFoundError(f"systemPrompt file not found: {prompt_path}")
    with open(prompt_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if not text.strip():
        raise ValueError(f"systemPrompt file is empty: {prompt_path}")
    return text


def _inject_inline_gates(tools: list, allowed_tools) -> list:
    """For every allowedTools entry that names a known inline HITL gate but is not
    already declared in `tools`, inject its inline_function definition from the
    registry so the gate is actually wired at create time."""
    declared = {t.get("name") for t in tools if isinstance(t, dict)}
    for entry in allowed_tools or []:
        # gateway-scoped tools use the @gateway/... grammar; those are not inline.
        if not isinstance(entry, str) or entry.startswith("@"):
            continue
        if entry in _INLINE_GATES and entry not in declared:
            gate = _INLINE_GATES[entry]
            tools.append(core.tool_inline(entry, gate["description"], gate["input_schema"]))
            declared.add(entry)
    return tools


# --------------------------------------------------------------------- public API
def load_harness_config(path: str) -> dict:
    """Load ``path`` (a harness.yaml) into kwargs ready for ``core.create_harness``.

    Returns a dict with keys: ``name``, ``system_prompt`` and the optional
    ``model`` / ``tools`` / ``memory`` / ``allowed_tools`` / ``max_iterations`` /
    ``timeout_seconds``. Makes NO AWS calls.
    """
    path = os.path.abspath(path)
    harness_dir = os.path.dirname(path)
    raw = _read_yaml(path)

    # Expand ${ENV_VAR} everywhere first (leaves ${arn:...} untouched).
    cfg = _expand(raw, where=os.path.basename(path))

    try:
        name = cfg["harnessName"]
    except KeyError as exc:
        raise ValueError(f"harness config missing required key: {exc}") from exc

    if "systemPrompt" not in cfg:
        raise ValueError("harness config missing required key: 'systemPrompt'")
    system_prompt = _resolve_system_prompt(cfg["systemPrompt"], harness_dir)

    tools = list(cfg.get("tools") or [])
    allowed_tools = cfg.get("allowedTools")
    # Validate allowedTools shape BEFORE using it (governance-critical):
    #  - it must be a list (a bare scalar string would be iterated CHARACTER by
    #    character in _inject_inline_gates, silently failing to wire a HITL gate);
    #  - '*' is FORBIDDEN (ironclad rule #1: allowedTools is always an explicit
    #    allowlist, never a wildcard that would grant every tool).
    if allowed_tools is not None:
        if not isinstance(allowed_tools, list):
            raise ValueError(
                f"allowedTools must be a list, got {type(allowed_tools).__name__} "
                f"({allowed_tools!r}); a bare scalar is a config error"
            )
        if "*" in allowed_tools:
            raise ValueError(
                "allowedTools must be an explicit allowlist — '*' (grant-all) is "
                "forbidden (ironclad rule #1)"
            )
    tools = _inject_inline_gates(tools, allowed_tools)

    kwargs: dict = dict(name=name, system_prompt=system_prompt)
    if cfg.get("model") is not None:
        kwargs["model"] = cfg["model"]
    if tools:
        kwargs["tools"] = tools
    if cfg.get("memory") is not None:
        kwargs["memory"] = cfg["memory"]
    if allowed_tools is not None:
        kwargs["allowed_tools"] = allowed_tools
    if cfg.get("maxIterations") is not None:
        kwargs["max_iterations"] = cfg["maxIterations"]
    if cfg.get("timeoutSeconds") is not None:
        kwargs["timeout_seconds"] = cfg["timeoutSeconds"]
    return kwargs


def create_from_config(path: str) -> dict:
    """Convenience: load ``path`` and create the harness. Reaches AWS."""
    return core.create_harness(**load_harness_config(path))
