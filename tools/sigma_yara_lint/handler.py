"""sigma_yara_lint — deterministic detection-rule linter (reference template).

SecOps purpose
--------------
Before a detection engineer publishes a Sigma or YARA rule, a security
operations team wants a cheap, deterministic structural check: are the
required fields present, is the logic well-formed, does every condition
reference a defined selection? This tool provides that as PURE PYTHON.

This tool is intentionally DETERMINISTIC and LLM-FREE. It uses no model,
consumes no tokens, and makes no network calls. Same input always yields
the same output. That makes it safe to run as a mandatory gate in an
automated detection pipeline: an LLM may draft a rule, but this linter —
not another LLM — decides whether the rule is structurally valid.

What it checks
--------------
Sigma (implemented here, functional):
  - Valid YAML (uses PyYAML if available, else a minimal built-in parser).
  - Required top-level keys: ``title``, ``logsource``, ``detection``.
  - ``detection`` must contain a ``condition`` plus at least one selection.
  - Every identifier referenced in ``condition`` must be a defined
    selection (or the ``them``/``all of``/``1 of`` aggregates).
  - Warnings for missing recommended fields (``id``, ``level``, ``status``,
    ``logsource.product``/``category``).
  - ``level`` must be one of the Sigma-defined values when present.

YARA (implemented here, lightweight structural check):
  - Presence of at least one ``rule <name> { ... }`` block.
  - Each rule has a ``condition:`` section.
  - Balanced braces.
  - Warns if ``strings:`` is absent while the condition references ``$``.

Egress & secrets posture
------------------------
- ZERO egress. No network, no external services, no tokens.
- ZERO secrets. Nothing is read from credential storage.
- Execution role / region are referenced via
  ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and ``AWS_PROFILE``
  for consistency with the rest of the harness, though this tool needs no
  AWS access to run.

Input contract
--------------
event = {"rule_type": "sigma" | "yara", "content": "<rule text>"}

Output contract
---------------
{
    "ok": True,                 # True if the tool ran (not "rule is valid")
    "rule_type": "sigma",
    "valid": True | False,      # whether the rule passed all hard checks
    "errors": ["..."],          # hard failures (rule is invalid)
    "warnings": ["..."],        # non-fatal style/best-practice issues
}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

_VALID_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
_CONDITION_KEYWORDS = {
    "and", "or", "not", "of", "them", "all", "1", "any",
    "|", "count", "by", "gt", "gte", "lt", "lte", "near",
}


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
def _validate(event: Dict[str, Any]) -> Tuple[str, str]:
    """Validate input; return (rule_type, content)."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    rule_type = event.get("rule_type")
    if not isinstance(rule_type, str) or rule_type.lower() not in {"sigma", "yara"}:
        raise ValueError("'rule_type' must be one of: 'sigma', 'yara'")
    content = event.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("missing required non-empty string field 'content'")
    return rule_type.lower(), content


# --------------------------------------------------------------------------
# Minimal YAML parser fallback (only used if PyYAML is unavailable).
# Handles the subset of YAML that Sigma rules use: nested mappings by
# indentation, simple scalars, and inline/block lists. This keeps the tool
# dependency-free and fully offline.
# --------------------------------------------------------------------------
def _parse_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return _parse_yaml_minimal(text)


def _parse_yaml_minimal(text: str) -> Any:
    lines = [
        ln.rstrip()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]

    def scalar(v: str) -> Any:
        v = v.strip()
        if v == "":
            return None
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            return v[1:-1]
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            if not inner:
                return []
            return [scalar(x) for x in inner.split(",")]
        low = v.lower()
        if low in ("true", "false"):
            return low == "true"
        if low in ("null", "~"):
            return None
        try:
            return int(v)
        except ValueError:
            pass
        try:
            return float(v)
        except ValueError:
            pass
        return v

    def indent_of(ln: str) -> int:
        return len(ln) - len(ln.lstrip(" "))

    def parse_block(idx: int, min_indent: int) -> Tuple[Any, int]:
        # List block?
        if idx < len(lines) and lines[idx].lstrip().startswith("- "):
            result_list: List[Any] = []
            while idx < len(lines):
                cur = lines[idx]
                ci = indent_of(cur)
                if ci < min_indent or not cur.lstrip().startswith("- "):
                    break
                item = cur.lstrip()[2:].strip()
                result_list.append(scalar(item))
                idx += 1
            return result_list, idx

        result: Dict[str, Any] = {}
        while idx < len(lines):
            cur = lines[idx]
            ci = indent_of(cur)
            if ci < min_indent:
                break
            stripped = cur.strip()
            if ":" not in stripped:
                idx += 1
                continue
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest:
                result[key] = scalar(rest)
                idx += 1
            else:
                # Nested block belongs to this key.
                child_indent = ci + 1
                if idx + 1 < len(lines):
                    child_indent = indent_of(lines[idx + 1])
                child, idx = parse_block(idx + 1, child_indent)
                result[key] = child
        return result, idx

    parsed, _ = parse_block(0, 0)
    return parsed


# --------------------------------------------------------------------------
# Sigma linter
# --------------------------------------------------------------------------
def _lint_sigma(content: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    try:
        doc = _parse_yaml(content)
    except Exception as exc:  # surface parse failure, don't swallow
        return ([f"YAML parse error: {exc}"], warnings)

    if not isinstance(doc, dict):
        return (["rule must be a YAML mapping at the top level"], warnings)

    # Required top-level keys.
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            errors.append(f"missing required top-level key: '{key}'")

    # Recommended keys.
    for key in ("id", "level", "status"):
        if key not in doc:
            warnings.append(f"missing recommended key: '{key}'")

    # level value check.
    level = doc.get("level")
    if isinstance(level, str) and level.lower() not in _VALID_SIGMA_LEVELS:
        errors.append(
            f"invalid 'level': {level!r}; expected one of "
            f"{sorted(_VALID_SIGMA_LEVELS)}"
        )

    # logsource sanity.
    logsource = doc.get("logsource")
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("product", "category", "service")):
            warnings.append(
                "'logsource' should specify at least one of "
                "product/category/service"
            )
    elif "logsource" in doc:
        errors.append("'logsource' must be a mapping")

    # detection block.
    detection = doc.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("'detection' must contain a 'condition'")
        selections = [k for k in detection.keys() if k != "condition"]
        if not selections:
            errors.append(
                "'detection' must define at least one selection besides "
                "'condition'"
            )
        # Validate that condition identifiers reference defined selections.
        cond = detection.get("condition")
        if isinstance(cond, str):
            errors.extend(_check_condition_refs(cond, set(selections)))
        elif isinstance(cond, list):
            for c in cond:
                if isinstance(c, str):
                    errors.extend(_check_condition_refs(c, set(selections)))
    elif "detection" in doc:
        errors.append("'detection' must be a mapping")

    return errors, warnings


def _check_condition_refs(condition: str, selections: set) -> List[str]:
    """Ensure every identifier used in a condition is a defined selection."""
    errors: List[str] = []
    # Tokenize on operators / whitespace / parentheses / pipe.
    tokens = re.split(r"[\s()]+", condition.strip())
    for tok in tokens:
        if not tok:
            continue
        low = tok.lower()
        if low in _CONDITION_KEYWORDS:
            continue
        if low.isdigit():
            continue
        # Wildcard selection references like 'selection_*' — match by prefix.
        if tok.endswith("*"):
            prefix = tok[:-1]
            if any(s.startswith(prefix) for s in selections):
                continue
            errors.append(
                f"condition references undefined selection pattern: {tok!r}"
            )
            continue
        if tok not in selections:
            errors.append(f"condition references undefined selection: {tok!r}")
    return errors


# --------------------------------------------------------------------------
# YARA linter (lightweight structural check)
# --------------------------------------------------------------------------
def _lint_yara(content: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    open_braces = content.count("{")
    close_braces = content.count("}")
    if open_braces != close_braces:
        errors.append(
            f"unbalanced braces: {open_braces} '{{' vs {close_braces} '}}'"
        )

    rule_headers = re.findall(r"\brule\s+([A-Za-z_]\w*)\s*(?::[^{]*)?\{", content)
    if not rule_headers:
        errors.append("no 'rule <name> { ... }' block found")
        return errors, warnings

    # Split into rule bodies to inspect each.
    for name in rule_headers:
        body_match = re.search(
            r"\brule\s+" + re.escape(name) + r"\s*(?::[^{]*)?\{(.*?)\}",
            content,
            re.DOTALL,
        )
        body = body_match.group(1) if body_match else ""
        if "condition:" not in body:
            errors.append(f"rule {name!r} is missing a 'condition:' section")
        if "strings:" not in body and "$" in body:
            warnings.append(
                f"rule {name!r} references string identifiers ($) but has no "
                "'strings:' section"
            )
    return errors, warnings


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Deterministically lint a Sigma or YARA detection rule.

    Pure Python: no LLM, no tokens, no network, no secrets. Same input
    always produces the same output, making it safe as a mandatory gate in
    an automated detection pipeline.
    """
    try:
        rule_type, content = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    if rule_type == "sigma":
        errors, warnings = _lint_sigma(content)
    else:  # yara
        errors, warnings = _lint_yara(content)

    return {
        "ok": True,
        "rule_type": rule_type,
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


if __name__ == "__main__":
    import json

    sample = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""
    print(json.dumps(handler({"rule_type": "sigma", "content": sample}, None), indent=2))
